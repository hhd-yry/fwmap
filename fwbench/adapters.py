"""适配器：只读工具后端 + 被测策略（rule / scripted）。

关键约束（来自实施计划）：

* 回放后端必须**按请求取材料**，不能不看请求就依次发预制答案；
* 初始视图只给材料元信息（id/type），不含内容和答案；
* 策略只能通过 `dispatch` 拿数据，拿到什么就记什么，供评分器核对引用。
"""

from __future__ import annotations

import random

from .cases import Case

__all__ = ["ReplayBackend", "RulePolicy", "ScriptedPolicy", "backend_for"]


class ReplayBackend:
    """只读回放后端：按 id 返回记录，记录本轮已经给过哪些证据。"""

    def __init__(self, records: dict[str, dict], seed: int = 0):
        self._records = records
        self._served: set[str] = set()
        self._order = sorted(records)
        rnd = random.Random(seed)
        self._order = rnd.sample(self._order, k=len(self._order))
        self._pos = 0
        self.calls = 0

    def dispatch(self, request: dict) -> dict:
        self.calls += 1
        tool = request.get("tool")
        if tool != "read_record":
            return {"ok": False, "error": f"未知工具：{tool!r}"}
        rid = str(request.get("id") or "")
        if rid not in self._records:
            return {"ok": False, "error": f"没有这条记录：{rid}"}
        rec = self._records[rid]
        self._served.add(rid)
        return {"ok": True, "evidence_ids": [rid],
                "content": {k: v for k, v in rec.items() if k != "id"}}

    def next_unread(self) -> str | None:
        """给降级策略用：按本轮随机顺序取一条还没读的。"""
        while self._pos < len(self._order):
            rid = self._order[self._pos]
            self._pos += 1
            if rid not in self._served:
                return rid
        return None

    @property
    def served(self) -> set[str]:
        return set(self._served)


class _Policy:
    name = "base"
    uses_model = False

    def attach(self, case: Case, backend: ReplayBackend) -> None:
        self.case = case
        self.backend = backend
        self.read: dict[str, dict] = {}

    def act(self, step: int, budget_left: dict) -> dict:
        raise NotImplementedError

    def observe(self, action: dict, result: dict) -> None:
        if result.get("ok"):
            for rid in result.get("evidence_ids") or []:
                self.read[rid] = result.get("content") or {}


class ScriptedPolicy(_Policy):
    """S：固定序列，只用于冒烟 —— 验证管线与评分，不代表任何能力。"""

    name = "scripted"
    uses_model = False

    def __init__(self, ids: list[str] | None = None):
        self._ids = ids or ["e1", "e2"]
        self._i = 0

    def act(self, step: int, budget_left: dict) -> dict:
        if self._i < len(self._ids) and budget_left["tool_calls"] > 0:
            rid = self._ids[self._i]
            self._i += 1
            return {"type": "read", "tool": "read_record", "id": rid}
        return self._submit()

    def _submit(self) -> dict:
        # 从已读记录里挑第一条带 state 的，照抄 —— 这就是"脚本能力"
        claim, cites, subject, when = "unknown", [], None, None
        for rid, rec in self.read.items():
            if rec.get("state"):
                claim = rec["state"]
                cites = [rid]
                subject, when = rec.get("subject"), rec.get("sample_time")
                break
        return {"type": "submit", "submission": {
            "outcome": "answered", "claim": claim, "subject": subject,
            "sample_time": when, "citations": cites}}


class RulePolicy(_Policy):
    """R：冻结的规则表 —— 先读 process_sample 类型的记录，再照它作答。

    规则表只在开发集上写一次就冻结，不针对单例调整。
    """

    name = "rule"
    uses_model = False
    PREFERRED_TYPE = "process_sample"

    def __init__(self):
        self._phase = "read"

    def act(self, step: int, budget_left: dict) -> dict:
        # 规则 1：已有"主体出现在任务描述里"的进程记录 → 直接作答
        if self._ready():
            return self._submit()
        # 规则 2：优先读 process_sample；读不到再退回任何未读记录
        if budget_left["tool_calls"] > 0:
            for item in self.case.catalog:
                rid = item["id"]
                if item.get("type") == self.PREFERRED_TYPE and rid not in self.read:
                    return {"type": "read", "tool": "read_record", "id": rid}
            nxt = self.backend.next_unread()
            if nxt:
                return {"type": "read", "tool": "read_record", "id": nxt}
        return self._submit()

    def _ready(self) -> bool:
        """任务描述里出现了哪台机器，就以那台的记录为准。"""
        task = self.case.task
        for rec in self.read.values():
            if rec.get("type") != self.PREFERRED_TYPE:
                continue
            subject = str(rec.get("subject") or "")
            if subject and subject in task and rec.get("state"):
                return True
        return False

    def _submit(self) -> dict:
        task = self.case.task
        for rid, rec in self.read.items():
            if rec.get("type") != "process_sample" or not rec.get("state"):
                continue
            subject = str(rec.get("subject") or "")
            if subject and subject in task:
                return {"type": "submit", "submission": {
                    "outcome": "answered", "claim": rec["state"],
                    "subject": rec.get("subject"),
                    "sample_time": rec.get("sample_time"),
                    "citations": [rid]}}
        return {"type": "submit", "submission": {
            "outcome": "abstained", "claim": None, "subject": None,
            "sample_time": None, "citations": []}}


def backend_for(records: dict[str, dict], seed: int = 0) -> ReplayBackend:
    return ReplayBackend(records, seed=seed)


POLICIES = {"rule": RulePolicy, "scripted": ScriptedPolicy}


def make_policy(name: str) -> _Policy:
    if name not in POLICIES:
        raise ValueError(f"未知策略：{name}（可选 {', '.join(POLICIES)}）")
    return POLICIES[name]()
