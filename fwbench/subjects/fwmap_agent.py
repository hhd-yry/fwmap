"""把 fwmap 的**生产决策循环**接成被测工具（run_subject 适配器）。

为什么这样接：`fwmap plan` 的决策函数是 `fwmap.agent.loop._decide(state, chat)`
——模型可用就用模型、否则退回 `_heuristic`，返回带 `_source` 的动作。
这里不重写决策，**直接调它**；只做两件适配：

1. 把 bench 的记录 id 映射成 fwmap 眼里的"候选端点"（`/e2`），
   `probe` 动作落到只读后端 `read_record`；
2. 把 fwmap 的产出（读了哪些记录、走了哪个分支）映射成 bench 的提交格式。

因此本适配器的分数标 `adapted`：**决策是生产的，执行是评测器的**。
"""

from __future__ import annotations

from . import SubjectBase

__all__ = ["FwmapAgentSubject"]


class FwmapAgentSubject(SubjectBase):
    subject_id = "fwmap-agent"
    version = "0.1.0"
    capability = "record-triage"
    requires = "fwmap（本仓库）"
    supports_interactive = True

    @classmethod
    def available(cls) -> tuple[bool, str]:
        try:
            from fwmap.agent import loop  # noqa: F401
            return True, ""
        except Exception as exc:                             # noqa: BLE001
            return False, f"导入 fwmap.agent.loop 失败：{type(exc).__name__}"

    def inspect_elf(self, data: bytes) -> dict:              # 不声明 elf-meta 能力
        return {"ok": False, "error": "unsupported", "fields": {}}

    # ------------------------------------------------------------------
    def run_interactive(self, case, backend, limits: dict, chat=None) -> dict:
        """返回 {events, submission, stop_reason, decisions, tool_calls}。"""
        from fwmap.agent import loop

        ids = [c["id"] for c in case.catalog]
        state = {
            "binary": "bench-subject", "rootfs": None, "arch": "",
            "routes": len(ids), "handlers": 0,
            "history": [{"action": "pages", "ok": True},
                        {"action": "routes", "ok": True}],
            "budget": limits["decisions"],
            "candidates": [f"/{i}" for i in ids],
            "probed": {}, "cand_meta": {}, "evidence": {},
            "probe_ready": True, "rejects": [], "last_reject": "",
            "anonymize": False, "model_enabled": chat is not None,
            "findings": [], "alias": {},
        }

        events, submission = [], None
        stop_reason, used_tools = "budget_exhausted", 0
        for step in range(1, limits["decisions"] + 1):
            state["budget"] = limits["decisions"] - step + 1
            act = loop._decide(state, chat)                  # ← 生产决策
            src = act.pop("_source", "model")
            mode = act.pop("_mode", "action")
            why = str(act.get("why") or "")

            if act.get("action") == "done":
                events.append({"type": "decision", "action": "done",
                               "proposed_by": src, "executed_by_policy": src,
                               "fallback_reason": why or None, "mode": mode})
                stop_reason = "done"
                break

            if act.get("action") != "probe":
                # 生产循环还能选 pages/routes；bench 只有只读记录，记下来不执行
                events.append({"type": "decision",
                               "action": str(act.get("action")),
                               "proposed_by": src, "executed_by_policy": None,
                               "fallback_reason": "unsupported_action_by_bench",
                               "mode": mode})
                continue

            if used_tools >= limits["tool_calls"]:
                events.append({"type": "decision", "action": "probe",
                               "proposed_by": src, "executed_by_policy": None,
                               "fallback_reason": "tool_budget_exhausted"})
                continue

            uri = str(act["args"].get("uri"))
            rid = uri.lstrip("/")
            result = backend.dispatch({"tool": "read_record", "id": rid})
            used_tools += 1
            events.append({"type": "decision", "action": f"read:{rid}",
                           "proposed_by": src, "executed_by_policy": src,
                           "mode": mode})
            events.append({"type": "tool_result", "tool": "read_record",
                           "ok": bool(result.get("ok")),
                           "evidence_ids": result.get("evidence_ids") or [],
                           "error": result.get("error"),
                           "content": result.get("content")})
            if result.get("ok"):
                rec = result.get("content") or {}
                state["probed"][uri] = "read"
                state["evidence"][uri] = {"verdict": "read", "len": 1,
                                          "status": None,
                                          "snippet": str(rec.get("message") or "")[:40]}

        # 输出映射：谁读过、哪条记录的主体与任务一致，就按它作答
        read = {e["evidence_ids"][0]: e.get("content") or {}
                for e in events if e["type"] == "tool_result" and e.get("ok")}
        claim, cites, subject, when = None, [], None, None
        for rid, rec in read.items():
            subj = str(rec.get("subject") or "")
            if rec.get("state") and subj and subj in case.task:
                claim, cites, subject = rec["state"], [rid], subj
                when = rec.get("sample_time")
                break
        submission = ({"outcome": "answered", "claim": claim, "subject": subject,
                       "sample_time": when, "citations": cites}
                      if claim else
                      {"outcome": "abstained", "claim": None, "subject": None,
                       "sample_time": None, "citations": []})
        return {"events": events, "submission": submission,
                "stop_reason": stop_reason,
                "decisions": min(len(events), limits["decisions"]),
                "tool_calls": used_tools}
