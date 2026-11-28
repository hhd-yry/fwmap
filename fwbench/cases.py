"""用例装载、校验与公开视图。

三条硬规矩（都会让实验失效，所以代码里直接强校验）：

1. **公开视图不能带答案**：catalog 只给 id 和 type，不给内容；
2. **金标不进公开视图**：oracle 由评分器单独加载，runner 拿不到；
3. **文件名/编号不编码语义**：case_id 用随机编号，不含 "exited"/"running"。
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field

from . import SCHEMA_VERSION

__all__ = ["Case", "load_suite", "load_oracle", "validate_suite", "digest"]

ANSWER_HINTS = ("exit", "run", "dead", "alive", "ok", "fail", "crash")


class CaseError(ValueError):
    pass


@dataclass
class Case:
    case_id: str
    family: str
    pair_id: str
    task: str
    catalog: list[dict]
    fixture_ref: str
    limits: dict = field(default_factory=dict)

    def public(self) -> dict:
        """给被测系统看的视图 —— 只有元信息，没有内容、没有答案。"""
        return {
            "case_id": self.case_id,
            "task": self.task,
            "catalog": [{"id": c["id"], "type": c["type"]} for c in self.catalog],
            "limits": dict(self.limits),
        }


def digest(obj) -> str:
    raw = json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def _read_json(path: str):
    with open(path, encoding="utf-8-sig") as fh:
        return json.load(fh)


def validate_suite(path: str) -> list[str]:
    """返回问题列表；空列表表示通过。"""
    problems: list[str] = []
    try:
        doc = _read_json(path)
    except (OSError, ValueError) as exc:
        return [f"{path}: 读不了（{exc}）"]

    if doc.get("schema_version") != SCHEMA_VERSION:
        problems.append(f"schema_version 应为 {SCHEMA_VERSION}，实际 "
                        f"{doc.get('schema_version')!r}")
    cases = doc.get("cases")
    if not isinstance(cases, list) or not cases:
        return problems + ["cases 必须是非空数组"]

    seen = set()
    for i, c in enumerate(cases):
        where = f"cases[{i}]"
        for key in ("case_id", "family", "pair_id", "task", "catalog",
                    "fixture_ref", "limits"):
            if key not in c:
                problems.append(f"{where}: 缺字段 {key}")
        cid = str(c.get("case_id", ""))
        if cid in seen:
            problems.append(f"{where}: case_id 重复（{cid}）")
        seen.add(cid)
        low = cid.lower()
        if any(h in low for h in ANSWER_HINTS):
            problems.append(f"{where}: case_id 含答案暗示（{cid}）")

        cat = c.get("catalog") or []
        if not isinstance(cat, list) or len(cat) < 2:
            problems.append(f"{where}: catalog 至少要两条记录")
        ids = [x.get("id") for x in cat if isinstance(x, dict)]
        if len(ids) != len(set(ids)):
            problems.append(f"{where}: catalog 的 id 重复")

        lim = c.get("limits") or {}
        for key in ("decisions", "tool_calls"):
            if not isinstance(lim.get(key), int) or lim.get(key) <= 0:
                problems.append(f"{where}: limits.{key} 必须是正整数")
    return problems


def load_suite(path: str) -> list[Case]:
    doc = _read_json(path)
    out = []
    for c in doc["cases"]:
        out.append(Case(case_id=c["case_id"], family=c["family"],
                        pair_id=c["pair_id"], task=c["task"],
                        catalog=list(c["catalog"]),
                        fixture_ref=c["fixture_ref"],
                        limits=dict(c.get("limits") or {})))
    return out


def load_oracle(path: str) -> dict[str, dict]:
    """金标只在评分阶段加载，runner 拿不到这个文件。"""
    doc = _read_json(path)
    return {row["case_id"]: row for row in doc["cases"]}


def load_fixture(fixtures_dir: str, ref: str) -> dict[str, dict]:
    """加载一个夹具目录下的所有记录：{id: 内容 dict}。"""
    folder = os.path.join(fixtures_dir, ref)
    if not os.path.isdir(folder):
        raise CaseError(f"夹具目录不存在：{folder}")
    out = {}
    for name in sorted(os.listdir(folder)):
        if not name.endswith(".json"):
            continue
        rec = _read_json(os.path.join(folder, name))
        rid = rec.get("id") or os.path.splitext(name)[0]
        out[rid] = rec
    return out
