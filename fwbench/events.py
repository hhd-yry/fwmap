"""事件：按步记录、归一化、旧字段兼容。

一个事件至少包含：run_id / case_id / repeat / seq / decision / type
/ tool 或动作名 / evidence_ids / ok / elapsed_ms / proposed_by。

三种类型：`decision`（选了哪一步）、`tool_result`（工具返回了什么）、
`submission`（最终提交了什么）。
"""

from __future__ import annotations

import json
import os
import time

__all__ = ["EventLog", "read_events", "normalize"]

TYPES = ("decision", "tool_result", "submission")


class EventLog:
    def __init__(self, path: str, run_id: str, case_id: str, repeat: int = 1):
        self.path = path
        self.run_id = run_id
        self.case_id = case_id
        self.repeat = repeat
        self.seq = 0
        self.decision = 0
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._fh = open(path, "a", encoding="utf-8")

    def emit(self, etype: str, **fields) -> dict:
        if etype not in TYPES:
            raise ValueError(f"未知事件类型：{etype}")
        self.seq += 1
        ev = {"schema_version": 1, "run_id": self.run_id,
              "case_id": self.case_id, "repeat": self.repeat,
              "seq": self.seq, "decision": self.decision, "type": etype,
              "ts": round(time.time(), 3)}
        ev.update({k: v for k, v in fields.items() if v is not None})
        self._fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
        self._fh.flush()
        return ev

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:                                    # noqa: BLE001
            pass


def read_events(path: str) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def normalize(ev: dict) -> dict:
    """旧记录兼容：缺字段补成 unknown，不猜。"""
    out = dict(ev)
    for key in ("proposed_by", "executed_by_policy", "fallback_reason"):
        out.setdefault(key, "unknown")
    out.setdefault("evidence_ids", [])
    out.setdefault("ok", None)
    return out
