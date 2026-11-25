"""P0-2 的测试：triage 默认开模型，模型不可用时显式降级。

不跑 Ghidra（太慢），把重活都打桩，只验证三件事：
  1. `triage()` 的 use_agent 默认是 True；
  2. 模型不可用 → 打降级日志、写 agent_error、流程继续；
  3. 模型可用 → 真的会去调 _agent。
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import triage  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


class _FakeTarget:
    rel_path = "bin/webs"
    abs_path = ""          # 由 main() 填成真实临时文件（triage 会 getsize）
    score = 90
    role = "web"
    arch = "mips"
    size = 1000


def _stub_pipeline(bin_path: str):
    """把 scan/m2/_m3 全部打桩，只留 agent 分支。返回需要恢复的原函数。"""
    _FakeTarget.abs_path = bin_path
    saved = (triage.scan, triage.m2_extract, triage._m3)

    triage.scan = lambda rootfs: type("R", (), {"targets": [_FakeTarget()]})()
    triage.m2_extract = lambda p: {"strategy": "inventory", "endpoints": []}
    triage._m3 = lambda p, lim, force=False: {
        "chains": [{"function": "f", "address": "0x1", "source_api": "websGetVar",
                    "source_param": "cmd", "sink": "system", "sink_category": "cmd",
                    "sink_args": "cmd", "guard": "", "via": "", "weak": False,
                    "induced_sink": "", "induced_source": "", "bounded_copy": False,
                    "confidence": 0.5, "hops": 1, "verdict": "keep", "reason": ""}],
        "sink_verified": 0}
    return saved


def _restore(saved):
    triage.scan, triage.m2_extract, triage._m3 = saved


def main() -> int:
    ok = True
    import inspect
    import tempfile

    tmp = tempfile.mkdtemp(prefix="fwmap-llm-")
    rootfs = os.path.join(tmp, "root")
    os.makedirs(os.path.join(rootfs, "bin"), exist_ok=True)
    binp = os.path.join(rootfs, "bin", "webs")
    with open(binp, "wb") as fh:
        fh.write(b"\x7fELF" + b"\x00" * 900)
    saved = _stub_pipeline(binp)

    ok &= check("use_agent 默认 True",
                inspect.signature(triage.triage).parameters["use_agent"].default is True)

    # ---- 模型不可用：降级 ----
    logs, called = [], {"n": 0}

    def _not_ready():
        return "没找到本地模型（测试桩）"

    def _should_not_run(*a, **k):
        called["n"] += 1
        return []

    old_ready, old_agent = triage._agent_ready, triage._agent
    triage._agent_ready, triage._agent = _not_ready, _should_not_run
    try:
        out = triage.triage(rootfs, os.path.join(tmp, "o1"), binaries=1,
                            log=logs.append, use_verify=False, use_auth=False)
        b = out["binaries"][0]
        ok &= check("降级时不调用 _agent", called["n"] == 0, called)
        ok &= check("写了 agent_error", "降级" in (b.get("agent_error") or ""), b.get("agent_error"))
        ok &= check("日志里能看到降级", any("降级为纯规则" in x for x in logs),
                    [x for x in logs if "LLM" in x][:2])
    finally:
        triage._agent_ready, triage._agent = old_ready, old_agent

    # ---- 模型可用：真的调用 ----
    called.clear()
    called["n"] = 0

    def _ready():
        return ""

    def _fake_agent(*a, **k):
        called["n"] += 1
        return [{"chain": {"function": "f", "address": "0x1",
                           "source_api": "websGetVar", "source_param": "cmd",
                           "sink": "system", "sink_category": "cmd", "hops": 1,
                           "verdict": "keep", "confidence": 0.5, "reason": ""},
                 "judge": {"verdict": "REFUTED", "confidence": "high",
                           "reason": "测试桩"}}]

    old_ready, old_agent = triage._agent_ready, triage._agent
    triage._agent_ready, triage._agent = _ready, _fake_agent
    try:
        logs2 = []
        out2 = triage.triage(rootfs, os.path.join(tmp, "o2"), binaries=1,
                             log=logs2.append, use_verify=False, use_auth=False)
        b2 = out2["binaries"][0]
        ok &= check("可用时调用 _agent", called["n"] == 1, called)
        ok &= check("没有降级标记", not b2.get("agent_error"), b2.get("agent_error"))
        ok &= check("日志里能看到 LLM 复核", any("LLM 复核" in x for x in logs2),
                    [x for x in logs2 if "LLM" in x][:2])
    finally:
        triage._agent_ready, triage._agent = old_ready, old_agent

    # ---- --no-llm：完全不碰模型 ----
    called.clear()
    called["n"] = 0
    old_agent = triage._agent
    triage._agent = _fake_agent
    try:
        out3 = triage.triage(rootfs, os.path.join(tmp, "o3"), binaries=1,
                             use_agent=False, log=lambda *_: None,
                             use_verify=False, use_auth=False)
        ok &= check("--no-llm 时不调用", called["n"] == 0, called)
        ok &= check("--no-llm 时没有 agent_error",
                    not out3["binaries"][0].get("agent_error"))
    finally:
        triage._agent = old_agent

    _restore(saved)
    import shutil

    shutil.rmtree(tmp, ignore_errors=True)
    print()
    print("PASS（默认开模型 + 显式降级）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
