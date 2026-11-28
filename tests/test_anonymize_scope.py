"""去标识化范围回归用例 —— 对应验收报告第五节 D。

要求：同一组记录在匿名模式下的**任何**提示里都不能出现真实 uri 或参数，
否则"只看行为能否判读"的对照就被污染（2026-11-28 实测就踩了：
5/5 轮在第 2 步走了通用提示，看见了 36 条真实 uri）。
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap.agent import loop  # noqa: E402

REAL = ["/login.cgi", "/apply.cgi", "/save_log.cgi", "/set_sta_enrollee_pin.cgi"]
PARAMS = ["submit_button", "graph_id"]


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name
          + (("  " + str(detail)) if not cond else ""))
    return cond


def _state(anon: bool) -> dict:
    st = {
        "binary": "/x/sbin/httpd", "rootfs": "/x/root", "arch": "mips",
        "routes": len(REAL), "handlers": 1, "budget": 5,
        "candidates": list(REAL), "probed": {}, "evidence": {},
        "cand_meta": {u: list(PARAMS) for u in REAL},
        "probe_ready": True, "history": [], "findings": [],
        "model_enabled": True, "anonymize": anon, "alias": {},
    }
    for i, u in enumerate(REAL[:2]):
        st["probed"][u] = "handler" if i == 0 else "unknown"
        st["evidence"][u] = {"verdict": "handler" if i == 0 else "unknown",
                             "len": 1818 if i == 0 else 0, "snippet": "<html>"}
    st["history"] = [{"action": "pages", "ok": True},
                     {"action": "routes", "ok": True}]
    return st


def _leaks(text: str) -> list[str]:
    bad = [r for r in REAL if r in text]
    bad += [p for p in PARAMS if p in text]
    return bad


def main() -> int:
    ok = True

    anon = _state(True)
    brief = loop.state_brief(anon)
    ok &= check("匿名：state_brief 不含真实 uri 与参数",
                not _leaks(brief), _leaks(brief))
    ok &= check("匿名：state_brief 用编号", "/slot-" in brief, brief[:120])

    # 挑选提示
    seen = []

    def cap_chat(messages, **kw):
        seen.append(messages[-1]["content"])
        return '{"uri": "/slot-01", "why": "瞎挑"}'

    loop._decide_probe(anon, cap_chat)
    ok &= check("匿名：挑选提示不含真实 uri",
                seen and not _leaks(seen[0]), _leaks(seen[0]) if seen else "未调用")

    # 结论提示（异常项会让它进入 verdict 分支）
    seen2 = []

    def cap_chat2(messages, **kw):
        seen2.append(messages[-1]["content"])
        return '{"uri": "/slot-02", "kind": "crash", "why": "没响应", "evidence": []}'

    act = loop._decide_verdict(anon, cap_chat2)
    ok &= check("匿名：结论提示不含真实 uri",
                seen2 and not _leaks(seen2[0]),
                _leaks(seen2[0]) if seen2 else "未调用")
    ok &= check("匿名：结论被映射回真实 uri",
                bool(act) and act["args"]["uri"] in REAL,
                act["args"]["uri"] if act else None)

    # 具名模式反过来：必须看得见（否则对照就没有意义）
    named = _state(False)
    brief_n = loop.state_brief(named)
    ok &= check("具名：state_brief 含真实 uri", "/login.cgi" in brief_n)
    seen3 = []

    def cap_chat3(messages, **kw):
        seen3.append(messages[-1]["content"])
        return '{"uri": "/login.cgi", "why": "登录页"}'

    loop._decide_probe(named, cap_chat3)
    ok &= check("具名：挑选提示含真实 uri 与参数",
                seen3 and "/save_log.cgi" in seen3[0]
                and "submit_button" in seen3[0],
                seen3[0][:160] if seen3 else "未调用")

    # 通用提示里模型直接回了编号 —— 必须换回真实 uri，不能拿 /slot-01 去探
    generic = []

    def slot_chat(messages, **kw):
        generic.append(messages[-1]["content"])
        return '{"action": "probe", "args": {"uri": "/slot-02"}, "why": "随便挑"}'

    act2 = loop._decide(_state(True), slot_chat)
    ok &= check("通用提示里的编号被换回真实 uri",
                act2.get("action") == "probe"
                and act2["args"]["uri"] in REAL, act2)

    bad = []

    def bad_slot_chat(messages, **kw):
        bad.append(messages[-1]["content"])
        return '{"action": "probe", "args": {"uri": "/slot-99"}}'

    act3 = loop._decide(_state(True), bad_slot_chat)
    ok &= check("不在候选里的编号会被拒（退回规则）",
                act3.get("_source") == "heuristic", act3)

    print()
    print("PASS（去标识化范围）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
