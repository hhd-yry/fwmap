"""「模型提议 + 规则兜底」的离线测试。

不加载真模型：把 `llm.chat` 换成假的，专门验证**兜底逻辑**——
模型选错、答非所问、想提前收工，程序都得自己扛住。

为什么这块必须测：模型选错一次的代价是等 Ghidra 跑十分钟，
所以「校验不过就退规则」这条路径比「模型选对」更重要。
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import planner  # noqa: E402
from fwmap import tools_api as T  # noqa: E402
from fwmap.agent import llm as L  # noqa: E402
from fwmap.agent import planner_llm as PL  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def fake_reply(text: str):
    L.chat = lambda *a, **k: text                      # noqa: ARG005


def main() -> int:
    ok = True
    real_chat = L.chat
    state = {"rootfs": "C:/fw/root", "checked": True, "check_clean": True,
             "targets": [{"path": "bin/webs", "score": 87}],
             "binary": "C:/fw/root/bin/webs", "chains": [], "llm_seen": set(),
             "plugins_done": set()}
    cat = T.catalog()

    try:
        # 1) 模型给出合法工具
        fake_reply('{"tool": "scan", "args": {}, "why": "先排序"}')
        act = PL.choose(state, cat, log=lambda *_: None)
        ok &= check("模型选了合法工具", act and act["tool"] == "scan", act)
        ok &= check("标记来源是 llm", act and act["source"] == "llm", act)

        # 2) 模型编了不存在的工具 → 返回 None，由调用方退回规则
        fake_reply('{"tool": "rm_rf", "why": "乱来"}')
        ok &= check("不存在的工具 → 拒绝", PL.choose(state, cat) is None)

        # 3) 答非所问（没有 JSON）
        fake_reply("我觉得应该先扫描一下比较好")
        ok &= check("解析不出 JSON → 拒绝", PL.choose(state, cat) is None)

        # 4) done 的判定
        fake_reply('{"done": true, "why": "没活了"}')
        act = PL.choose(state, cat)
        ok &= check("done 被识别", act and act.get("done") is True, act)

        # 5) 硬校验：重复动作 / 依赖没满足
        okb, why = PL.allowed_by_state({"tool": "check", "kwargs": {}}, state)
        ok &= check("重复 check 被拦", okb is False and "做过" in why, why)
        okb, why = PL.allowed_by_state({"tool": "m2", "kwargs": {}},
                                       {**state, "binary": None})
        ok &= check("没目标就 m2 被拦", okb is False, why)

        # 6) 模型说停，但规则认为还有活 → 按规则继续
        fake_reply('{"done": true, "why": "我累了"}')
        state2 = dict(state, chains=[], verified=False, skip_ghidra=False)
        act = planner._next_action(state2, True, None, lambda *_: None)
        ok &= check("模型想停但规则不放 → 继续", act and act["tool"] == "m2", act)

        # 7) 模型选的工具参数由程序注入（不采信模型给的路径）
        fake_reply('{"tool": "m3", "args": {"binary": "C:/evil/path", "limit": 3}, '
                   '"why": "跑数据流"}')
        act = PL.choose(state2, cat)
        act = planner._hydrate(act, state2)
        ok &= check("路径由程序注入，不用模型给的",
                    act["kwargs"]["binary"] == state2["binary"], act["kwargs"])

        # 8) 模型加载失败 → 自动退回规则，不抛
        def boom(*a, **k):
            raise RuntimeError("no cuda")
        L.chat = boom
        act = planner._next_action(dict(state), True, None, lambda *_: None)
        ok &= check("模型不可用时退回规则", act and act.get("source") != "llm", act)
    finally:
        L.chat = real_chat

    print()
    print("PASS（模型决策与规则兜底）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
