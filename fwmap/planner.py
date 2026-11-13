"""决策循环：让工具**自己决定下一步**，而不是人按固定顺序敲命令。

老师那句话的落点是：智能体不该每次从零写脚本，而该「看清楚手上有什么，
再决定调哪个现有工具」。这个模块就是那个「决定」的部分。

现在的实现是**规则优先**的：每一步根据 state 选一个动作，理由写进日志。
为什么先上规则而不是直接让模型选：

- 7B 模型做工具选择不稳定，选错一次要等 Ghidra 跑十分钟才发现；
- 规则的决策链路是**可解释**的 —— 日志里能写清「为什么这一步要跑 verify」；
- 等链路稳定后，把 `decide()` 换成模型输出即可，接口不用动。

收敛条件也是显式的：拿到「未命中」的链、且动态验证给不出结论，就停，
并说明**卡在哪**——不允许「跑完一圈什么都没说」。
"""

from __future__ import annotations

import json
import os
import time

from . import tools_api as T


def _pick_binary(targets: list[dict]) -> dict | None:
    """挑目标：优先 HTTP 服务，其次分数最高的。"""
    if not targets:
        return None
    http = [t for t in targets if t.get("role") == "http_server"]
    return (http or targets)[0]


def decide(state: dict) -> dict | None:
    """根据当前状态选下一步。返回 {tool, kwargs, why}，或 None 表示收敛。"""
    if not state.get("checked"):
        return {"tool": "check", "kwargs": {"rootfs": state["rootfs"]},
                "why": "先确认解包完整——解包不全，后面所有结论都不可信"}

    if not state.get("targets"):
        if not state.get("scan_ok"):
            return {"tool": "scan", "kwargs": {"rootfs": state["rootfs"], "top": 6},
                    "why": "还没选目标，先按攻击面排序"}
        return None

    # 外部工具优先跑一次：既验证了「融合」这条链，也把对方的结果纳入决策。
    done = state.setdefault("plugins_done", set())
    pending = [p for p in (state.get("plugins") or []) if p not in done]
    if pending:
        return {"tool": pending[0], "kwargs": {"target": state["rootfs"]},
                "why": f"调外部工具 {pending[0]}（融合的关键：能调别人做的东西）"}

    # skip_ghidra 只跳过「要 Ghidra」的两步（m2/m3），
    # 后面的 verify / dyn 该跑还得跑 —— dyn 要的是 qemu，不是 Ghidra。
    if not state.get("endpoints") and not state.get("skip_ghidra"):
        return {"tool": "m2",
                "kwargs": {"binary": state["binary"]},
                "why": "要把函数对上 URL，才能按路由名做双路检索"}

    if not state.get("chains") and not state.get("skip_ghidra"):
        return {"tool": "m3",
                "kwargs": {"binary": state["binary"], "limit": state["limit"]},
                "why": "端点知道了，现在找「外部输入 → 危险函数」的链"}

    if not state.get("verified") and state.get("chains"):
        return {"tool": "verify",
                "kwargs": {"chains": state["chains"],
                           "context": state.get("context", "")},
                "why": "链出来了，先查有没有人报过——没报过的才值得花时间验证"}

    unknown = state.get("unknown_fns") or []
    if unknown and not state.get("dyn_tried"):
        return {"tool": "dyn",
                "kwargs": {"chains": [c for c in state["chains"]
                                      if c.get("function") in unknown],
                           "binary": state["binary"], "rootfs": state["rootfs"],
                           "port": state.get("port", 80)},
                "why": f"这 {len(unknown)} 个函数没被报过，试着真打一发"}
    return None


def _hydrate(act: dict, state: dict) -> dict:
    """把模型选的工具补上真实参数。

    路径类参数一律由程序注入，不采信模型填的 —— 模型负责「选哪个工具」，
    「用什么路径」是我们这边的事实。这样即使模型编了个不存在的路径也不会出事。
    """
    t = act["tool"]
    kw = dict(act.get("kwargs") or {})
    if t == "check":
        kw = {"rootfs": state["rootfs"]}
    elif t == "scan":
        kw = {"rootfs": state["rootfs"], "top": 6}
    elif t == "m2":
        kw = {"binary": state["binary"]}
    elif t == "m3":
        kw = {"binary": state["binary"], "limit": state.get("limit", 20)}
    elif t == "verify":
        kw = {"chains": state.get("chains") or [],
              "context": state.get("context", "")}
    elif t == "dyn":
        kw = {"chains": state.get("chains") or [], "binary": state["binary"],
              "rootfs": state["rootfs"], "port": state.get("port", 80)}
    elif t.startswith("plugin."):
        kw = {**kw, "target": state["rootfs"]}
    act["kwargs"] = kw
    return act


def _next_action(state: dict, use_llm: bool, llm_model: str | None, log) -> dict | None:
    """先请模型提议，校验不过或没开就退回规则。"""
    if use_llm:
        from .agent import planner_llm as PL

        act = PL.choose(state, T.catalog(), model_path=llm_model, log=log)
        if act and act.get("done"):
            # 模型说停 —— 只有当规则也认为该停时才接受，否则按规则继续
            rule = decide(state)
            if rule is None:
                log(f"     模型判断可以停：{act.get('why')}")
                return None
            log(f"     模型想停（{act.get('why')}），但规则认为还要做 {rule['tool']}，按规则继续")
            return rule
        if act:
            ok, why = PL.allowed_by_state(act, state)
            if ok:
                key = (act["tool"], json.dumps(act.get("kwargs") or {},
                                               sort_keys=True, default=str))
                state.setdefault("llm_seen", set()).add(key)
                return _hydrate(act, state)
            log(f"     模型这一步被拦下（{why}），带原因重试一次")
            act = PL.choose(state, T.catalog(), model_path=llm_model, log=log,
                            hint=f"你上次选的 {act['tool']} 不能用：{why}。请换一个动作。")
            if act and not act.get("done"):
                ok2, why2 = PL.allowed_by_state(act, state)
                if ok2:
                    key = (act["tool"], json.dumps(act.get("kwargs") or {},
                                                   sort_keys=True, default=str))
                    state.setdefault("llm_seen", set()).add(key)
                    return _hydrate(act, state)
                log(f"     重试仍被拦下（{why2}），退回规则")
            else:
                log("     重试没给出可用动作，退回规则")
    return decide(state)


def autopilot(rootfs: str, binary: str | None = None, limit: int = 20,
              port: int = 80, context: str = "", max_steps: int = 8,
              skip_ghidra: bool = False, plugins: list[str] | None = None,
              use_llm: bool = False, llm_model: str | None = None,
              flow: str | None = None, log=print) -> dict:
    state = {
        "rootfs": os.path.abspath(rootfs), "binary": binary, "limit": limit,
        "port": port, "context": context, "skip_ghidra": skip_ghidra,
        "chains": [], "targets": [], "unknown_fns": [], "history": [],
        "plugins": [], "plugins_done": set(), "llm_seen": set(),
    }
    if flow:
        # 两机分工：静态分析在 Windows（有 Ghidra）跑出 flow.json，
        # 拿它到 Linux（有 qemu）上做动态验证 —— 这样才不用在两边都装全套。
        from .verify import _read_json

        raw = _read_json(flow)
        chains = [c for c in (raw.get("chains") or [])
                  if c.get("verdict", "keep") == "keep"]
        state["chains"] = chains
        state["flow"] = os.path.abspath(flow)
        state["skip_ghidra"] = True          # 有现成的链，就不用再跑 m2/m3 了
        # flow.json 里的 binary 是「做静态分析那台机器」的路径，
        # 跨机器跑时它一定是错的 —— 只有显式没给 --binary 才用它兜底。
        if raw.get("binary") and not binary:
            state["binary"] = raw["binary"]
        log(f"[autopilot] 预载 {os.path.basename(flow)}：{len(chains)} 条链")
    if plugins:
        from . import plugins as P

        state["plugins"] = P.load(plugins, log)
    t0 = time.time()
    log(f"[autopilot] 目标 rootfs：{state['rootfs']}")
    if skip_ghidra:
        log("[autopilot] --skip-ghidra：只做不依赖 Ghidra 的步骤")

    for step in range(1, max_steps + 1):
        act = _next_action(state, use_llm, llm_model, log)
        if act is None:
            log("[autopilot] 收敛：没有更多该做的一步了")
            break
        tag = "模型" if act.get("source") == "llm" else "规则"
        log(f"[{step}] ({tag}) {act['why']}")
        log(f"     → 调用 {act['tool']}")
        res = T.call(act["tool"], **act["kwargs"])
        log(f"     ← {res.get('summary')}")
        state["history"].append({"step": step, "tool": act["tool"],
                                 "why": act["why"],
                                 "source": act.get("source", "rule"),
                                 "result": res})
        _absorb(state, act["tool"], res)

    return _report(state, time.time() - t0)


def _absorb(state: dict, tool: str, res: dict) -> None:
    """把工具结果吸收进状态，供下一步决策。"""
    if not tool.startswith("plugin."):
        state.setdefault("ran", []).append(tool)
    if tool == "check":
        state["checked"] = True
        state["check_clean"] = res.get("ok_clean", False)
    elif tool == "scan":
        state["scan_ok"] = True
        targets = res.get("targets") or []
        state["targets"] = targets
        if not state.get("binary") and targets:
            state["binary"] = os.path.join(state["rootfs"], targets[0]["path"])
    elif tool == "m2":
        state["endpoints"] = res.get("endpoints") or []
    elif tool == "m3":
        state["chains"] = res.get("chains") or []
    elif tool == "verify":
        state["verified"] = True
        state["unknown_fns"] = res.get("unknown") or []
        state["verify_stat"] = res.get("summary_stat") or {}
    elif tool == "dyn":
        state["dyn_tried"] = True
    elif tool.startswith("plugin."):
        state.setdefault("plugins_done", set()).add(tool)


def _report(state: dict, elapsed: float) -> dict:
    stat = state.get("verify_stat") or {}
    known = stat.get("known", 0)
    unknown = stat.get("unknown", 0)
    chains = len(state.get("chains") or [])
    lines = [
        f"用时 {elapsed:.1f}s，共 {len(state['history'])} 步",
        f"目标二进制：{state.get('binary') or '（没选出来）'}",
        f"端点 {len(state.get('endpoints') or [])} 个 · 链 {chains} 条",
    ]
    # 结论必须区分「分析没跑到」和「分析了没有」——这两件事混在一起，
    # 就会出现「0 条链 ⇒ 这个固件很干净」这种错误结论。
    if not state.get("verified"):
        lines.append("新颖性：没跑（没有可核对的链）")
        if state.get("skip_ghidra"):
            lines.append("→ 用了 --skip-ghidra，只做了不依赖 Ghidra 的步骤；"
                         "要出链得去掉这个参数跑 M2/M3")
        elif not chains:
            lines.append("→ 数据流没产出链：可能这个二进制确实没有外部可达的源→汇，"
                         "也可能候选被 limit 截断（加大 --limit 再试）")
    else:
        lines.append(f"新颖性：已公开 {known} · 未命中 {unknown}"
                     f" · 需人工 {stat.get('manual', 0)}")
        if unknown:
            lines.append(f"值得人工深挖：{', '.join(state['unknown_fns'][:6])}")
        elif chains:
            lines.append("有链，但都已有公开记录——这个攻击面被研究过了")

    if state.get("check_clean") is False:
        lines.append("⚠ 解包自检有阻断项，先看 `fwmap check` 的输出再采信后面的结论")
    return {"ok": True, "state": state, "lines": lines,
            "history": state["history"], "elapsed": round(elapsed, 1)}


def run(args, log=print) -> int:
    res = autopilot(args.rootfs, binary=args.binary, limit=args.limit,
                    port=args.port, context=args.context or "",
                    max_steps=args.max_steps,
                    skip_ghidra=getattr(args, "skip_ghidra", False),
                    plugins=getattr(args, "plugin", None),
                    use_llm=getattr(args, "llm", False),
                    llm_model=getattr(args, "llm_model", None),
                    flow=getattr(args, "flow", None), log=log)
    print()
    for ln in res["lines"]:
        print("  " + ln)
    if getattr(args, "out", None):
        import json
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({"lines": res["lines"],
                       "history": [{k: v for k, v in h.items() if k != "result"}
                                   | {"summary": h["result"].get("summary")}
                                   for h in res["history"]]},
                      fh, ensure_ascii=False, indent=1)
        print(f"\n[+] 调查日志：{args.out}")
    return 0
