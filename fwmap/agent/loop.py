"""Agent 循环：让模型决定"下一步做什么"（P0-1）。

和之前所有"用模型"的地方不同：那些都是**问一道选择题**（选机制、排工具、答是非题）。
这里是一个真正的循环：

    观察状态 → 模型选一个动作 → 代码执行并验收 → 结果写回状态 → 再来一步

三条纪律（和工具总线一致）：

1. **动作只能从白名单里选**，参数必须过 schema；
2. **每步都要验收**（路由要能对上 handler、工具要过自己的 success 判据）；
3. **有预算**（`max_steps`），超了就停，并如实说停在哪一步。

模型不可用时退化为固定策略（`_heuristic`），保证工具在没模型的环境也能跑——
这是"端到端"的底线，也是消融实验的对照组。
"""

from __future__ import annotations

import json
import os
import re
import tempfile

__all__ = ["ACTIONS", "run", "state_brief"]

# 动作白名单：名字 → 参数 schema（只允许列出来的取值）
ACTIONS = {
    "routes": {
        "desc": "用某种机制从固件里抽路由（URL → 参数名）",
        "args": {"mechanism": ["page_derived", "strings_goform", "form_define",
                               "pointer_table", "strcmp_chain"]},
        "required": ["mechanism"],
    },
    "pages": {
        "desc": "扫描固件自带的网页表单，拿到浏览器真实提交的 URL 与字段",
        "args": {},
        "required": [],
    },
    "analyze": {
        "desc": "对二进制做静态分析，确认架构/入口/函数表",
        "args": {"tool": ["readelf", "rabin2", "rizin", "lief"]},
        "required": ["tool"],
    },
    "probe": {
        "desc": "把候选路由真的发给固件，问它这条路径在不在（**你来挑试哪条**）",
        "args": {"uri": "<string 或 string 列表，每项以 / 开头>"},
        "required": ["uri"],
    },
    "done": {"desc": "收工（已经有结论，或继续下去没有意义）", "args": {}, "required": []},
}

_PROMPT = """你在控制一个固件分析工具。每一步只能做一个动作。

当前状态：
{state}

可选动作：
{actions}

规则：
- 只输出 JSON：{{"action": "名字", "args": {{...}}, "why": "一句话"}}
- 只能从上面的动作里选；参数必须符合取值范围；
- 用 probe 时，**你自己挑**最值得试的那条 uri，并在 why 里说为什么是它
  （名字像表单目标的 / 带参数的 / 只有它可能是处理入口的，优先）；
- pages 和 routes 各做一次就够，做完就该进 probe；
- 已经「已试」过的 uri 不要再试；
- 如果已经有足够信息（或者再试也没用），输出 action = "done"；
- 不要重复做过且失败的动作。
"""


def state_brief(state: dict) -> str:
    """把状态压成几行——模型不需要看原始 JSON。"""
    lines = [f"二进制: {os.path.basename(state.get('binary') or '?')}"
             f"（{state.get('arch') or '?'}）",
             f"rootfs: {'有' if state.get('rootfs') else '无'}",
             f"已抽路由: {state.get('routes', 0)} 条，其中能应答: {state.get('handlers', 0)} 条",
             f"探针: {'可用（能真的发请求）' if state.get('probe_ready') else '不可用（没 qemu / 服务起不来）'}",
             f"剩余步数: {state.get('budget', 0)}"]

    # 候选要让模型真看见 —— 只报「有 N 条」等于没给它挑的依据。
    # 已经探过的标出来，免得重复花预算。
    cands = state.get("candidates") or []
    probed = state.get("probed") or {}
    if cands:
        lines.append("候选路由（probe 时从这里挑）：")
        for i, uri in enumerate(cands[:12], 1):
            hit = probed.get(uri)
            tag = f" → 已试：{hit}" if hit else ""
            lines.append(f"  {i}. {uri}{tag}")
        if len(cands) > 12:
            lines.append(f"  ……另有 {len(cands) - 12} 条没列出")
    else:
        lines.append("候选路由：还没有（先做 pages 或 routes）")

    # 模型被拒过就当场告诉它，否则 1.5B 会一直重复同一个动作
    # （实测连着 4 步都选 pages，一步没走到 probe）。
    if state.get("last_reject"):
        lines.append(f"上一次的选择没有执行：{state['last_reject']}")

    # 阶段收束：规则给范围，模型在范围内挑。不给这句话，小模型会原地打转。
    done_actions = {h.get("action") for h in (state.get("history") or [])
                    if h.get("ok")}
    if ({"pages", "routes"} <= done_actions and state.get("probe_ready")
            and cands):
        left = [u for u in cands if u not in probed]
        if left:
            lines.append("现在该 probe 了：从上面的候选里挑一条最可能被固件"
                         "真的处理的（不是随便挑），或者 done。")

    hist = state.get("history") or []
    if hist:
        lines.append("最近的动作：")
        for h in hist[-4:]:
            flag = "成功" if h.get("ok") else "失败"
            lines.append(f"  - {h.get('action')}({h.get('args')}) → {flag}："
                         f"{str(h.get('detail'))[:60]}")
    return "\n".join(lines)


def _actions_text() -> str:
    out = []
    for name, spec in ACTIONS.items():
        args = ", ".join(f"{k}∈{v}" if isinstance(v, list) else f"{k}:{v}"
                         for k, v in (spec["args"] or {}).items())
        out.append(f"- {name}: {spec['desc']}" + (f"（参数 {args}）" if args else ""))
    return "\n".join(out)


# ---------------------------------------------------------------- 受限决策
# 1.5B 在「自由选动作」这个空间里选不动：实测连跑 6 步，一次都没选过 probe，
# 全被兜底成规则。问题不在模型不知道要探端点，而在「又要选动作、又要选参数、
# 又要掂量预算」三件事挤在一次输出里。
# 所以阶段由规则收束，模型只在收束后的窄问题里做主：**这几条里挑哪一条**。
_PROBE_PROMPT = """固件已经抽出 {n} 条候选端点，现在要挑一条交给固件去验证。

候选（uri   参数）：
{cands}

挑哪一条最可能是**固件真正在处理**的入口：
- 有名字像表单目标的（apply / login / set / form*）比静态页更像入口；
- 带参数的比不带参数的更可能是处理逻辑，而不是纯静态页；
- 带 submit_button / action 这类"提交"标记的，一般是真提交入口。

只输出 JSON：{{"uri": "/...", "why": "一句话"}}
"""


def _probe_phase(state: dict) -> bool:
    """是不是到了「该挑端点」的阶段。

    这里看的是**做没做过**，不是成没成功：routes 抽到 0 条也算做过，
    否则「抽不到」会把循环卡在反复抽路由上（实测 DIR-615 就卡在这）。
    """
    tried = {h.get("action") for h in (state.get("history") or [])}
    if not ({"pages", "routes"} <= tried and state.get("probe_ready")):
        return False
    return any(u not in (state.get("probed") or {})
               for u in state.get("candidates") or [])


def _decide_probe(state: dict, chat) -> dict | None:
    """窄问题：从候选里挑一条。挑不出合法答案就返回 None，交给通用逻辑。"""
    probed = state.get("probed") or {}
    left = [u for u in state.get("candidates") or [] if u not in probed]
    if not left:
        return None
    meta = state.get("cand_meta") or {}
    rows = []
    for i, uri in enumerate(left[:20], 1):
        ps = meta.get(uri) or []
        rows.append(f"{i}. {uri}" + (f"   {', '.join(ps[:6])}" if ps else "   （无参数）"))

    prompt = _PROBE_PROMPT.format(n=len(left), cands="\n".join(rows))
    try:
        reply = chat([{"role": "user", "content": prompt}], max_new_tokens=120) or ""
    except Exception:                                          # noqa: BLE001
        return None
    m = re.search(r"\{.*\}", reply, re.S)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except ValueError:
        return None
    uri = obj.get("uri")
    if not isinstance(uri, str) or uri not in left:
        return None                      # 编了个不在候选里的 uri，不算数
    state["last_reject"] = ""
    return {"action": "probe", "args": {"uri": uri}, "why": obj.get("why", ""),
            "_source": "model", "_mode": "probe-select"}


def _probe_uris(args) -> list[str]:
    """把 uri 参数规整成列表：模型可能给一个字符串，也可能给数组。"""
    raw = (args or {}).get("uri")
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    out = []
    for u in raw:
        u = str(u).strip()
        if u and u.startswith("/") and u not in out:
            out.append(u)
    return out


def _validate(act: dict) -> tuple[bool, str]:
    """动作是否合法（名字在白名单、参数取值在 schema 内）。"""
    name = act.get("action")
    if name not in ACTIONS:
        return False, f"没有这个动作：{name}"
    spec = ACTIONS[name]
    args = act.get("args") or {}
    if not isinstance(args, dict):
        return False, "args 必须是对象"
    for key in spec.get("required") or []:
        if key not in args:
            return False, f"缺参数 {key}"
    for key, allowed in (spec.get("args") or {}).items():
        if key in args and isinstance(allowed, list) and args[key] not in allowed:
            return False, f"{key}={args[key]} 不在允许取值里"
    # probe 的 uri 不在枚举里，只能自己校验：必须是绝对路径，且不能是空的
    if name == "probe" and not _probe_uris(args):
        return False, "uri 得是以 / 开头的路径（可以给数组）"
    return True, ""


def _decide(state: dict, chat) -> dict:
    """让模型选下一步；模型不可用或输出不合法时退回固定策略。

    返回值里带 `_source`：model 表示「这条是模型挑的」，heuristic 表示退回规则。
    必须分开记 —— 否则报告里会把规则的功劳算到模型头上（第一版就踩了：
    trace 里三条 probe 看着像模型挑的，实际全是 heuristic 按顺序发的）。
    """
    if chat is None:
        return _heuristic(state)

    # 到了挑端点的阶段就先问窄问题：这么问 1.5B 才答得出来（见 _PROBE_PROMPT 注释）
    if _probe_phase(state):
        act = _decide_probe(state, chat)
        if act is not None:
            return act

    prompt = _PROMPT.format(state=state_brief(state), actions=_actions_text())
    try:
        reply = chat([{"role": "user", "content": prompt}], max_new_tokens=200) or ""
    except Exception as ex:                                    # noqa: BLE001
        return _heuristic(state, why=f"模型调用失败：{ex}")
    m = re.search(r"\{.*\}", reply, re.S)
    if not m:
        return _heuristic(state, why="模型没给出 JSON，退回固定策略")
    try:
        act = json.loads(m.group(0))
    except ValueError:
        return _heuristic(state, why="模型 JSON 解析失败，退回固定策略")
    ok, why = _validate(act)
    if not ok:
        return _heuristic(state, why=f"动作不合法（{why}）")

    # 防打转：同一个动作用同样的参数已经成功做过，就不再重复
    # （实测 1.5B 模型会连着两次选 pages，浪费预算）
    key = (act.get("action"), json.dumps(act.get("args") or {}, sort_keys=True))
    done = {(h.get("action"), json.dumps(h.get("args") or {}, sort_keys=True))
            for h in state.get("history") or [] if h.get("ok")}
    if key in done:
        return _heuristic(state, why=f"{act.get('action')} 已经成功做过，换一个")

    # probe 特殊一点：**试过就算数**，哪怕结果是 not-found。
    # 否则模型会反复探同一条 404，把预算烧光（实测 1.5B 特别爱这么干）。
    if act.get("action") == "probe":
        seen = state.get("probed") or {}
        fresh = [u for u in _probe_uris(act.get("args")) if u not in seen]
        if not fresh:
            return _heuristic(state, why="这几条都试过了，换没试过的")

    act["_source"] = "model"
    state["last_reject"] = ""
    return act


def _heuristic(state: dict, why: str = "") -> dict:
    """没有模型时的固定顺序：网页表单 → 字符串路由 → 按发现顺序逐条探 → 收工。

    这个顺序就是消融实验的对照组：**不挑**，谁先被抽出来就先试谁。
    模型那一组可以自己挑——两边差多少，就是「模型会不会挑端点」的量化答案。
    """
    if why:
        state["last_reject"] = why
    done = {h.get("action") for h in state.get("history") or []}
    if "pages" not in done:
        return {"action": "pages", "args": {}, "why": why or "先看固件自带网页",
                "_source": "heuristic"}
    if "routes" not in done:
        return {"action": "routes", "args": {"mechanism": "strings_goform"},
                "why": why or "再从二进制里找路由字符串", "_source": "heuristic"}

    # 探针不可用就别硬发：否则会一路失败到预算用光，看上去像"试过都不行"。
    if state.get("probe_ready"):
        seen = state.get("probed") or {}
        for uri in state.get("candidates") or []:
            if uri not in seen:
                return {"action": "probe", "args": {"uri": uri},
                        "why": why or "按发现顺序试下一条", "_source": "heuristic"}
    return {"action": "done", "args": {},
            "why": why or ("没探针，探不了" if not state.get("probe_ready")
                           else "候选都试完了"), "_source": "heuristic"}


def _execute(act: dict, state: dict, *, probe=None, log=print) -> dict:
    """执行一个动作并**当场验收**。返回 {ok, detail, ...}。"""
    name, args = act.get("action"), act.get("args") or {}
    binary, rootfs = state.get("binary"), state.get("rootfs")

    if name == "pages":
        if not rootfs:
            return {"ok": False, "detail": "没有 rootfs，抽不了网页"}
        from .. import pages

        forms = pages.scan(rootfs)
        return {"ok": bool(forms), "detail": f"{len(forms)} 个表单",
                "routes": len(forms),
                "candidates": [f.get("uri") or "" for f in forms],
                "cand_meta": {f.get("uri") or "": list(f.get("params") or [])
                              for f in forms}}

    if name == "routes":
        from .. import discover

        res = discover.apply_plan(args.get("mechanism") or "page_derived", binary, rootfs)
        routes = res.get("routes") or []
        return {"ok": bool(routes), "detail": res.get("note") or f"{len(routes)} 条",
                "routes": len(routes),
                "candidates": [r.get("uri") or "" for r in routes],
                "cand_meta": {r.get("uri") or "": list(r.get("params") or [])
                              for r in routes}}

    if name == "analyze":
        from .. import toolbus, tools_analyze

        tools_analyze.register_all()
        tool = args.get("tool") or "readelf"
        outdir = os.path.join(tempfile.mkdtemp(prefix="fwmap-loop-"), tool)
        res = toolbus.run(tool, binary, outdir)
        return {"ok": res["ok"], "detail": res.get("detail") or res.get("error") or ""}

    if name == "probe":
        if probe is None:
            return {"ok": False, "detail": "没有可用的固件探针（服务起不来 / 没 qemu）"}
        uris = _probe_uris(args)
        if not uris:
            return {"ok": False, "detail": "没给 uri"}
        try:
            res = probe(uris)
        except Exception as ex:                                # noqa: BLE001
            return {"ok": False, "detail": f"探测失败：{ex}"}

        verdicts = dict(res.get("routes") or {})
        hits = sum(1 for u in uris if verdicts.get(u) == "handler")
        shown = ", ".join(f"{u}→{verdicts.get(u, '?')}" for u in uris[:4])
        return {"ok": hits > 0, "detail": shown or f"{len(uris)} 条都没应答",
                "handlers": hits, "verdicts": verdicts}

    return {"ok": False, "detail": f"未知动作 {name}"}


def run(binary: str, rootfs: str | None = None, *, chat=None, max_steps: int = 8,
        probe=None, log=print, arch: str = "") -> dict:
    """主循环。返回 {trace, ok, steps, routes, handlers, candidates, probed}。"""
    state = {"binary": binary, "rootfs": rootfs, "arch": arch,
             "routes": 0, "handlers": 0, "history": [], "budget": max_steps,
             "candidates": [], "probed": {}, "cand_meta": {},
             "probe_ready": probe is not None,
             "findings": []}
    trace = []

    for i in range(max_steps):
        state["budget"] = max_steps - i
        act = _decide(state, chat)
        src = act.pop("_source", "model")
        mode = act.pop("_mode", "action")
        tag = "" if src == "model" else "［规则兜底］"
        log(f"[loop] 第 {i + 1} 步：{tag}{act.get('action')} {act.get('args') or ''}"
            f" —— {str(act.get('why'))[:70]}")
        if act.get("action") == "done":
            trace.append({"step": i + 1, "action": "done", "source": src,
                          "mode": mode, "why": act.get("why", "")})
            break

        res = _execute(act, state, probe=probe, log=log)
        if res.get("routes"):
            state["routes"] = max(state["routes"], res["routes"])

        # 候选要攒起来给下一步看：模型挑端点靠的就是这份清单。
        for uri in res.get("candidates") or []:
            uri = str(uri or "")
            if uri.startswith("/") and uri not in state["candidates"]:
                state["candidates"].append(uri)
        state["cand_meta"].update(res.get("cand_meta") or {})
        if len(state["candidates"]) > 60:
            del state["candidates"][60:]

        # 探过的 uri 记下来：既用于累计命中数，也用于"别再试同一条"。
        if res.get("verdicts"):
            state["probed"].update(res["verdicts"])
            state["handlers"] = sum(1 for v in state["probed"].values()
                                    if v == "handler")
        elif res.get("handlers"):
            state["handlers"] = max(state["handlers"], res["handlers"])

        rec = {"action": act.get("action"), "args": act.get("args") or {},
               "ok": res["ok"], "detail": res.get("detail", ""),
               "source": src, "mode": mode, "why": act.get("why", "")}
        state["history"].append(rec)
        trace.append({"step": i + 1, **rec})
        log(f"[loop]   {'✓' if res['ok'] else '·'} {str(res.get('detail'))[:70]}")

    return {"trace": trace, "ok": bool(state["handlers"] or state["routes"]),
            "steps": len(trace), "routes": state["routes"],
            "handlers": state["handlers"], "candidates": state["candidates"],
            "probed": state["probed"], "state": state}
