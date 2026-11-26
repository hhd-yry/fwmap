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
    "verdict": {
        "desc": "根据你看到的证据下结论。引用的证据必须在你看到的清单里，编的会被拒",
        "args": {"uri": "<string>", "kind": ["crash", "suspicious", "normal"],
                 "why": "<一句话，说清你怎么判断的>",
                 "evidence": "<string 列表，每条写成 'uri 长度B 裁决'>"},
        "required": ["uri", "kind"],
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
- 探到反常的东西（0 字节、5xx、明显不像静态页）就用 verdict 下结论，
  并在 evidence 里逐条引用**你实际看到的**那几行（照抄，别改写）；
- verdict 的 kind：crash=服务被打死了；suspicious=行为反常但没崩；normal=正常页面；
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

    # 证据板：模型下结论时能引用的就只有这几行，写别的就是编。
    ev = state.get("evidence") or {}
    if ev:
        lines.append("你看到过的证据（下 verdict 时照抄其中几行）：")
        for uri, d in list(ev.items())[-10:]:
            lines.append(f"  · {uri} {d.get('len')}B {d.get('verdict')}"
                         + (f" 首行:{d['snippet']}" if d.get("snippet") else ""))
        odd = [u for u, d in ev.items()
               if d.get("len") == 0 or d.get("verdict") == "unknown"]
        if odd and not state.get("findings"):
            lines.append(f"注意：{', '.join(odd[:3])} 没有正常响应 —— "
                         "该用 verdict 下结论了。")

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


def _verdict_phase(state: dict) -> bool:
    """看到反常（0 字节 / 服务没了）且还没下过结论 —— 该收了。"""
    ev = state.get("evidence") or {}
    if not ev or state.get("findings"):
        return False
    return any(d.get("len") == 0 or d.get("verdict") == "unknown"
               for d in ev.values())


_VERDICT_PROMPT = """固件对 {target} 返回了 **0 字节**（服务直接没了），而同一轮里别的请求都正常。

你实测到的全部记录：
{rows}

请就 **{target}** 这条**下结论**，并**照抄**上面记录里的几行作为证据（不许改写，不许编）。
- kind：crash=服务被打死了 / suspicious=行为反常但没崩 / normal=正常页面
- 如果 0 字节其实是别的原因，就选 suspicious 并说清楚。

只输出 JSON：
{{"uri": "{first}", "kind": "crash", "why": "一句话", "evidence": ["{first} 0B unknown"]}}
"""


def _decide_verdict(state: dict, chat) -> dict | None:
    """窄问题之二：给已有证据下结论。

    必须就**真正反常的那条**下结论 —— 否则模型会挑个安全页面说"正常"，
    把异常撂在那儿（实测第一次就是这么绕过去的）。
    """
    ev = state.get("evidence") or {}
    odd = [u for u, d in ev.items()
           if d.get("len") == 0 or d.get("verdict") == "unknown"]
    if not odd:
        return None
    rows = []
    for uri, d in list(ev.items())[-8:]:
        rows.append(f"  · {uri} {d.get('len')}B {d.get('verdict')}"
                    + (f" 首行:{d['snippet']}" if d.get("snippet") else ""))
    prompt = _VERDICT_PROMPT.format(target=", ".join(odd[:3]), first=odd[0],
                                    rows="\n".join(rows))
    try:
        reply = chat([{"role": "user", "content": prompt}], max_new_tokens=160) or ""
    except Exception:                                          # noqa: BLE001
        return None
    m = re.search(r"\{.*\}", reply, re.S)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except ValueError:
        return None
    if obj.get("uri") not in odd:
        return None                      # 挑了条不反常的说"正常"，不算回答
    if obj.get("kind") not in ACTIONS["verdict"]["args"]["kind"]:
        return None
    ev_lines = obj.get("evidence")
    if not isinstance(ev_lines, list):
        ev_lines = [f"{obj['uri']} {ev[obj['uri']].get('len')}B "
                    f"{ev[obj['uri']].get('verdict')}"]
    state["last_reject"] = ""
    return {"action": "verdict",
            "args": {"uri": obj["uri"], "kind": obj["kind"],
                     "why": str(obj.get("why") or "")[:160],
                     "evidence": [str(x) for x in ev_lines][:6]},
            "why": str(obj.get("why") or "")[:160],
            "_source": "model", "_mode": "verdict"}


_PROBE_PROMPT_ANON = """固件里抽出了 {n} 条候选端点，**名字和参数都被藏起来了**，只剩编号。

候选：
{cands}

挑一个编号交给固件去验证。既然看不到名字，就按你的直觉挑，别编编号。

只输出 JSON：{{"uri": "/slot-01", "why": "一句话"}}
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
    """窄问题：从候选里挑一条。挑不出合法答案就返回 None，交给通用逻辑。

    `anonymize` 打开时把 uri 换成 /slot-01 这种编号，参数也藏起来 ——
    这是"名字还是行为"的对照：名字藏了，模型就只能瞎挑。
    """
    probed = state.get("probed") or {}
    left = [u for u in state.get("candidates") or [] if u not in probed]
    if not left:
        return None
    meta = state.get("cand_meta") or {}
    anon = bool(state.get("anonymize"))
    label_to_real: dict[str, str] = {}

    rows = []
    if anon:
        for i, uri in enumerate(left[:20], 1):
            label = f"/slot-{i:02d}"
            label_to_real[label] = uri
            rows.append(f"{i}. {label}")
        prompt = _PROBE_PROMPT_ANON.format(n=len(left), cands="\n".join(rows))
    else:
        for i, uri in enumerate(left[:20], 1):
            ps = meta.get(uri) or []
            rows.append(f"{i}. {uri}"
                        + (f"   {', '.join(ps[:6])}" if ps else "   （无参数）"))
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
    picked = obj.get("uri")
    if anon:
        picked = label_to_real.get(picked)
        if not picked:
            return None                  # 编了个不存在的编号，不算数
    elif not isinstance(picked, str) or picked not in left:
        return None                      # 编了个不在候选里的 uri，不算数
    state["last_reject"] = ""
    return {"action": "probe", "args": {"uri": picked}, "why": obj.get("why", ""),
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
    # 多余参数直接拒：模型很爱给 pages 编个 url/urls（实测连编三次），
    # 以前这些键被静默忽略，看起来"动作成功了"，其实是蒙对的。
    allowed_keys = set((spec.get("args") or {}).keys())
    extra = [k for k in args if k not in allowed_keys]
    if extra:
        hint = ", ".join(sorted(allowed_keys)) or "这个动作不收参数"
        return False, f"多余的参数 {', '.join(extra)}（它只认 {hint}）"
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

    # 每一步先清空"上次被拒"，免得上一轮的拒绝被重复计数
    state["last_reject"] = ""

    # 到了挑端点的阶段就先问窄问题：这么问 1.5B 才答得出来（见 _PROBE_PROMPT 注释）
    if _verdict_phase(state):
        act = _decide_verdict(state, chat)
        if act is not None:
            return act
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

    # 防打转：同一个动作用同样的参数已经成功做过，就不再重复。
    # pages 这类不带参数的动作，换个 url/urls 也算同一个 —— 否则改个参数名就能绕过。
    if act.get("action") == "pages":
        key = ("pages", "{}")
    else:
        key = (act.get("action"),
               json.dumps(act.get("args") or {}, sort_keys=True))
    done = {(h.get("action") if h.get("action") != "pages" else "pages",
             "{}" if h.get("action") == "pages"
             else json.dumps(h.get("args") or {}, sort_keys=True))
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
        detail_map = res.get("detail") or {}
        hits = sum(1 for u in uris if verdicts.get(u) == "handler")
        shown = ", ".join(f"{u}→{verdicts.get(u, '?')}" for u in uris[:4])
        ev = {}
        for u in uris:
            d = detail_map.get(u) or {}
            ev[u] = {"verdict": d.get("verdict") or verdicts.get(u, "?"),
                     "len": d.get("len", -1), "status": d.get("status"),
                     "snippet": d.get("snippet") or ""}
        return {"ok": hits > 0, "detail": shown or f"{len(uris)} 条都没应答",
                "handlers": hits, "verdicts": verdicts, "evidence": ev}

    if name == "verdict":
        # 模型写结论，规则核证据：引用的必须是实测过的东西，且不能和自己测到的数字打架。
        # 这一条是"模型取证、规则裁决"的落点 —— 模型可以判断，但不能凭空断言。
        uri = str(args.get("uri") or "")
        kind = args.get("kind")
        ev_all = state.get("evidence") or {}
        if uri not in ev_all:
            return {"ok": False, "detail": f"{uri} 没有实测证据，不能下结论"}
        d = ev_all[uri]

        known = set(ev_all)
        for raw in (args.get("evidence") or []):
            text = str(raw)
            if not any(u in text for u in known):
                return {"ok": False,
                        "detail": f"证据「{text[:40]}」里没有任何一条实测过的 uri，像编的"}
        if kind == "crash" and d.get("len") != 0:
            return {"ok": False,
                    "detail": f"你说是 crash，但 {uri} 返回了 {d.get('len')} 字节"}
        if kind == "normal" and d.get("verdict") != "handler":
            return {"ok": False,
                    "detail": f"你说是 normal，但 {uri} 的裁决是 {d.get('verdict')}"}

        finding = {"uri": uri, "kind": kind,
                   "why": str(args.get("why") or "")[:200],
                   "evidence": [str(x) for x in (args.get("evidence") or [])][:6],
                   "measured": d}
        state.setdefault("findings", []).append(finding)
        return {"ok": True, "detail": f"结论已记录：{uri} = {kind}",
                "findings": [finding]}

    return {"ok": False, "detail": f"未知动作 {name}"}


def _reason_kind(text: str) -> str:
    """把退回规则的原因归个类 —— 报告里要看的是分布，不是逐条原文。"""
    for key, label in (("多余的参数", "多余参数"), ("不在允许取值", "非法参数"),
                       ("已经成功做过", "重复动作"), ("都试过了", "重复探测"),
                       ("没有这个动作", "非法动作"), ("缺参数", "缺参数"),
                       ("JSON", "输出非JSON"), ("模型调用失败", "模型不可用")):
        if key in text:
            return label
    return "其它"


def _summarize(state: dict, trace: list[dict]) -> dict:
    """一次跑完的自评：模型到底参与了没有，参与得对不对。

    没有这张表，"错误率高"只能靠感觉 —— 有了它才能说清是模型不行，
    还是流程把模型锁死了。
    """
    steps = len(trace)
    model_steps = sum(1 for t in trace if t.get("source") == "model")
    rejects = state.get("rejects") or []
    kinds: dict[str, int] = {}
    for r in rejects:
        k = _reason_kind(r)
        kinds[k] = kinds.get(k, 0) + 1

    ev = state.get("evidence") or {}
    anomalies = [u for u, d in ev.items()
                 if d.get("len") == 0 or d.get("verdict") == "unknown"]
    v_try = sum(1 for t in trace if t.get("action") == "verdict")
    v_ok = len(state.get("findings") or [])

    return {
        "steps": steps,
        "model_steps": model_steps,
        "fallback_steps": steps - model_steps,
        "model_share": round(model_steps / steps, 2) if steps else 0.0,
        "rejects": len(rejects),
        "reject_kinds": kinds,
        "probed": len(state.get("probed") or {}),
        "handlers": state.get("handlers", 0),
        "anomalies": anomalies,
        "verdict_tried": v_try,
        "verdict_accepted": v_ok,
        "verdict_accept_rate": round(v_ok / v_try, 2) if v_try else 0.0,
    }


def run(binary: str, rootfs: str | None = None, *, chat=None, max_steps: int = 8,
        probe=None, log=print, arch: str = "", anonymize: bool = False) -> dict:
    """主循环。返回 {trace, ok, steps, routes, handlers, candidates, probed}。"""
    state = {"binary": binary, "rootfs": rootfs, "arch": arch,
             "routes": 0, "handlers": 0, "history": [], "budget": max_steps,
             "candidates": [], "probed": {}, "cand_meta": {}, "evidence": {},
             "probe_ready": probe is not None, "rejects": [], "last_reject": "",
             "anonymize": anonymize,
             "findings": []}
    trace = []

    for i in range(max_steps):
        state["budget"] = max_steps - i
        act = _decide(state, chat)
        src = act.pop("_source", "model")
        mode = act.pop("_mode", "action")
        if state.get("last_reject"):
            state["rejects"].append(state["last_reject"])
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
            state["evidence"].update(res.get("evidence") or {})
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
            "probed": state["probed"], "evidence": state["evidence"],
            "findings": state.get("findings") or [], "state": state,
            "stats": _summarize(state, trace)}
