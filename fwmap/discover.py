"""让工具在「没见过的固件」上也能自己找路由 —— LLM 出策略，规则来执行，证据来验收。

为什么不是「全都交给 LLM」：
    模型会编。让它直接报 URL，报出来的东西没法核实（幻觉率在长上下文里很高）。

为什么不是「全都是规则」：
    规则只认自己写过的形状。今天在 Edimax 上就吃够了亏 —— `strcmp-chain` 策略
    0/45 命中，而"扫网页"这条路 21/22 命中，两条路都不在最初的设计里。

所以走中间：**LLM 只做选路和给参数，绝不给结论**。
    1. 收集一组证据（字符串表、网页表单、已有策略的产出）
    2. 问模型：这台固件最可能用哪种注册方式？返回严格 JSON，只许从枚举里选
    3. 用对应的**确定性代码**去抽路由（不是模型在抽）
    4. 用**三对照探测**验收：路由真能在固件上答话吗？
    5. 验不过就把失败原因回给模型，换一种机制再来（最多 2 轮）
    6. 验过了把这套策略存成 profile，同厂固件下次直接用

这样适应性来自模型，可验证性来自代码和证据。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess

__all__ = ["evidence", "ask", "apply_plan", "discover", "firmware_probe", "MECHANISMS", "PROMPT"]

# 支持的机制。新固件用哪一条，由模型根据证据选，选完由代码执行。
MECHANISMS = {
    "page_derived": "从固件自带的网页里读 <form action> + <input name>（不需要 Ghidra）",
    "strings_goform": "从二进制的字符串表里 grep /goform/、/cgi-bin/ 这类路径（只有 URL，没有参数名）",
    "strcmp_chain": "反编译 handler，读 strcmp(url,\"formX\") 里的常量（需要 Ghidra，慢）",
    "pointer_table": "找 {名字, 函数指针} 的注册表（需要 Ghidra，固件得是表格驱动）",
    "form_define": "找 websFormDefine(name, handler) 这类注册调用（需要 Ghidra）",
}

PROMPT = """你在判断一台嵌入式固件的 Web 服务是怎么把 URL 映射到处理函数的。
只能从下面这些机制里选一个最可能的：

{mechanisms}

证据：
{evidence}

只输出一个 JSON 对象，不要解释：
{{"mechanism": "<枚举之一>", "confidence": 0.0, "reason": "一句话"}}

规则：
- confidence ∈ [0,1]，证据不足就写 0.3 以下；
- reason 里必须引用上面证据中的具体数字或字符串；
- 不确定就选 page_derived（它最便宜，且不依赖反编译）。"""


def _strings(binary: str, limit: int = 4000) -> list[str]:
    """取二进制里的可打印字符串。优先用系统的 strings，没有就自己扫。"""
    try:
        out = subprocess.run(["strings", "-a", "-n", "5", binary],
                             capture_output=True, timeout=120).stdout.decode(
                                 "latin-1", "replace")
        rows = out.splitlines()
    except Exception:                                     # noqa: BLE001
        rows = []
        try:
            with open(binary, "rb") as fh:
                data = fh.read()
            rows = [m.group(0).decode("latin-1") for m in re.finditer(rb"[\x20-\x7e]{5,}", data)]
        except OSError:
            rows = []
    return rows[:limit]


def evidence(binary: str, rootfs: str | None = None, pages_mod=None) -> dict:
    """收集一组「够模型做判断题、又不至于爆上下文」的证据。"""
    rows = _strings(binary)
    route_like = [s for s in rows if re.search(r"/(goform|cgi-bin|boafrm|apply|admin)/", s)]
    form_names = [s for s in rows if re.fullmatch(r"form[A-Za-z0-9_]{3,40}", s or "")]
    cmp_names = [s for s in rows if s.startswith("form") or s.startswith("wiz_")]

    pack = {
        "binary": os.path.basename(binary),
        "size_kb": round(os.path.getsize(binary) / 1024) if os.path.exists(binary) else 0,
        "strings": len(rows),
        "route_like": route_like[:12],
        "route_like_count": len(route_like),
        "form_like_names": form_names[:12],
        "form_like_count": len(form_names),
        "cmp_like_count": len(cmp_names),
    }
    if rootfs:
        try:
            if pages_mod is None:
                from . import pages as pages_mod
            forms = pages_mod.scan(rootfs)
            pack["pages_files"] = len({f["file"] for f in forms})
            pack["pages_forms"] = len(forms)
            pack["pages_sample"] = [{"uri": f["uri"], "params": f["params"][:4]}
                                    for f in forms[:5]]
        except Exception as ex:                           # noqa: BLE001
            pack["pages_error"] = str(ex)[:120]
    return pack


def _fmt_evidence(pack: dict) -> str:
    return json.dumps(pack, ensure_ascii=False, indent=1)[:2400]


def ask(pack: dict, chat=None) -> dict:
    """问模型该用哪种机制。`chat` 可注入，测试用假模型。"""
    if chat is None:
        from .agent import llm as chat_mod

        def chat(messages, **kw):                          # noqa: E306
            return chat_mod.chat(messages, **kw)

    mech_text = "\n".join(f"- {k}: {v}" for k, v in MECHANISMS.items())
    prompt = PROMPT.format(mechanisms=mech_text, evidence=_fmt_evidence(pack))
    reply = chat([{"role": "user", "content": prompt}], max_new_tokens=200)
    obj = _json_of(reply) or {}
    mech = str(obj.get("mechanism") or "").strip()
    if mech not in MECHANISMS:
        mech = "page_derived"                    # 兜底：最便宜且不依赖反编译
    try:
        conf = max(0.0, min(1.0, float(obj.get("confidence", 0.0))))
    except (TypeError, ValueError):
        conf = 0.0
    return {"mechanism": mech, "confidence": conf,
            "reason": str(obj.get("reason") or "")[:200], "raw": reply[:400]}


def _json_of(text: str) -> dict | None:
    if not text:
        return None
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except ValueError:
        return None


def apply_plan(mech: str, binary: str, rootfs: str | None, pages_mod=None) -> dict:
    """按选定的机制去抽路由。返回 {routes, source, note}。

    注意：这里全是确定性代码 —— 模型只负责"选哪条路"，不负责"抽出什么"。
    """
    routes: list[dict] = []
    if mech == "page_derived":
        if not rootfs:
            return {"routes": [], "source": mech, "note": "没有 rootfs，抽不了网页"}
        if pages_mod is None:
            from . import pages as pages_mod
        for f in pages_mod.scan(rootfs):
            routes.append({"uri": f["uri"], "params": f["params"],
                           "source": "page", "file": f["file"]})
        return {"routes": routes, "source": mech,
                "note": f"{len(routes)} 个表单"}

    if mech == "strings_goform":
        rows = _strings(binary)
        seen, out = set(), []
        for s in rows:
            for m in re.finditer(r"(/(?:goform|cgi-bin|boafrm)/[A-Za-z0-9_.\-]+)", s):
                uri = m.group(1)
                if uri not in seen:
                    seen.add(uri)
                    out.append({"uri": uri, "params": [], "source": "strings"})
        return {"routes": out, "source": mech, "note": f"{len(out)} 个路径"}

    # 需要 Ghidra 的三条：这里只给"该干什么"，真正执行交给 m2
    return {"routes": [], "source": mech,
            "note": f"{mech} 需要 Ghidra，交给 M2 执行（本函数不重复实现）"}


def _cache_path(binary: str) -> str:
    try:
        h = hashlib.sha256(open(binary, "rb").read(1 << 20)).hexdigest()[:12]
    except OSError:
        h = "unknown"
    base = os.environ.get("FWMAP_PROFILE_DIR") or os.path.join(
        os.path.expanduser("~"), ".fwmap", "profiles")
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, f"{h}.json")


def _load_profile(binary: str) -> dict | None:
    try:
        with open(_cache_path(binary), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if data.get("mechanism") not in MECHANISMS:
        return None
    return data


def _save_profile(binary: str, *, mechanism: str, validated: bool,
                  routes: int, reason: str = "") -> str:
    path = _cache_path(binary)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"mechanism": mechanism, "validated": bool(validated),
                       "routes": routes, "reason": reason,
                       "when": __import__("time").strftime("%Y-%m-%d %H:%M")},
                      fh, ensure_ascii=False, indent=1)
    except OSError:
        pass
    return path


# 模型反复选同一条时的兜底顺序：先便宜的后贵的
FALLBACK_ORDER = ("page_derived", "strings_goform", "form_define",
                  "pointer_table", "strcmp_chain")


def _feedback(tried: list[dict]) -> str:
    """把「试过什么、为什么不行」整理成给模型看的反馈。"""
    lines = []
    for t in tried:
        v = t.get("probe")
        if v is None:
            why = "抽到了路由，但没条件验收（没有 qemu）"
        elif v.get("handler"):
            why = f"抽出 {t['routes']} 条，探测 {v['checked']} 条，{v['handler']} 条能应答"
        else:
            why = (f"抽出 {t['routes']} 条，探测 {v['checked']} 条，**一条都不能应答**"
                   f" —— 这条路在这台固件上不对")
        lines.append(f"- {t['mechanism']}：{why}")
    return "\n".join(lines)


def discover(binary: str, rootfs: str | None = None, *, chat=None, probe=None,
             log=print, rounds: int = 3, use_profile: bool = True,
             use_knowledge: bool = True, use_policy: bool = True) -> dict:
    """完整流程：证据 → 模型选机制 → 代码抽取 → 固件验收 → 不行就换一条再来。

    和上一版的区别只有一点，但很关键：**选错不是终点**。
    探测（固件自己答不答话）失败时，把失败原因喂回模型，让它换一种机制；
    模型如果还选同一条，就按 FALLBACK_ORDER 依次试剩下的 —— 直到有一条被验收通过，
    或者全部试完（那时如实说「都没对上」，而不是假装找到了）。
    """
    cached = _load_profile(binary) if use_profile else None
    tried: list[dict] = []
    pack = None

    # 先查「厂商经验」：同一家厂商的固件，机制往往是一样的。
    # 命中条件：记得上次用的机制，且那次确实抽出过路由。
    # 分两种说法：验收过的直接信；没验收过的照样用，但会再验一遍。
    from . import knowledge as kb

    vkey = kb.vendor_key(rootfs or os.path.dirname(os.path.abspath(binary)))
    kprofile = kb.vendor_profile(vkey) if use_knowledge else {}
    hit_knowledge = False
    if (kprofile.get("mechanism") in MECHANISMS
            and int(kprofile.get("routes") or 0) > 0):
        ok_before = bool(kprofile.get("validated"))
        plan = {"mechanism": kprofile["mechanism"],
                "confidence": 1.0 if ok_before else 0.6,
                "reason": (f"厂商经验命中（{vkey}，上次验收通过）" if ok_before
                           else f"厂商经验命中（{vkey}，上次未验收，这次会再验）"),
                "raw": ""}
        hit_knowledge = True
        tail = "（跳过模型）" if ok_before else "（跳过模型，但仍会验收）"
        log(f"[discover] 命中厂商经验：{vkey} → {plan['mechanism']}{tail}")
    elif cached and cached.get("validated"):
        plan = {"mechanism": cached["mechanism"], "confidence": 1.0,
                "reason": f"上次在这台固件上验收通过（{cached.get('when', '')}）", "raw": ""}
        log(f"[discover] 用上次的结论：{plan['mechanism']}（跳过模型）")
    else:
        pack = evidence(binary, rootfs)
        log(f"[discover] 证据：{pack.get('strings')} 条字符串、"
            f"{pack.get('route_like_count')} 个路径候选、{pack.get('pages_forms', 0)} 个网页表单")
        plan = ask(pack, chat=chat)

    # 经验排序（L2）：把「机制 × 厂商」的历史成功率变成顺序。
    # 只有一条硬规则会**覆盖**模型的选择：某个机制在这家厂商上成功过，
    # 而模型选的这条历史成功率明显更低时，按经验来（并记日志说明）。
    policy_order: list[str] = []
    if use_knowledge and use_policy:
        from . import policy as _policy

        stats = kb._load("stats")
        policy_order = _policy.rank(list(MECHANISMS), vkey,
                                    model_order=[plan["mechanism"]], stats=stats)
        if policy_order:
            top = policy_order[0]
            if _policy.should_override(top, plan["mechanism"], vkey, stats=stats):
                top_score = _policy.score(top, vkey, stats)
                cur_score = _policy.score(plan["mechanism"], vkey, stats)
                log(f"[discover] 按历史成功率改用 {top}"
                    f"（{top_score:.2f} vs {cur_score:.2f}）—— 原选 {plan['mechanism']}")
                plan = {"mechanism": top,
                        "confidence": max(plan.get("confidence", 0.0), 0.6),
                        "reason": f"经验优先：{top} 在这家厂商成功过",
                        "raw": plan.get("raw", "")}
            log("[discover] 经验排序：" + " → ".join(policy_order[:3]) + " …")

    best = None
    for rnd in range(max(1, rounds)):
        mech = plan["mechanism"]
        if any(t["mechanism"] == mech for t in tried):
            mech = next((m for m in FALLBACK_ORDER
                         if m not in {t["mechanism"] for t in tried}), "")
            if not mech:
                break
            plan = {"mechanism": mech, "confidence": 0.0,
                    "reason": "这条已经试过了，按兜底顺序换一条", "raw": ""}

        log(f"[discover] 第 {rnd + 1} 轮：{mech}（置信 {plan['confidence']:.2f}）"
            f" —— {plan['reason'][:80]}")
        result = apply_plan(mech, binary, rootfs)
        routes = result["routes"]
        log(f"[discover]   抽出 {len(routes)} 条（{result['note']}）")

        verdict = None
        if probe and routes:
            verdict = probe([r["uri"] for r in routes[:3]])
            log(f"[discover]   验收：{verdict}")

        rec = {"mechanism": mech, "confidence": plan["confidence"],
               "reason": plan["reason"], "routes": len(routes),
               "probe": verdict, "note": result["note"]}
        tried.append(rec)

        if verdict is None:
            # 没法验收：抽到东西就算可用的最好结果，但如实标「未验收」
            if routes:
                best = rec
                break
        elif verdict.get("handler"):
            best = rec
            break

        if rnd + 1 >= rounds:
            break
        # 带着失败原因重问
        if pack is None:
            pack = evidence(binary, rootfs)
        fb = dict(pack, tried=_feedback(tried),
                  hint="上一次选的机制在这台固件上没通过验收，换一个更可能的")
        plan = ask(fb, chat=chat)
        if plan["mechanism"] in {t["mechanism"] for t in tried}:
            order = policy_order or list(FALLBACK_ORDER)
            plan = {"mechanism": next((m for m in order
                                       if m not in {t["mechanism"] for t in tried}),
                                      plan["mechanism"]),
                    "confidence": 0.0, "reason": "模型又选了试过的，按经验顺序换一条",
                    "raw": ""}

    final = best or (tried[-1] if tried else None)
    validated = bool(final and (final.get("probe") or {}).get("handler"))
    routes = []
    if final:
        routes = apply_plan(final["mechanism"], binary, rootfs)["routes"]

    profile = ""
    if final:
        profile = _save_profile(binary, mechanism=final["mechanism"],
                                validated=validated, routes=len(routes),
                                reason=final.get("reason", ""))

    if validated:
        log(f"[discover] 通过验收：{final['mechanism']}"
            f"（{final['probe']['handler']}/{final['probe']['checked']} 条能应答）")
    elif final and final["probe"] is not None:
        log("[discover] 试过的机制都没通过验收 —— 这台固件可能不在目前的能力范围内，"
            "不要把「没对上」当成「没有接口」")

    # 把这次的结论写回经验库：下次同厂固件直接命中，不用再问模型。
    #
    # 注意：**没验收就不能记成功/失败**。之前这里直接按 validated 记，
    # 导致"没有 qemu、根本没验"被当成"机制失败"，把 stats 污染成
    # page_derived@p5: fail=2 —— 下次排序就会把正确机制排到最后。
    if final and use_knowledge:
        kb.remember_vendor(vkey, mechanism=final["mechanism"], validated=validated,
                           routes=len(routes), web=final.get("note", "")[:80])
        if final.get("probe") is not None:
            kb.bump(final["mechanism"], vkey, validated)
        else:
            log("[discover] 本次没有拿到验收结果（服务没应答/没 qemu），不计入机制成功率")
        if not validated and final["probe"] is not None:
            kb.add_lesson(f"{vkey}：{'/'.join(t['mechanism'] for t in tried)} 都没通过路由验收，"
                          f"需要新机制", scope=vkey, evidence=final.get("reason", ""))

    return {"binary": binary, "plan": final or {}, "routes": routes[:400],
            "routes_count": len(routes), "probe": (final or {}).get("probe"),
            "validated": validated, "tried": tried, "profile": profile,
            "vendor": vkey, "knowledge_hit": hit_knowledge}

def firmware_probe(binary: str, rootfs: str | None = None, port: int = 80,
                   timeout: float = 8.0, sample: int = 3, log=print,
                   positive_path: str = "/"):
    """返回一个「能真的问固件」的探针；没有 qemu 就返回 None。

    为什么要用固件自己来验收：模型说这条路对，不算数；
    把路由发过去，固件答不答话，才算数。
    """
    from . import dyn, routes as routes_mod

    rt = dyn.find_runtime(dyn._guess_arch(binary), rootfs, binary)
    if not rt:
        return None

    def _probe(uris):
        # 一次启动、连打多个地址：逐请求重启既慢又容易撞端口（实测 DIR-615 会拿到空响应）
        with dyn.ServiceSession(rt, port=port, log=log) as sess:
            out = routes_mod.probe(list(uris)[:sample], sess.request, rt,
                                   port=port, timeout=timeout, log=log,
                                   positive_path=positive_path)
        handler = sum(1 for v in out["routes"].values()
                      if v["verdict"] == routes_mod.HANDLER)
        return {"checked": len(out["routes"]), "handler": handler,
                "routes": {k: v["verdict"] for k, v in out["routes"].items()},
                "control": {"negative": out["negative"], "positive": out["positive"]}}

    return _probe