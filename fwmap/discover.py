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

__all__ = ["evidence", "ask", "apply_plan", "discover", "MECHANISMS", "PROMPT"]

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


def discover(binary: str, rootfs: str | None = None, *, chat=None, probe=None,
             log=print, rounds: int = 2) -> dict:
    """完整流程：证据 → 模型选路 → 代码执行 → 探测验收（→ 不满意就再来一轮）。"""
    pack = evidence(binary, rootfs)
    log(f"[discover] 证据：{pack.get('strings')} 条字符串、"
        f"{pack.get('route_like_count')} 个路径候选、{pack.get('pages_forms', 0)} 个网页表单")
    plan = ask(pack, chat=chat)
    log(f"[discover] 模型选择：{plan['mechanism']}（置信 {plan['confidence']:.2f}）"
        f" —— {plan['reason']}")

    result = apply_plan(plan["mechanism"], binary, rootfs)
    routes = result["routes"]
    log(f"[discover] 抽出 {len(routes)} 条路由（{result['note']}）")

    verdict = None
    if probe and routes:
        sample = [r["uri"] for r in routes[:3]]
        verdict = probe(sample)          # 交给调用方决定怎么探测（需要固件能跑）
        log(f"[discover] 探测结果：{verdict}")

    out = {"binary": binary, "plan": plan, "routes": routes[:400],
           "routes_count": len(routes), "probe": verdict,
           "profile": _cache_path(binary)}
    try:
        with open(out["profile"], "w", encoding="utf-8") as fh:
            json.dump({"plan": plan, "routes_count": len(routes)}, fh,
                      ensure_ascii=False, indent=1)
    except OSError:
        pass
    return out
