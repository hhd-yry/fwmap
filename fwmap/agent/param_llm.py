"""参数补全：从页面与 JS 里找出"真正被提交的字段"（P1）。

为什么需要：`<input name=...>` 只能覆盖静态表单。很多固件用 JS 拼查询串，
或者把 `tmprootAPmac` 改个名字再提交 —— 只抽 input 就会漏，动态验证自然打不中。
实测 Edimax 的 `formStaDrvSetup` 就卡在这里。

防幻觉（硬约束）：
  **模型给出的每个参数名，必须能在页面原文里 grep 到。**
  模型擅长"看出来它叫啥"，不擅长"不编"。这条规则用页面文本就能验，
  比任何提示词都可靠。
"""

from __future__ import annotations

import json
import os
import re

__all__ = ["extract_form_params", "js_names", "infer", "params_for_uri"]

_INPUT = re.compile(r'name\s*=\s*["\']([A-Za-z_][\w.\-]*)["\']', re.I)
_JS_ASSIGN = re.compile(r'["\']([A-Za-z_][\w.\-]{2,40})\s*[=+:]', re.I)
_JS_VAR = re.compile(r'\bvar\s+([A-Za-z_][\w]{2,40})\b')
_SUBMITISH = re.compile(r'(submit|query|param|url|action|form)', re.I)

_PROMPT = """这是一个固件网页表单（含 JS）。请找出**实际会被提交**的字段名。

页面上已静态出现的字段：{known}

页面原文（截断）：
---
{page}
---

规则：
- 只输出 JSON：{{"params": ["字段名", ...]}}
- 字段名必须是页面里**原样出现过**的字符串，不要自己拼；
- 最多 8 个，按你判断的可能性排序；
- 如果找不到新字段，输出空数组。
"""


def extract_form_params(page_text: str) -> list[str]:
    """确定性抽取：所有 name= 字段（去重保序）。"""
    out, seen = [], set()
    for m in _INPUT.finditer(page_text or ""):
        name = m.group(1)
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


_JS_QUERY = re.compile(r"""["']([A-Za-z_][\w.\-]{1,40})\s*=""", re.I)


def js_query_fields(page_text: str) -> list[str]:
    """从 JS 拼的查询串里抽字段名。

    典型写法：``var q = "rootAPmac=" + v; q += "&stadrv_band=" + b;``
    这类字段**不会出现在 <input name=> 里**（页面用的是 tmprootAPmac，
    提交时改名叫 rootAPmac），只抽 input 必然漏掉。

    这是确定性解析：模型答不出来时它照样能找出来；模型答得出来时它用来交叉验证。
    """
    out, seen = [], set()
    for m in _JS_QUERY.finditer(page_text or ""):
        name = m.group(1)
        if name in seen or len(name) < 2:
            continue
        seen.add(name)
        out.append(name)
    return out


def js_names(page_text: str) -> list[str]:
    """从 JS 片段里捞"像字段名"的字符串（确定性，用于给模型当线索）。"""
    out, seen = [], set()
    text = page_text or ""
    for m in _JS_ASSIGN.finditer(text):
        name = m.group(1)
        if name in seen or len(name) < 3:
            continue
        seen.add(name)
        out.append(name)
    for m in _JS_VAR.finditer(text):
        name = m.group(1)
        if name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out[:40]


_SCRIPT = re.compile(r"<script[^>]*>(.*?)</script>", re.I | re.S)
_FORM = re.compile(r"<form\b.*?</form>", re.I | re.S)


def _focus(text: str, limit: int = 6000) -> str:
    """挑最相关的部分给模型看：JS 块 + 表单块。

    直接截前 6000 字符经常把 JS 切掉，而"字段名被 JS 改过"恰恰是最需要看的地方。
    """
    parts = []
    for m in _SCRIPT.finditer(text or ""):
        body = m.group(1)
        if any(k in body.lower() for k in ("submit", "action", "form", "value", "+=")):
            parts.append(body)
        if sum(len(x) for x in parts) > limit:
            break
    for m in _FORM.finditer(text or ""):
        parts.append(m.group(0))
        if sum(len(x) for x in parts) > limit:
            break
    out = "\n".join(parts)
    return (out or text)[:limit]


def _greppable(page_text: str, name: str) -> bool:
    """名字必须原样出现在页面里（防模型编造）。"""
    if not name or len(name) < 2:
        return False
    return re.search(rf"(?<![\w]){re.escape(name)}(?![\w])", page_text or "") is not None


def infer(page_text: str, known: list[str] | None = None, chat=None,
          *, max_params: int = 8, log=print) -> dict:
    """让模型补字段。返回 {params, dropped, source}。"""
    known = list(known or [])
    known_set = set(known)
    text = _focus(page_text or "")
    if chat is None:
        return {"params": [], "dropped": [], "source": "no-llm"}

    hint = js_names(text)[:20]
    prompt = _PROMPT.format(known=", ".join(known) or "（无）", page=text)
    if hint:
        prompt += "\n补充线索（JS 里出现的标识符，仅供参考）：" + ", ".join(hint)
    try:
        reply = chat([{"role": "user", "content": prompt}], max_new_tokens=200) or ""
    except Exception as ex:                                  # noqa: BLE001
        return {"params": [], "dropped": [], "source": f"error:{ex}"}

    m = re.search(r"\{.*\}", reply, re.S)
    if not m:
        return {"params": [], "dropped": [], "source": "no-json"}
    try:
        data = json.loads(m.group(0))
    except ValueError:
        return {"params": [], "dropped": [], "source": "bad-json"}

    got = [str(x).strip() for x in (data.get("params") or []) if str(x).strip()]
    kept, dropped = [], []
    for name in got:
        if name in known_set:
            continue
        if _greppable(text, name):
            kept.append(name)
        else:
            dropped.append(name)                 # 模型编的，丢掉并记账
    if dropped:
        log(f"[params] 丢掉模型编造的字段 {len(dropped)} 个：{', '.join(dropped[:5])}")
    return {"params": kept[:max_params], "dropped": dropped, "source": "llm"}


def _pages_referencing(rootfs: str, uri: str) -> list[str]:
    """找出页面里提到这个 URL 的 asp/html（最多 3 个）。"""
    from .. import pages

    target = (uri or "").strip("/").split("?")[0]
    if not target:
        return []
    hits = []
    for base, _dirs, files in os.walk(rootfs):
        for fn in files:
            if not fn.lower().endswith((".asp", ".html", ".htm", ".js")):
                continue
            p = os.path.join(base, fn)
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            if target.lower() in text.lower():
                hits.append(p)
                if len(hits) >= 3:
                    return hits
    return hits


def params_for_uri(rootfs: str, uri: str, chat=None, *, log=print) -> dict:
    """组合入口：给一个 URI，返回该页面上的全部字段（静态 + 模型补的）。"""
    files = _pages_referencing(rootfs, uri)
    if not files:
        return {"uri": uri, "pages": [], "static": [], "inferred": [],
                "dropped": [], "source": "no-page"}
    static, inferred, dropped = [], [], []
    for path in files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        names = extract_form_params(text) + js_query_fields(text)
        for n in names:
            if n not in static:
                static.append(n)
        res = infer(text, known=static, chat=chat, log=log)
        for n in res["params"]:
            if n not in inferred and n not in static:
                inferred.append(n)
        dropped.extend(res["dropped"])
    js_only = []
    for path in files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for n in js_query_fields(text):
            if n not in js_only:
                js_only.append(n)
    return {"uri": uri, "pages": files, "static": static,
            "js_fields": js_only, "inferred": inferred, "dropped": dropped,
            "source": "llm" if inferred else ("static" if static else "none")}
