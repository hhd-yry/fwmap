"""错误页解读 + 自动补全重打（P1-2）。

动机（实测）：Edimax 的 `formStaDrvSetup` 只带 4 个字段时返回 184–199 字节的
错误页，带齐页面上的 18 个字段后返回 1523 字节的正常页 —— 处理器"接受"了请求。

所以"没崩"不等于"没打到"，更不等于"这处理器不吃这个参数"。
这一层做的事：

    响应像错误页  →  从页面抽出完整字段集  →  把载荷放进源参数重打一次

模型可选：让它判断"这些字段里哪些是必须的"，但**字段名必须来自页面原文**
（复用 `param_llm` 的 grep 校验），不允许自己编。
"""

from __future__ import annotations

import os

__all__ = ["looks_like_error", "full_fields", "plan_retry"]

# 常见"被处理器拒绝"的痕迹（大小写不敏感）
ERROR_MARKERS = (
    "invalid", "error", "fail", "failed", "denied", "not allowed",
    "missing", "required", "please select", "please input", "cannot",
    "not support", "unsupported", "illegal",
)

# 只有这么小、又没有任何管理页特征的响应，才更像错误页
_MAX_ERROR_BYTES = 600


def looks_like_error(resp: str, resp_len: int | None = None) -> bool:
    """响应像不像"处理器拒绝了这次请求"。"""
    text = (resp or "").lower()
    size = resp_len if resp_len is not None else len(text)
    if not text:
        return False
    # 正常管理页通常几千字节，还带一堆表单/脚本
    big = size > _MAX_ERROR_BYTES and ("<form" in text or "<script" in text)
    if big:
        return False
    return any(m in text for m in ERROR_MARKERS)


def _default_value(name: str, page_text: str) -> str:
    """给字段挑一个"最像默认值"的值：页面里写了 value= 就用它。"""
    import re

    m = re.search(rf'name\s*=\s*["\']{re.escape(name)}["\'][^>]*value\s*=\s*["\']([^"\']*)["\']',
                  page_text or "", re.I)
    if not m:
        return ""
    val = m.group(1)
    # 页面里的默认值常是模板片段（`<% getInfo(...) %>`）或 JS 拼接，直接用会出错
    if "<%" in val or ">" in val or "document." in val or "function" in val:
        return ""
    return val


def _best_page(rootfs: str, uri: str, want: str = "") -> str:
    """挑出"表单 action 正是这个 URI"的那一页。

    为什么不能把所有提到该 URI 的页面混在一起：实测 Edimax 有 3 个页面提到
    formStaDrvSetup（inter_wan / inter_wisp / mstart_iqsetup），字段并集 110 个，
    混着发过去处理器直接不认——必须先锁定真正提交它的表单页。
    """
    import glob
    import re as _re

    target = (uri or "").split("?")[0]
    if not target:
        return ""
    best, best_score = "", -1
    for path in glob.glob(os.path.join(rootfs, "**", "*.asp"), recursive=True) + \
            glob.glob(os.path.join(rootfs, "**", "*.html"), recursive=True):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        has_action = bool(_re.search(
            rf"action\s*=\s*[\"']?{_re.escape(target)}[\"']?", text, _re.I))
        has_uri = target.lower() in text.lower()
        has_want = bool(want) and want in text
        if not (has_action or has_uri):
            continue
        # 优先：表单 action 精确匹配 + 页面里确实出现源参数（如 rootAPmac）
        score = (2 if has_action else 0) + (2 if has_want else 0)
        if score > best_score:
            best, best_score = path, score
    return best


_SENSIBLE = (
    (("ssid",), "test"),
    (("band", "mode", "type", "format", "encrypt"), "0"),
    (("cipher",), "2"),
    (("psk", "passwd", "password", "pass"), "admin12345"),
    (("mac",), "00:11:22:33:44:55"),
    (("chan",), "6"),
    (("ipaddr", "ip"), "192.168.1.100"),
    (("hostname",), "test"),
    (("submit", "save"), "Save"),
)


def _sensible(name: str, value: str) -> str:
    """空字段给一个"看起来合理"的值。

    实测：字段全带上、但值全空时，处理器照样提前 return（19 个字段也没打出命令执行）。
    所以不仅要有字段，还要有能过校验的值。
    """
    if value:
        return value
    low = name.lower()
    for keys, val in _SENSIBLE:
        if any(k in low for k in keys):
            return val
    if low.startswith("is") or low.endswith("enable"):
        return "1"
    return ""


def full_fields(rootfs: str, uri: str, *, payload: str = "", payload_key: str = "",
                page_path: str = "") -> dict:
    """把页面上的字段铺开，载荷放进 `payload_key`。"""
    from ..agent import param_llm

    if page_path:
        try:
            with open(page_path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            text = ""
        names = param_llm.extract_form_params(text) + param_llm.js_query_fields(text)
        res = {"pages": [page_path], "static": names}
    else:
        res = param_llm.params_for_uri(rootfs, uri, chat=None)
    fields: dict[str, str] = {}
    page_text = ""
    for path in res.get("pages") or []:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                page_text += fh.read()
        except OSError:
            continue

    for name in res.get("static") or []:
        fields[name] = _sensible(name, _default_value(name, page_text))

    if payload_key:
        fields[payload_key] = payload
    # submit-url 指向发起页；有的处理器会校验它（实测填 "Save" 会被拒）
    if "submit-url" in fields:
        # 指向"发起这个请求的页面"（如 /inter_wisp.asp），不是接口自身
        fields["submit-url"] = ("/" + os.path.basename(page_path)) if page_path else uri
    return fields


def plan_retry(chain: dict, resp: str, rootfs: str, *, resp_len: int | None = None,
               current_fields: dict | None = None, payload_value: str = "",
               chat=None, force: bool = False, log=print) -> dict | None:
    """判断要不要重打；要，就给出完整字段集。

    返回 {"uri": ..., "fields": {...}, "payload_key": ..., "why": ...} 或 None。
    """
    # force=True：命令注入类链"没崩也没执行"时，不管响应像不像错误页都补全字段重打一次
    # （实测 handler 在字段不全时也会回正常页面，光看错误页会漏）
    if not force and not looks_like_error(resp, resp_len):
        return None
    uri = ""
    try:
        from .. import poc

        uri = poc.guess_path(chain.get("function") or "", chain.get("uri") or "")
    except Exception:                                    # noqa: BLE001
        uri = chain.get("uri") or ""
    if not uri:
        return None

    payload_key = chain.get("source_param") or ""
    # 关键：把**原来那一发的载荷**放进完整字段集里，否则重打等于"用空值再发一次"
    page = _best_page(rootfs, uri, chain.get("source_param") or "")
    fields = (full_fields(rootfs, uri, payload=payload_value, payload_key=payload_key,
                          page_path=page)
              if payload_key else full_fields(rootfs, uri, page_path=page))
    if not fields:
        return None
    if current_fields and len(fields) <= len(current_fields):
        return None                                      # 没有更多字段可加，别原地打转

    why = f"响应像错误页（{len(resp or '')}B），改用页面上的 {len(fields)} 个字段重打"
    if chat is not None and payload_key:
        # 让模型只在"哪些字段必须带"上给意见，字段名仍要能在页面里找到
        try:
            from . import param_llm

            pick = param_llm.infer(resp or "", known=list(fields), chat=chat, log=log)
            for name in pick.get("params") or []:
                if name in fields:
                    fields[name] = fields.get(name) or "1"
        except Exception:                                # noqa: BLE001
            pass
    return {"uri": uri, "fields": fields, "payload_key": payload_key, "why": why}
