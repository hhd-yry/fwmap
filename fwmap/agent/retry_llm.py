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
    return m.group(1) if m else ""


def full_fields(rootfs: str, uri: str, *, payload: str = "", payload_key: str = "") -> dict:
    """把页面上的字段全铺开，载荷放进 `payload_key`。"""
    from . import param_llm

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
        fields[name] = _default_value(name, page_text)

    if payload_key:
        fields[payload_key] = payload
    # 很多固件要求带上 submit-url，缺了就当非法请求
    if "submit-url" in fields and not fields["submit-url"]:
        fields["submit-url"] = uri
    return fields


def plan_retry(chain: dict, resp: str, rootfs: str, *, resp_len: int | None = None,
               current_fields: dict | None = None, chat=None, log=print) -> dict | None:
    """判断要不要重打；要，就给出完整字段集。

    返回 {"uri": ..., "fields": {...}, "payload_key": ..., "why": ...} 或 None。
    """
    if not looks_like_error(resp, resp_len):
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
    payload = ""
    fields = full_fields(rootfs, uri, payload=payload, payload_key="") if payload_key else \
        full_fields(rootfs, uri)
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
