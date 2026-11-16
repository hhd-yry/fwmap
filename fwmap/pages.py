"""从固件自带的网页里，把「URL → 参数名」直接读出来。

为什么值得单独一个模块：**这是最便宜、最贴近真实请求的一条路**。
浏览器提交什么字段、打到哪个 action，页面上写得明明白白；
而反编译里的 `websGetVar(a1, "xxx")` 常常因为字符串被优化成 DAT_ 而抽不出来。

实测（Edimax BR-6478AC）：165 个页面文件里，4/4 条链的表单都找到了，
其中 `formWdsEncrypt` 的真实 URL 是 `/goform/formWdsEncrypt5G` ——
跟函数名对不上，靠猜永远猜不到。

局限（必须写清，不然会被当成"没有这个接口"）：
- 只覆盖**有页面**的功能；隐藏接口、纯 API 设备抽不到
- action 由 JS 动态拼（`"/goform/" + x`）时抽不到
- 所有表单打同一个总入口（`/goform/aspRpm`）时，参数名还在，URL 对不上
"""

from __future__ import annotations

import os
import re

__all__ = ["scan", "lookup", "forms_of"]

PAGE_EXT = (".asp", ".htm", ".html", ".shtml", ".js", ".cgi", ".xml")
MAX_FILE = 512 * 1024
# 我们自己产出的报告别当成固件页面：曾经有一份 triage 报告被写进了固件目录，
# 结果被当成"页面"扫出来，给出一个没有参数的假路由。
_SKIP_NAMES = ("fwmap-report.html", "report.html", "survey.html")


def _skip(path: str) -> bool:
    name = os.path.basename(path).lower()
    if name in _SKIP_NAMES or name.startswith("fwmap-"):
        return True
    return False

_RE_FORM_OPEN = re.compile(r"<form\b[^>]*>", re.I)
_RE_ACTION = re.compile(r"""action\s*=\s*["']([^"']+)["']""", re.I)
_RE_JS_ACTION = re.compile(r"""\.action\s*=\s*["']([^"']+)["']""", re.I)
_RE_INPUT = re.compile(r"""<(?:input|select|textarea|button)\b[^>]*?"""
                       r"""name\s*=\s*["']([^"']{1,40})["']""", re.I)
_RE_GOFORM = re.compile(r"""["']?(/?goform/[A-Za-z0-9_.\-]+)""")
_RE_URI_ATTR = re.compile(r"""["'](/?[A-Za-z0-9_./\-]*goform/[A-Za-z0-9_.\-]+)["']""")


def _norm(uri: str) -> str:
    uri = uri.strip().strip('"\'')
    uri = uri.split("?", 1)[0].split("#", 1)[0]
    if not uri.startswith("/"):
        uri = "/" + uri.lstrip("./")
    return uri


def _params_in(block: str) -> list[str]:
    out: list[str] = []
    for name in _RE_INPUT.findall(block):
        if name.lower() in ("submit", "reset", "button") or name in out:
            continue
        out.append(name)
    return out


def forms_of(text: str) -> list[dict]:
    """从一个页面的文本里抽出它的表单：[{uri, params}]。"""
    found: list[dict] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()

    def add(uri: str, params: list[str]) -> None:
        if not uri:
            return
        u = _norm(uri)
        key = (u, tuple(params))
        if key in seen:
            return
        seen.add(key)
        found.append({"uri": u, "params": params})

    # 1) 正常表单：<form action=...> ... </form>
    blocks = [(m.start(), m.group(0)) for m in _RE_FORM_OPEN.finditer(text)]
    for i, (pos, tag) in enumerate(blocks):
        m = _RE_ACTION.search(tag)
        if not m:
            continue
        end = text.lower().find("</form>", pos)
        end = len(text) if end < 0 else end
        add(m.group(1), _params_in(text[pos:end]))

    # 2) JS 里拼 action 的，参数名只能整页找
    if not found:
        for m in _RE_JS_ACTION.finditer(text):
            add(m.group(1), _params_in(text))

    # 3) 页面里只是提到 /goform/xxx（没有 form 标签）：参数名靠整页
    if not found:
        for m in _RE_GOFORM.finditer(text):
            add(m.group(1), _params_in(text))
    return found


def scan(rootfs: str, max_files: int = 800) -> list[dict]:
    """扫一个 rootfs，返回 [{'uri','params','file'}]，按文件去重。"""
    out: list[dict] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    n = 0
    for base, dirs, files in os.walk(rootfs):
        dirs[:] = [d for d in dirs if d not in ("proc", "sys", "dev", "tmp")]
        for name in files:
            if not name.lower().endswith(PAGE_EXT):
                continue
            path = os.path.join(base, name)
            if _skip(path):
                continue
            try:
                if os.path.getsize(path) > MAX_FILE:
                    continue
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            rel = os.path.relpath(path, rootfs)
            for f in forms_of(text):
                key = (f["uri"], tuple(f["params"]))
                if key in seen:
                    continue
                seen.add(key)
                out.append({**f, "file": rel})
            n += 1
            if n >= max_files:
                return out
    return out


def lookup(forms: list[dict], function: str) -> dict | None:
    """按函数名找最像它的表单。

    匹配顺序（先严后松）：
      1. URI 末段 == 函数名            `/goform/formiNICWdsEncrypt`
      2. URI 末段以函数名开头          `/goform/formWdsEncrypt5G`
      3. 函数名出现在 URI 里
      4. 函数名出现在参数名里（少见，但便宜）
    """
    if not forms or not function:
        return None
    fn = function.strip()
    low = fn.lower()

    def last_seg(uri: str) -> str:
        return uri.rstrip("/").rsplit("/", 1)[-1].lower()

    def best(cands: list[dict]) -> dict | None:
        """同一个 URL 有多条记录时，取参数最全的那条（页面上字段才是真实提交的）。"""
        if not cands:
            return None
        return max(cands, key=lambda f: len(f["params"]))

    for f in forms:
        if last_seg(f["uri"]) == low:
            return best([x for x in forms if last_seg(x["uri"]) == low])
    for f in forms:
        seg = last_seg(f["uri"])
        if seg.startswith(low) or low.startswith(seg):
            return best([x for x in forms
                         if last_seg(x["uri"]).startswith(low) or low.startswith(
                             last_seg(x["uri"]))])
    for f in forms:
        if low in f["uri"].lower():
            return best([x for x in forms if low in x["uri"].lower()])
    for f in forms:
        if any(low == p.lower() for p in f["params"]):
            return f
    return None
