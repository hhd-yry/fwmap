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
    # 前缀剥离不能写成 lstrip("./") —— 那是字符集剥离，"../x" 会被吃成 "/x"
    while uri.startswith(("./", "../")):
        uri = uri[2:] if uri.startswith("./") else uri[3:]
    if not uri or uri in ("#", "/"):
        return ""                      # 空 action / "#" / 裸斜杠不是路由
    if not uri.startswith("/"):
        uri = "/" + uri
    return uri


def _params_in(block: str) -> list[str]:
    out: list[str] = []
    for name in _RE_INPUT.findall(block):
        if name.lower() in ("submit", "reset", "button") or name in out:
            continue
        out.append(name)
    return out


_RE_CGI = re.compile(r"""["']([^"'\s]*?/(?:cgi-bin/)?[\w\-]+\.cgi)(?:\?([^"'\s]*))?["']""")
_RE_QS = re.compile(r"([A-Za-z_][\w\-]{0,30})=")


def cgi_routes(text: str) -> list[dict]:
    """从页面/JS 里抽 CGI 入口：`index.cgi?v2_action=xxx&...`

    很多固件（D-Link 的 enduser 固件就是）没有 /goform，只有一个 CGI 分发器：
    URL 永远是某个 .cgi，功能靠 query 里的 action 区分。
    这种形态下"参数名"就是 query 里的键，比瞎猜强得多。
    """
    out: list[dict] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for m in _RE_CGI.finditer(text):
        raw, qs = m.group(1), (m.group(2) or "")
        uri = "/" + raw.split("/")[-1]          # 只保留文件名：/index.cgi
        params = []
        for k in _RE_QS.findall(qs):
            if k not in params and k not in ("submit", "action"):
                params.append(k)
        key = (uri, tuple(params))
        if key in seen:
            continue
        seen.add(key)
        out.append({"uri": uri, "params": params, "kind": "cgi"})
    return out


def forms_of(text: str) -> list[dict]:
    """从一个页面的文本里抽出它的表单：[{uri, params}]。"""
    found: list[dict] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()

    def add(uri: str, params: list[str]) -> None:
        if not uri:
            return
        u = _norm(uri)
        if not u:                      # 归一化之后才丢弃：action="#" / action="/"
            return
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

    # 4) CGI 分发器形态（index.cgi?v2_action=xxx）：和表单并存，不互斥
    for r in cgi_routes(text):
        key = (r["uri"], tuple(r["params"]))
        if key not in seen:
            seen.add(key)
            found.append(dict(r))
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
    # 段为空（uri 是 "/"）或太短时，"以它开头"会命中任意函数：
    #   last_seg("/") == ""    → low.startswith("") 恒为 True
    #   last_seg("/a") == "a"  → 任何以 a 开头的函数都命中
    def usable(seg: str, min_len: int = 3) -> bool:
        return len(seg) >= min_len

    for f in forms:
        seg = last_seg(f["uri"])
        if usable(seg) and (seg.startswith(low) or low.startswith(seg)):
            return best([x for x in forms
                         if usable(last_seg(x["uri"]))
                         and (last_seg(x["uri"]).startswith(low)
                              or low.startswith(last_seg(x["uri"])))])
    for f in forms:
        if low in f["uri"].lower():
            return best([x for x in forms if low in x["uri"].lower()])
    for f in forms:
        if any(low == p.lower() for p in f["params"]):
            return f
    return None
