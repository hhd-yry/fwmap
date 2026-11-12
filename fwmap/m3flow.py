"""M3.2：函数内 + 一层 helper 调用的数据流（源调用 → 汇调用）。

做法：把函数的反编译 C 取出来，在 C 文本上做变量级污点。
为什么不用 p-code：栈变量在 p-code 里是 STORE/LOAD 链，在 C 里就是 local_40 这样的名字。
代价是脆弱（依赖反编译器的变量命名），所以结论最高只给 medium。

两跳：
  1. handler 里找"污染变量被当实参传给内部 helper"的调用；
  2. 把 helper 的第 N 个形参 param_N 当污染种子，在 helper 里找 sink。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

from .m2 import find_ghidra
from .m3 import catalog_path

ASSIGN = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*(.+)$", re.S)


# ---------------------------------------------------------------- 目录

def _load_catalog(path: str) -> tuple[set[str], dict[str, str], dict[str, str]]:
    sources, sinks, weak = set(), {}, {}
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        kind, name = parts[0], parts[-1]
        if kind == "source":
            sources.add(name)
            EXPLICIT_SOURCES.add(name)
        elif kind == "source-weak":
            weak[name] = "weak"
            sources.add(name)
            EXPLICIT_SOURCES.add(name)
        elif kind == "source-induced":
            # 归纳出来的源和归纳出来的汇一样，是"弱证据"：
            # 它只是"被很多调用点用不同字符串调用"的形状，日志函数、错误上报、
            # inet_ntop 包装全都长这样。P2 实测：新固件上仅有的 4 条强源链
            # 全部来自 sa_straddr（inet_ntop 包装，返回客户端 IP），4/4 假阳性。
            # 和 sink-ci-induced 对称：仍当源用，但单独记一份名单，不进"强源"组。
            #
            # 但**显式目录压倒归纳**：把归纳阈值降到 3 之后，归纳器会重新"发现"
            # get_cgi 这种已经在 taint.txt 里的取参 API（它本来就长成"被很多
            # 调用点用不同字符串调用"的样子）。不排除的话，F1 会把 Cisco 的
            # CVE-2020-3331 正例一起降级——实测整份二进制 20 条强源全变弱。
            sources.add(name)
            if name not in EXPLICIT_SOURCES:
                INDUCED_SOURCES.add(name)
        elif kind.startswith("sink-"):
            cat = kind[5:]
            # 归纳出来的汇是"弱证据"：它是"能走到 system"的函数，不是直接调 system 的调用点。
            # 类别仍记 ci（下游规则/排序都按 ci 处理），但单独记一份名单给排序用。
            if cat == "ci-induced":
                INDUCED_SINKS.add(name)
                cat = "ci"
            sinks[name] = cat
    return sources, sinks, weak


# 由 InduceSinks 归纳出来的 sink（名字集合）。run_flow 用它把"直接汇"排在"诱导汇"前面。
INDUCED_SINKS: set[str] = set()

# 由 InduceSources 归纳出来的 source（名字集合）。和 INDUCED_SINKS 对称：
# 命中它的链照常保留，但**不进强源组**，单列出来给人看。
INDUCED_SOURCES: set[str] = set()

# 人工/目录里**显式**确认过的源。必须先于 profile 加载（m3.py 和 run_flow 都是
# 先目录后 profile），这样 profile 里同名的 source-induced 就不会覆盖显式结论。
EXPLICIT_SOURCES: set[str] = set()


# ---------------------------------------------------------------- C 文本解析

C_KEYWORDS = {"if", "while", "for", "switch", "return", "sizeof", "else", "do", "case"}


def _calls(stmt: str) -> list[tuple[str, str]]:
    """语句里所有 函数名(参数)。参数用括号配对取。"""
    out = []
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", stmt):
        name = m.group(1)
        if name in C_KEYWORDS:
            continue
        start = m.end()
        depth, i = 1, start
        while i < len(stmt) and depth:
            if stmt[i] == "(":
                depth += 1
            elif stmt[i] == ")":
                depth -= 1
            i += 1
        out.append((name, stmt[start:i - 1] if depth == 0 else stmt[start:]))
    return out


def _body(c_text: str) -> str:
    """去掉函数签名，只留花括号之后的函数体（否则签名会被当成一次自调用）。"""
    i = c_text.find("{")
    return c_text[i + 1:] if i >= 0 else c_text


def _strip_line_comments(text: str) -> str:
    """去掉 `//` 行注释，但**不能碰字符串字面量里的 `//`**。

    原来的写法是 `re.sub(r"//[^\\n]*", "", text)`，于是
        local_22c = "http://purenetworks.com/HNAP1/GetDeviceSettings";
    里的 `//` 被当成注释，整行后半截被删掉 —— 语句被切碎、后面的 if/else 连成一句、
    `pcVar1 = strrchr(local_22c,'/')` 根本不成语句，污点传播永远跑不到，
    归因就停在旧源上（DIR-842 实测：报成 HNAP_AUTH，实际是 SOAPACTION）。
    厂商固件里 URL、`http://` 遍地都是，这个 bug 影响面很大。
    """
    out, i, n = [], 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:          # 转义字符原样带过
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            if j < 0:
                break
            i = j
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _statements(c_text: str) -> list[str]:
    """按分号切语句（忽略字符串和圆括号里的分号）。反编译的 C 是多行的，不能按行切。"""
    text = _strip_line_comments(c_text)
    out, buf = [], []
    depth, in_str, i = 0, False, 0
    while i < len(text):
        ch = text[i]
        if in_str:
            buf.append(ch)
            if ch == '"' and text[i - 1] != "\\":
                in_str = False
        elif ch == '"':
            in_str = True
            buf.append(ch)
        elif ch in "([":
            depth += 1
            buf.append(ch)
        elif ch in ")]":
            depth -= 1
            buf.append(ch)
        elif ch == ";" and depth == 0:
            s = "".join(buf).strip()
            if s:
                out.append(s)
            buf = []
        else:
            buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        out.append(tail)
    return out


def _assign(stmt: str):
    """取语句里的赋值——可能藏在 `if (...) {` 后面（实测 formSetMacFilterCfg 就是这样）。

    也要剥掉**前导的 `}`**：按 `;` 切语句时，上一个 if 块的收尾 `}` 会挂在下一句开头，
    形如 `}\\n  iVar1 = httpGetEnv(param_1,"ping_addr")`。不剥的话这一句的赋值
    直接判成"没有赋值"，污染从第一步就丢了——TP-Link WR940N 的 ping_addr 就是这样
    整条断掉的（CVE-2017-13772）。
    """
    body = stmt.rsplit("{", 1)[-1].strip()
    body = re.sub(r"^[\s}]+", "", body)
    return ASSIGN.match(body)


def _first_string(args: str) -> str:
    m = re.search(r'"([^"]{1,40})"', args)
    return m.group(1) if m else ""


def _split_args(args: str) -> list[str]:
    """按顶层逗号切实参。"""
    out, depth, cur = [], 0, []
    for ch in args:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur).strip())
    return out


# ---------------------------------------------------------------- 源的强弱重判
#
# taint.txt 把 getenv 一律标成 source-weak。但 `getenv("REQUEST_URI")` 和
# `getenv("PATH")` 完全不是一回事：前者是外部输入，后者是环境配置。
# CGI 型固件（D-Link 全家）取参就走 getenv，一律按弱源处理等于整类目标失明。
REQUEST_ENV = re.compile(
    r"^(REQUEST_URI|QUERY_STRING|PATH_INFO|PATH_TRANSLATED|CONTENT_TYPE|"
    r"HTTP_[A-Za-z0-9_]+)$")
# 注意：REQUEST_METHOD / CONTENT_LENGTH 不算。前者是 GET/POST 这种定值，
# 后者是数字——把它们当强源会直接产出 `getenv(REQUEST_METHOD) -> system`
# 这种假阳性（实测在 D-Link cgibin 上就冒出来了）。


def _is_weak(api: str, args: str, weak: dict[str, str]) -> bool:
    """这个源调用算不算弱源。"""
    if api not in weak:
        return False
    if api == "getenv" and REQUEST_ENV.match(_first_string(args) or ""):
        return False
    return True


def normalize_weak(functions: list[dict], weak: dict[str, str]) -> int:
    """按上面的规则重算每个函数的 source.weak 标记，返回被翻强的条数。

    m3.py 用它筛"有强源但本函数没有汇"的补充池；不重算的话
    genacgi_main（只有 getenv）永远进不了分析池。
    """
    flipped = 0
    for fn in functions:
        for s in fn.get("sources") or []:
            if not s.get("weak"):
                continue
            if not _is_weak(s.get("api", ""), '"%s"' % s.get("param", ""), weak):
                s["weak"] = False
                flipped += 1
    return flipped


# ---------------------------------------------------------------- 缓冲区写入
#
# snprintf(buf, n, fmt, ..., 污染, ...) 之后 buf 就带着污染了。
# 不建模这一步，"先拼字符串、再交给执行器"的写法整条断掉——
# D-Link 的 `SHELL_FILE=/var/run/<service>.sh` 就是这种。
BUFFER_WRITE = {
    "snprintf": 0, "sprintf": 0, "vsnprintf": 0, "vsprintf": 0,
    "strcpy": 0, "strncpy": 0, "strcat": 0, "strncat": 0,
    "memcpy": 0, "memmove": 0,
}


def _const_len(expr: str) -> int | None:
    """实参是不是常数长度；是就返回它。"""
    e = expr.strip()
    m = re.fullmatch(r"(0x[0-9a-fA-F]+|\d+)", e)
    if m:
        return int(m.group(1), 0)
    return None


# 这些函数把"最多多少个字节"写在第 3 个实参（index 2）上
LEN_AT_2 = {"strncpy", "strncat", "memcpy", "memmove"}


def _taint_buffer_write(calls: list[tuple[str, str]], tainted: dict[str, dict]) -> None:
    """把"污染值写进缓冲"这一步补上，并记下这个缓冲**最多多长**。

    记 maxlen 是关键：`strncpy(buf, src, 4)` 之后 `strcpy(dst, buf)` 永远溢不出，
    但引擎原来只记"buf 有污染"，不记"buf 最多 4 字节"，
    于是 WR841N 上 6 条 CONFIRMED 里有 4 条是这种有界拷贝（全假阳性）。
    """
    if not calls or not tainted:
        return
    for name, args in calls:
        if name not in BUFFER_WRITE:
            continue
        parts = _split_args(args)
        if len(parts) < 2:
            continue
        hit = None
        for a in parts[1:]:
            for v, info in tainted.items():
                if re.search(rf"\b{re.escape(v)}\b", a):
                    hit = dict(info)
                    break
            if hit:
                break
        if not hit:
            continue

        # 这次写入能给目标缓冲多少字节的**上界**
        cap = None
        if name in LEN_AT_2 and len(parts) >= 3:
            cap = _const_len(parts[2])
        elif name in ("snprintf", "vsnprintf") and len(parts) >= 2:
            n = _const_len(parts[1])
            cap = None if n is None else n - 1
        elif name in ("strncat",):
            cap = None
        # sprintf/strcpy/strcat：长度不受控 → cap 保持 None（比来源的 maxlen 更宽）
        if cap is None:
            cap = hit.get("maxlen")          # 无界拷贝，最多等于来源的上界
        hit["maxlen"] = cap

        dm = re.match(r"&?\s*([A-Za-z_]\w*)", parts[0].strip())
        if dm:
            # 已有的污染不覆盖（先来的通常更接近真正的源），但 maxlen 要取更紧的
            cur = tainted.get(dm.group(1))
            if cur is None:
                tainted[dm.group(1)] = hit
            else:
                cur["maxlen"] = cap if cur.get("maxlen") is None else \
                    min(cur["maxlen"], cap) if cap is not None else cur["maxlen"]


# 往缓冲里写**非污染数据**的调用：会把之前的污染冲掉。
#   memset(buf,0,n)     清空
#   fgets(buf,n,fp)     从文件读
# 不处理的话会出现这种假阳性（Cisco Check_TSSI 实测）：
#   sprintf(acStack_1d0, fmt, 来自 get_cgi 的值)   ; 污染
#   fgets(acStack_1d0, 0x50)                      ; 覆盖成文件内容
#   strcpy(local_30, acStack_1d0)                 ; 仍按 get_cgi 报
# 注意 recv/recvfrom 不在此列——它们是源，不是清污染。
BUFFER_KILL = {"memset", "fgets", "bzero"}


def _kill_buffer_taint(calls: list[tuple[str, str]], tainted: dict[str, dict]) -> None:
    if not calls or not tainted:
        return
    for name, args in calls:
        if name not in BUFFER_KILL:
            continue
        parts = _split_args(args)
        if not parts:
            continue
        dm = re.match(r"&?\s*([A-Za-z_]\w*)", parts[0].strip())
        if dm:
            tainted.pop(dm.group(1), None)


# ---------------------------------------------------------------- 出参污染
#
# 厂商的解析 API 普遍用出参：返回值只是错误码，数据写在 &x 里。
#     iVar1 = ATP_XML_GetChildNodeByName(node, "NewStatusURL", 0, &local_414);
# 只认 `x = f(...)` 的返回值形式，这类源一个都接不上——华为 HG532 的
# CVE-2017-17215 就断在这里（整份二进制 0 条链）。
OUT_PARAM = re.compile(r"^\s*&\s*([A-Za-z_]\w*)\s*$")


def _taint_out_params(src_args: str, info: dict, tainted: dict[str, dict]) -> None:
    """源调用的 &x 实参算被污染。"""
    for a in _split_args(src_args):
        m = OUT_PARAM.match(a)
        if m:
            tainted.setdefault(m.group(1), dict(info))


# ---------------------------------------------------------------- 缓冲区型源
#
# 上面那种"返回值型源"（websGetVar/getenv）只是源的一半。
# 另一半是**副作用型源**：数据不是返回值，是被写进去的那个实参。经典的：
#     read(fd, buf, n);        recv(fd, buf, n, 0);      recvmsg(fd, msg, 0);
# Semgrep 把这类叫 by-side-effect source。我们原来只有 `recv`（还得是返回值恰好
# 被赋给一个变量才接得上），VIVOTEK 的 httpd 用 recvmsg 读 socket，
# 整个 212 个函数里 **0 个 recv 类源**，污点连起点都没有。
#
# 值是该 API 的"数据落到第几个实参"：
BUFFER_SOURCE = {
    "read": 1, "recv": 1, "recvfrom": 1, "recvmsg": 1,
}

_CAST = re.compile(
    r"\(\s*(?:char|void|int|uint|uint\d*|undefined\d*|uchar|byte|short|long|"
    r"size_t|code|FILE)\s*\*?\s*\)")


def _first_var(expr: str) -> str | None:
    """表达式里第一个"像变量"的标识符（跳过强制类型转换）。

    `pcVar7 + param_1[0x65d]`        -> pcVar7
    `(char *)((int)param_1 + 0x357a)` -> param_1
    """
    e = _CAST.sub(" ", expr)
    m = re.search(r"\b([A-Za-z_]\w*)\b", e)
    return m.group(1) if m else None


def _taint_buffer_sources(api: str, src_args: str, info: dict,
                          tainted: dict[str, dict]) -> None:
    """缓冲区型源：把"数据落到的那个实参"的基变量标脏。"""
    idx = BUFFER_SOURCE.get(api)
    if idx is None:
        return
    parts = _split_args(src_args)
    if idx >= len(parts):
        return
    v = _first_var(parts[idx])
    if v:
        tainted.setdefault(v, dict(info))


# ---------------------------------------------------------------- 传播器
#
# `pcVar10 = strstr(pcVar7, "...")` —— 返回值是指向污染缓冲的指针，
# 但 analyze_c 原来只在"右边没有调用"时才传播（简单赋值）。
# 于是指针运算一律断链：VIVOTEK 的 strncpy 溢出，源是 read 进缓冲，
# 中间过了 strstr/strchr 三次，一次都没传过去。
#
# Semgrep 把这层叫 pattern-propagators。这里只收"返回入参之一/其子串"的函数。
PROPAGATORS = {
    "strstr", "strchr", "strrchr", "strcasestr", "strpbrk", "strsep",
    "strdup", "strndup", "strtok", "strtok_r", "memchr", "index", "rindex",
    "basename", "dirname",
}


def _propagate_through_calls(calls: list[tuple[str, str]], m,
                             tainted: dict[str, dict]) -> None:
    """y = f(..., 污染, ...) 且 f 是传播器 → y 也脏。

    这里必须是**覆盖**，不能是 `setdefault`。
    DIR-842 实测的归因错误就出在这：`pcVar1` 先被 `getenv("HTTP_HNAP_AUTH")`
    标脏，后面 `pcVar1 = strrchr(local_22c, '/')` 已经换成了 SOAPACTION 里面的
    一段路径；`setdefault` 让旧源留了下来，最后报出来的是"HNAP_AUTH → sprintf"，
    而真正进 sprintf 的是 SOAPACTION 的一段。
    变量被重新赋值之后，它装的就是这次调用的返回值，旧的源已经不在了。
    """
    if not m or not calls or not tainted:
        return
    for name, args in calls:
        if name not in PROPAGATORS:
            continue
        for v, info in list(tainted.items()):
            if re.search(rf"\b{re.escape(v)}\b", args):
                tainted[m.group(1)] = dict(info)
                return


# ---------------------------------------------------------------- 赋值清污染
#
# 变量被**重新赋值**时，旧的污染要清掉。不清的话会出现这种假阳性：
#     uVar3 = websGetVar(param_1,"security","")   ; 污染
#     ...
#     uVar3 = get_uptime()                        ; 换成运行时间，是个数字
#     doSystemCmd("...string_info=%d", 3, uVar3)  ; 工具仍按 websGetVar 报
#
# 实测这一条同时污染了 Tenda（formWifiBasicSet）、TOTOLINK（FUN_0042aeec 的
# loginAuthUrl/http_host/username）、Cisco（Check_TSSI）三个样本。
def _kill_stale_taint(target: str, rhs: str, tainted: dict[str, dict],
                      from_source: bool, raw_stmt: str = "") -> None:
    """右侧不再引用任何污染变量 → 这次赋值把 target 的旧污染冲掉。

    `raw_stmt` 用来识别"这句在分支里"。分支里的赋值**不能清**：
       if (local_22c == 0) { local_22c = "http://..."; } else { 用 local_22c }
    另一条路径上 local_22c 还是原值。原来一刀切清掉，DIR-842 那条链
    （SOAPACTION → strrchr → sprintf）就整个消失了。
    """
    if from_source:
        return                      # 源调用本身产出的值，交给上游处理
    if "if (" in raw_stmt or "else {" in raw_stmt or "} else" in raw_stmt:
        return                      # 分支内的赋值，不构成"所有路径都覆盖"
    for v in tainted:
        if re.search(rf"\b{re.escape(v)}\b", rhs):
            return                  # 右侧还带着污染（含自引用 y = y + 1）
    tainted.pop(target, None)


# ---------------------------------------------------------------- 规则去噪
#
# 只处理"符号问题"那几类误报——它们用规则就能定，交给 LLM 是浪费：
#   1. 格式串：printf("%s", x) 这种，格式串是字面量且没有 %n，就不是格式串漏洞；
#   2. 有界拷贝：strncpy/snprintf 本身有长度上限，不该按溢出报；
#   3. 常量实参：污染值根本没进 sink 的实参（理论上不该发生，防御性检查）。
#
# 判不了的（"前面的校验够不够""这个源可不可控"）留给人或 LLM，规则不碰。

# 只把**格式串类**的汇放进来。sprintf/vsprintf 不放：
# 它们的风险是"写爆第 0 个实参"，不是"格式串被控制"。
# 之前把它们放进来，导致 `sprintf(acStack_108,"%s%s",param_3,param_1)`
# 这种真栈溢出被 "taint-not-in-format" 降级（DIR-842 实测）。
FMT_INDEX = {"printf": 0, "fprintf": 1, "syslog": 1, "vprintf": 0, "vfprintf": 1}
BUF_FMT = {"sprintf", "vsprintf"}


def _format_is_numeric_only(fmt: str) -> bool:
    """格式串是字面量且**所有**转换都是数值类（%d/%x/%c…）→ 掺不进字符串，不会写爆。"""
    fmt = fmt.strip()
    if not fmt.startswith('"'):
        return False
    if "%n" in fmt:
        return False
    specs = re.findall(r"%[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|z|j|t)?([a-zA-Z%])", fmt)
    return bool(specs) and all(s in "diouxXc%" for s in specs)
# strncpy 不在这里：它的"有界"是条件性的（看第三个实参），单独判。
BOUNDED = {"snprintf", "vsnprintf", "memmove"}

# "有界"的第三个实参长这样：常数或 sizeof(...)。别的都算长度不受控。
_CONST_LEN = re.compile(r"(?:-?(?:0x[0-9a-fA-F]+|\d+)|sizeof\s*\(.*\))")


# 第 0 个实参是**目标缓冲**的函数。污染落在这里不等于溢出：
#   strcpy(pcVar3, &local_118)   ← pcVar3 是 websGetVar 拿到的指针，但它是**目的地**
# 真正的溢出方向是"污染从源头读进来、写进固定大小的目标"。
# TOTOLINK 的 FUN_0042aeec 有一条 `websGetVar(username) -> strcpy via pcVar3`，
# 实际语句是 `strcpy(pcVar3,&local_118)` —— 污染在目标参数上，不是漏洞。
DST_ARG0 = {"strcpy", "strcat", "sprintf", "vsprintf", "strncpy",
            "snprintf", "vsnprintf", "memcpy", "memmove", "strlcpy", "strlcat"}


def _rule_check(chain: dict) -> tuple[str, str]:
    """返回 (verdict, reason)。verdict: keep / demoted。"""
    sink = chain.get("sink", "")
    args = _split_args(chain.get("sink_args", ""))
    via = chain.get("via", "")

    # 污染只出现在目标参数里 → 写进去的是别人，不是把污染拷出去
    if sink in DST_ARG0 and via and via != "inline" and args:
        in_dst = bool(re.search(rf"\b{re.escape(via)}\b", args[0]))
        in_src = any(re.search(rf"\b{re.escape(via)}\b", a) for a in args[1:])
        if in_dst and not in_src:
            return "demoted", "taint-in-destination"

    # 诱导汇确认失败：那个函数里确实有 system()，但这个实参走不到它
    if chain.get("sink_verified") is False:
        return "demoted", "induced-sink-unreachable"

    # 来源缓冲自己有上界（被 strncpy(...,N) 之类填过），且上界比目标小：
    #   strncpy(buf, src, 4) ... strcpy(dst, buf)   ->  buf 最多 4 字节，溢不出
    # WR841N 上 6 条 CONFIRMED 里有 4 条是这种。
    if chain.get("bounded_copy"):
        return "demoted", "bounded-source"

    # sscanf 的第 0 个实参是**输入串**，不是目标；污染落在那里根本不是溢出。
    #   sscanf(param_1," HTTP/1.%*c %3d",&x)   <- 污染在输入串
    if sink == "sscanf" and via and via != "inline" and args:
        in_input = bool(re.search(rf"\b{re.escape(via)}\b", args[0]))
        in_dest = any(re.search(rf"\b{re.escape(via)}\b", a) for a in args[2:])
        if in_input and not in_dest:
            return "demoted", "sscanf-input-not-destination"
        # 格式串是字面量且全是数值转换（%d/%x/%u…）→ 写的是整数，不是缓冲
        #   sscanf(buf+1,"0x%x",buf)   <- %x 进 int
        if len(args) >= 2 and _format_is_numeric_only(args[1]):
            return "demoted", "numeric-format-only"

    # strncpy 是"按长度有界"，不是"安全"。长度实参是常数才算有界；
    # 长度是变量/表达式时，它就是一次长度不受控的拷贝。
    # VIVOTEK CC8160 的真溢出正是 `strncpy(16 字节栈, src, 请求头长度)`——
    # 原来的 BOUNDED 把 strncpy 一票否决，等于把真漏洞当安全代码杀掉，还不报错。
    #
    # 长度不受控时**不在这里返回 keep**：继续往下走，让下面的
    # length-checked（前面有 strlen + 上界比较）还能把它降下来。
    if sink == "strncpy" and (len(args) < 3
                              or _CONST_LEN.fullmatch(args[2].strip())):
        return "demoted", "bounded-copy"

    if sink in BOUNDED:
        return "demoted", "bounded-copy"

    # 有界拷贝的另一种写法：前面先 strlen + 比较/截断，再拷。
    #     if ((x == 0) || (n = strlen(x), 0x38 < n - 8)) goto skip;
    #     strcpy(dst, x);
    # 不认这种，"安全代码"会被报成溢出（TP-Link 上实测 10 条）。
    if chain.get("sink_category") == "bof" and chain.get("guard") and via != "inline":
        for g in chain["guard"].split("\x00"):
            if "strlen" not in g or not re.search(rf"\b{re.escape(via)}\b", g):
                continue
            # 下界检查不是保护：`if (strlen(x) < 4) goto skip` 只挡太短的，
            # 更长的照样进 strcpy（Tenda formSetFirewallCfg 就是这样，是真漏洞）。
            if re.search(r"<\s*(0x[0-9a-fA-F]+|\d+)", g) and not re.search(r">\s*(0x[0-9a-fA-F]+|\d+)", g):
                continue
            return "demoted", "length-checked"

    # 目标是污染变量、其余实参全是字面量/常数 —— 拷进去的是常量，不是污染值。
    #     memcpy(dst, "2400", 4)
    # 必须限定"污染在**第 0 个**实参"，否则会误杀
    #     doSystemCmd("echo %s", *(iVar4 + DAT))     ← 污染在第 2 个实参里
    if via != "inline" and len(args) >= 2 and re.search(rf"\b{re.escape(via)}\b", args[0]):
        others = args[1:]
        if all(a.strip().startswith('"') or re.fullmatch(r"-?0x[0-9a-fA-F]+|-?\d+", a.strip())
               for a in others):
            return "demoted", "literal-only-args"

    # sprintf 类：把**第几个实参**和**第几个转换符**对上，才知道这条数据是被 %d
    # 吃掉的还是被 %s 吃掉的。只看"格式串里有没有 %s"会漏判：
    #   sprintf(&DAT,"%s/pid%d","/runtime/services/upnp",_Var5)  ← _Var5 进的是 %d，安全
    # 实测 DIR-842 就是这么报出一条确认的假阳性（而且它还先被 getpid() 覆盖过）。
    if sink in BUF_FMT:
        parts = _split_args(chain.get("sink_args", ""))
        if len(parts) < 2:
            return "keep", ""
        fmt = parts[1].strip()
        if not fmt.startswith('"'):
            return "keep", ""              # 格式串不是字面量，可能是格式串漏洞本体
        if _format_is_numeric_only(fmt):
            return "demoted", "numeric-format-only"
        if via and via != "inline":
            vidx = -1
            for i, a in enumerate(parts):
                if re.search(rf"\b{re.escape(via)}\b", a):
                    vidx = i
                    break
            if vidx >= 2:
                convs = re.findall(
                    r"%[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|z|j|t)?([a-zA-Z%])", fmt)
                ci = vidx - 2
                if ci < len(convs) and convs[ci] in "diouxXc%":
                    return "demoted", "numeric-format-arg"
        return "keep", ""

    idx = FMT_INDEX.get(sink)
    if idx is not None and idx < len(args):
        if via == "inline":
            return "keep", ""              # 分不清在不在格式位，保守保留
        via_idx = -1
        for i, a in enumerate(args):
            if re.search(rf"\b{re.escape(via)}\b", a):
                via_idx = i
                break
        if via_idx >= 0 and via_idx != idx:
            # 污染值进的是参数位，不是格式位 —— 这不是格式串漏洞。
            # 格式位本身是字面量还是符号引用都不影响这个判断。
            return "demoted", "taint-not-in-format"
        if via_idx < 0:
            # 污染变量根本没出现在实参里 —— 要么实参解析失败，要么链本身是错的。
            # 以前这种情况落到最后 return "keep"，白留了一堆假链。
            return "demoted", "via-not-in-sink-args"
        if via_idx == idx:
            # 污染值就是格式串本身：再看有没有 %n（否则只是格式串解析，不是写）
            fmt = args[idx].strip()
            if fmt.startswith('"') and "%n" not in fmt:
                return "keep", "format-string-user-controlled"
            return "keep", ""

    return "keep", ""


def apply_rules(chains: list[dict]) -> list[dict]:
    """给每条链打 verdict/reason。不删——删了人就看不见了，只降序。"""
    for c in chains:
        verdict, reason = _rule_check(c)
        c["verdict"] = verdict
        c["reason"] = reason
    return chains


def _normalize(c_text: str) -> str:
    """MIPS 上间接调用长这样： (*(code *)PTR_nvram_get_0052cf3c)(...)
    把指针变量名还原成函数名，否则源/汇一个都认不出来。

    还有一种更隐蔽的写法——反编译器先把 GOT 槽提到局部变量，再通过它调用：
        pcVar13 = (code *)get_cgi;
        pcVar12 = (*pcVar13)(DAT_004d6fe0 + -0x3b8);
    这种调用名是 pcVar13 而不是 get_cgi。Cisco 的 guest_logout_cgi 整段都是这样，
    不解析别名的话，这个函数 128 个 source 一个都认不出来（CVE-2020-3331 就卡在这）。
    """
    c_text = re.sub(r"PTR_([A-Za-z_]\w*?)_[0-9a-fA-F]{6,}", r"\1", c_text)
    c_text = re.sub(r"\(\*\(code \*\)([A-Za-z_]\w*)\)", r"\1", c_text)
    return _resolve_func_aliases(c_text)


# 局部函数指针别名：x = name;  /  x = (code *)name;
ALIAS_DEF = re.compile(
    r"\b([A-Za-z_]\w*)\s*=\s*(?:\(\s*(?:code|undefined\d?|void)\s*\*\s*\)\s*)?"
    r"([A-Za-z_]\w*)\s*;")


def _resolve_func_aliases(text: str) -> str:
    """把 `(*var)(...)` 还原成 `name(...)`：var 在上面被赋成了某个函数。"""
    aliases: dict[str, str] = {}
    for m in ALIAS_DEF.finditer(text):
        var, fn = m.group(1), m.group(2)
        if var == fn or fn in ("NULL", "true", "false"):
            continue
        aliases.setdefault(var, fn)
    if not aliases:
        return text
    for var, fn in aliases.items():
        # 只在"确实通过这个变量调用"时才替换，避免把普通变量拷贝也改了
        if not re.search(r"\(\s*\*\s*[^)]*" + re.escape(var) + r"\s*\)", text):
            continue
        text = re.sub(
            r"\(\s*\*\s*(?:\(\s*(?:code|undefined\d?|void)\s*\*\s*\)\s*)?"
            + re.escape(var) + r"\s*\)", fn, text)
    return text


# ---------------------------------------------------------------- 分析

# 局部缓冲的声明：`char acStack_108 [256];`
DECL_ARRAY = re.compile(
    r"(?:char|undefined1|uchar|byte|uint8_t)\s+(\w+)\s*\[\s*(0x[0-9a-fA-F]+|\d+)\s*\]")


def _local_sizes(c_text: str) -> dict[str, int]:
    """函数内局部数组 名字 -> 字节数。用来判断"拷进这个目标会不会溢"。"""
    return {m.group(1): int(m.group(2), 0) for m in DECL_ARRAY.finditer(c_text)}


def analyze_c(func_name: str, addr: str, c_text: str,
              sources: set[str], sinks: dict[str, str], weak: dict[str, str],
              seed: dict[str, dict] | None = None) -> list[dict]:
    """在一个函数的 C 里找 source -> sink。seed 用于两跳（把 helper 的形参当已污染）。"""
    tainted: dict[str, dict] = dict(seed or {})
    hits = []
    c_text = _body(_normalize(c_text))
    stmts = _statements(c_text)
    sizes = _local_sizes(c_text)

    for si, stmt in enumerate(stmts):
        calls = _calls(stmt)
        src_call = next(((n, a) for n, a in calls if n in sources), None)
        sink_call = next(((n, a) for n, a in calls if n in sinks), None)
        m = _assign(stmt) if calls else None
        skip_assign = False

        if src_call:
            info = {"api": src_call[0], "param": _first_string(src_call[1]),
                    "weak": _is_weak(src_call[0], src_call[1], weak)}
            if src_call[0] in BUFFER_SOURCE:
                # 缓冲区型源（read/recv/recvmsg…）：数据在实参里，
                # 返回值是"读了多少字节"，不是数据本身——不能把返回值当污染。
                _taint_buffer_sources(src_call[0], src_call[1], info, tainted)
                m = None
            else:
                if m:
                    tainted[m.group(1)] = dict(info)
                # 出参形式：数据在 &x 里，返回值只是错误码
                _taint_out_params(src_call[1], info, tainted)
                if m:
                    # 本语句是 "x = 源(...)"。不能直接 continue——否则
                    # `x = sprintf(dst, fmt, websGetVar(...))` 这类「源内联在汇实参里」
                    # 的语句连汇都检查不到，整条链会漏掉。只跳过重复的赋值处理。
                    skip_assign = True

        _kill_buffer_taint(calls, tainted)
        _taint_buffer_write(calls, tainted)

        if m and not skip_assign:
            _kill_stale_taint(m.group(1), m.group(2), tainted, src_call is not None, stmt)
            _propagate_through_calls(calls, m, tainted)

        if sink_call:
            arg = sink_call[1]
            via = None
            for var in tainted:
                if re.search(rf"\b{re.escape(var)}\b", arg):
                    via = var
                    break
            if via is None:
                for srcn in sources:
                    if re.search(rf"\b{re.escape(srcn)}\s*\(", arg):
                        via = "inline"
                        break
            if via:
                src = "inline" if via == "inline" else tainted[via]["api"]
                param = "inline" if via == "inline" else tainted[via]["param"]
                is_weak = via == "inline" or tainted[via]["weak"]
                # 归纳出来的汇是"能走到 system 的函数"，不是"这个调用点执行了命令"。
                # 把用户名传进 swDhcpcRelease 未必真拼命令 —— 降为低置信，单独成组。
                induced = sink_call[0] in INDUCED_SINKS
                # 源是"归纳"出来的（不是人工确认的取参 API）——和 induced_sink 对称，
                # 不进强源组。P2 里 4/4 的强源假阳性都是这一类。
                induced_src = src in INDUCED_SOURCES

                # 这个拷贝到底会不会溢出：如果来源缓冲有上界（maxlen），
                # 而目标是一个已知更大的局部数组 → 溢不出。
                bounded = False
                if via != "inline":
                    ml = tainted[via].get("maxlen")
                    if ml is not None and sink_call[0] in DST_ARG0:
                        dparts = _split_args(arg)
                        if dparts:
                            dm = re.match(r"&?\s*([A-Za-z_]\w*)", dparts[0].strip())
                            cap = sizes.get(dm.group(1)) if dm else None
                            if cap is not None and ml < cap:
                                bounded = True

                hits.append({
                    "function": func_name, "address": addr,
                    "source_api": src, "source_param": param,
                    "sink": sink_call[0], "sink_category": sinks[sink_call[0]],
                    # 不能截断：格式串规则要靠它判断污染值落在第几个实参上。
                    # 截到 120 字符时，长 HTTP 头串会把后面的实参切掉，
                    # 规则找不到 via 就默认放行——实测 D-Link 上因此多留了 5 条假链。
                    "sink_args": arg,
                    # 前 6 句原文：用来判"前面有没有 strlen + 长度比较"。
                    # 3 句不够——常见写法是 `n = strlen(x)` / `if (n > 63) n = 63` / `memcpy(dst,x,n)`，
                    # 中间还夹着别的赋值（TP-Link 上因此漏掉 4 条）。
                    "guard": "\x00".join(" ".join(s.split()) for s in stmts[max(0, si - 6):si]),
                    "via": via, "weak": bool(is_weak),
                    "induced_sink": induced,
                    "induced_source": induced_src,
                    "bounded_copy": bounded,
                    "confidence": "low" if (is_weak or induced or induced_src) else "medium",
                })
            continue

        # 简单传播：y = x; 或 y = (cast)x;
        if m and not calls:
            rhs = re.sub(r"^\([^()]*\)\s*", "", m.group(2).strip())
            if rhs in tainted:
                tainted[m.group(1)] = dict(tainted[rhs])
    return hits


def tainted_helper_calls(c_text: str, sources: set[str], sinks: dict[str, str],
                         weak: dict[str, str], seed: dict[str, dict] | None = None) -> list[dict]:
    """找函数里"污染变量被传给内部 helper"的调用——多跳的起点。

    seed：多跳时把当前 helper 的形参当已污染（和 analyze_c 一致）。
    """
    tainted: dict[str, dict] = dict(seed or {})
    out: list[dict] = []
    c_text = _body(_normalize(c_text))

    for stmt in _statements(c_text):
        calls = _calls(stmt)
        src_call = next(((n, a) for n, a in calls if n in sources), None)
        m = _assign(stmt)
        if src_call:
            info = {"api": src_call[0], "param": _first_string(src_call[1]),
                    "weak": _is_weak(src_call[0], src_call[1], weak)}
            if m:
                tainted[m.group(1)] = dict(info)
            _taint_out_params(src_call[1], info, tainted)
            if m:
                continue
        _kill_buffer_taint(calls, tainted)
        _taint_buffer_write(calls, tainted)
        if m:
            _kill_stale_taint(m.group(1), m.group(2), tainted, src_call is not None, stmt)
            # 传播器赋值也要在这里做。少了这一句，多跳链的归因会停在旧源上：
            # pcVar1 先被 getenv("HTTP_HNAP_AUTH") 标脏，之后
            # pcVar1 = strrchr(local_22c,'/') 换成了 SOAPACTION 的一段，
            # 但这里不传播 → helper 调用拿到的还是 HNAP_AUTH（DIR-842 实测）。
            _propagate_through_calls(calls, m, tainted)
        # 别名传播：local_48 = param_2;（多跳必需，否则第二跳接不上）
        if m and not calls:
            rhs = re.sub(r"^\([^()]*\)\s*", "", m.group(2).strip())
            if rhs in tainted:
                tainted[m.group(1)] = dict(tainted[rhs])
            continue
        if not calls:
            continue
        for name, args in calls:
            if name in sources or name in sinks:
                continue
            for idx, a in enumerate(_split_args(args)):
                for var, info in tainted.items():
                    if re.search(rf"\b{re.escape(var)}\b", a):
                        rec = {"helper": name, "arg_index": idx, "var": var,
                               "source_api": info["api"], "source_param": info["param"],
                               "weak": info["weak"]}
                        if rec not in out:
                            out.append(rec)
                        break
    return out


# ---------------------------------------------------------------- Ghidra 调用

def _script_path() -> str:
    from .m2 import _script_dir
    return _script_dir()


def decompile(ghidra_home: str, binary: str, targets: list[str], timeout: int | None = None) -> dict[str, str]:
    """批量反编译。targets 可以是地址，也可以是函数名（两跳时只有名字）。"""
    from .m2 import run_ghidra, TIMEOUT as _GHIDRA_TIMEOUT
    if timeout is None:
        timeout = _GHIDRA_TIMEOUT
    headless = os.path.join(ghidra_home, "support", "analyzeHeadless.bat")
    if not os.path.exists(headless):
        headless = os.path.join(ghidra_home, "support", "analyzeHeadless")
    base = os.environ.get("FWMAP_M2_DIR") or os.path.join(os.getcwd(), "fwmap-m2")
    os.makedirs(base, exist_ok=True)
    run_dir = os.path.join(base, f"flow-{os.getpid()}-{os.getpid() % 97}")
    proj_dir = os.path.join(run_dir, "proj")
    os.makedirs(proj_dir, exist_ok=True)

    cmd = [headless, proj_dir, "flow", "-import", binary, "-overwrite",
           "-scriptPath", _script_path(), "-postScript", "DecompileFuncs.java",
           ",".join(targets)]
    try:
        out = run_ghidra(cmd, timeout, label=os.path.basename(binary))
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)

    blocks: dict[str, str] = {}
    cur, buf = None, []
    for line in out.splitlines():
        i = line.find("===== ")
        if i >= 0 and "END" not in line:
            cur, buf = line[i + 6:].split(" @ ")[0].strip(), []
            continue
        if "===== END" in line and cur:
            blocks[cur] = "\n".join(buf)
            cur = None
            continue
        k = line.find("C| ")
        if k >= 0 and cur is not None:
            buf.append(line[k + 3:])
    return blocks


def run_flow(binary: str, candidates: list[dict], ghidra_home: str | None = None,
             profile: str | None = None, limit: int = 40) -> dict:
    home = ghidra_home or find_ghidra()
    if not home:
        raise RuntimeError("找不到 Ghidra：设置 GHIDRA_HOME 环境变量")

    sources, sinks, weak = _load_catalog(catalog_path())
    if profile and os.path.exists(profile):
        s2, k2, w2 = _load_catalog(profile)
        sources |= s2
        sinks.update(k2)
        weak.update(w2)

    # 候选排序：有命令执行汇的优先，其次是"名字像 handler"的（form/do_/from/ej_…），
    # 最后才是普通内部函数。否则没有本函数 sink 的 handler（形如 formSetMacFilterCfg）
    # 会排到 limit 之外，永远进不了分析。
    def rank(c: dict) -> tuple:
        cats = {s["category"] for s in c["sinks"]}
        strong = any(not s["weak"] for s in c["sources"])
        name = c["function"].lower()
        # "像 handler"的命名：Tenda/Realtek 用 form*/from*/do_* 前缀，
        # Cisco/D-Link 用 *_cgi / *_main 后缀。只认前缀会把 guest_logout_cgi
        # 这种 Cisco CGI 入口排到第 111 位，limit 40 永远轮不到。
        #
        # 名字之外还要看行为：一个函数如果读了 ≥5 个**不同**的请求参数，
        # 它几乎不可能不是请求处理器。TP-Link 的 httpd 是 stripped 的，
        # 那个读 ping_addr/doType/isNew/trHops/pSize/sendNum/overTime 的
        # 处理器就叫 FUN_00453c50（CVE-2017-13772 的入口），靠名字永远认不出来。
        nparams = len({s["param"] for s in c["sources"] if s.get("param")})
        named = (name.startswith(("form", "do_", "from", "ej_", "set", "get", "asp", "web"))
                 or name.endswith(("_cgi", "_main", "cgi_main")))
        paramish = nparams >= 5
        # 直接调 system/popen 的汇（强证据）优先于归纳出来的包装函数（弱证据）。
        # 不分开的话，诱导汇会把一堆"只是能走到 system"的函数抬到第一梯队，
        # 把真正有链的函数挤出 limit（实测 wr940n 从 3 条保留链掉到 0）。
        direct_ci = any(s["category"] == "ci" and s["api"] not in INDUCED_SINKS
                        for s in c["sinks"])
        # 四档：0 直接命令执行 → 1 名字像 handler → 2 行为像 handler（读很多参数）
        # 或有 ci 汇 → 3 其他。
        # 名字和"行为"必须分档：混在一档时，那批"读参数多"的函数会把
        # guest_logout_cgi 从 39 挤到 44，Cisco 的 CVE 又丢了。
        if direct_ci:
            tier = 0
        elif named:
            tier = 1
        elif "ci" in cats or paramish:
            tier = 2
        else:
            tier = 3
        # 同层内：先看"有没有内存破坏类汇"（strcpy/sprintf/sscanf），再看输入面。
        # 只有格式串汇的函数价值低于有溢出汇的——这是分诊时最该先看的一类。
        # 没有这一条时，Cisco 的 guest_logout_cgi（128 个 source，64 字节栈缓冲 + sscanf）
        # 排在 42 位，默认 limit 40 差两位轮不到——而它是 CVE-2020-3331 的落点。
        return (tier, 0 if strong else 1,
                0 if "bof" in cats else 1,
                -len(c["sources"]))

    # ---- 两轮取池
    #
    # 只按一个池子排序时，把归纳阈值调低会让候选暴增、真 handler 被挤出去
    # （实测 TP-Link 的 FUN_00453c50 从池内掉到 137/800）。
    # 但如果阈值不调低，厂商自研的小取值函数又进不了目录
    # （DIR-842 的 FUN_0041c560 只有 3 个调用点，阈值 5 收不到，
    #  于是依赖它的登录函数 FUN_0041d0a8 连候选都不是）。
    #
    # 办法：**第一轮只从"有显式源"的候选里取**（保住原来的排序质量），
    #      取不满 limit 时，**第二轮才用"只有诱导源"的候选补满**。
    # 大二进制第一轮就满了，不受影响；小二进制则能把私有取值函数捡回来。
    def has_explicit_source(c: dict) -> bool:
        return any((not s["weak"]) and s["api"] not in INDUCED_SOURCES
                   for s in c["sources"])

    explicit = [c for c in candidates if has_explicit_source(c)]
    induced_only = [c for c in candidates if not has_explicit_source(c)]
    picks = sorted(explicit, key=rank)[:limit]
    if len(picks) < limit and induced_only:
        picks += sorted(induced_only, key=rank)[: limit - len(picks)]
        print(f"    两轮取池：显式源 {min(len(explicit), limit)} 个 + "
              f"诱导源 {len(picks) - min(len(explicit), limit)} 个", flush=True)
    blocks = decompile(home, binary, [c["address"] for c in picks])

    chains: list[dict] = []
    for c in picks:
        text = blocks.get(c["function"])
        if not text:
            continue
        for hit in analyze_c(c["function"], c["address"], text, sources, sinks, weak):
            hit["hops"] = 1
            chains.append(hit)

    # ---- 多跳：逐层展开 helper 调用（最多 3 跳）
    frontier: list[dict] = []
    for c in picks:
        text = blocks.get(c["function"])
        if not text:
            continue
        for h in tainted_helper_calls(text, sources, sinks, weak):
            h.update({"handler": c["function"], "handler_addr": c["address"]})
            frontier.append(h)

    depth = 2
    seen_pairs: set[tuple] = set()
    # 没有任何 handler 调过带污染的 helper 时，frontier 一开始就是空的，
    # while 体一次都不进 —— 下面的 return 会引用未赋值的 hblocks 而崩。
    # 这不改任何判定语义，只是让"没有多跳"这个正常情况能正常返回。
    hblocks: dict[str, str] = {}
    while frontier and depth <= 3:
        names = sorted({f["helper"] for f in frontier})
        hblocks = decompile(home, binary, names)
        nxt: list[dict] = []
        for f in frontier:
            text = hblocks.get(f["helper"])
            if not text:
                continue
            seed = {f"param_{f['arg_index'] + 1}": {
                "api": f["source_api"], "param": f["source_param"], "weak": f["weak"]}}
            for hit in analyze_c(f["handler"], f["handler_addr"], text,
                                 sources, sinks, weak, seed=seed):
                hit["hops"] = depth
                hit["helper"] = f["helper"]
                chains.append(hit)
            for h in tainted_helper_calls(text, sources, sinks, weak, seed=seed):
                # 去重键必须带 handler：同一个 helper 可能被多个 handler 以不同源调用，
                # 不带 handler 会让后来的那个直接被跳过（实测 MacFilter 就这样丢了）。
                key = (f["handler"], h["helper"], h["arg_index"])
                if key in seen_pairs:
                    continue
                seen_pairs.add(key)
                h.update({"handler": f["handler"], "handler_addr": f["handler_addr"]})
                nxt.append(h)
        frontier = nxt
        depth += 1
        if not frontier:
            break

    seen = set()
    uniq = []
    for c in sorted(chains, key=lambda x: x["hops"]):
        key = (c["function"], c["sink"], c["source_param"], c["via"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(c)

    verified = verify_induced_sinks(home, binary, uniq, sinks, weak)
    uniq = apply_rules(uniq)

    uniq.sort(key=lambda x: (x["verdict"] != "keep",
                             x["weak"] or x.get("induced_source"),
                             x["sink_category"] != "ci", x["hops"]))
    return {"binary": binary, "decompiled": len(blocks),
            "helpers": len(hblocks), "sink_verified": verified, "chains": uniq}


# ---------------------------------------------------------------- 诱导汇确认
#
# 诱导汇只说明"这个函数里有 system/popen"，**不说明传进去的数据进了 system**。
# P3（Netgear R8300）实测：recvfrom 的数据传给 FUN_0001cd94，它里面确实有
# system()，但参数全是常量（system(DAT_0001d008)）—— 数据根本没进命令。
# 只按"有没有转义"去问 LLM，会得到一条自信的假阳性。
#
# 做法：把这个汇函数反编译出来，把**污染落在的那个形参**当种子，
# 看它能不能走到内部的**直接** sink 调用。这就是 CTADL 里 propagation model
# （input=Argument(k)）那件事，只不过我们只做一跳、只做确认，不做通用摘要。
MARKER = "__sinkparam__"


def _arg_index_of(args: str, via: str) -> int:
    if not via or via == "inline":
        return -1
    for i, a in enumerate(_split_args(args or "")):
        if re.search(rf"\b{re.escape(via)}\b", a):
            return i
    return -1


def verify_induced_sinks(home, binary, chains: list[dict],
                         sinks: dict[str, str], weak: dict[str, str]) -> int:
    """给每条"诱导汇"链补一个 sink_verified: True/False/None，返回确认的条数。

    只在**同一类别**里验证：诱导汇是 ci（能走到 system）时，就只问
    "这个实参走不走得到直接的 system/popen"，不能拿 memcpy 充当"到了汇"——
    第一版没限制类别，FUN_0001cd94 里那句 `memcpy(__dest,param_2,param_3)`
    就把 param_2 判成"到了汇"，而它的 system() 明明吃的是常量。
    """
    todo: list[tuple[dict, int, dict]] = []
    for c in chains:
        if not c.get("induced_sink"):
            continue
        idx = _arg_index_of(c.get("sink_args", ""), c.get("via", ""))
        if idx < 0:
            c["sink_verified"] = None       # 找不到污染在第几个实参，不猜
            continue
        cat = sinks.get(c["sink"], "ci")
        same_cat = {k: v for k, v in sinks.items()
                    if k not in INDUCED_SINKS and v == cat}
        todo.append((c, idx, same_cat))
    if not todo:
        return 0

    names = sorted({c["sink"] for c, _, _ in todo})
    blocks = decompile(home, binary, names)
    n = 0
    for c, idx, same_cat in todo:
        text = blocks.get(c["sink"])
        if not text:
            c["sink_verified"] = None
            continue
        seed = {f"param_{idx + 1}": {"api": MARKER, "param": "", "weak": True}}
        hits = analyze_c(c["sink"], "0x0", text, set(), same_cat, weak, seed=seed)
        reaches = any(h["source_api"] == MARKER for h in hits)
        has_direct = any(re.search(rf"\b{re.escape(k)}\s*\(", text) for k in same_cat)
        if reaches:
            c["sink_verified"] = True
        elif has_direct:
            c["sink_verified"] = False      # 里面有同类汇，但吃不到这条数据
        else:
            c["sink_verified"] = None       # 里面没有同类直接汇，可能还有一层包装
        n += 1
    return n
