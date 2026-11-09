"""裁决：**规则**消费"有没有上界检查"这个事实，不是 LLM 自己下结论。

分工：
  - 输入来源 = 确定性引擎给的 `source_api`（`read` / `getenv("HTTP_...")` / …），**不问模型**；
  - 有没有上界检查 = LLM 看一段代码给的，必须带语句编号；
  - 结论 = 这里算出来的。
这样换模型不会改变判定口径，且每条结论都能追到一句真实代码。
"""

from __future__ import annotations

import re
from collections import Counter

CONFIRMED = "CONFIRMED"
REFUTED = "REFUTED"
UNPROVEN = "UNPROVEN"
REVIEW = "REVIEW"

# source_api -> 输入类别。没列到的（多半是归纳出来的 FUN_xxx）一律 unknown。
SOURCE_KIND = {
    "getenv": "env",
    # TP-Link 的取参函数（归纳出来的，但语义上确实是 HTTP 参数）
    "httpGetEnv": "http_param", "getEnvToInt": "http_param", "httpGetEnvInt": "http_param",
    "read": "socket", "recv": "socket", "recvfrom": "socket", "recvmsg": "socket",
    "websGetVar": "http_param", "webGetVar": "http_param", "websGetVarN": "http_param",
    "get_cgi": "http_param", "get_cgi_var": "http_param",
    "cgiFormString": "http_param", "cgiFormStringNoNewlines": "http_param",
    "json_object_get_string": "http_param", "json_string_value": "http_param",
    "nvram_get": "config", "nvram_safe_get": "config", "acosNvramConfig_get": "config",
}
# 一条语句"像不像上界检查"：必须有比较/strlen/sizeof/带长度的拷贝之一。
# 模型经常指着一句无关代码说"检查过了"（实测把 strchr 当 strlen 用），
# 所以"yes"必须有证据佐证，否则降为 REVIEW 而不是直接 REFUTED。
BOUND_HINT = re.compile(r"[<>]=?|strlen|sizeof|snprintf|vsnprintf|strncpy\s*\(|strlcpy")


def _looks_like_bound(stmt: str) -> bool:
    return bool(stmt) and bool(BOUND_HINT.search(stmt))


REMOTE_KINDS = {"env", "socket", "http_param", "http_param(induced)", "stdin"}


def kind_of(chain: dict) -> str:
    api = chain.get("source_api", "")
    if api == "inline":
        return "unknown"
    if api in SOURCE_KIND:
        k = SOURCE_KIND[api]
        # getenv 的键名也要看：getenv("REQUEST_URI") 才是外部输入
        if api == "getenv":
            param = (chain.get("source_param") or "").upper()
            if param in ("REQUEST_URI", "QUERY_STRING", "PATH_INFO",
                         "PATH_TRANSLATED", "CONTENT_TYPE") or param.startswith("HTTP_"):
                return "env"
            return "config"
        return k
    # 归纳出来的取参函数（Tenda 的 FUN_0002babc 之类）：名字不认识，
    # 但**参数名**是字段名形状（deviceName / cmdinput / security_5g），
    # 这类在厂商固件里几乎都是表单取值。归类为 http_param(induced)，
    # 置信度靠 judge 那边的一致度体现，不靠这里猜死。
    param = chain.get("source_param") or ""
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{1,30}", param):
        return "http_param(induced)"
    return "unknown"


def _looks_like_lower_bound(stmt: str) -> bool:
    """`strlen(x) < 4` 这种是**下界**检查，只挡太短的，不构成保护。"""
    if not stmt:
        return False
    return bool(re.search(r"<\s*(0x[0-9a-fA-F]+|\d+)", stmt)) and \
        not re.search(r">\s*(0x[0-9a-fA-F]+|\d+)", stmt)


def _sink_has_constant_size(chain: dict) -> bool:
    """sink 自己带了常数长度（snprintf(dst,0x40,...)）也算有界。"""
    args = chain.get("sink_args", "")
    if chain.get("sink") not in ("snprintf", "strncpy", "vsnprintf", "memcpy"):
        return False
    parts = [a.strip() for a in args.split(",")]
    if len(parts) < 3:
        return False
    return bool(re.fullmatch(r"-?(0x[0-9a-fA-F]+|\d+)|sizeof\(.*\)", parts[2]))


def judge(chain: dict, res: dict) -> dict:
    facts = res.get("facts")
    ev = res.get("evidence") or {}
    agree = res.get("agreement") or 0.0
    kind = kind_of(chain)

    if not facts:
        if res.get("sink_not_found"):
            return {"verdict": UNPROVEN, "confidence": "none", "source_kind": kind,
                    "reason": "反编译里定位不到 sink 语句（多半是归因错/多跳链），不判"}
        return {"verdict": UNPROVEN, "confidence": "none", "source_kind": kind,
                "reason": "模型没有给出可解析的回答（JSON 解析失败）"}

    bc = facts.get("bounds_check", "unclear")
    san = facts.get("sanitized", "unclear")
    check_ev = ev.get("check") or ""
    conf = "high" if agree >= 0.99 else ("medium" if agree >= 0.67 else "low")
    is_ci = chain.get("sink_category") == "ci"

    # 归因错：变量在源和 sink 之间被重新赋值，污染根本没到 sink。
    # 这是上一轮人工判读里 TOTOLINK 那批的主要假阳性成因（4/4）。
    if facts.get("reassigned") == "yes":
        re_ev = ev.get("reassign") or ""
        if re_ev and not _looks_like_lower_bound(re_ev):
            return {"verdict": REFUTED, "confidence": conf, "source_kind": kind,
                    "reason": f"`{chain.get('via')}` 在 sink 之前被重新赋值，污染已断：{re_ev[:140]}"}

    # 命令注入和缓冲区溢出的保护条件根本不同：
    # 拿"有没有长度上界"去问 system()/doSystem()，问题本身就是错的
    #（评测里 TOTOLINK 三条真链就是这么被判成 REFUTED 的）。
    #
    # 诱导出来的汇 = "这个函数里有 system()"，不等于"这条数据进了 system()"。
    # P3 实测：FUN_0001d020 的 recvfrom 数据传进 FUN_0001cd94，而后者里的
    # system() 全是常量参数（system(DAT_0001d008)），模型却因为"没转义"判了 CONFIRMED。
    # 引擎现在会做一次"形参有没有走到内部直接 sink"的确认（m3flow.verify_induced_sinks），
    # 确认通过才允许 CONFIRMED；确认失败直接 REFUTED；看不出来才 REVIEW。
    if is_ci and chain.get("induced_sink"):
        sv = chain.get("sink_verified")
        if sv is False:
            return {"verdict": REFUTED, "confidence": "medium", "source_kind": kind,
                    "reason": f"`{chain.get('sink')}` 里有命令执行调用，但这条数据到不了它"
                              f"（引擎确认形参未流到终极 sink）"}
        if sv is not True:
            return {"verdict": REVIEW, "confidence": "low", "source_kind": kind,
                    "reason": f"汇 `{chain.get('sink')}` 是**归纳出来的**执行包装函数，"
                              f"确认不了污染真的进了 system()，需人工核对"}
        # sv is True: 形参确实流到了内部的 system()，继续按正常 ci 判定

    if is_ci:
        if san == "yes":
            return {"verdict": REFUTED, "confidence": conf, "source_kind": kind,
                    "reason": f"命令串前有转义/白名单：{check_ev[:140]}"}
        if san == "no":
            if kind in REMOTE_KINDS:
                return {"verdict": CONFIRMED, "confidence": conf, "source_kind": kind,
                        "reason": f"输入来自 {kind}，未见转义/白名单，直达 `{chain.get('sink')}`"}
            return {"verdict": UNPROVEN, "confidence": "low", "source_kind": kind,
                    "reason": f"未见转义，但输入类别是 {kind}（未确认外部可控）"}
        return {"verdict": REVIEW, "confidence": "low", "source_kind": kind,
                "reason": f"模型判断不了转义情况（unclear），输入类别 {kind}，需人工"}

    if bc == "yes":
        if not _looks_like_bound(check_ev):
            return {"verdict": REVIEW, "confidence": "low", "source_kind": kind,
                    "reason": f"模型称有检查，但引用的语句不像上界检查：{check_ev[:100]}"}
        if _looks_like_lower_bound(check_ev):
            return {"verdict": REVIEW, "confidence": "low", "source_kind": kind,
                    "reason": f"模型说有检查，但引用的语句像**下界**检查（不构成保护）：{check_ev[:100]}"}
        return {"verdict": REFUTED, "confidence": conf, "source_kind": kind,
                "reason": f"危险调用前有上界检查：{check_ev[:140]}"}

    if bc == "no":
        if _sink_has_constant_size(chain):
            return {"verdict": REFUTED, "confidence": conf, "source_kind": kind,
                    "reason": "sink 的长度实参是常数"}
        if kind in REMOTE_KINDS:
            return {"verdict": CONFIRMED, "confidence": conf, "source_kind": kind,
                    "reason": f"输入来自 {kind}，未见上界检查，污染值直达 `{chain.get('sink')}`"}
        return {"verdict": UNPROVEN, "confidence": "low", "source_kind": kind,
                "reason": f"没有上界检查，但输入类别是 {kind}（引擎未确认外部可控）"}

    return {"verdict": REVIEW, "confidence": "low", "source_kind": kind,
            "reason": f"模型判断不了（unclear），输入类别 {kind}，需人工"}


def summary(rows: list[dict]) -> dict:
    return dict(Counter(r["judge"]["verdict"] for r in rows))
