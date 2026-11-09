"""M2.5：端点鉴权检查——handler 及其调用者里有没有认证/会话校验。

在 M2 的端点表上加一列"鉴权状态"，产出未鉴权端点候选：
  - protected    handler 或其调用者里出现已知鉴权函数调用，或内联 cookie/session 检查；
  - unprotected  handler 已定位且反编译成功，但 handler 与调用者都找不到鉴权证据；
  - unknown      handler 未定位 / 反编译失败 / 登录类端点——不猜。

为什么还要查调用者：很多固件把鉴权集中在派发函数里做一次
（D-Link cgibin 的 dispatcher、GoAhead 的 websSecurityHandler 注册回调），
handler 本体反而是干净的。只看 handler 会把这批全部误报成未鉴权。

边界（写进报告，必须一起读）：
  - "protected" 只说明有鉴权动作，不说明鉴权实现正确（弱比较、可预测 token 查不出来）；
  - "unprotected" 是候选，不是漏洞：经其它路径（如前置代理、父函数）鉴权的无法完全排除。

用法：
    python -m fwmap auth <binary> [-i m2.json] [-o auth.json]
"""

from __future__ import annotations

import json
import os
import re
import shutil

from .m2 import _script_dir, extract as m2_extract, find_ghidra, run_ghidra, TIMEOUT
from .m3flow import decompile

PROTECTED = "protected"
UNPROTECTED = "unprotected"
UNKNOWN = "unknown"

# 登录/认证相关端点本来就"不该有鉴权"，标未鉴权是纯噪声。
LOGIN_RE = re.compile(r"login|logon|signin|captcha|auth", re.I)


def catalog_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "auth.txt")


def load_catalog(path: str | None = None) -> tuple[set[str], list[tuple[str, re.Pattern]]]:
    funcs: set[str] = set()
    inlines: list[tuple[str, re.Pattern]] = []
    with open(path or catalog_path(), encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            kind, value = parts
            if kind == "func":
                funcs.add(value)
            elif kind == "inline":
                inlines.append((value, re.compile(value, re.I)))
    return funcs, inlines


def _line_of(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    line = text[start:end if end >= 0 else len(text)]
    return " ".join(line.split())[:160]


def find_auth_evidence(c_text: str, funcs: set[str],
                       inlines: list[tuple[str, re.Pattern]]) -> tuple[str, str] | None:
    """在一段反编译 C 里找鉴权证据，返回 (证据说明, 所在行)。找不到返回 None。"""
    for name in sorted(funcs):
        m = re.search(rf"\b{re.escape(name)}\s*\(", c_text)
        if m:
            return (f"调用鉴权函数 {name}()", _line_of(c_text, m.start()))
    for pat, rx in inlines:
        m = rx.search(c_text)
        if m:
            return (f"内联会话检查（{pat}）", _line_of(c_text, m.start()))
    return None


def verdict_for(uri: str, handler_name: str, handler_text: str | None,
                caller_evidence: list[dict], funcs: set[str],
                inlines: list[tuple[str, re.Pattern]]) -> dict:
    """单个端点的判定。caller_evidence: [{where, label, line}]，由 analyze 预先算好。"""
    if LOGIN_RE.search(uri):
        return {"status": UNKNOWN, "reason": "登录/认证相关端点，不做未鉴权判定"}
    if handler_text is None:
        return {"status": UNKNOWN, "reason": "handler 未定位或反编译失败"}
    ev = find_auth_evidence(handler_text, funcs, inlines)
    if ev:
        return {"status": PROTECTED, "where": handler_name, "evidence": ev[0], "line": ev[1]}
    if caller_evidence:
        c = caller_evidence[0]
        return {"status": PROTECTED, "where": c["where"],
                "evidence": c["label"] + "（在调用者中）", "line": c["line"]}
    return {"status": UNPROTECTED,
            "reason": "handler 及其调用者均未见鉴权证据（候选，需人工确认）"}


def _parse_callers(out: str, names: list[str]) -> dict[str, list[str]]:
    """解析 ListCallers.java 的输出（FUNC name @ addr / <- addr in caller）。

    Ghidra 的实际行形如 "INFO  FUNC x @ 00405a1c (GhidraScript)"，
    带 INFO 前缀和 (GhidraScript) 尾巴，不能用 startswith。
    """
    result: dict[str, list[str]] = {n: [] for n in names}
    cur = None
    for line in out.splitlines():
        if "NOFUNC " in line:
            cur = None
            continue
        i = line.find("FUNC ")
        if i >= 0:
            parts = line[i:].split()
            cur = parts[1] if len(parts) > 1 else None
            continue
        j = line.find("<- ")
        if j >= 0 and cur in result:
            caller = line[j:].rsplit(" in ", 1)[-1].split(" (")[0].strip()
            if caller and caller != "<none>" and caller != cur \
                    and caller not in result[cur]:
                result[cur].append(caller)
    return result


def _callers(home: str, binary: str, names: list[str], timeout: int = TIMEOUT) -> dict[str, list[str]]:
    """一次 Ghidra 调用列出多个函数的调用者，返回 {函数名: [调用者名]}。"""
    headless = os.path.join(home, "support", "analyzeHeadless.bat")
    if not os.path.exists(headless):
        headless = os.path.join(home, "support", "analyzeHeadless")
    base = os.environ.get("FWMAP_M2_DIR") or os.path.join(os.getcwd(), "fwmap-m2")
    run_dir = os.path.join(base, f"auth-{os.getpid()}")
    proj_dir = os.path.join(run_dir, "proj")
    os.makedirs(proj_dir, exist_ok=True)
    cmd = [headless, proj_dir, "auth", "-import", binary, "-overwrite",
           "-scriptPath", _script_dir(), "-postScript", "ListCallers.java", ",".join(names)]
    try:
        out = run_ghidra(cmd, timeout, label=os.path.basename(binary) + " callers")
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)
    return _parse_callers(out, names)


def analyze(binary: str, m2: dict | None = None, ghidra_home: str | None = None,
            limit: int = 0, log=print) -> dict:
    """对 M2 的端点表做鉴权检查。limit>0 时只检查前 N 个已定位 handler。"""
    if m2 is None:
        m2 = m2_extract(binary, ghidra_home=ghidra_home)
    funcs, inlines = load_catalog()
    endpoints = m2.get("endpoints", [])

    located = [e for e in endpoints if e.get("handler")]
    if limit > 0:
        located = located[:limit]

    # 没有任何已定位 handler 时不碰 Ghidra（合成样本/纯前缀固件直接走这里）。
    if not located:
        rows = [dict(e, auth=verdict_for(e["uri"], "", None, [], funcs, inlines))
                for e in endpoints]
        return _pack(binary, rows)

    home = ghidra_home or find_ghidra()
    if not home:
        raise RuntimeError("找不到 Ghidra：设置 GHIDRA_HOME 环境变量")

    log(f"[*] 鉴权检查：反编译 {len(located)} 个 handler …")
    targets = [e["handler_name"] or e["handler"] for e in located]
    texts = decompile(home, binary, targets)

    handler_text: dict[str, str | None] = {}
    for e in located:
        handler_text[e["uri"]] = texts.get(e["handler_name"]) if e["handler_name"] else None

    # 只对"handler 本体没有证据"的端点查调用者，省一轮 Ghidra。
    need = [e for e in located
            if handler_text[e["uri"]] is not None
            and not find_auth_evidence(handler_text[e["uri"]], funcs, inlines)]
    names = sorted({e["handler_name"] for e in need if e["handler_name"]})
    caller_evidence: dict[str, list[dict]] = {}
    if names:
        log(f"[*] {len(names)} 个 handler 本体无证据，查调用者 …")
        callers_map = _callers(home, binary, names)
        caller_names = sorted({c for cs in callers_map.values() for c in cs})
        caller_texts = decompile(home, binary, caller_names) if caller_names else {}
        for e in need:
            hits = []
            for caller in callers_map.get(e["handler_name"], []):
                text = caller_texts.get(caller)
                if not text:
                    continue
                ev = find_auth_evidence(text, funcs, inlines)
                if ev:
                    hits.append({"where": caller, "label": ev[0], "line": ev[1]})
            caller_evidence[e["uri"]] = hits

    rows = []
    for e in endpoints:
        if e not in located:
            auth = verdict_for(e["uri"], "", None, [], funcs, inlines)
        else:
            auth = verdict_for(e["uri"], e.get("handler_name", ""),
                               handler_text.get(e["uri"]),
                               caller_evidence.get(e["uri"], []), funcs, inlines)
        rows.append(dict(e, auth=auth))
    return _pack(binary, rows)


def _pack(binary: str, rows: list[dict]) -> dict:
    summary = {PROTECTED: 0, UNPROTECTED: 0, UNKNOWN: 0}
    for r in rows:
        summary[r["auth"]["status"]] += 1
    summary["total"] = len(rows)
    return {"binary": binary, "endpoints": rows, "summary": summary}


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="fwmap auth", description="端点鉴权检查（Ghidra）")
    ap.add_argument("binary", help="单个 ELF 文件")
    ap.add_argument("-i", "--input", help="已有 M2 JSON（跳过 M2）")
    ap.add_argument("-o", "--output", help="输出 JSON")
    ap.add_argument("--limit", type=int, default=0, help="最多检查多少个已定位 handler（默认全部）")
    args = ap.parse_args(argv)

    m2 = None
    if args.input:
        with open(args.input, encoding="utf-8") as fh:
            m2 = json.load(fh)
    res = analyze(args.binary, m2=m2, limit=args.limit)
    s = res["summary"]
    print(f"[*] 端点 {s['total']}：protected {s[PROTECTED]} · "
          f"unprotected {s[UNPROTECTED]} · unknown {s[UNKNOWN]}")
    for e in res["endpoints"]:
        a = e["auth"]
        note = a.get("evidence") or a.get("reason", "")
        print(f"  {e['uri']:<30} {a['status']:<12} {note[:90]}")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(res, fh, ensure_ascii=False, indent=2)
        print(f"[+] {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
