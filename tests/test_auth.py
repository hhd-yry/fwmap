"""auth.py 的纯逻辑回归测试：不碰 Ghidra，只测判定分支。

运行：python tests/test_auth.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fwmap.auth import (PROTECTED, UNKNOWN, UNPROTECTED, analyze,  # noqa: E402
                        find_auth_evidence, load_catalog, verdict_for)

FUNCS, INLINES = load_catalog()

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"ok   {name}")
    else:
        FAIL += 1
        print(f"FAIL {name}")


def v(uri, text, callers=None):
    return verdict_for(uri, "FUN_00405a1c", text, callers or [], FUNCS, INLINES)


# 1) handler 直接调鉴权函数 → protected
r = v("/apply.cgi", 'void apply(void) {\n  if (check_auth(param_1) == 0) return;\n  system(cmd);\n}')
check("handler 调 check_auth → protected", r["status"] == PROTECTED and "check_auth" in r["evidence"])

# 2) 内联 cookie/session 检查 → protected
r = v("/status.cgi", 'void status(void) {\n  char *c = getenv("HTTP_COOKIE");\n  if (c == 0) return;\n}')
check("getenv(HTTP_COOKIE) → protected", r["status"] == PROTECTED and "内联" in r["evidence"])

# 3) 干净 handler、无调用者证据 → unprotected
r = v("/reboot.cgi", 'void reboot(void) {\n  system("reboot");\n}')
check("无鉴权证据 → unprotected", r["status"] == UNPROTECTED)

# 4) 登录类端点不判未鉴权
r = v("/login.cgi", 'void login(void) {\n  system("x");\n}')
check("login.cgi → unknown", r["status"] == UNKNOWN)

# 5) handler 干净但调用者（dispatcher）统一鉴权 → protected
callers = [{"where": "dispatch", "label": "调用鉴权函数 websSecurityHandler()", "line": "websSecurityHandler(wp);"}]
r = v("/apply.cgi", 'void apply(void) {\n  system(cmd);\n}', callers)
check("调用者鉴权 → protected", r["status"] == PROTECTED and r["where"] == "dispatch")

# 6) handler 未定位/反编译失败 → unknown
r = verdict_for("/apply.cgi", "", None, [], FUNCS, INLINES)
check("无 handler → unknown", r["status"] == UNKNOWN)

# 7) 词边界：recheck_auth( 不能匹配 check_auth(
ev = find_auth_evidence("void f(void) {\n  recheck_auth(p);\n}", {"check_auth"}, [])
check("recheck_auth 不误配 check_auth", ev is None)

# 8) 函数名后必须跟 (：check_auth 作为变量名不算
ev = find_auth_evidence("void f(void) {\n  int check_auth = 1;\n}", {"check_auth"}, [])
check("check_auth 变量名不算证据", ev is None)

# 9) stok 词边界：stock 不算，"stok=" 算
ev1 = find_auth_evidence('char *s = "stock";', set(), INLINES)
ev2 = find_auth_evidence('char *s = "stok=abc";', set(), INLINES)
check("stock 不误配 / stok= 命中", ev1 is None and ev2 is not None)

# 10) analyze 短路：M2 没有已定位 handler 时不应触碰 Ghidra
m2 = {"endpoints": [{"uri": "/a.cgi", "handler": "", "handler_name": "", "confidence": "low"},
                    {"uri": "/login.cgi", "handler": "", "handler_name": "", "confidence": "low"}]}
res = analyze("dummy", m2=m2, log=lambda *a: None)
check("无 handler 时全部 unknown 且不跑 Ghidra",
      res["summary"][UNKNOWN] == 2 and res["summary"]["total"] == 2)

# 11) 混合端点的 analyze 汇总（含一个已定位但反编译不到的 handler）
m2 = {"endpoints": [
    {"uri": "/a.cgi", "handler": "00405a1c", "handler_name": "FUN_00405a1c", "confidence": "medium"},
    {"uri": "/b.cgi", "handler": "", "handler_name": "", "confidence": "low"}]}
# 没有真实二进制，handler 反编译会失败；monkeypatch decompile 返回空，
# 验证 analyze 的组装路径不依赖 Ghidra 也能走通
import fwmap.auth as auth_mod  # noqa: E402
orig_decompile = auth_mod.decompile
auth_mod.decompile = lambda home, binary, targets: {}
orig_find = auth_mod.find_ghidra
auth_mod.find_ghidra = lambda verbose=False: "/nonexistent"
try:
    res = analyze("dummy", m2=m2, log=lambda *a: None)
    check("反编译失败 → unknown，且不中断",
          res["endpoints"][0]["auth"]["status"] == UNKNOWN
          and res["endpoints"][1]["auth"]["status"] == UNKNOWN)
finally:
    auth_mod.decompile = orig_decompile
    auth_mod.find_ghidra = orig_find

# 12) ListCallers 输出解析：去重、排除 <none>、排除自调用
from fwmap.auth import _parse_callers  # noqa: E402
out = """INFO  FUNC FUN_00405a1c @ 00405a1c (GhidraScript)
INFO     <- 00401000 in dispatch (GhidraScript)
INFO     <- 00401004 in dispatch (GhidraScript)
INFO     <- 00401008 in <none> (GhidraScript)
INFO     <- 0040100c in FUN_00405a1c (GhidraScript)
INFO  NOFUNC ghost (GhidraScript)"""
cm = _parse_callers(out, ["FUN_00405a1c"])
check("ListCallers 解析", cm["FUN_00405a1c"] == ["dispatch"])

# 13) 完整编排（mock Ghidra）：handler 无证据 → 查调用者 → 调用者有鉴权 → protected
m2 = {"endpoints": [
    {"uri": "/apply.cgi", "handler": "00405a1c", "handler_name": "FUN_00405a1c", "confidence": "medium"},
    {"uri": "/open.cgi", "handler": "00406000", "handler_name": "FUN_00406000", "confidence": "medium"}]}
texts = {"FUN_00405a1c": "void f(void) {\n  system(cmd);\n}",
         "FUN_00406000": "void g(void) {\n  system(cmd);\n}",
         "dispatch": "void d(void) {\n  websSecurityHandler(wp);\n  FUN_00405a1c();\n}"}
auth_mod.decompile = lambda home, binary, targets: {t: texts[t] for t in targets if t in texts}
auth_mod._callers = lambda home, binary, names: {"FUN_00405a1c": ["dispatch"], "FUN_00406000": []}
try:
    res = analyze("dummy", m2=m2, log=lambda *a: None)
    st = {e["uri"]: e["auth"]["status"] for e in res["endpoints"]}
    check("编排：调用者鉴权使 /apply.cgi protected",
          st["/apply.cgi"] == PROTECTED)
    check("编排：dispatch 与 /open.cgi 无关 → 仍 unprotected",
          st["/open.cgi"] == UNPROTECTED)
    check("编排：summary 计数正确",
          res["summary"][PROTECTED] == 1 and res["summary"][UNPROTECTED] == 1)
finally:
    auth_mod.decompile = orig_decompile

# 14) 报告渲染冒烟：鉴权列、未鉴权候选清单、边界说明都要出现
from fwmap.triage import render  # noqa: E402
fake = {"rootfs": "/x", "time": "t", "agent": False,
        "binaries": [{"path": "bin/httpd", "score": 90, "role": "http_server", "arch": "MIPS",
                      "size": 1024, "m2_strategy": "strcmp-chain", "endpoints": 1,
                      "endpoint_list": res["endpoints"], "auth_summary": res["summary"],
                      "chain_list": [], "chains": 0, "sink_verified": 0}],
        "agent_rows": [],
        "stats": {"oneline": "x", "confirmed": 0, "kept": 0, "chains": 0, "elapsed": 1}}
html = render(fake)
check("报告包含鉴权列与未鉴权候选",
      "鉴权" in html and "未见鉴权" in html and "有鉴权" in html and "未鉴权端点候选" in html)

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)