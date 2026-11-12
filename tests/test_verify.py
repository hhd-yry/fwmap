"""离线测试：verify 的路由解析与判定逻辑（不联网）。

重点覆盖这次踩到的坑：
  - 函数名查不到、但路由名能查到（formDLNAserver → SetDlnaCfg → CVE-2024-10661）
  - FUN_xxxx 这类不可检索的名字必须落到「需人工」，而不是「未命中」
  - 关键词有命中但描述里没提到它，不能算 known
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fwmap import verify  # noqa: E402


def check(name, cond, detail=""):
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def main() -> int:
    ok = True

    # 1) 路由名提取
    ok &= check("route_name /goform/SetDlnaCfg",
                verify.route_name("/goform/SetDlnaCfg") == "SetDlnaCfg")
    ok &= check("route_name .asp",
                verify.route_name("/addressNatList.asp") == "addressNatList")
    ok &= check("route_name 尾斜杠",
                verify.route_name("/goform/formexeCommand/") == "formexeCommand")

    # 2) 函数 → 路由映射
    eps = [
        {"uri": "/goform/SetDlnaCfg", "handler_name": "formDLNAserver"},
        {"uri": "/goform/GetDlnaCfg", "handler_name": "getDLNAserverCfg"},
        {"uri": "/goform/SetDlnaCfg", "handler_name": "formDLNAserver"},  # 重复
        {"uri": "/orphan.asp", "handler_name": ""},
    ]
    m = verify.routes_by_function(eps)
    ok &= check("routes_by_function 去重",
                m.get("formDLNAserver") == ["SetDlnaCfg"], m.get("formDLNAserver"))

    # 3) FUN_xxxx 必须判「需人工」
    r = verify.judge_function("FUN_000a88a4", [], {}, refresh=False, delay=0, dry=False)
    ok &= check("FUN_xxxx → manual", r["verdict"] == "manual", r["verdict"])

    # 2b) inventory 策略：没有 handler_name，用 refs 里的函数名兜底
    eps2 = [
        {"uri": "/goform/formStaDrvSetup", "handler_name": "",
         "refs": [{"in": "formStaDrvSetup"}]},
        {"uri": "/index.asp", "handler_name": "", "refs": [{"in": "formFoo"}]},
        {"uri": "/goform/GetXYZ", "handler_name": "",
         "refs": [{"in": "FUN_0001"}]},
    ]
    m2 = verify.routes_by_function(eps2)
    ok &= check("refs 兜底出路由", m2.get("formStaDrvSetup") == ["formStaDrvSetup"], m2)
    ok &= check("通用页面 /index.asp 不挂路由", "formFoo" not in m2, m2)
    ok &= check("FUN_ 名字不挂路由", "FUN_0001" not in m2, m2)

    # 4) 函数名查不到、路由名查到 → known（这是 CVE-2024-10661 的真实情形）
    calls = []

    def fake_search(kw, cache, refresh=False):
        calls.append(kw)
        if kw == "SetDlnaCfg":
            return [{"id": "CVE-2024-10661",
                     "desc": "Tenda AC15 15.03.05.19 ... function SetDlnaCfg ... scanList"}]
        return []

    orig = verify.nvd_search
    verify.nvd_search = fake_search
    try:
        r = verify.judge_function("formDLNAserver", ["SetDlnaCfg"], {},
                                  refresh=False, delay=0, dry=False)
    finally:
        verify.nvd_search = orig
    ok &= check("双路检索：路由名命中", r["verdict"] == "known", r["verdict"])
    ok &= check("命中记录正确",
                r["matched"] and r["matched"][0]["id"] == "CVE-2024-10661", r["matched"])
    ok &= check("两个关键词都查了",
                set(calls) == {"formDLNAserver", "SetDlnaCfg"}, calls)

    # 5) 有关键词命中但描述没提到它 → 不能算 known
    verify.nvd_search = lambda kw, cache, refresh=False: [
        {"id": "CVE-2099-0001", "desc": "unrelated vulnerability in some other product"}]
    try:
        r = verify.judge_function("formFoo", ["FooBar"], {}, refresh=False, delay=0, dry=False)
    finally:
        verify.nvd_search = orig
    ok &= check("无关命中 → unknown", r["verdict"] == "unknown", r["verdict"])

    # 6) 完全没命中 → unknown，且提示不能当成新漏洞
    verify.nvd_search = lambda kw, cache, refresh=False: []
    try:
        r = verify.judge_function("formBar", [], {}, refresh=False, delay=0, dry=False)
    finally:
        verify.nvd_search = orig
    ok &= check("无命中 → unknown", r["verdict"] == "unknown", r["verdict"])

    # 7) dry-run 不发请求
    called = []
    verify.nvd_search = lambda kw, cache, refresh=False: called.append(kw) or []
    try:
        verify.judge_function("formBaz", ["Baz"], {}, refresh=False, delay=0, dry=True)
    finally:
        verify.nvd_search = orig
    ok &= check("dry-run 不发请求", not called, called)

    # 8) 大小写不同不算命中（真实踩过的坑：getInfo 命中 curl/Xen/LuaJIT 的 getinfo）
    verify.nvd_search = lambda kw, cache, refresh=False: [
        {"id": "CVE-2026-94266", "desc": "libcurl curl_easy_getinfo() leaks credentials"}]
    try:
        r = verify.judge_function("getInfo", [], {}, refresh=False, delay=0, dry=False)
    finally:
        verify.nvd_search = orig
    ok &= check("getinfo（小写）不算命中 → unknown", r["verdict"] == "unknown", r["verdict"])
    ok &= check("但记下疑似同名", r["weaks"] and r["weaks"][0]["id"] == "CVE-2026-94266",
                r.get("weaks"))

    verify.nvd_search = lambda kw, cache, refresh=False: [
        {"id": "CVE-2023-50330", "desc": "boa getInfo functionality of Realtek rtl819x"}]
    try:
        r = verify.judge_function("getInfo", [], {}, refresh=False, delay=0, dry=False)
    finally:
        verify.nvd_search = orig
    ok &= check("getInfo（原样大写）算命中 → known", r["verdict"] == "known", r["verdict"])

    # 9) 给了目标上下文，要能标出「同厂商 / 他厂商」
    verify.nvd_search = lambda kw, cache, refresh=False: [
        {"id": "CVE-2026-10127",
         "desc": "Edimax BR-6478AC 1.23 has overflow in formStaDrvSetup"},
        {"id": "CVE-2026-9999",
         "desc": "TOTOLINK X2000R has overflow in formStaDrvSetup"}]
    try:
        r = verify.judge_function("formStaDrvSetup", [], {}, refresh=False, delay=0,
                                  dry=False, context=["edimax", "br-6478ac"])
    finally:
        verify.nvd_search = orig
    on = [m["id"] for m in r["matched"] if m.get("on_context")]
    ok &= check("同厂商标出来", on == ["CVE-2026-10127"], on)
    ok &= check("置信度=high", r["confidence"] == "high", r["confidence"])
    ok &= check("说明里写了同厂商条数", "1 条提到目标厂商" in r["note"], r["note"])

    # 10) 查询失败必须报 error，不能落到「未命中」
    def boom(kw, cache=None, refresh=False):
        raise RuntimeError("NVD 查询失败：timeout")

    r = verify.judge_function("formX", [], {}, refresh=False, delay=0, dry=False,
                              searcher=lambda kw: boom(kw))
    ok &= check("查询失败 → error（不是 unknown）", r["verdict"] == "error", r["verdict"])

    # 11) handlers_of：把 M2 端点表里所有 handler 摊平（补覆盖率用）
    eps3 = [{"uri": "/goform/A", "handler_name": "formA", "refs": []},
            {"uri": "/goform/B", "handler_name": "", "refs": [{"in": "formB"}]},
            {"uri": "/index.asp", "handler_name": "", "refs": [{"in": "write_body"}]},
            {"uri": "/x.asp", "handler_name": "", "refs": [{"in": "FUN_0001"}]}]
    hs = verify.handlers_of(eps3)
    ok &= check("handlers_of 摊平 + 过滤 FUN_/内部例程",
                hs == ["formA", "formB"], hs)

    print()
    print("PASS（verify 路由解析与判定）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
