"""2026-11-17 修掉的 bug 的回归测试。

这些缺陷当时都能静默产生错误结论，而且现有测试一条都没覆盖：

1. `poc.channel_of` 对 `getenv("HTTP_COOKIE")` 判成 form 通道 —— 载荷打进 body，
   程序读的是 Cookie 头，**打不中也不报错**。
2. `pages.lookup` 遇到 `<form action="#">` 会产出一个假路由 `/`，然后拿它匹配任意函数。
3. `merge_mango._routes` 把 CVE 描述里的 `/etc/passwd`、`/tmp/x` 当成路由。
4. `plugins` 里 manifest 占位符写错（`{0}` / `{}`）抛 IndexError，逃出结构化返回。
5. `judge._reassign_breaks_taint` 只认 source_param，漏了 via，
   导致 `uVar3 = uVar3 + 1` 这种自引用累加被误判成"污染断了"。
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import merge_mango, pages, plugins, poc  # noqa: E402
from fwmap import tools_api as T  # noqa: E402
from fwmap.agent import judge as J  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def main() -> int:
    ok = True

    # 1) 通道识别：键名在 source_param 里，不在 source_api
    c = {"function": "f", "source_api": "getenv", "source_param": "HTTP_COOKIE",
         "sink": "strcpy", "sink_category": "bof",
         "guard": 'local_28 = getenv("HTTP_COOKIE")', "via": "local_28"}
    ch, hdr = poc.channel_of(c)
    ok &= check("getenv(HTTP_COOKIE) → header/Cookie", (ch, hdr) == ("header", "Cookie"),
                (ch, hdr))
    req = poc.build_requests(c, None)[0]
    ok &= check("Cookie 载荷进头、不进 body",
                "Cookie" in req["headers"] and req["body"] == "",
                {"headers": list(req["headers"]), "body": req["body"][:40]})

    ch, hdr = poc.channel_of({"source_api": "getenv", "source_param": "HTTP_USER_AGENT"})
    ok &= check("HTTP_USER_AGENT → header/User-Agent", (ch, hdr) == ("header", "User-Agent"),
                (ch, hdr))

    ch, _ = poc.channel_of({"source_api": "getenv", "source_param": "REQUEST_URI"})
    ok &= check("REQUEST_URI → query 通道", ch == "query", ch)

    ch, hdr = poc.channel_of({"source_api": "websGetVar", "source_param": "rootAPmac"})
    ok &= check("表单字段仍走 form", ch == "form" and hdr == "rootAPmac", (ch, hdr))

    # 2) action="#" 不能产出假路由
    forms = pages.forms_of('<form action="#"><input name="a"></form>')
    ok &= check("action=# 不产出路由", forms == [], forms)
    ok &= check("lookup 对空表返回 None", pages.lookup(forms, "formDLNAserver") is None)

    # 真表单仍要认出来
    real = pages.forms_of('<form action="/goform/formWds"><input name="ssid"></form>')
    ok &= check("真表单仍能识别", pages.lookup(real, "formWds") is not None, real)

    # ../ 前缀剥离不能变成字符集剥离
    ok &= check("_norm('../x') → '/x'", pages._norm("../x") == "/x", pages._norm("../x"))
    ok &= check("_norm('#') → ''", pages._norm("#") == "", repr(pages._norm("#")))

    # 3) 文件路径不能当路由
    routes = merge_mango._routes(
        "attacker: cp /etc/passwd /tmp/pwned ; reachable /goform/telnet")
    ok &= check("文件路径被排除", routes == ["/goform/telnet"], routes)

    # 4) 坏占位符要结构化返回，不能抛
    name = plugins.register_manifest(
        {"name": "_regr", "cmd": [sys.executable, "-c", "pass", "{0}"]})
    try:
        res = T.REGISTRY[name]["run"](x=1)
        ok &= check("坏占位符返回 ok=False", res.get("ok") is False, res)
    except Exception as e:                              # noqa: BLE001
        ok &= check("坏占位符返回 ok=False", False, f"抛出了 {type(e).__name__}: {e}")

    # 5) 断链判据：via 和 source_param 两个名字都要认
    ok &= check("via 自引用累加不算断链",
                not J._reassign_breaks_taint(
                    {"sink": "system", "via": "uVar3", "source_param": "rootAPmac"},
                    "uVar3 = uVar3 + 1"))
    ok &= check("source_param 在右侧（Edimax formUploadIE）也不算断链",
                not J._reassign_breaks_taint(
                    {"sink": "memcpy", "via": "x", "source_param": "param_3"},
                    "*(int *)mid = *(int *)mid + param_3"))
    ok &= check("右边换成常量仍是真断链",
                J._reassign_breaks_taint(
                    {"sink": "system", "via": "c", "source_param": "q"}, 'c = "fixed";'))

    print()
    print("PASS（2026-11-17 bug 回归）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
