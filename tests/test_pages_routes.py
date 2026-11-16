"""网页兜底 + 路由三对照 + 证据优先。

三件事，都是今天在 Edimax 上被现实打出来的：

1. **URL 和参数名从固件自己的网页里读**（`pages.py`）
   页面上的 `<form action>` / `<input name>` 就是浏览器真实提交的东西。
   实测把 `formWdsEncrypt` 纠正成 `/goform/formWdsEncrypt5G` —— 跟函数名不一样，
   靠"按函数名拼 /goform/<fn>"永远猜不到。

2. **路由三对照**（`routes.py`）
   正对照 `/`、负对照（瞎编路径）、再加候选。跟负对照一样 = 大概不存在；
   不一样 = 存在。判不出来就说不知道。

3. **证据优先于推理**
   dyn 打出 exec-confirmed 时，裁决必须改成 CONFIRMED —— 否则报告自己打自己脸。
"""

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import pages  # noqa: E402
from fwmap import poc  # noqa: E402
from fwmap import routes  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


WDS = """<html><body>
<form method="post" action="/goform/formiNICWdsEncrypt">
  <input type="hidden" name="wepEnabled" value="1">
  <input type="text" name="method" value="">
  <input type="submit" name="save" value="Apply">
</form>
<form method="post" action="/goform/formWdsEncrypt5G">
  <select name="wepEnabled"></select>
  <textarea name="key1"></textarea>
</form>
</body></html>
"""


def main() -> int:
    ok = True

    # 1) 从页面抽 URL + 参数名
    forms = pages.forms_of(WDS)
    uris = [f["uri"] for f in forms]
    ok &= check("抽出两个表单", len(forms) == 2, forms)
    ok &= check("URL 归一化成 / 开头", all(u.startswith("/") for u in uris), uris)
    wds = next((f for f in forms if "formWdsEncrypt5G" in f["uri"]), None)
    ok &= check("5G 那个表单的参数", wds and wds["params"] == ["wepEnabled", "key1"], wds)
    ok &= check("submit 不算参数", wds and "save" not in wds["params"], wds)

    # 2) 按函数名找表单：函数名和 URL 不同名也要能找到
    got = pages.lookup(forms, "formWdsEncrypt")
    ok &= check("formWdsEncrypt → 命中 formWdsEncrypt5G",
                got and got["uri"].endswith("formWdsEncrypt5G"), got)
    got2 = pages.lookup(forms, "formiNICWdsEncrypt")
    ok &= check("精确同名优先", got2 and got2["uri"].endswith("formiNICWdsEncrypt"), got2)
    ok &= check("找不到就返回 None", pages.lookup(forms, "no_such_form") is None)

    # 3) 页面上只有 JS 拼 action 的情况
    js = """<script>document.f.action = "/goform/formSetWlan";</script>
            <input name="ssid">"""
    jf = pages.forms_of(js)
    ok &= check("JS 拼的 action 也能抽", jf and jf[0]["uri"] == "/goform/formSetWlan", jf)

    # 4) 扫描一个假 rootfs
    tmp = tempfile.mkdtemp(prefix="fwmap-pages-")
    os.makedirs(os.path.join(tmp, "web"))
    with open(os.path.join(tmp, "web", "wds.asp"), "w", encoding="utf-8") as fh:
        fh.write(WDS)
    scanned = pages.scan(tmp)
    ok &= check("scan 能扫到文件", len(scanned) == 2, scanned)
    ok &= check("scan 记了来源文件", all(f["file"].endswith("wds.asp") for f in scanned))

    # 5) 路由三对照
    sig = routes.signature
    neg = sig("<html><script>window.top.location.assign('http://x/')</script>404</html>")
    pos = sig("<html><body>hello</body></html>")
    ok &= check("和负对照一样 → not-found",
                routes.classify("/x", neg, pos, sig("<html><script>window.top.location"
                                                    ".assign('http://x/')</script>404</html>"))
                == routes.NOT_FOUND)
    ok &= check("不一样 → handler",
                routes.classify("/x", neg, pos, sig("<html><body>form ok</body></html>"))
                == routes.HANDLER)
    ok &= check("服务没起来 → unknown",
                routes.classify("/x", neg, (0, ""), sig("")) == routes.UNKNOWN)

    # 6) 参数名优先级：source_param > 网页参数 > 守卫 > input
    chain = {"function": "formX", "source_param": "", "page_params": ["wepEnabled"],
             "guard": 'websGetVar(a1,"fromGuard",x)', "sink_category": "bof"}
    req = poc.build_requests(chain, None, port=80)[0]
    ok &= check("网页里的参数名优先于守卫推断", req["param"] == "wepEnabled", req["param"])

    chain2 = dict(chain, source_param="fromChain")
    ok &= check("链上记的参数名最优先",
                poc.build_requests(chain2, None, port=80)[0]["param"] == "fromChain")

    # 7) URL 优先级：endpoint > 网页 > 按函数名拼
    chain3 = {"function": "formWdsEncrypt", "page_uri": "/goform/formWdsEncrypt5G",
              "sink_category": "bof"}
    ok &= check("网页里的 URL 优先于拼接",
                poc.build_requests(chain3, None, port=80)[0]["path"]
                == "/goform/formWdsEncrypt5G")
    ok &= check("没有网页信息时才拼",
                poc.build_requests({"function": "formA", "sink_category": "bof"}, None,
                                   port=80)[0]["path"] == "/goform/formA")

    import shutil

    shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("PASS（网页兜底 + 路由判定）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
