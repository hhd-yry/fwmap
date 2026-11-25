"""参数补全的测试：模型可以帮看，但不许编。

核心是一条硬规则：**模型给出的字段名必须能在页面原文里 grep 到**。
这条规则让"防幻觉"变成可执行的检查，而不是提示词里的希望。
"""

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap.agent import param_llm as P  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


PAGE = """<html><body>
<form action="/goform/formStaDrvSetup" method="post">
  <input type="text" name="stadrv_ssid" value="">
  <input type="text" name="tmprootAPmac" value="">
  <input type="hidden" name="submit-url" value="/inter_wisp.asp">
</form>
<script>
function saveChanges(){
  var q = "rootAPmac=" + document.form1.tmprootAPmac.value;
  q += "&stadrv_band=" + band;
  return q;
}
</script>
</body></html>
"""


def main() -> int:
    ok = True

    # 1) 静态抽取
    static = P.extract_form_params(PAGE)
    ok &= check("抽到 3 个 input 字段", len(static) == 3, static)
    ok &= check("字段名正确", "stadrv_ssid" in static and "tmprootAPmac" in static, static)

    # 2) JS 线索
    names = P.js_names(PAGE)
    ok &= check("JS 里捞到 rootAPmac", "rootAPmac" in names, names[:8])

    # 3) 模型给了一个真字段 + 一个编的 → 编的被丢
    def chat_ok(messages, **kw):
        return '{"params": ["rootAPmac", "fakeParamXYZ", "stadrv_band"]}'

    res = P.infer(PAGE, known=static, chat=chat_ok, log=lambda *_: None)
    ok &= check("保留能 grep 到的字段", "rootAPmac" in res["params"], res)
    ok &= check("丢掉编造的字段", "fakeParamXYZ" in res["dropped"], res)
    ok &= check("不重复已知字段", "stadrv_ssid" not in res["params"], res)

    # 4) 模型输出废 JSON → 不崩
    def chat_bad(messages, **kw):
        return "抱歉我不知道"

    res2 = P.infer(PAGE, chat=chat_bad, log=lambda *_: None)
    ok &= check("没有 JSON 时返回空", res2["params"] == [], res2)

    # 5) 没有模型 → 不编
    res3 = P.infer(PAGE, chat=None)
    ok &= check("无模型时不返回任何字段", res3["params"] == [], res3)

    # 6) params_for_uri 能找到页面并合并
    tmp = tempfile.mkdtemp(prefix="fwmap-param-")
    root = os.path.join(tmp, "root", "www")
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, "inter_wisp.asp"), "w", encoding="utf-8") as fh:
        fh.write(PAGE)
    got = P.params_for_uri(os.path.join(tmp, "root"), "/goform/formStaDrvSetup",
                           chat=chat_ok, log=lambda *_: None)
    ok &= check("找到引用该 URI 的页面", len(got["pages"]) == 1, got["pages"])
    ok &= check("合并后包含静态字段", "stadrv_ssid" in got["static"], got["static"])
    ok &= check("合并后包含补全字段", "rootAPmac" in got["inferred"], got["inferred"])

    # 7) 找不到页面时如实说
    none = P.params_for_uri(os.path.join(tmp, "root"), "/goform/nothing", chat=chat_ok)
    ok &= check("没有页面时 source=no-page", none["source"] == "no-page", none)

    import shutil

    shutil.rmtree(tmp, ignore_errors=True)
    print()
    print("PASS（参数补全）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
