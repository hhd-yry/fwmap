"""错误页重打的测试：判据要准，字段要真，别原地打转。

三个容易出错的地方：
  1. 把正常页面误判成错误页 → 白白多打一发；
  2. 补出来的字段是模型编的 → 必须在页面原文里 grep 得到；
  3. 字段数没变还重打 → 死循环。
"""

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap.agent import retry_llm as R  # noqa: E402

PAGE = """<html><form action="/goform/formStaDrvSetup" method="post">
<input type="text" name="stadrv_ssid" value="test">
<input type="text" name="tmprootAPmac" value="00:11:22:33:44:55">
<input type="hidden" name="submit-url" value="/inter_wisp.asp">
<input type="hidden" name="isApply" value="1">
</form></html>
"""

ERROR_PAGE = "<html><body>Invalid MAC address. Please input again.</body></html>"


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def main() -> int:
    ok = True

    # 1) 错误页判定
    ok &= check("小错误页判为 error", R.looks_like_error(ERROR_PAGE) is True)
    ok &= check("大管理页不算 error",
                R.looks_like_error("<html><form>" + "x" * 2000 + "</form></html>") is False)
    ok &= check("空响应不算 error", R.looks_like_error("") is False)
    ok &= check("正常短页面不误判",
                R.looks_like_error("<html>settings saved</html>") is False)

    # 2) 铺开字段
    tmp = tempfile.mkdtemp(prefix="fwmap-retry-")
    root = os.path.join(tmp, "root")
    os.makedirs(os.path.join(root, "web"), exist_ok=True)
    with open(os.path.join(root, "web", "inter_wisp.asp"), "w", encoding="utf-8") as fh:
        fh.write(PAGE)

    fields = R.full_fields(root, "/goform/formStaDrvSetup", payload=";id;",
                           payload_key="rootAPmac")
    ok &= check("字段来自页面", {"stadrv_ssid", "tmprootAPmac", "isApply"} <= set(fields), fields)
    ok &= check("默认值取自 value=", fields.get("tmprootAPmac") == "00:11:22:33:44:55", fields)
    ok &= check("载荷放进源参数", fields.get("rootAPmac") == ";id;", fields)

    # 3) plan_retry：错误页 + 字段更多 → 给出计划
    chain = {"function": "formStaDrvSetup", "source_param": "rootAPmac",
             "sink_category": "ci"}
    plan = R.plan_retry(chain, ERROR_PAGE, root, current_fields={"rootAPmac": ";id;"})
    ok &= check("错误页触发重打", plan is not None, plan)
    if plan:
        ok &= check("URI 猜对", plan["uri"].endswith("formStaDrvSetup"), plan["uri"])
        ok &= check("字段数变多", len(plan["fields"]) > 1, plan["fields"])
        ok &= check("原因写清楚", "错误页" in plan["why"], plan["why"])

    # 4) 字段没变 → 不重打（防死循环）
    same = R.plan_retry(chain, ERROR_PAGE, root,
                        current_fields={k: v for k, v in fields.items()})
    ok &= check("字段没增加就不重打", same is None, same)

    # 5) 正常响应 → 不重打
    ok &= check("正常响应不触发",
                R.plan_retry(chain, "<html>ok</html>", root) is None)

    import shutil

    shutil.rmtree(tmp, ignore_errors=True)
    print()
    print("PASS（错误页重打）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
