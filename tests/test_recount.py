"""离线重算的验收用例 —— 对应评估报告第五节 C 的验收条件。

构造一组 5 条计划记录：
  r1 命中（结论在第一位）
  r2 命中（结论在**第二位**，用来抓「只看第一条」的旧口径）
  r3 有效但类别不符
  r4 损坏（不是 JSON）
  r5 缺失（根本没有文件）

期望：命中/有效 = 2/3，命中/计划 = 2/5，损坏 1，缺失 1。
"""

import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from lab import recount  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name
          + (("  " + str(detail)) if not cond else ""))
    return cond


def _write(d, name, findings) -> str:
    path = os.path.join(d, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"status": "completed", "findings": findings}, fh)
    return path


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="fwmap-recount-")

    f1 = _write(tmp, "r1.json",
                [{"uri": "/login.cgi", "kind": "crash", "support": "observed-only"}])
    # 目标在第二位 —— 只看第一条的旧脚本会漏
    f2 = _write(tmp, "r2.json",
                [{"uri": "/apply.cgi", "kind": "normal"},
                 {"uri": "/login.cgi", "kind": "crash"}])
    f3 = _write(tmp, "r3.json",
                [{"uri": "/login.cgi", "kind": "suspicious"}])
    f4 = os.path.join(tmp, "r4.json")
    with open(f4, "w", encoding="utf-8") as fh:
        fh.write("{ 这不是 JSON")

    files = [f1, f2, f3, f4]                      # r5 故意不给，模拟缺失
    res = recount.recount(files, "/login.cgi", "crash", planned=5)

    ok = True
    ok &= check("命中在第二位的轮次被计入", res["hit"] == 2, res["hit"])
    ok &= check("有效轮次为 3", res["valid"] == 3, res["valid"])
    ok &= check("损坏轮次为 1", res["corrupt"] == 1, res["corrupt"])
    ok &= check("缺失轮次为 1", res["missing"] == 1, res["missing"])
    ok &= check("命中/有效 = 2/3",
                res["rate_of_valid"] == round(2 / 3, 3), res["rate_of_valid"])
    ok &= check("命中/计划 = 2/5", res["rate_of_planned"] == 0.4,
                res["rate_of_planned"])
    ok &= check("类别不符不计命中",
                res["rows"][2]["hit"] is False, res["rows"][2])

    text = recount.render_markdown(res)
    ok &= check("汇总里两个分母都写出来",
                "2/3" in text and "2/5" in text, text)
    ok &= check("有缺失时给出警示", "不能当作完整样本" in text)

    import shutil

    shutil.rmtree(tmp, ignore_errors=True)
    print()
    print("PASS（离线重算）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
