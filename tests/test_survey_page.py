"""结论页测试：autopilot 跑完要有一张能打开、能截图的页面。

背景：以前 `autopilot` 只写 `survey.json`，界面上「打开报告」是灰的，
跑完十几分钟屏幕上只有滚动的日志 —— 用户的第一反应是「怎么没输出」。
"""

import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import planner  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


RES = {
    "elapsed": 612.0,
    "lines": ["用时 612.0s，共 3 步", "端点 45 个 · 链 26 条",
              "还缺什么（按条数）：没做动态验证（9 条）"],
    "history": [
        {"step": 1, "tool": "scan", "why": "还没选目标，先按攻击面排序",
         "source": "llm", "result": {"summary": "78 个 ELF，最高分 87"}},
        {"step": 2, "tool": "m2", "why": "要把函数对上 URL", "source": "rule",
         "result": {"summary": "端点 45 个"}},
        {"step": 3, "tool": "dyn", "why": "试着真打一发", "source": "rule",
         "result": {"summary": "跳过：没有 mipsel 运行时"}},
    ],
}


def main() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="fwmap-html-")
    out = os.path.join(tmp, "survey.html")
    planner.write_html(out, RES, r"C:\fw\p5\root")

    ok &= check("文件写出来了", os.path.exists(out), out)
    text = open(out, encoding="utf-8").read() if os.path.exists(out) else ""
    ok &= check("有个正经的 HTML 头", text.startswith("<!doctype html>"), text[:40])
    ok &= check("目标路径在页面里", "p5" in text)
    ok &= check("结论在里面", "端点 45 个" in text)
    ok &= check("每一步的理由在里面", "要把函数对上 URL" in text)
    ok &= check("标明这步是模型还是规则定的", "模型" in text and "规则" in text)
    ok &= check("说清和「完整报告」的区别", "完整报告" in text)

    # 转义：函数名里带尖括号也不能把页面搞坏
    bad = dict(RES)
    bad["lines"] = ["<script>alert(1)</script>"]
    bad["history"] = [{"step": 1, "tool": "<b>m2</b>", "why": "", "source": "rule",
                       "result": {"summary": "a<b"}}]
    out2 = os.path.join(tmp, "esc.html")
    planner.write_html(out2, bad, "<x>")
    t2 = open(out2, encoding="utf-8").read()
    ok &= check("内容做了 HTML 转义", "<script>alert(1)</script>" not in t2, t2[:200])
    ok &= check("转义后仍可读", "&lt;script&gt;" in t2)

    # 空结果也不能崩
    out3 = os.path.join(tmp, "empty.html")
    planner.write_html(out3, {"lines": [], "history": [], "elapsed": 0}, "x")
    ok &= check("没有步骤时也能生成", os.path.exists(out3))

    import shutil

    shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("PASS（结论页）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
