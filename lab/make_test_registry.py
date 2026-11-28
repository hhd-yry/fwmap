"""生成逐项测试登记表：文件、运行方式、解释器、检查数、退出码。

报告 E 要求"逐项测试登记记录文件、运行方式、解释器、通过／失败／跳过和原因"，
所以这张表不手写，每次跑脚本重新生成，避免数字和实际不符。

    py -3 lab/make_test_registry.py [输出路径]
"""

import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.join(ROOT, "tests")
OUT = (sys.argv[1] if len(sys.argv) > 1
       else os.path.join(ROOT, "docs", "测试登记表-2026-11-28.md"))

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> int:
    files = sorted(f for f in os.listdir(TESTS)
                   if f.startswith("test_") and f.endswith(".py"))
    rows = []
    for name in files:
        path = os.path.join(TESTS, name)
        t0 = time.time()
        proc = subprocess.run([sys.executable, path], capture_output=True,
                              text=True, encoding="utf-8", errors="replace",
                              timeout=1800)
        elapsed = time.time() - t0
        out = (proc.stdout or "") + (proc.stderr or "")
        checks = len(re.findall(r"(?m)^ok\s", out))
        fails = len(re.findall(r"(?m)^FAIL\s", out))
        rows.append({"file": name, "rc": proc.returncode, "ok": checks,
                     "fail": fails, "sec": round(elapsed, 1)})
        print(f"{name:34s} rc={proc.returncode} ok={checks} fail={fails} "
              f"{elapsed:.1f}s")

    total = len(rows)
    passed = sum(1 for r in rows if r["rc"] == 0)
    checks = sum(r["ok"] for r in rows)
    fails = sum(r["fail"] for r in rows)

    lines = [
        "# 测试登记表（逐项）",
        "",
        f"> 生成方式：`py -3 lab/make_test_registry.py`　"
        f"生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"> 解释器：`{sys.executable}`　Python {sys.version.split()[0]}",
        "> 运行方式：每个文件都是一个脚本，`py -3 tests/<文件>`，看退出码；",
        "> 仓库内没有 pytest 配置，也没有 `test_*` 函数或 `Test*` 类，",
        "> 所以不能用一次 `pytest` 收集结果代替全套执行。",
        "",
        f"**合计：{passed}/{total} 个文件通过，{checks} 项检查，{fails} 项失败。**",
        "",
        "| # | 文件 | 运行方式 | 检查数 | 失败 | 耗时(s) | 退出码 | 结论 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(rows, 1):
        verdict = "通过" if r["rc"] == 0 else "**失败**"
        lines.append(f"| {i} | `tests/{r['file']}` | `py -3 tests/{r['file']}` | "
                     f"{r['ok']} | {r['fail']} | {r['sec']} | {r['rc']} | {verdict} |")
    lines += [
        "",
        "## 说明",
        "",
        "- 每个测试文件自带 `check()`，打印 `ok`/`FAIL` 行并以退出码表示整体结果；",
        "- 「检查数」= 打印 `ok` 的行数，失败数同理；",
        "- 全部测试只用临时文件、替身与固定记录，**不需要 GPU、固件、网络**；",
        "- 需要真机/模拟器的实验不在这张表里，见 `docs/实验数据表-2026-11-28.md`。",
    ]
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"\n登记表已写出：{OUT}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
