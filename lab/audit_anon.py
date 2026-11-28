"""检查匿名组有没有走过会暴露真名的分支。

匿名只作用在「挑端点」这道窄问题上。通用提示（模型被拒后兜底走的那条）
和结论提示都会出现真实 uri —— 如果实际运行中走了这两条，匿名条件就被污染了。

    py -3 lab/audit_anon.py
"""

import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REC = os.path.join(ROOT, "lab", "recordings")

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> int:
    bad = 0
    for path in sorted(glob.glob(os.path.join(REC, "anon", "*.json"))):
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        trace = d.get("trace") or []
        fb = [t for t in trace if t.get("source") == "heuristic"]
        vd = [t for t in trace if t.get("mode") == "verdict"]
        ps = [t for t in trace if t.get("mode") == "probe-select"]
        print(f"{os.path.basename(path):14s} 步 {len(trace)}："
              f"匿名挑选 {len(ps)} · 通用提示(兜底) {len(fb)} · 结论 {len(vd)}"
              f"　status={d.get('status')}")
        if fb or vd:
            bad += 1
            for t in fb + vd:
                print(f"    [!] 走过暴露分支：{t.get('action')} {t.get('args')}")
    print()
    if bad:
        print(f"⚠️ {bad}/5 轮走过会暴露真名的分支 —— 匿名条件被污染")
    else:
        print("✅ 5 轮都只走了匿名挑选分支，没有走通用提示/结论分支")
    return 0


if __name__ == "__main__":
    sys.exit(main())
