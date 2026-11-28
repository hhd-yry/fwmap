"""离线重算：把一批 plan 运行记录汇总成可核对的结果表。

为什么需要它：以前的汇总脚本只看**第一条**结论、按名字子串计命中、
读到损坏文件就跳过却仍用"成功读入数"当分母 —— 同一个目录能算出不同答案。

这里的口径写死并写清楚：

- 每轮遍历**全部**结论，按 uri（精确）与 kind（精确）匹配，每轮最多计一次；
- 两个分母都给：`命中/有效`（成功读入的轮次）和 `命中/计划`（计划轮次）；
- 损坏、缺失分别计数，不静默跳过；
- 原始文件、汇总结果、人工标签分开保存，本工具只读不写原件。

用法：

    python lab/recount.py lab/recordings/temp07 \
        --target /login.cgi --kind crash --planned 5

    python lab/recount.py <目录> --target /x --kind crash --planned 5 --json out.json
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys

__all__ = ["recount", "render_markdown"]


def _load(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _hits(doc: dict, target: str, kind: str) -> bool:
    """这一轮有没有判出目标 —— 遍历全部结论，不只看第一条。"""
    for f in doc.get("findings") or []:
        if not isinstance(f, dict):
            continue
        if str(f.get("uri")) == target and str(f.get("kind")) == kind:
            return True
    return False


def recount(files: list[str], target: str, kind: str,
            planned: int | None = None) -> dict:
    rows = []
    corrupt = 0
    for path in files:
        doc = _load(path)
        if doc is None:
            corrupt += 1
            rows.append({"file": os.path.basename(path), "state": "损坏",
                         "hit": False, "status": None, "findings": 0})
            continue
        n = len(doc.get("findings") or [])
        rows.append({"file": os.path.basename(path), "state": "有效",
                     "hit": _hits(doc, target, kind),
                     "status": doc.get("status") or "（旧记录，无状态字段）",
                     "findings": n})

    valid = [r for r in rows if r["state"] == "有效"]
    hit = sum(1 for r in valid if r["hit"])
    missing = max(0, (planned or 0) - len(files))
    return {
        "target": target, "kind": kind,
        "rows": rows,
        "valid": len(valid), "corrupt": corrupt, "missing": missing,
        "planned": planned if planned is not None else len(files),
        "hit": hit,
        "rate_of_valid": round(hit / len(valid), 3) if valid else None,
        "rate_of_planned": (round(hit / planned, 3)
                            if planned else None),
    }


def render_markdown(res: dict) -> str:
    lines = [f"目标：`{res['target']}` = `{res['kind']}`", "",
             "| 轮次 | 状态 | 判出目标 | 结论数 |",
             "|---|---|---|---|"]
    for r in res["rows"]:
        lines.append(f"| {r['file']} | {r['state']} | "
                     f"{'✓' if r['hit'] else '·'} | {r['findings']} |")
    lines.append("")
    lines.append(f"- 计划轮次：{res['planned']}　找到文件：{len(res['rows'])}　"
                 f"有效：{res['valid']}　损坏：{res['corrupt']}　"
                 f"缺失：{res['missing']}")
    ro = res["rate_of_valid"]
    rp = res["rate_of_planned"]
    lines.append(f"- 命中/有效：{res['hit']}/{res['valid']}"
                 f"（{ro * 100:.0f}%）" if ro is not None else "- 命中/有效：不适用")
    lines.append(f"- 命中/计划：{res['hit']}/{res['planned']}"
                 f"（{rp * 100:.0f}%）" if rp is not None else "- 命中/计划：不适用")
    if res["corrupt"] or res["missing"]:
        lines.append("- ⚠️ 有损坏或缺失轮次，上表不能当作完整样本使用")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="离线重算运行记录")
    ap.add_argument("directory", help="存放 result JSON 的目录")
    ap.add_argument("--pattern", default="*.json")
    ap.add_argument("--target", required=True, help="目标 uri，精确匹配")
    ap.add_argument("--kind", default="crash", help="目标结论类别")
    ap.add_argument("--planned", type=int, default=None, help="计划轮次")
    ap.add_argument("--json", help="把汇总写到这个文件")
    a = ap.parse_args(argv)

    files = sorted(glob.glob(os.path.join(a.directory, a.pattern)))
    files = [f for f in files if not f.endswith("summary.json")]
    res = recount(files, a.target, a.kind, a.planned)
    text = render_markdown(res)
    print(text)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump(res, fh, ensure_ascii=False, indent=1)
        print(f"\n汇总已写出：{a.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
