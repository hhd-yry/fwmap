"""报告：Markdown + 机器可读汇总，两者从**同一个汇总对象**渲染。

这样「图表和文字同源」不是靠自觉，是结构上做不到不一致。
"""

from __future__ import annotations

import json
import os

__all__ = ["render_markdown", "write_reports"]


def render_markdown(summary: dict) -> str:
    m = summary.get("metrics") or {}
    lines = [
        "# fwbench 运行报告",
        "",
        f"- 运行目录：`{summary.get('run_dir')}`",
        f"- 用例数：{m.get('cases')}　通过：{m.get('passed')}"
        f"（{_pct(m.get('pass_rate'))}）",
        f"- 双例通过：{m.get('pairs_both_passed')}/{m.get('pairs')}"
        f"（{_pct(m.get('pair_rate'))}）",
        f"- 无依据的确定结论：{m.get('ungrounded_answered')}/{m.get('answered')}"
        f"（{_pct(m.get('ungrounded_rate'))}）",
        "",
        "| 用例 | 家族 | 配对 | 结论 | 期望 | 引用 | 结果 |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in summary.get("results") or []:
        mark = "✅" if r["passed"] else "❌"
        why = "" if r["passed"] else f"（{r['failure']}）"
        lines.append(
            f"| {r['case_id']} | {r['family']} | {r['pair_id']} | "
            f"{r.get('claim')} | {r.get('expected')} | "
            f"{', '.join(r.get('citations') or [])} | {mark}{why} |")
    lines += [
        "",
        "> 未通过原因只记第一处能解释失败的地方；引用必须本轮读过且支持主张。",
        "",
    ]
    return "\n".join(lines)


def _pct(v) -> str:
    return "—" if v is None else f"{v * 100:.0f}%"


def write_reports(summary: dict, out_dir: str | None = None) -> dict:
    out_dir = out_dir or summary["run_dir"]
    os.makedirs(out_dir, exist_ok=True)
    md = render_markdown(summary)
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(md)
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=1)
    summary["report_path"] = os.path.join(out_dir, "report.md")
    return summary


def compare_markdown(comp: dict) -> str:
    lines = ["# fwbench 对照", "",
             f"- 运行：{'、'.join(comp['run_dirs'])}", ""]
    if comp.get("mismatch"):
        lines += ["**拒绝给合并结论**：" + "；".join(comp["mismatch"]), ""]
        return "\n".join(lines)

    lines += ["| 用例 | " + " | ".join(comp["labels"]) + " | 差异 |",
              "|---|" + "---|" * len(comp["labels"]) + "---|"]
    for row in comp["rows"]:
        cells = ["✅" if row["passed"].get(k) else "❌" for k in comp["labels"]]
        diff = ""
        if len(set(cells)) > 1:
            diff = "**不一致**"
        lines.append(f"| {row['case_id']} | " + " | ".join(cells) + f" | {diff} |")
    m = comp["metrics"]
    lines += ["", "| 指标 | " + " | ".join(comp["labels"]) + " |",
              "|---|" + "---|" * len(comp["labels"])]
    for key, label in (("pass_rate", "通过率"), ("pair_rate", "双例通过率"),
                       ("ungrounded_rate", "无依据确定结论率")):
        vals = " | ".join(_pct(m[k].get(key)) for k in comp["labels"])
        lines.append(f"| {label} | {vals} |")
    return "\n".join(lines)
