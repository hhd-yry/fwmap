"""Summarize an archived plan JSON without replaying the run."""

import argparse
from collections import Counter
import json
from pathlib import Path


def summarize(record, budget=None):
    if not isinstance(record, dict) or not isinstance(record.get("trace"), list):
        raise ValueError("运行记录必须包含 trace 数组")
    trace = record["trace"]
    if any(not isinstance(step, dict) or not isinstance(step.get("action"), str)
           or not step["action"].strip() for step in trace):
        raise ValueError("trace 中每一步须有动作名称")
    if budget is not None and (budget < 1 or len(trace) > budget):
        raise ValueError("原运行预算须为正整数，且不少于记录步数")

    ended = bool(trace and trace[-1]["action"] == "done")
    if any(step["action"] == "done" for step in trace[:-1]):
        raise ValueError("结束标记之后仍有步骤")
    if ended:
        status = "recorded_done"
    elif budget is not None and len(trace) == budget:
        status = "budget_reached"
    else:
        status = "unknown"

    sources = Counter(
        step.get("source") for step in trace if step.get("source") in ("model", "heuristic")
    )
    stats = record.get("stats")
    rejects = stats.get("rejects") if isinstance(stats, dict) else None
    if type(rejects) is not int or rejects < 0:
        rejects = None

    findings = record.get("findings")
    if findings is not None and (
        not isinstance(findings, list) or any(not isinstance(item, dict) for item in findings)
    ):
        raise ValueError("findings 须为对象数组")
    cited = sum(
        isinstance(item.get("evidence"), list)
        and any(isinstance(ref, str) and ref.strip() for ref in item["evidence"])
        for item in findings or []
    )
    return {
        "status": status,
        "steps": len(trace),
        "model": sources["model"],
        "heuristic": sources["heuristic"],
        "unknown_source": len(trace) - sum(sources.values()),
        "rejects": rejects,
        "findings": len(findings) if findings is not None else None,
        "cited": cited,
    }


def render_handoff(summary):
    status = summary["status"]
    status_text = {
        "recorded_done": "记录包含正常结束标记",
        "budget_reached": "已达填写的原运行预算，缺少结束标记",
        "unknown": "缺少结束标记，完成状态无法确认",
    }[status]
    rejects = summary["rejects"]
    lines = [
        "# 运行记录交接",
        "",
        f"**结束状态**　{status_text}",
        "",
        "## 已记录的",
        "",
        f"- 共 {summary['steps']} 步。模型 {summary['model']} 步，"
        f"规则兜底 {summary['heuristic']} 步，来源未知 {summary['unknown_source']} 步。",
        f"- 模型被拒 {rejects} 次。" if rejects is not None else "- 记录缺少模型被拒统计。",
    ]
    gaps = []
    findings = summary["findings"]
    if findings is None:
        gaps.append("记录缺少发现清单，发现数量未知。")
    else:
        lines.append(f"- 记录有 {findings} 条发现，其中 {summary['cited']} 条附有证据引用。")
        if findings > summary["cited"]:
            gaps.append(f"有 {findings - summary['cited']} 条发现缺少证据引用。")
    if status != "recorded_done":
        gaps.append("核对原运行日志和预算，确认停止原因及尚未完成的事项。")
    if summary["unknown_source"]:
        gaps.append("核对缺少动作来源的步骤。")
    lines.extend(["", "## 待核对的", ""])
    lines.extend(f"- {gap}" for gap in gaps)
    lines.append("- 本交接依据归档字段汇总。证据引用及其结论由原始证据复核。")
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="从已保存的 plan JSON 生成离线交接报告")
    parser.add_argument("record", type=Path, help="已保存的 plan JSON")
    parser.add_argument("--budget", type=int, help="原运行实际设置的步数预算")
    parser.add_argument("--output", type=Path, help="写入新 Markdown 文件，默认输出到终端")
    args = parser.parse_args(argv)
    try:
        record = json.loads(args.record.read_text(encoding="utf-8-sig"))
        summary = summarize(record, args.budget)
        report = render_handoff(summary)
        if args.output:
            with args.output.open("x", encoding="utf-8") as output:
                output.write(report)
        else:
            print(report, end="")
    except (OSError, ValueError) as error:
        parser.exit(2, f"无法生成离线交接报告：{error}\n")
    return 0 if summary["status"] == "recorded_done" else 1


if __name__ == "__main__":
    raise SystemExit(main())
