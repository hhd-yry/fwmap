"""归档回放：把 `lab/recordings/` 的历史原始记录导入并按独立口径复算。

对应实施计划第 7 节 #1–#4：
  1. 离线复算：三组各 5 份，期望 5/5、5/5、0/5
  2. 百分比：temp00 汇总 40 步中 30 步来自模型 → 内部 0.75、展示 75%
  3. 证据强度：命中结论的 `support` 分布，缺字段单独计
  4. 分母：命中/有效 与 命中/计划 两个分母都给，且命中在第二位的轮次也要算到

**不写死答案**：全部从 JSON 现算；旧记录缺字段记 unknown，不猜。
"""

from __future__ import annotations

import glob
import json
import os

__all__ = ["load_group", "recount", "model_share", "support_counts",
           "summarize_groups"]


def _read(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def load_group(folder: str) -> dict:
    """返回 {name, docs, corrupt, files}；损坏文件单独计数。"""
    files = sorted(glob.glob(os.path.join(folder, "*.json")))
    docs, corrupt = [], 0
    for p in files:
        d = _read(p)
        if d is None:
            corrupt += 1
        else:
            docs.append(d)
    return {"name": os.path.basename(os.path.normpath(folder)),
            "files": [os.path.basename(p) for p in files],
            "docs": docs, "corrupt": corrupt}


def _hits(doc: dict, target: str, kind: str) -> bool:
    """遍历**全部** conclusions，不只看第一条。"""
    for f in doc.get("findings") or []:
        if not isinstance(f, dict):
            continue
        if str(f.get("uri")) == target and str(f.get("kind")) == kind:
            return True
    return False


def recount(group: dict, target: str, kind: str, planned: int | None = None) -> dict:
    docs = group["docs"]
    hit = sum(1 for d in docs if _hits(d, target, kind))
    valid = len(docs)
    planned = planned if planned is not None else valid
    return {"group": group["name"], "planned": planned, "valid": valid,
            "corrupt": group["corrupt"],
            "missing": max(0, planned - len(group["files"])),
            "hit": hit,
            "rate_of_valid": round(hit / valid, 3) if valid else None,
            "rate_of_planned": round(hit / planned, 3) if planned else None}


def model_share(docs: list[dict]) -> dict:
    """按 trace.source 统计模型参与率；返回比例（内部 0.75 这种形式）。"""
    model = total = 0
    for d in docs:
        for t in d.get("trace") or []:
            total += 1
            if t.get("source") == "model":
                model += 1
    return {"model_steps": model, "steps": total,
            "share": round(model / total, 4) if total else None}


def support_counts(docs: list[dict], target: str, kind: str) -> dict:
    """命中结论的证据强度分布；旧记录没有 support 字段的记 missing。"""
    out = {"process-exit": 0, "observed-only": 0, "missing": 0, "no_finding": 0}
    for d in docs:
        found = False
        for f in d.get("findings") or []:
            if str(f.get("uri")) != target or str(f.get("kind")) != kind:
                continue
            found = True
            key = f.get("support")
            if key in ("process-exit", "observed-only"):
                out[key] += 1
            else:
                out["missing"] += 1
            break
        if not found:
            out["no_finding"] += 1
    return out


def summarize_groups(root: str, target: str, kind: str,
                     planned: int = 5) -> dict:
    groups = {}
    for name in ("temp00", "temp07", "anon"):
        folder = os.path.join(root, name)
        if not os.path.isdir(folder):
            groups[name] = {"group": name, "error": "目录不存在"}
            continue
        g = load_group(folder)
        row = recount(g, target, kind, planned)
        row["model"] = model_share(g["docs"])
        row["support"] = support_counts(g["docs"], target, kind)
        groups[name] = row
    return {"root": root, "target": target, "kind": kind,
            "planned": planned, "groups": groups}


def _strength_text(sup: dict) -> str:
    """把证据强度分布翻成一句人话 —— 文字必须由计数决定，不能写死。"""
    if sup.get("no_finding") and not (sup.get("process-exit")
                                      or sup.get("observed-only")
                                      or sup.get("missing")):
        return "没有形成结论"
    if sup.get("process-exit"):
        return "进程退出已确认"
    if sup.get("observed-only"):
        return "仅观测到空响应，进程状态未确认"
    if sup.get("missing"):
        return "旧记录缺 support 字段，强度未知"
    return "无记录"


def render_markdown(summary: dict) -> str:
    lines = ["# 归档复算（独立口径）", "",
             f"- 来源：`{summary['root']}`",
             f"- 目标：`{summary['target']}` = `{summary['kind']}`"
             f"　计划轮次：{summary['planned']}", "",
             "| 组 | 命中/有效 | 命中/计划 | 模型参与 | 证据强度 |",
             "|---|---|---|---|---|"]
    for name, row in summary["groups"].items():
        if row.get("error"):
            lines.append(f"| {name} | {row['error']} | — | — | — |")
            continue
        m = row["model"]
        share = "—" if m["share"] is None else f"{m['share'] * 100:.0f}%"
        lines.append(f"| {name} | {row['hit']}/{row['valid']} | "
                     f"{row['hit']}/{row['planned']} | {share} "
                     f"（{m['model_steps']}/{m['steps']} 步） | "
                     f"{_strength_text(row['support'])} |")
    lines += ["", "> 比例内部存小数、展示按百分比；损坏与缺失分别计数，不静默跳过。", ""]
    return "\n".join(lines)
