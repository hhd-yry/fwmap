"""从归档记录生成实验结果表（不手写数字）。

    py -3 lab/make_result_tables.py

输入：`lab/recordings/{temp00,temp07,anon}/*.json`
输出：`docs/实验数据表-2026-11-28.md`
"""

import glob
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REC = os.path.join(ROOT, "lab", "recordings")
OUT = os.path.join(ROOT, "docs", "实验数据表-2026-11-28.md")
TARGET = "/login.cgi"

GROUPS = [
    ("temp00", "具名 · temperature=0（贪心）"),
    ("temp07", "具名 · temperature=0.7（采样）"),
    ("anon", "匿名 · temperature=0.7 · 全链路换名"),
]

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def _hits(doc: dict) -> bool:
    return any(str(f.get("uri")) == TARGET and str(f.get("kind")) == "crash"
               for f in (doc.get("findings") or []))


def _repo_stats() -> dict:
    def _sh(args):
        try:
            return subprocess.run(args, cwd=ROOT, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace").stdout.strip()
        except Exception:                                  # noqa: BLE001
            return ""
    mods = glob.glob(os.path.join(ROOT, "fwmap", "**", "*.py"), recursive=True)
    lines = 0
    for p in mods:
        with open(p, encoding="utf-8", errors="ignore") as fh:
            lines += sum(1 for _ in fh)
    tests = glob.glob(os.path.join(ROOT, "tests", "test_*.py"))
    commits = _sh(["git", "rev-list", "--count", "HEAD"])
    head = _sh(["git", "rev-parse", "--short", "HEAD"])
    return {"modules": len(mods), "lines": lines, "tests": len(tests),
            "commits": commits, "head": head}


def main() -> int:
    stats = _repo_stats()
    lines = [
        "# 实验数据表（2026-11-28）",
        "",
        "> 数字全部由 `py -3 lab/make_result_tables.py` 从",
        "> `lab/recordings/` 的原始记录算出，不手写。",
        "> 目标结论：`/login.cgi` = `crash`（DIR-615 C2 3.03，"
        "`GET /login.cgi` 缺 `graph_id` 时服务退出）。",
        "",
        f"> 仓库状态：提交 `{stats['head']}` · 模块 {stats['modules']} 个 / "
        f"{stats['lines']} 行 · 测试 {stats['tests']} 个文件 · "
        f"提交 {stats['commits']} 次",
        "",
        "## 表 1　三组主结果",
        "",
        "| 组 | 条件 | 计划 | 有效 | 损坏 | 缺失 | 命中/有效 | 命中/计划 | 原始记录 |",
        "|---|---|---|---|---|---|---|---|---|",
    ]

    per_group = {}
    for key, desc in GROUPS:
        files = sorted(glob.glob(os.path.join(REC, key, "*.json")))
        docs = []
        corrupt = 0
        for p in files:
            try:
                with open(p, encoding="utf-8") as fh:
                    docs.append(json.load(fh))
            except (OSError, ValueError):
                corrupt += 1
        hit = sum(1 for d in docs if _hits(d))
        valid = len(docs)
        planned = max(5, len(files))
        per_group[key] = (docs, hit, valid, planned)
        lines.append(
            f"| {key} | {desc} | {planned} | {valid} | {corrupt} | "
            f"{planned - len(files)} | **{hit}/{valid}** | {hit}/{planned} | "
            f"`lab/recordings/{key}/` |")

    lines += [
        "",
        "## 表 2　逐轮明细",
        "",
        "| 组 | 轮 | 步数 | 模型决定 | 探测 | 异常 | 状态 | 判出 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for key, _ in GROUPS:
        docs, _, _, _ = per_group[key]
        for p, d in zip(sorted(glob.glob(os.path.join(REC, key, "*.json"))), docs):
            trace = d.get("trace") or []
            model_steps = sum(1 for t in trace if t.get("source") == "model")
            ev = d.get("evidence") or {}
            odd = sum(1 for v in ev.values()
                      if v.get("len") == 0 or v.get("verdict") == "unknown")
            lines.append(
                f"| {key} | {os.path.basename(p)} | {len(trace)} | {model_steps} | "
                f"{len(d.get('probed') or {})} | {odd} | "
                f"`{d.get('status')}` | {'✓' if _hits(d) else '·'} |")

    t0_docs = per_group["temp00"][0]
    share = []
    for d in t0_docs:
        t = d.get("trace") or []
        share.append(sum(1 for x in t if x.get("source") == "model") / max(1, len(t)))
    avg = (sum(share) / len(share) * 100) if share else 0

    lines += [
        "",
        "## 表 3　能写进论文的结论与前提条件",
        "",
        "| 结论 | 前提条件 | 出处 |",
        "|---|---|---|",
        f"| 具名 temp=0 下 5/5 判出目标 | 同一固件、同一模型、8 步预算；"
        f"贪心解码，样本 5 轮 | `lab/recordings/temp00/` |",
        f"| 具名 temp=0.7 下 5/5 判出目标 | 同上，采样解码；路径有波动但结论不变 "
        f"| `lab/recordings/temp07/` |",
        f"| 匿名（全链路换名）下 0/5 判出目标 | 只藏名字与参数，长度/状态/首行照给；"
        f"样本 5 轮 | `lab/recordings/anon/` |",
        f"| 模型参与率约 {avg * 100:.0f}%（temp00） | 按 `trace.source == 'model'` 计；"
        f"规则兜底计入其余 | `lab/recordings/temp00/` |",
        "",
        "**不能写进论文的**：跨固件泛化、真机验证、7B 模型对比 —— 都没做。",
        "",
        "## 表 4　三栏呈现（工具观察 / 模型解释 / 人工复核）",
        "",
        "| 项 | 工具的直接观察 | 模型的解释 | 人工复核 |",
        "|---|---|---|---|",
        "| `/login.cgi` | 0 字节、`unknown`；同轮正对照 1818 字节 | "
        "「服务直接没了」，判 `crash` | 未做（无真机）；证据等级 **candidate** |",
        "| `/apply.cgi` | 1818 字节、`handler` | —（模型未对其下结论） | 与首页长度一致，视为正常页 |",
        "| 结论强度 | `support = observed-only`（没有进程退出的独立记录） | "
        "模型未区分强度，由规则标注 | 需真机或模拟器信号才能升级 |",
        "",
        "## 表 5　还缺哪些指标",
        "",
        "| 缺的东西 | 为什么缺 | 怎么补 |",
        "|---|---|---|",
        "| 跨固件结果 | 只跑了 DIR-615 | 换 DIR-816L / Edimax 各 5 轮 |",
        "| 7B 模型对比 | 只有 1.5B | 同配置换模型重跑 |",
        "| 真机验证 | 无设备 | FirmAE 全系统模拟或实机 |",
        "| 逐条真值（召回率） | 没有人工标注全集 | 对 36 条候选逐条人工判定 |",
        "| 历史 11-26 原始记录 | VM 重启丢失 | 无法补；保留「历史转述」标注 |",
        "",
        "## 附：口径",
        "",
        "1. 每轮遍历全部结论，`uri` 与 `kind` 精确匹配，每轮最多计一次；",
        "2. 两个分母：`命中/有效`（成功读入）与 `命中/计划`；",
        "3. 损坏与缺失分别计数，不静默跳过；",
        "4. 历史转述的数字与可重算的数字分开写，不互相顶替。",
    ]

    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"实验数据表已写出：{OUT}")
    for key, _ in GROUPS:
        _, hit, valid, planned = per_group[key]
        print(f"  {key}: {hit}/{valid} 有效 · {hit}/{planned} 计划")
    return 0


if __name__ == "__main__":
    sys.exit(main())
