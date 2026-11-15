"""把我们的链导出成别的工具能直接吃的格式。

目前只有一种：**Mango 的结果 JSON**。

为什么需要这一层：同学那边的审查 agent（Mango-Agent）只认一种输入 ——
`cmdi_results.json`，结构是 `closures[]`，每条写着「汇点函数 + 指令地址 + rank + depth」。
我们 `m3 --flow` 出来的链里本来就有这些信息，而且还多两样她没有的：
**输入参数名**（`source_param`）和**守卫条件**（`guard`）。换个壳，她的 IDA
审查循环一行不改就能啃我们的候选；反过来她的 report.json 也能喂回我们的
verify / dyn。

两边都不改自己代码，这是「融合」唯一能长期活下来的样子。

一个诚实的说明：她的 `rank` 是 Mango 的排序分，我们这里没有可比的分值，
所以导出的 `rank` 就是**我们这边的名次**（1 起，越小越靠前），不是概率。
她那边报告里也写「不是漏洞概率」，语义正好对上。
"""

from __future__ import annotations

import json
import os
import time

from .integrity import sha256_of

__all__ = ["to_mango", "sha256_of", "run"]

# 她的 prompt 里会把 candidate 整个塞给模型，所以这里给个上限，
# 别让一段 3 KB 的守卫字符串把上下文吃掉。
_MAX_TEXT = 300


def _clip(text, limit: int = _MAX_TEXT) -> str:
    s = "" if text is None else str(text)
    return s if len(s) <= limit else s[:limit] + "…"


def _rank_of(chain: dict) -> float:
    """只是个排序用的分数 —— 她那边只显示，不参与判断。"""
    conf = chain.get("confidence") or ""
    score = {"high": 0.9, "medium": 0.6, "low": 0.35}.get(conf, 0.3)
    if chain.get("weak"):
        score -= 0.15
    if chain.get("bounded_copy"):
        score -= 0.1
    return round(max(score, 0.05), 2)


def to_mango(flow: dict, binary_sha256: str = "", top: int = 0,
             include_demoted: bool = False) -> dict:
    """flow.json（`m3 --flow` 的输出）→ Mango results 形状的 dict。"""
    chains = list(flow.get("chains") or [])
    if not include_demoted:
        chains = [c for c in chains if c.get("verdict", "keep") == "keep"]
    # 稳一点：先按我们自己的可信度排，同分保持原始顺序
    chains.sort(key=lambda c: -_rank_of(c))
    if top and top > 0:
        chains = chains[:top]

    closures = []
    for i, c in enumerate(chains, 1):
        addr = str(c.get("address") or "").strip().lower()
        if addr.startswith("0x"):
            addr = addr[2:]
        ins = ("0x" + addr) if addr else ""
        closures.append({
            "rank": i,
            "depth": c.get("hops", 1),
            "sink": {"function": c.get("sink", ""), "ins_addr": ins},
            # 她那边会把 candidate 原样喂给模型，多带的这几项正好补上
            # Mango 没有的信息（从哪来、过了什么检查、强不强）。
            "fwmap": {
                "handler": c.get("function", ""),
                "category": c.get("sink_category", ""),
                "source_api": c.get("source_api", ""),
                "source_param": _clip(c.get("source_param")),
                "sink_args": _clip(c.get("sink_args")),
                "guard": _clip(c.get("guard")),
                "confidence": c.get("confidence", ""),
                "weak": bool(c.get("weak")),
                "hops": c.get("hops", 1),
                "verdict": c.get("verdict", "keep"),
            },
        })

    return {
        "sha256": binary_sha256,
        "generator": {
            "tool": "fwmap",
            "source": "m3 --flow",
            "binary": flow.get("binary", ""),
            "chains_total": len(flow.get("chains") or []),
            "exported": len(closures),
            "note": "rank 是 fwmap 这边的名次，不是漏洞概率",
        },
        "closures": closures,
    }


def run(args) -> int:
    src = args.input
    with open(src, encoding="utf-8-sig") as fh:
        flow = json.load(fh)
    if "chains" not in flow:
        print(f"[!] {src} 里没有 chains —— 这是 m3 --flow 的输出吗？")
        return 2

    sha = ""
    binary = args.binary or flow.get("binary", "")
    if args.binary:
        if not os.path.isfile(args.binary):
            print(f"[!] --binary 不存在：{args.binary}")
            return 2
        sha = sha256_of(args.binary)
    elif binary and os.path.isfile(binary):
        # flow 里记的通常是分析当时那台机器上的路径，还在就顺手算上
        sha = sha256_of(binary)

    out = to_mango(flow, sha, top=args.top, include_demoted=args.all)
    dst = args.output or (os.path.splitext(src)[0] + ".mango.json")
    with open(dst, "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=2)

    print(f"[+] 导出 {len(out['closures'])} 条链 → {dst}")
    if not sha:
        print("    [!] 没算 sha256（没给 --binary，flow 里记的路径也不在了）")
        print("        她的 agent 会拒绝运行，因为对不上 IDA 里打开的二进制。")
        print("        真要用：fwmap export --to mango <flow.json> --binary <同一个 ELF>")
    else:
        print(f"    sha256 {sha[:16]}…")
    print()
    print("    下一步（在她那边，不用改她的代码）：")
    print(f"      python agent.py list --results {dst}")
    print(f"      python agent.py review --results {dst} --candidate 0 --mode api")
    print("    （review 要 IDA 里开着同一个二进制、MCP 插件在 13337 上）")
    return 0
