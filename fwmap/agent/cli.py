"""fwmap agent：把「静态分析给的假设」交给本地 LLM 取证，再由规则裁决。

用法：
    python -m fwmap.agent <flow.json> --binary <ELF> [--out report.md]
      --top 12       最多复核多少条链
      --samples 3    每条链采样几次（自一致性）
      --mock         不加载模型，只跑管线（测试用）
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from ..m2 import find_ghidra
from ..m3flow import decompile, _body, _normalize, _statements
from . import extract as ex
from . import judge as jd


def _statements_norm(text: str) -> list[str]:
    return [" ".join(s.split()) for s in _statements(_body(_normalize(text)))]


NET_SOURCES = {"read", "recv", "recvfrom", "recvmsg"}


def _pick_chains(flow: dict, top: int) -> list[dict]:
    """**网络源优先**，其次强源，最后弱源；同组内短跳优先。

    远程可达的链才值得先看：配置值（nvram）的链在 P3 里占了 27/43，
    把它们排在前面等于把 LLM 的时间全花在"正确弃权"上。
    """
    kept = [c for c in flow["chains"] if c.get("verdict", "keep") == "keep"]
    kept.sort(key=lambda c: (
        0 if c.get("source_api") in NET_SOURCES else 1,
        bool(c.get("weak")) or bool(c.get("induced_source")) or bool(c.get("induced_sink")),
        c.get("hops", 1)))
    seen, out = set(), []
    for c in kept:
        k = (c["function"], c["sink"], c.get("source_param", ""))
        if k in seen:
            continue
        seen.add(k)
        out.append(c)
        if len(out) >= top:
            break
    return out


def run(flow_path: str, binary: str, top: int, samples: int, mock: bool,
        model: str | None = None) -> dict:
    flow = json.load(open(flow_path, encoding="utf-8"))
    chains = _pick_chains(flow, top)
    print(f"[*] 复核 {len(chains)} 条链（来自 {os.path.basename(flow_path)}）", flush=True)

    # 多跳链的 sink 在 helper 里，只反编译 handler 的话根本锚不到那句代码，
    # 结果就是 UNPROVEN（实测 DIR-842 那条 2 跳链）。所以把 helper 一起反编译，
    # 分析时优先用 helper 的文本。
    addrs = sorted({c["address"] for c in chains if c.get("address")})
    helpers = sorted({c["helper"] for c in chains if c.get("helper")})
    blocks = decompile(find_ghidra(), binary, addrs + helpers)
    print(f"[*] 反编译 {len(blocks)} 个函数（含 {len(helpers)} 个 helper）", flush=True)

    rows = []
    for i, c in enumerate(chains, 1):
        text = blocks.get(c["helper"]) if c.get("helper") else None
        if text:
            print(f"       ↳ {c['function']} 的 sink 在 helper {c['helper']} 里", flush=True)
        else:
            text = blocks.get(c["function"])
        if not text:
            rows.append({"chain": c, "facts": None, "judge": {
                "verdict": jd.UNPROVEN, "confidence": "none", "reason": "反编译失败"}})
            continue
        stmts = _statements_norm(text)
        if mock:
            res = {"facts": None, "evidence": {}, "agreement": 0.0, "raw": []}
        else:
            t0 = time.time()
            res = ex.extract(c, stmts, samples=samples)
            print(f"  [{i}/{len(chains)}] {c['function'][:26]:<26} "
                  f"{c['source_api']}->{c['sink']:<10} "
                  f"{(res.get('facts') or {}).get('bounds_check','?'):<8} "
                  f"agree={res.get('agreement',0):.2f} {time.time()-t0:.0f}s", flush=True)
        rows.append({"chain": c, "facts": res.get("facts"), "evidence": res.get("evidence"),
                     "agreement": res.get("agreement"), "judge": jd.judge(c, res),
                     "statements": stmts})
    return {"flow": flow_path, "binary": binary, "rows": rows,
            "model": model or os.environ.get("FWMAP_LLM_MODEL") or llm_model()}


def llm_model() -> str:
    from . import llm
    return os.path.basename(os.environ.get("FWMAP_LLM_MODEL") or llm.DEFAULT_MODEL)


def render_md(result: dict) -> str:
    rows = result["rows"]
    s = jd.summary(rows)
    L = ["# fwmap agent 复核报告", "",
         f"- 二进制：`{os.path.basename(result['binary'])}`",
         f"- 假设来源：`{os.path.basename(result['flow'])}`",
         f"- 模型：`{result['model']}`（本地，4-bit）",
         f"- 复核链数：{len(rows)}", "",
         "## 裁决汇总", "",
         "| 裁决 | 条数 |", "|---|---|"]
    for k in (jd.CONFIRMED, jd.REVIEW, jd.REFUTED, jd.UNPROVEN):
        L.append(f"| {k} | {s.get(k, 0)} |")
    L += ["", "> 裁决由**规则**给出（`agent/judge.py`），LLM 只负责从反编译代码里抽事实。", ""]

    order = {jd.CONFIRMED: 0, jd.REVIEW: 1, jd.REFUTED: 2, jd.UNPROVEN: 3}
    for n, r in enumerate(sorted(rows, key=lambda x: order.get(x["judge"]["verdict"], 9)), 1):
        c, j = r["chain"], r["judge"]
        L.append(f"## {n}. {c['function']} — **{j['verdict']}**")
        L.append("")
        L.append(f"- 链：`{c['source_api']}({c.get('source_param','')})` → "
                 f"`{c['sink']}` [{c.get('sink_category')}]，via `{c.get('via')}`，{c.get('hops',1)} 跳")
        L.append(f"- 置信：{j['confidence']}（一致度 {r.get('agreement') or 0:.2f}）")
        L.append(f"- 理由：{j['reason']}")
        if r.get("facts"):
            f = r["facts"]
            ev = r.get("evidence") or {}
            L.append(f"- 事实：上界检查 `{f['bounds_check']}`，输入类别 `{j.get('source_kind')}`")
            if ev.get("check"):
                L.append(f"- 取证·检查语句（全文第 {ev.get('check_idx')} 句）：")
                L.append(f"  ```c\n  {ev['check']}\n  ```")
            if f.get("why"):
                L.append(f"- 模型备注：{f['why']}")
        L.append(f"- 危险调用原文：`{' '.join(c.get('sink_args','').split())[:200]}`")
        L.append("")
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fwmap agent")
    ap.add_argument("flow", help="m3 --flow 产出的 *.flow.json")
    ap.add_argument("--binary", required=True, help="对应的 ELF")
    ap.add_argument("--out", help="输出 markdown")
    ap.add_argument("--top", type=int, default=12)
    ap.add_argument("--samples", type=int, default=3)
    ap.add_argument("--model", help="模型路径（默认 FWMAP_LLM_MODEL 或内置默认）")
    ap.add_argument("--mock", action="store_true", help="不加载模型，只跑管线")
    a = ap.parse_args(argv)

    res = run(a.flow, a.binary, a.top, a.samples, a.mock, a.model)
    md = render_md(res)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(md)
        print(f"[+] {a.out}")
    else:
        print(md)
    s = jd.summary(res["rows"])
    print(f"[=] {s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
