"""fwbench 命令入口。

    python -m fwbench validate --suite bench/suites/smoke.json
    python -m fwbench run --suite ... --profile bench/profiles/rule.json --out runs/smoke-rule
    python -m fwbench report runs/smoke-rule --recompute
    python -m fwbench compare runs/smoke-rule runs/smoke-scripted --out runs/cmp

退出码：0 正常；2 参数/校验问题；3 有检查未达标（--check-gates）。
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import cases as cases_mod
from . import report as report_mod
from . import scoring as scoring_mod
from .runner import run_suite

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = os.path.join(ROOT, "bench")


def _paths(args) -> tuple[str, str, str]:
    suite = args.suite or os.path.join(BENCH, "suites", "smoke.json")
    fixtures = args.fixtures or os.path.join(BENCH, "fixtures")
    oracle = args.oracle or os.path.join(BENCH, "oracle", "smoke.json")
    return suite, fixtures, oracle


def cmd_validate(args) -> int:
    suite, _, oracle = _paths(args)
    problems = cases_mod.validate_suite(suite)
    for p in problems:
        print(f"[!] {p}")
    if not problems:
        print(f"[+] 用例校验通过：{suite}")
    # 金标单独校验：每条都要有 expected，且引用集合非空
    try:
        rows = cases_mod.load_oracle(oracle)
    except (OSError, ValueError, KeyError) as exc:
        print(f"[!] 金标读不了：{exc}")
        return 2
    suite_cases = cases_mod.load_suite(suite)
    missing = [c.case_id for c in suite_cases if c.case_id not in rows]
    if missing:
        print(f"[!] 金标缺少用例：{', '.join(missing)}")
        problems.append("oracle-missing")
    for cid, row in rows.items():
        if not row.get("expected") and not row.get("allow_abstain"):
            print(f"[!] 金标 {cid} 既没有 expected 也不允许弃权")
            problems.append("oracle-expected")
    print(f"[+] 金标校验：{len(rows)} 条")
    return 0 if not problems else 2


def cmd_run(args) -> int:
    suite, fixtures, _ = _paths(args)
    profile = args.profile or os.path.join(BENCH, "profiles", "rule.json")
    res = run_suite(suite, fixtures, profile, args.out, seed=args.seed,
                    resume=args.resume)
    print(f"[+] {len(res['rows'])} 个用例已落盘：{args.out}")
    return 0


def _load_summary(run_dir: str, oracle: dict) -> dict:
    return scoring_mod.score_run(run_dir, oracle)


def cmd_report(args) -> int:
    _, _, oracle = _paths(args)
    rows = cases_mod.load_oracle(oracle)
    summary = _load_summary(args.run_dir, rows)
    if args.check_gates:
        m = summary["metrics"]
        bad = []
        if m["pass_rate"] is not None and m["pass_rate"] < 1.0:
            bad.append(f"通过率 {m['pass_rate']:.0%} < 100%")
        if m["pair_rate"] is not None and m["pair_rate"] < 1.0:
            bad.append(f"双例通过率 {m['pair_rate']:.0%} < 100%")
        summary["gates"] = bad
    report_mod.write_reports(summary, args.out or args.run_dir)
    print(json.dumps(summary["metrics"], ensure_ascii=False, indent=1))
    if args.check_gates and summary.get("gates"):
        print("[!] 未达标：" + "；".join(summary["gates"]))
        return 3
    return 0


def cmd_compare(args) -> int:
    _, _, oracle = _paths(args)
    rows = cases_mod.load_oracle(oracle)
    summaries, mismatch = {}, []
    for d in args.run_dirs:
        summaries[d] = _load_summary(d, rows)
        man = os.path.join(d, "manifest.json")
        try:
            with open(man, encoding="utf-8-sig") as fh:
                summaries[d]["manifest"] = json.load(fh)
        except (OSError, ValueError):
            mismatch.append(f"{d} 缺 manifest.json")

    base = summaries[args.run_dirs[0]].get("manifest") or {}
    for d in args.run_dirs[1:]:
        man = summaries[d].get("manifest") or {}
        for key in ("suite_digest", "seed"):
            if base.get(key) != man.get(key):
                mismatch.append(f"{os.path.basename(d)} 的 {key} 与基准不一致")
        for key in ("limits", "repeats"):
            if (base.get("profile") or {}).get(key) != (man.get("profile") or {}).get(key):
                mismatch.append(f"{os.path.basename(d)} 的 profile.{key} 与基准不一致")

    comp = {"run_dirs": args.run_dirs,
            "labels": [os.path.basename(os.path.normpath(d)) for d in args.run_dirs],
            "mismatch": mismatch,
            "rows": [], "metrics": {}}
    if not mismatch:
        ids = sorted({r["case_id"] for s in summaries.values() for r in s["results"]})
        for cid in ids:
            row = {"case_id": cid, "passed": {}}
            for d in args.run_dirs:
                hit = next((r for r in summaries[d]["results"]
                            if r["case_id"] == cid), None)
                row["passed"][os.path.basename(os.path.normpath(d))] = bool(
                    hit and hit["passed"])
            comp["rows"].append(row)
        for d in args.run_dirs:
            comp["metrics"][os.path.basename(os.path.normpath(d))] = \
                summaries[d]["metrics"]

    os.makedirs(args.out, exist_ok=True)
    md = report_mod.compare_markdown(comp)
    with open(os.path.join(args.out, "compare.md"), "w", encoding="utf-8") as fh:
        fh.write(md)
    with open(os.path.join(args.out, "compare.json"), "w", encoding="utf-8") as fh:
        json.dump(comp, fh, ensure_ascii=False, indent=1)
    print(md)
    return 0 if not mismatch else 2


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="fwbench", description="fwmap 端到端交互能力评测")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--suite")
        p.add_argument("--fixtures")
        p.add_argument("--oracle")

    v = sub.add_parser("validate", help="校验用例与金标")
    common(v)
    v.set_defaults(func=cmd_validate)

    r = sub.add_parser("run", help="跑一个套件")
    common(r)
    r.add_argument("--profile")
    r.add_argument("--out", required=True)
    r.add_argument("--seed", type=int, default=0)
    r.add_argument("--resume", action="store_true")
    r.set_defaults(func=cmd_run)

    rp = sub.add_parser("report", help="重新评分并渲染报告")
    common(rp)
    rp.add_argument("run_dir")
    rp.add_argument("--out")
    rp.add_argument("--recompute", action="store_true",
                    help="从已落盘事件重算（不重跑工具）")
    rp.add_argument("--check-gates", action="store_true",
                    help="不达标时返回非零退出码（CI 用）")
    rp.set_defaults(func=cmd_report)

    cp = sub.add_parser("compare", help="对照多个同条件运行")
    common(cp)
    cp.add_argument("run_dirs", nargs="+")
    cp.add_argument("--out", required=True)
    cp.set_defaults(func=cmd_compare)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
