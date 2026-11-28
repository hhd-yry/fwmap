"""fwbench 自身的测试：验证评测器，不是验证 fwmap。

对应实施计划第 7 节的验收点：
  · 用例校验能挡住"答案写进 id"
  · 回放后端按请求取材料，未知 id 报错
  · 答对但引错记录判失败
  · 引用本轮没读过 → citation_not_read
  · 预算用尽后不能再读
  · 重新评分不需要重跑工具（甚至不需要夹具）
  · 金标替换成相反答案后，旧的运行记录会被重判
"""

import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwbench import cases as C          # noqa: E402
from fwbench import runner as R         # noqa: E402
from fwbench import scoring as S        # noqa: E402
from fwbench import report as RP        # noqa: E402
from fwbench.adapters import ScriptedPolicy, backend_for  # noqa: E402

BENCH = os.path.join(ROOT, "bench")
SUITE = os.path.join(BENCH, "suites", "smoke.json")
FIX = os.path.join(BENCH, "fixtures")
ORACLE = os.path.join(BENCH, "oracle", "smoke.json")
PROF_RULE = os.path.join(BENCH, "profiles", "rule.json")
PROF_SCRIPT = os.path.join(BENCH, "profiles", "scripted.json")


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name
          + (("  " + str(detail)) if not cond else ""))
    return cond


def _copy_suite(tmp, mutate) -> str:
    with open(SUITE, encoding="utf-8-sig") as fh:
        doc = json.load(fh)
    mutate(doc)
    path = os.path.join(tmp, "suite.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False)
    return path


def main() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="fwbench-test-")

    # 1) 正常套件能过校验
    ok &= check("smoke 套件校验通过", C.validate_suite(SUITE) == [],
                C.validate_suite(SUITE))

    # 2) 答案写进 case_id → 必须被拒
    bad = _copy_suite(tmp, lambda d: d["cases"][0].__setitem__("case_id", "c-exited"))
    probs = C.validate_suite(bad)
    ok &= check("case_id 含答案暗示被拒", any("答案暗示" in p for p in probs), probs)

    # 3) 回放后端：按 id 取，未知 id 报错
    records = C.load_fixture(FIX, "f017")
    be = backend_for(records)
    r1 = be.dispatch({"tool": "read_record", "id": "e2"})
    r2 = be.dispatch({"tool": "read_record", "id": "nope"})
    ok &= check("按请求返回记录", r1["ok"] and r1["evidence_ids"] == ["e2"])
    ok &= check("未知记录被拒", r2["ok"] is False and "没有这条记录" in r2["error"])
    ok &= check("初始视图不含内容", "state" not in json.dumps(
        [c for c in C.load_suite(SUITE)[0].public()["catalog"]]))

    # 4) 跑一份规则版，四例指标正常
    run_dir = os.path.join(tmp, "rule")
    R.run_suite(SUITE, FIX, PROF_RULE, run_dir)
    oracle = C.load_oracle(ORACLE)
    summary = S.score_run(run_dir, oracle)
    ok &= check("规则版双例全过", summary["metrics"]["passed"] == 2,
                summary["metrics"])
    ok &= check("双例通过率 1/1", summary["metrics"]["pair_rate"] == 1.0)

    # 5) 答对但引错记录 → citation_unsupported（e3 是另一台机器）
    case_dir = os.path.join(run_dir, "cases", "c017")
    sub = json.load(open(os.path.join(case_dir, "submission.json"),
                         encoding="utf-8"))
    sub["citations"] = ["e3"]
    # 先读完 e3 再提交，制造"读过但引用不支持"的情形
    with open(os.path.join(case_dir, "events.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"type": "tool_result", "ok": True,
                             "evidence_ids": ["e3"],
                             "content": {"subtype": "process_sample",
                                         "subject": "svc-71",
                                         "sample_time": "10:00:10",
                                         "state": "exited"}},
                            ensure_ascii=False) + "\n")
    json.dump(sub, open(os.path.join(case_dir, "submission.json"), "w",
                        encoding="utf-8"), ensure_ascii=False)
    row = S.score_case(case_dir, oracle["c017"])
    ok &= check("引用不支持的记录被判失败",
                row["failure"] == "citation_unsupported", row)

    # 6) 引用本轮从没读过的记录 → citation_not_read
    sub["citations"] = ["e1"]
    json.dump(sub, open(os.path.join(case_dir, "submission.json"), "w",
                        encoding="utf-8"), ensure_ascii=False)
    # e1 从未被读过（规则先读 e2）
    row2 = S.score_case(case_dir, oracle["c017"])
    ok &= check("引用未读记录被判失败",
                row2["failure"] == "citation_not_read", row2)

    # 7) 重新评分不需要工具、不需要夹具
    moved = os.path.join(tmp, "fixtures-gone")
    shutil.copytree(FIX, moved)
    shutil.rmtree(moved)
    re = S.score_run(run_dir, oracle)
    ok &= check("无夹具也能重算", re["metrics"]["cases"] == 2, re["metrics"])
    md = RP.render_markdown(re)
    ok &= check("报告与汇总同源",
                f"{re['metrics']['passed']}" in md and "通过率" not in md)

    # 8) 金标换成相反答案 → 旧的运行记录被重判
    flipped = dict(oracle["c017"])
    flipped["expected"] = "running"
    row3 = S.score_case(case_dir, flipped)
    ok &= check("换金标后旧记录被重判",
                row3["passed"] is False, row3["failure"])

    # 9) 预算：工具调用上限 1 时，脚本策略读不到关键记录
    tight = os.path.join(tmp, "tight.json")
    with open(tight, "w", encoding="utf-8") as fh:
        json.dump({"name": "scripted", "policy": "scripted", "repeats": 1,
                   "limits": {"decisions": 6, "tool_calls": 1}}, fh)
    tight_run = os.path.join(tmp, "tight-run")
    R.run_suite(SUITE, FIX, tight, tight_run)
    ts = S.score_run(tight_run, oracle)
    ok &= check("工具预算收紧后通过率下降",
                ts["metrics"]["passed"] < 2, ts["metrics"])

    # 10) 运行目录里没有金标文件
    leaked = [f for _, _, fs in os.walk(run_dir) for f in fs if "oracle" in f]
    ok &= check("运行目录不含金标", not leaked, leaked)

    shutil.rmtree(tmp, ignore_errors=True)
    print()
    print("PASS（fwbench 自身）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
