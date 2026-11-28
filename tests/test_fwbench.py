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
import subprocess
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
                f"通过：{re['metrics']['passed']}" in md and f"用例数：{re['metrics']['cases']}" in md)

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

    # 11) A 层：两份 ELF 夹具 + 截断，三个被测工具用同一份金标
    ELF_SUITE = os.path.join(BENCH, "suites", "elfmeta.json")
    ELF_ORACLE = os.path.join(BENCH, "oracle", "elfmeta.json")
    ok &= check("elfmeta 套件校验通过", C.validate_suite(ELF_SUITE) == [],
                C.validate_suite(ELF_SUITE))
    elf_oracle = C.load_oracle(ELF_ORACLE)

    for subject in ("fwmap", "stdlib"):
        d = os.path.join(tmp, f"elf-{subject}")
        R.run_suite(ELF_SUITE, FIX, PROF_RULE, d, subject=subject)
        s = S.score_run(d, elf_oracle)
        ok &= check(f"{subject} 三例全过", s["metrics"]["passed"] == 3,
                    s["metrics"])

    # 12) 未安装的可选依赖 → 不适用，且不进分母
    d = os.path.join(tmp, "elf-elftools")
    R.run_suite(ELF_SUITE, FIX, PROF_RULE, d, subject="elftools")
    s = S.score_run(d, elf_oracle)
    ok &= check("未安装的依赖记 not_run",
                s["metrics"]["not_run"] == 3 and s["metrics"]["applicable"] == 0,
                s["metrics"])
    ok &= check("全不适用时通过率是 null 而不是 0",
                s["metrics"]["pass_rate"] is None, s["metrics"])

    # 13) 截断文件要归类成 truncated（本用例发现了 fwmap 的分类缺陷）
    from fwbench.subjects import get as get_subject
    trunc = open(os.path.join(FIX, "elf-t", "input.bin"), "rb").read()
    got = get_subject("fwmap").inspect_elf(trunc)
    ok &= check("fwmap 把截断文件报成 truncated",
                got["error"] == "truncated", got)

    # 14) 内核不依赖 fwmap：阻断导入后仍能跑 stdlib
    script = (
        "import sys; sys.modules['fwmap'] = None\n"
        "import fwbench.cases, fwbench.scoring, fwbench.report, fwbench.runner\n"
        "from fwbench.subjects import get\n"
        "s = get('stdlib')\n"
        "d = open(r'%s/bench/fixtures/elf-a/input.bin','rb').read()\n"
        "r = s.inspect_elf(d)\n"
        "print('OK' if r['fields'].get('machine_id') == 'mips' else 'BAD')\n"
    ) % ROOT
    proc = subprocess.run([sys.executable, "-c", script], cwd=ROOT,
                          capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    ok &= check("内核在无 fwmap 环境可独立运行",
                "OK" in (proc.stdout or ""),
                (proc.stdout or "") + (proc.stderr or "")[-200:])

    # 15) 第 7 节 #1：归档复算（三组 5/5、5/5、0/5）
    from fwbench import archive as A
    REC = os.path.join(ROOT, "lab", "recordings")
    arc = A.summarize_groups(REC, "/login.cgi", "crash", planned=5)
    hits = {k: v["hit"] for k, v in arc["groups"].items()}
    ok &= check("归档复算 5/5、5/5、0/5",
                hits == {"temp00": 5, "temp07": 5, "anon": 0}, hits)

    # 16) 第 7 节 #2：百分比（内部 0.75，展示 75%）
    g0 = arc["groups"]["temp00"]["model"]
    ok &= check("temp00 模型参与率内部为 0.75",
                abs(g0["share"] - 0.75) < 1e-9 and g0["steps"] == 40, g0)
    md_arc = A.render_markdown(arc)
    ok &= check("报告文字显示 75%", "75%" in md_arc)
    synth = [{"trace": [{"source": "model"}] * 2 + [{"source": "heuristic"}] * 6}]
    ok &= check("合成 2/8 显示 25%",
                abs(A.model_share(synth)["share"] - 0.25) < 1e-9)

    # 17) 第 7 节 #3：证据强度转述（文字由计数决定，不写死）
    sup = arc["groups"]["temp00"]["support"]
    ok &= check("具名归档命中记录是 process-exit",
                sup["process-exit"] == 5 and sup["observed-only"] == 0, sup)
    ok &= check("渲染文字与计数一致", "进程退出已确认" in md_arc)
    obs_only = {"process-exit": 0, "observed-only": 5, "missing": 0,
                "no_finding": 0}
    ok &= check("只有观察时文字不同",
                A._strength_text(obs_only) == "仅观测到空响应，进程状态未确认",
                A._strength_text(obs_only))

    # 18) 第 7 节 #4：分母（2 命中含第二位、1 未命中、1 损坏、1 缺失）
    d = os.path.join(tmp, "denom")
    os.makedirs(d, exist_ok=True)
    json.dump({"findings": [{"uri": "/login.cgi", "kind": "crash"}]},
              open(os.path.join(d, "a.json"), "w", encoding="utf-8"))
    json.dump({"findings": [{"uri": "/apply.cgi", "kind": "normal"},
                            {"uri": "/login.cgi", "kind": "crash"}]},
              open(os.path.join(d, "b.json"), "w", encoding="utf-8"))
    json.dump({"findings": [{"uri": "/login.cgi", "kind": "suspicious"}]},
              open(os.path.join(d, "c.json"), "w", encoding="utf-8"))
    open(os.path.join(d, "d.json"), "w", encoding="utf-8").write("{坏的")
    rc = A.recount(A.load_group(d), "/login.cgi", "crash", planned=5)
    ok &= check("命中在第二位也计入", rc["hit"] == 2, rc)
    ok &= check("损坏与缺失分别计数",
                rc["corrupt"] == 1 and rc["missing"] == 1, rc)
    ok &= check("两个分母 2/3 与 2/5",
                rc["valid"] == 3 and rc["rate_of_planned"] == 0.4, rc)

    # 19) 第 7 节 #6：--resume 只补缺的那一轮
    rdir = os.path.join(tmp, "resume")
    R.run_suite(SUITE, FIX, PROF_RULE, rdir)
    shutil.rmtree(os.path.join(rdir, "cases", "c018"))
    res2 = R.run_suite(SUITE, FIX, PROF_RULE, rdir, resume=True)
    ok &= check("resume 只补缺的用例",
                [r["case_id"] for r in res2["rows"]] == ["c018"], res2["rows"])
    ok &= check("已有成功轮次没被覆盖",
                os.path.exists(os.path.join(rdir, "cases", "c017",
                                            "submission.json")))

    # 20) 生产决策入口：fwmap 自己的 _decide 跑 C 层
    adir = os.path.join(tmp, "agent")
    R.run_suite(SUITE, FIX, PROF_RULE, adir, subject="fwmap-agent")
    sa = S.score_run(adir, oracle)
    ok &= check("生产决策循环跑通双例", sa["metrics"]["passed"] == 2, sa["metrics"])
    evs = [json.loads(line) for line in open(
        os.path.join(adir, "cases", "c017", "events.jsonl"), encoding="utf-8")]
    ok &= check("事件记录决策来源",
                any(e.get("proposed_by") == "heuristic" for e in evs), evs[:2])

    shutil.rmtree(tmp, ignore_errors=True)
    print()
    print("PASS（fwbench 自身）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
