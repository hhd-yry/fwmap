"""补齐三件事：① 少读用例 ② holdout 新材料 ③ 重复 3 次的配置。

① c081：同一批材料，预算只给 2 次工具调用，正确记录排在最后 —— 规则会先读错人，
   模型必须**少读且读得准**才答对。
② 给 fts 加 e5（10:02:00 svc-17 exited），holdout 用新时刻出题（不是 dev 的原题）。
③ 写一个大 repeats 的 profile 供重复实验。

    py -3 bench/_make_extra.py
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(p):
    with open(p, encoding="utf-8-sig") as fh:
        return json.load(fh)


def _save(p, doc):
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1)


def main() -> int:
    # ② 新材料：10:02:00 又回到 exited
    e5 = {"id": "e5", "type": "process_sample", "subject": "svc-17",
          "sample_time": "10:02:00", "state": "exited", "source": "进程监控"}
    _save(os.path.join(HERE, "fixtures", "fts", "e5.json"), e5)

    catalog_std = [{"id": "e1", "type": "service_log"},
                   {"id": "e2", "type": "process_sample"},
                   {"id": "e3", "type": "process_sample"},
                   {"id": "e4", "type": "process_sample"},
                   {"id": "e5", "type": "process_sample"}]
    # ① 少读：干扰项在前，正确记录（e2）在最后
    catalog_late = [{"id": "e4", "type": "process_sample"},
                    {"id": "e3", "type": "process_sample"},
                    {"id": "e1", "type": "service_log"},
                    {"id": "e2", "type": "process_sample"}]

    spath = os.path.join(HERE, "suites", "dev.json")
    opath = os.path.join(HERE, "oracle", "dev.json")
    suite, oracle = _load(spath), _load(opath)
    have = {c["case_id"] for c in suite["cases"]}
    if "c081" not in have:
        suite["cases"].append({
            "case_id": "c081", "kind": "interactive", "family": "lowread",
            "pair_id": "p36",
            "task": "根据归档材料，判断实例 svc-17 在 10:00:10 采样时的进程状态；"
                    "给出支持判断的记录编号。",
            "catalog": catalog_late, "fixture_ref": "fts",
            "limits": {"decisions": 4, "tool_calls": 2}})
        oracle["cases"].append({
            "case_id": "c081", "family": "lowread", "pair_id": "p36",
            "expected": "exited", "acceptable_evidence_sets": [["e2"]],
            "subject": "svc-17", "sample_time": "10:00:10",
            "allow_abstain": False, "provisional": True})
        _save(spath, suite)
        _save(opath, oracle)

    # ② holdout：用新材料、新时刻（10:02:00 exited / 10:01:00 running）
    hpath = os.path.join(HERE, "suites", "holdout.json")
    hopath = os.path.join(HERE, "oracle", "holdout.json")
    hs, ho = _load(hpath), _load(hopath)
    hhave = {c["case_id"] for c in hs["cases"]}
    for cid, when, expected, ev in (("c073", "10:02:00", "exited", "e5"),
                                    ("c074", "10:01:00", "running", "e3")):
        if cid in hhave:
            continue
        hs["cases"].append({
            "case_id": cid, "kind": "interactive", "family": "timeshift",
            "pair_id": "p37",
            "task": f"根据归档材料，判断实例 svc-17 在 {when} 采样时的进程状态；"
                    "给出支持判断的记录编号。",
            "catalog": catalog_std, "fixture_ref": "fts",
            "limits": {"decisions": 6, "tool_calls": 4}})
        ho["cases"].append({
            "case_id": cid, "family": "timeshift", "pair_id": "p37",
            "expected": expected, "acceptable_evidence_sets": [[ev]],
            "subject": "svc-17", "sample_time": when,
            "allow_abstain": False, "provisional": True})
    _save(hpath, hs)
    _save(hopath, ho)

    # ③ 重复 3 次
    _save(os.path.join(HERE, "profiles", "model-r3.json"),
          {"name": "model", "policy": "model", "chat": "local",
           "temperature": 0.0, "submit": "model", "repeats": 3,
           "limits": {"decisions": 6, "tool_calls": 4},
           "note": "M ×3：看同一用例的稳定性"})
    _save(os.path.join(HERE, "profiles", "rule-r3.json"),
          {"name": "rule", "policy": "rule", "repeats": 3,
           "limits": {"decisions": 6, "tool_calls": 4},
           "note": "H ×3：确定性检查"})

    print(f"dev {len(suite['cases'])} 例 / holdout {len(hs['cases'])} 例 / profile 已写")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
