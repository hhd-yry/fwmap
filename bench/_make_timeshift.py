"""加一对"时间错位"用例：同一批材料，两题只改询问时间。

材料（两题共用）：
  e1 业务日志 10:00:09 "没有返回业务响应"      ← 只能支持"无响应"
  e2 进程记录 10:00:10 svc-17 exited           ← 回答「10:00:10」要靠它
  e3 进程记录 10:01:00 svc-17 running          ← 回答「10:01:00」要靠它
  e4 进程记录 10:00:10 svc-71 exited           ← 干扰项（另一台机器）

规则若"按类型取第一条"就会两题都答 exited → 第二题错。
这正是能区分"按类型取"和"按内容判断"的用例。

    py -3 bench/_make_timeshift.py
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
RECORDS = {
    "e1": {"id": "e1", "type": "service_log", "subject": "svc-17",
           "sample_time": "10:00:09",
           "message": "svc-17 在 10:00:09 没有返回业务响应", "source": "业务日志"},
    "e2": {"id": "e2", "type": "process_sample", "subject": "svc-17",
           "sample_time": "10:00:10", "state": "exited", "source": "进程监控"},
    "e3": {"id": "e3", "type": "process_sample", "subject": "svc-17",
           "sample_time": "10:01:00", "state": "running", "source": "进程监控"},
    "e4": {"id": "e4", "type": "process_sample", "subject": "svc-71",
           "sample_time": "10:00:10", "state": "exited", "source": "进程监控"},
}

TASK = ("根据归档材料，判断实例 svc-17 在 {t} 采样时的进程状态；"
        "给出支持判断的记录编号。")

NEW_CASES = [
    ("c071", "p35", "10:00:10", "exited", ["e2"]),
    ("c072", "p35", "10:01:00", "running", ["e3"]),
]


def main() -> int:
    folder = os.path.join(HERE, "fixtures", "fts")
    os.makedirs(folder, exist_ok=True)
    for rid, rec in RECORDS.items():
        with open(os.path.join(folder, f"{rid}.json"), "w", encoding="utf-8") as fh:
            json.dump(rec, fh, ensure_ascii=False, indent=1)

    catalog = [{"id": "e1", "type": "service_log"},
               {"id": "e2", "type": "process_sample"},
               {"id": "e3", "type": "process_sample"},
               {"id": "e4", "type": "process_sample"}]

    spath = os.path.join(HERE, "suites", "dev.json")
    opath = os.path.join(HERE, "oracle", "dev.json")
    suite = json.load(open(spath, encoding="utf-8-sig"))
    oracle = json.load(open(opath, encoding="utf-8-sig"))
    have = {c["case_id"] for c in suite["cases"]}

    for cid, pair, when, expected, evidence in NEW_CASES:
        if cid in have:
            continue
        suite["cases"].append({
            "case_id": cid, "kind": "interactive", "family": "timeshift",
            "pair_id": pair, "task": TASK.format(t=when),
            "catalog": catalog, "fixture_ref": "fts",
            "limits": {"decisions": 6, "tool_calls": 4}})
        oracle["cases"].append({
            "case_id": cid, "family": "timeshift", "pair_id": pair,
            "expected": expected, "acceptable_evidence_sets": [evidence],
            "subject": "svc-17", "sample_time": when,
            "allow_abstain": False, "provisional": True})

    for path, doc in ((spath, suite), (opath, oracle)):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=1)
    print(f"dev 套件现有 {len(suite['cases'])} 例；金标 {len(oracle['cases'])} 条")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
