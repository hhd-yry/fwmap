"""生成 dev / holdout 两份套件与对应金标（配对，两例只差一条记录）。

dev 用于开发；holdout 封存，只在 P3 阶段末跑一次。

    py -3 bench/_make_suites.py
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

TASK = {
    "lifecycle": "根据归档材料，判断实例 svc-17 在 10:00:10 采样时的进程状态；给出支持判断的记录编号。",
    "integrity": "根据归档材料，判断 pkg-7 的制品能否提交给下一环节；给出支持判断的记录编号。",
    "timing": "根据归档材料，判断 run-12 的那条记录是否属于本次运行；给出支持判断的记录编号。",
    "version": "根据归档材料，确定 fw-main 对应的版本；给出支持判断的记录编号。",
    "availability": "根据归档材料，判断 img-3 的验收材料是否齐全；给出支持判断的记录编号。",
}

# (case_id, family, pair, fixture, expected)
DEV = [
    ("c017", "lifecycle", "p03", "f017", "exited"),
    ("c018", "lifecycle", "p03", "f018", "running"),
    ("c031", "integrity", "p31", "finta", "complete"),
    ("c032", "integrity", "p31", "fintb", "truncated"),
    ("c041", "timing", "p32", "ftima", "current"),
    ("c042", "timing", "p32", "ftimb", "stale"),
]

HOLDOUT = [
    ("c051", "version", "p33", "fvera", "v2.5.12"),
    ("c052", "version", "p33", "fverb", "v3.03"),
    ("c061", "availability", "p34", "favaa", "present"),
    ("c062", "availability", "p34", "favab", "missing"),
]

AUTHORITATIVE = {"lifecycle": "process_sample", "integrity": "artifact_check",
                 "timing": "run_record", "version": "inventory",
                 "availability": "verification"}


def catalog(family):
    """对外只暴露真实用途（记录类型），不暴露取值。"""
    at = AUTHORITATIVE[family]
    return [{"id": "e1", "type": "service_log"},
            {"id": "e2", "type": at}, {"id": "e3", "type": at}]


def cases(rows):
    out = []
    for cid, family, pair, fixture, _expected in rows:
        out.append({
            "case_id": cid, "kind": "interactive", "family": family,
            "pair_id": pair, "task": TASK[family],
            "catalog": catalog(family), "fixture_ref": fixture,
            "limits": {"decisions": 6, "tool_calls": 4},
        })
    return out


def oracle(rows):
    out = []
    for cid, family, pair, _fixture, expected in rows:
        out.append({"case_id": cid, "family": family, "pair_id": pair,
                    "expected": expected,
                    "acceptable_evidence_sets": [["e2"]],
                    "allow_abstain": False, "provisional": True})
    return out


def write(path, doc):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1)
    print("写出", os.path.relpath(path, HERE))


if __name__ == "__main__":
    for name, rows in (("dev", DEV), ("holdout", HOLDOUT)):
        write(os.path.join(HERE, "suites", f"{name}.json"),
              {"schema_version": 1, "name": name,
               "description": f"{name} 套件：配对双例，两例只差一条记录的取值",
               "cases": cases(rows)})
        write(os.path.join(HERE, "oracle", f"{name}.json"),
              {"schema_version": 1,
               "note": "金标只在评分阶段加载；全部标记 provisional",
               "cases": oracle(rows)})
