"""生成 C 层各家族的配对夹具（同一形状，只换记录类型与取值）。

每个家族一对，两例**只差一条记录**的 `state`；e1 是只能支持弱结论的日志，
e3 是另一对象的同类记录（引用它 = 无证据命中）。

    py -3 bench/fixtures/_make_families.py
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

# family -> (权威记录类型, 对象, 两例的取值, e1 的弱结论)
FAMILIES = {
    "integrity": ("artifact_check", "pkg-7",
                  ("complete", "truncated"),
                  "pkg-7 的打包任务在 10:00:09 报过一次重试"),
    "timing": ("run_record", "run-12",
               ("current", "stale"),
               "run-12 在 10:00:09 输出过一条普通消息"),
    "version": ("inventory", "fw-main",
                ("v2.5.12", "v3.03"),
                "fw-main 的文件名在两份清单里都出现过"),
    "availability": ("verification", "img-3",
                     ("present", "missing"),
                     "img-3 的校验任务在 10:00:09 启动过"),
}

PAIR = {
    "integrity": "p31", "timing": "p32", "version": "p33", "availability": "p34",
}


def build():
    n = 0
    for family, (ctype, subject, (a, b), weak) in FAMILIES.items():
        for suffix, value in (("a", a), ("b", b)):
            ref = f"f{family[:3]}{suffix}"
            folder = os.path.join(HERE, ref)
            os.makedirs(folder, exist_ok=True)
            recs = {
                "e1": {"id": "e1", "type": "service_log", "subject": subject,
                       "sample_time": "10:00:09", "message": weak,
                       "source": "业务日志"},
                "e2": {"id": "e2", "type": ctype, "subject": subject,
                       "sample_time": "10:00:10", "state": value,
                       "source": "权威记录"},
                "e3": {"id": "e3", "type": ctype, "subject": "other-9",
                       "sample_time": "10:00:10", "state": value,
                       "source": "权威记录"},
            }
            for rid, rec in recs.items():
                with open(os.path.join(folder, f"{rid}.json"), "w",
                          encoding="utf-8") as fh:
                    json.dump(rec, fh, ensure_ascii=False, indent=1)
            n += 1
    return n


if __name__ == "__main__":
    print(f"生成 {build()} 个夹具目录")
