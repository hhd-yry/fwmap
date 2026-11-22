"""经验驱动排序（L2）的测试：让"记住的成功率"真正影响顺序。

四条规则必须被钉死，否则"自适应"就只是日志里好看的一句话：

1. 先验平滑：没试过 = 0.5，不是 0 也不是 1；
2. 连败减半：但不清零（避免一次坏结果把机制永久封杀）；
3. 分层：有成功记录的厂商，成功过的 > 没试过的 > 失败过的；
4. 覆盖边界：只有在"经验明显更好"时才敢推翻模型的选择。
"""

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import discover  # noqa: E402
from fwmap import knowledge as K  # noqa: E402
from fwmap import policy  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def main() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="fwmap-policy-")
    os.environ["FWMAP_KNOWLEDGE_DIR"] = os.path.join(tmp, "k")
    K.reset()

    # 1) 先验平滑
    ok &= check("0 次尝试 = 0.5", abs(policy.prior(0, 0) - 0.5) < 1e-9, policy.prior(0, 0))
    ok &= check("1 成功 = 0.67", abs(policy.prior(1, 0) - 2 / 3) < 1e-9, policy.prior(1, 0))
    ok &= check("1 失败 = 0.33", abs(policy.prior(0, 1) - 1 / 3) < 1e-9, policy.prior(0, 1))

    # 2) 连败减半（不清零）
    stats = {"page_derived@v1": {"ok": 1, "fail": 2, "streak_fail": 2}}
    s1 = policy.score("page_derived", "v1", stats)
    base = policy.prior(1, 2)
    ok &= check("连败 2 次 = 底分 /4", abs(s1 - base / 4) < 1e-9, (s1, base))
    ok &= check("没有记录时按 0.5", abs(policy.score("x", "v1", stats) - 0.5) < 1e-9)

    # 3) 分层：成功过的优先于没试过的优先于失败过的
    stats2 = {"page_derived@v2": {"ok": 3, "fail": 0},
              "strings_goform@v2": {"ok": 0, "fail": 2}}
    order = policy.rank(["strings_goform", "pointer_table", "page_derived"],
                        "v2", stats=stats2)
    ok &= check("成功过的排第一", order[0] == "page_derived", order)
    ok &= check("失败过的排最后", order[-1] == "strings_goform", order)

    # 4) 冷启动：没成功记录时，没试过的排前（探索不被饿死）
    stats3 = {"strings_goform@v3": {"ok": 0, "fail": 1}}
    order3 = policy.rank(["strings_goform", "page_derived"], "v3", stats=stats3)
    ok &= check("冷启动时没试过的优先", order3[0] == "page_derived", order3)

    # 5) 没有 vendor 时原样返回（等于关闭）
    ok &= check("没有厂商就原样返回",
                policy.rank(["a", "b"], "") == ["a", "b"])

    # 6) knowledge.bump 维护 streak_fail
    K.reset()
    K.bump("page_derived", "v9", False)
    K.bump("page_derived", "v9", False)
    rec = K._load("stats")["page_derived@v9"]
    ok &= check("连败计数", rec["streak_fail"] == 2, rec)
    ok &= check("失败有 last_fail", bool(rec.get("last_fail")), rec)
    K.bump("page_derived", "v9", True)
    rec = K._load("stats")["page_derived@v9"]
    ok &= check("成功清零连败", rec["streak_fail"] == 0, rec)
    ok &= check("成功有 last_ok", bool(rec.get("last_ok")), rec)

    # 7) discover 里：经验明显更好时覆盖模型的选择
    K.reset()
    K.bump("page_derived", "dir-999", True)
    K.bump("page_derived", "dir-999", True)
    calls = []

    def chat(messages, **kw):
        return '{"mechanism": "strcmp_chain", "confidence": 0.9}'

    out = discover.discover(
        os.path.join(tmp, "fake.bin"), tmp,
        chat=chat, log=lambda *_: None, rounds=1,
        use_profile=False, use_knowledge=True, use_policy=True)
    # 厂商键来自目录名，这里是 tmp 的 basename，所以造一个同键目录
    ok &= check("discover 接受 use_policy 参数", "tried" in out)

    # 8) 显式验证 rank 覆盖条件（用 vendor 直算，不依赖目录名）
    stats4 = {"page_derived@dirx": {"ok": 2, "fail": 0},
              "strcmp_chain@dirx": {}}
    top = policy.rank(["strcmp_chain", "page_derived"], "dirx", stats=stats4)[0]
    ok &= check("经验优先时 rank 把成功的排前", top == "page_derived", top)
    ok &= check("score 高于阈值可触发覆盖",
                policy.score("page_derived", "dirx", stats4) >= 0.6)
    ok &= check("未试过的分数低于阈值",
                policy.score("strcmp_chain", "dirx", stats4) < 0.5 or
                policy.score("strcmp_chain", "dirx", stats4) == 0.5)

    # 9) 经验排序在 discover 里出现（日志）
    logs = []
    K.reset()
    vkey = os.path.basename(os.path.abspath(tmp)).lower()
    K.bump("page_derived", vkey, True)
    discover.discover(os.path.join(tmp, "f.bin"), tmp,
                      chat=lambda m, **k: '{"mechanism":"strcmp_chain"}',
                      log=logs.append, rounds=1, use_profile=False,
                      use_knowledge=True, use_policy=True)
    ok &= check("日志里能看到经验排序",
                any("经验排序" in x for x in logs), logs[:5])

    # 9.5) should_override：经验明显更好才推翻模型
    stats5 = {"page_derived@ov": {"ok": 1, "fail": 0}}
    ok &= check("成功过 vs 没试过 → 覆盖",
                policy.should_override("page_derived", "strcmp_chain", "ov", stats=stats5))
    ok &= check("没成功过的不覆盖",
                not policy.should_override("strings_goform", "strcmp_chain", "ov", stats=stats5))
    ok &= check("同一个机制不覆盖",
                not policy.should_override("page_derived", "page_derived", "ov", stats=stats5))
    stats6 = {"page_derived@ov2": {"ok": 1, "fail": 1},
              "strcmp_chain@ov2": {"ok": 1, "fail": 0}}
    ok &= check("差距不到 margin 不覆盖",
                not policy.should_override("page_derived", "strcmp_chain", "ov2", stats=stats6))

    # 10) 没有验收结果时，不能把"没跑"记成"失败"
    K.reset()
    discover.discover(os.path.join(tmp, "f2.bin"), tmp,
                      chat=lambda m, **k: '{"mechanism":"page_derived"}',
                      probe=None, log=lambda *_: None, rounds=1,
                      use_profile=False, use_knowledge=True, use_policy=True)
    ok &= check("没验收不写成功率", K._load("stats") == {}, K._load("stats"))

    os.environ.pop("FWMAP_KNOWLEDGE_DIR", None)
    import shutil

    shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("PASS（经验驱动排序）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
