"""缺口语义测试 —— 每条链都要说清「我还缺什么」。

这个字段是照同学的 agent 抄的（她的报告里 missing_evidence 是一等字段）。
要点：
- 每条链至少一条缺口（"没做动态验证"兜底），不能出现空清单假装证完了；
- 缺口必须由链上的具体环节推出来，不能是万能话术；
- 老 flow.json 没有这个字段时，报告要显示 —，不能崩。
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import m3flow  # noqa: E402
from fwmap import triage  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def chain(**kw):
    base = {"function": "formSetX", "sink": "system", "sink_category": "ci",
            "source_api": "websGetVar", "source_param": "a", "via": "x",
            "sink_args": "x", "guard": "if (a) {}", "weak": False,
            "induced_sink": False, "induced_source": False, "bounded_copy": False,
            "hops": 1, "confidence": "high", "verdict": "keep", "sink_verified": None}
    base.update(kw)
    return base


def main() -> int:
    ok = True

    # 1) 干净的一跳强源链：至少要有「没做动态验证」这一条
    g = m3flow.missing_evidence(chain())
    ok &= check("干净的链也有缺口（不假装证完了）", len(g) >= 1, g)
    ok &= check("兜底那一条是动态验证", "动态验证" in g[-1], g)

    # 2) 每个标志都要能翻成一句人话
    cases = [
        ({"induced_source": True}, "归纳", "输入点是归纳的"),
        ({"induced_sink": True}, "归纳", "汇点是归纳的"),
        ({"sink_verified": False}, "汇点核对失败", "实参里找不到"),
        ({"induced_sink": True, "sink_verified": None}, "没定位", "第几个实参"),
        ({"weak": True}, "弱源", "写脏"),
        ({"bounded_copy": True}, "上限", "绕过"),
        ({"hops": 3}, "3 跳", "逐条核对"),
        ({"guard": "", "hops": 1}, "没有守卫代码", "没取到前置语句"),
    ]
    for kw, want, why in cases:
        got = " ".join(m3flow.missing_evidence(chain(**kw)))
        ok &= check(f"{why} → 有对应缺口", want in got, got)

    # 3) 类别不同，最后一条不一样（ci/bof/fmt 不能都写"没做动态验证"）
    ci = m3flow.missing_evidence(chain(sink_category="ci"))[-1]
    bof = m3flow.missing_evidence(chain(sink_category="bof"))[-1]
    fmt = m3flow.missing_evidence(chain(sink_category="fmt"))[-1]
    ok &= check("ci/bof/fmt 的缺口各不相同", len({ci, bof, fmt}) == 3, (ci, bof, fmt))
    ok &= check("bof 那条提到阈值", "阈值" in bof, bof)

    # 4) apply_rules 会把 verdict 和缺口一起打好
    cs = m3flow.apply_rules([chain(), chain(function="f2", weak=True)])
    ok &= check("apply_rules 打了 verdict", all("verdict" in c for c in cs))
    ok &= check("apply_rules 打了缺口", all(c.get("missing_evidence") for c in cs),
                [c.get("missing_evidence") for c in cs])

    # 5) 报告侧：单元格 + 汇总
    cell = triage._gap_cell(cs[0])
    ok &= check("单元格显示第一条缺口", "动态验证" in cell or len(cell) > 0, cell)
    cell_many = triage._gap_cell({"missing_evidence": ["a", "b", "c"]})
    ok &= check("多条缺口标 +N", "+2" in cell_many, cell_many)
    ok &= check("老 flow 没这字段 → 显示 —", triage._gap_cell({}) == "—")
    summ = triage._gap_summary(cs + [chain(function="f3")])
    ok &= check("汇总按条数排序且最多 3 条", len(summ) <= 3 and summ[0][1] >= summ[-1][1], summ)

    # 6) 整份报告能渲染出来（新列在最窄的输入上也要成立）
    res = {
        "rootfs": "/x", "time": "2026-11-15 16:00", "meta": {},
        "stats": {"files": 1, "targets": 1, "elfs": 1, "high": 1, "oneline": "最小报告"},
        "agent_rows": [],
        "binaries": [{"name": "httpd", "binary": "/x/httpd", "path": "/x/httpd",
                      "score": 87, "role": "web", "arch": "mipsel", "size": 991088,
                      "chains": 1, "chain_list": [cs[0]], "endpoints": 1,
                      "endpoint_list": [], "sink_verified": 0,
                      "binary_sha256": "ab" * 32, "m2_strategy": "registration"}],
    }
    html = triage.render(res)
    ok &= check("报告能渲染", len(html) > 1000, len(html))
    ok &= check("报告里有「还缺什么」这一列", "还缺什么" in html)
    ok &= check("报告里有缺口汇总", "这批链共同的缺口" in html)

    print()
    print("PASS（每条链的缺口）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
