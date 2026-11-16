"""短函数名的 CVE 匹配是噪音 —— 这条规则是实测打出来的。

Edimax 的 `mp` 在 CVE 库里"命中" 21 条（CVE-1999-1136、CVE-2001-0406…），
但**一条都没提 Edimax** —— 全是别的东西里带 "mp" 两个字。
如果就这么算成「已公开」，一个真候选会被划掉。
实测那次 /goform/mp + command 512 字节确实打崩了。
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import verify  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def fake_searcher(rows):
    def _s(kw):
        return [dict(r) for r in rows]
    return _s


def judge(fn, rows, ctx=("edimax",)):
    return verify.judge_function(fn, [], {}, False, 0.0, False,
                                 searcher=fake_searcher(rows), context=list(ctx))


def main() -> int:
    ok = True

    # 一堆提到 mp 但没提厂商的 CVE
    many = [{"id": f"CVE-1999-{1000 + i}",
             "desc": f"mp in some unrelated product allows memory corruption ({i})"}
            for i in range(21)]

    r = judge("mp", many)
    ok &= check("短函数名 + 没提厂商 → manual（不叫 known）",
                r["verdict"] == "manual", r)
    ok &= check("说明里点出'名字太短'", "太短" in r["note"], r["note"])
    ok &= check("仍保留匹配到的条目，供人工看", len(r["matched"]) == 21, len(r["matched"]))

    # 同样的命中，但有一条提到厂商 → 这不是噪音，算 known
    with_ctx = many[:3] + [{"id": "CVE-2026-10127",
                            "desc": "Edimax BR-6478AC mp command injection"}]
    r2 = judge("mp", with_ctx)
    ok &= check("短名字但提到了厂商 → known", r2["verdict"] == "known", r2)

    # 长函数名不受这条规则影响
    long_rows = [{"id": "CVE-2026-10127",
                  "desc": "formStaDrvSetup in Edimax BR-6478AC allows command injection"}]
    r3 = judge("formStaDrvSetup", long_rows)
    ok &= check("长函数名照常判 known", r3["verdict"] == "known", r3)
    ok &= check("提到厂商 → 置信 high", r3["confidence"] == "high", r3["confidence"])

    long_noctx = [{"id": "CVE-2025-1", "desc": "formStaDrvSetup buffer overflow"}]
    r4 = judge("formStaDrvSetup", long_noctx)
    ok &= check("长函数名没提厂商 → known/medium（不是 manual）",
                r4["verdict"] == "known" and r4["confidence"] == "medium", r4)

    # 没有厂商上下文时，这条规则不启用（离线/未知目标的场景）
    r5 = judge("mp", many, ctx=())
    ok &= check("没给厂商信息时不启用短名规则", r5["verdict"] == "known", r5)

    print()
    print("PASS（短函数名不算已公开）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
