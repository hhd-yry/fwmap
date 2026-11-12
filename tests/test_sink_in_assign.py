"""回归测试：源内联在「带返回值的汇」的实参里时，不能漏掉。

历史 bug（m3flow.analyze_c）：
    语句 `iVar1 = sprintf(dst, fmt, websGetVar(...))` 既是一次赋值（m 非空），
    又含一个汇调用。旧代码在「已处理赋值」后直接 `continue`，
    把后面的汇检查整段跳过 —— 这类链一条都出不来，且**不报错**。

修复：用 skip_assign 只跳过重复的赋值处理，汇检查照常执行。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fwmap.m3flow import analyze_c  # noqa: E402

SRC_ASSIGN = """void FUN_1000(int wp) {
  char d [8];
  iVar1 = sprintf (d, "%s", websGetVar (wp, "name", ""));
}
"""

SRC_PLAIN = """void FUN_1001(int wp) {
  char d [8];
  sprintf (d, "%s", websGetVar (wp, "name", ""));
}
"""


def main() -> int:
    ok = True

    r1 = analyze_c("FUN_1000", "1000", SRC_ASSIGN,
                   {"websGetVar"}, {"sprintf": "bof"}, {})
    hit = [c for c in r1 if c.get("sink") == "sprintf"]
    print(("ok   " if hit else "FAIL ") + "赋值形式 x = sprintf(..., 源(...)) 能出链")
    ok &= bool(hit)

    r2 = analyze_c("FUN_1001", "1001", SRC_PLAIN,
                   {"websGetVar"}, {"sprintf": "bof"}, {})
    hit2 = [c for c in r2 if c.get("sink") == "sprintf"]
    print(("ok   " if hit2 else "FAIL ") + "非赋值形式仍然出链（回归保护）")
    ok &= bool(hit2)

    # 纯赋值、无汇的语句不应凭空产生链
    r3 = analyze_c("FUN_1002", "1002",
                   'void FUN_1002(int wp) {\n  char *p = websGetVar (wp, "a", "");\n}\n',
                   {"websGetVar"}, {"sprintf": "bof"}, {})
    print(("ok   " if not r3 else "FAIL ") + "只有源没有汇 → 不出链")
    ok &= not r3

    print()
    print("PASS（源内联在带返回值的汇实参里）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
