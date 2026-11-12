"""污点引擎的回归测试（都是踩过的真坑，不联网、不需要 Ghidra）。

覆盖四条：

1. **覆盖清污**：`x = websGetVar(); x = "CONST"; system(x);` 不该报链。
   旧实现只在「本句有函数调用」时才识别赋值，这一句没有调用，
   于是 x 的旧污点活到 system()，报出假链。
2. **纯别名传播**：`x = websGetVar(); y = x; system(y);` 该报链。
   旧实现里 `if m and not calls` 恒不成立（m 在这个分支恒为 None），整段是死代码。
3. **字符串以反斜杠结尾**：`"C:\\"` 的闭合引号前面是反斜杠，
   旧实现只看前一个字符，判定「引号被转义」，把函数后半截全吞成字符串，
   整个函数只剩 1 条语句 —— 后面所有源/汇都看不到。
4. **函数名含 END**：反编译输出的块头若被判成结束标记，
   `SEND_RESPONSE` 这类函数会被整块丢弃，表现为「没漏洞」其实是「没分析」。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fwmap import m3flow  # noqa: E402

SOURCES = {"websGetVar"}
SINKS = {"system": "cmd"}


def check(name, cond, detail=""):
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def hits(c_body: str):
    return m3flow.analyze_c("f", "0x1", c_body, set(SOURCES), dict(SINKS), {})


def main() -> int:
    ok = True

    # 1) 覆盖之后不该再有链
    h = hits('void f(){ char *x; x = websGetVar(1,"a"); x = "CONST"; system(x); }')
    ok &= check("覆盖清污：常量覆盖后无链", len(h) == 0,
                [(x["source_api"], x["sink"]) for x in h])

    # 2) 别名传播
    h = hits('void f(){ char *x; char *y; x = websGetVar(1,"a"); y = x; system(y); }')
    ok &= check("别名传播：y=x 后仍能连到汇", len(h) == 1,
                [(x["source_api"], x["sink"]) for x in h])

    # 3) 基准：直接传递仍要出链（防止上面两条的修法把正常路径改坏）
    h = hits('void f(){ char *x; x = websGetVar(1,"a"); system(x); }')
    ok &= check("基准：直接传递出链", len(h) == 1, h)

    # 4) 字符串以反斜杠结尾
    st = m3flow._statements('a = "C:\\\\"; b = 1; c = 2;')
    ok &= check("反斜杠结尾的字符串不吞后续语句", len(st) == 3, st)

    st = m3flow._statements('a = "x\\\\\\"y"; b = 1;')
    ok &= check("字符串内的转义引号仍正确处理", len(st) == 2, st)

    # 5) 函数名含 END 不能被当成块尾
    out = "\n".join([
        "===== FUN_00401000 @ 00401000 =====",
        "C| int a = 1;",
        "===== END =====",
        "===== SEND_RESPONSE @ 00402000 =====",
        "C| int b = 2;",
        "===== END =====",
    ])
    blocks = m3flow._parse_decompile_output(out)
    ok &= check("函数名含 END 的块不丢",
                set(blocks) == {"FUN_00401000", "SEND_RESPONSE"}, list(blocks))
    ok &= check("块内容正确", "int b = 2;" in blocks.get("SEND_RESPONSE", ""),
                blocks.get("SEND_RESPONSE"))

    # 6) DecompileAt 的块尾带函数名，也要认
    out2 = "\n".join(["===== sub_x @ 0040 =====", "C| q = 1;", "===== END sub_x ====="])
    ok &= check("带函数名的块尾也认", m3flow._parse_decompile_output(out2) == {"sub_x": "q = 1;"},
                m3flow._parse_decompile_output(out2))

    print()
    print("PASS（污点引擎回归）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
