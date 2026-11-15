"""裁决回归测试：这两种「撤回」以前撤回错了，别再犯。

材料是 Edimax 那轮真实报告里的 4 条 REFUTED（用户当场质疑「LLM 复核没啥用」）：

1. `formUpload`：理由是「危险调用前有上界检查：if (0 < param_3) { memcpy(...) }」
   —— `0 < param_3` 只说明长度是正数，**不是上界**。
2. `formStaDrvSetup`：理由是「`acStack_340` 被重新赋值：sprintf(acStack_340, ...)」
   —— 那正是把污染写进缓冲的那一步，是汇，不是重新赋值。
3. `wiz_5in1_redirect`：理由是「`pcVar1` 被重新赋值：if (*pcVar1 != '\\0') { system(...) }」
   —— 引用的代码里就调了 system，是汇。
4. `formUploadIE`：`*(int *)x = *(int *)x + param_3` —— 右边还带着源参数，污染没断。
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap.agent import judge as J  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def main() -> int:
    ok = True

    # 1) 下界检查的两种写法都要认出来
    for stmt in ("if (0 < param_3) { memcpy(a, b, param_3);",
                 "if (param_3 > 0) {",
                 "if (strlen(s) < 4) {",
                 "if (0x10 < n) {"):
        ok &= check(f"下界检查要认出来：{stmt[:28]}", J._looks_like_lower_bound(stmt), stmt)

    # 真正的上界检查不能被当成下界
    for stmt in ("if (param_3 <= 0x40) {", "if (n < sizeof(buf)) {",
                 "if (len > 0x100) return -1;"):
        ok &= check(f"上界检查不能误判成下界：{stmt[:28]}",
                    not J._looks_like_lower_bound(stmt), stmt)

    # 2) 汇语句本身不能当「重新赋值」
    ci = {"sink": "system", "via": "pcVar1", "source_param": "cmd"}
    ok &= check("if 守卫里调 sink 的，不算重新赋值",
                not J._reassign_breaks_taint(ci, "if (*pcVar1 != '\\0') { system(x)"),
                "wiz_5in1_redirect 那条")
    sp = {"sink": "sprintf", "via": "acStack_340", "source_param": "local_38"}
    ok &= check("sprintf 写缓冲 = 污染到位，不是断链",
                not J._reassign_breaks_taint(sp, 'sprintf(acStack_340,"echo %d",local_38)'))

    # 3) 赋值右边还带着源参数，污染没断
    ok &= check("累加式赋值不算断链",
                not J._reassign_breaks_taint(
                    {"sink": "memcpy", "via": "x", "source_param": "param_3"},
                    "*(int *)mid = *(int *)mid + param_3"))

    # 4) 真正的重新赋值（右边是常量/别的变量）要照旧判成断链
    ok &= check("右边是常量 → 真断链",
                J._reassign_breaks_taint({"sink": "system", "via": "c", "source_param": "q"},
                                         'c = "fixed";'))
    ok &= check("右边是别的变量 → 真断链",
                J._reassign_breaks_taint({"sink": "system", "via": "c", "source_param": "q"},
                                         "c = other_buf;"))

    print()
    print("PASS（裁决回归）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
