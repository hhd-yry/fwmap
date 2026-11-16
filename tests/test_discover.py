"""适应性测试：换一种固件形态，工具还能不能自己找到路由。

核心主张（这是跟"全靠规则"和"全靠模型"都不同的第三条路）：

    **模型只负责"选哪条路"，代码负责"怎么走"，证据负责"走对了没有"。**

所以这里测三件事：
1. 模型给出的机制，必须落在已知枚举里；胡说就退回最便宜的那条（page_derived）；
2. 三种形态的固件（有网页 / 只有字符串 / 什么都没有）都要有对应的处理，不能崩；
3. 探测验收失败时，不能谎报成功。
"""

import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import discover  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def fake_chat(reply: str):
    def _c(messages, **kw):
        return reply
    return _c


def main() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="fwmap-disc-")

    # 造一个小固件：一个二进制（带 goform 字符串）+ web 页面
    binp = os.path.join(tmp, "webs")
    with open(binp, "wb") as fh:
        fh.write(b"MIPS\x00" + b"\x00" * 64
                 + b"/goform/formStaDrvSetup\x00/goform/setWAN\x00"
                 + b"formLogin\x00websGetVar\x00\x00" * 4)
    os.makedirs(os.path.join(tmp, "web"))
    with open(os.path.join(tmp, "web", "a.asp"), "w", encoding="utf-8") as fh:
        fh.write('<form action="/goform/formStaDrvSetup">'
                 '<input name="rootAPmac"></form>')

    # 1) 证据收集
    pack = discover.evidence(binp, tmp)
    ok &= check("证据里有 goform 路径", pack["route_like_count"] >= 2, pack["route_like"])
    ok &= check("证据里有 form 形态函数名", pack["form_like_count"] >= 1, pack["form_like_count"])
    ok &= check("证据里有网页表单数", pack.get("pages_forms") == 1, pack.get("pages_forms"))

    # 2) 模型选路：正常选
    plan = discover.ask(pack, chat=fake_chat(
        '{"mechanism": "page_derived", "confidence": 0.8, "reason": "有 1 个表单"}'))
    ok &= check("按模型的选择走", plan["mechanism"] == "page_derived", plan)
    ok &= check("置信度解析正确", abs(plan["confidence"] - 0.8) < 0.01, plan["confidence"])

    # 3) 模型胡说：必须退回最便宜的路，而不是崩
    plan2 = discover.ask(pack, chat=fake_chat(
        '{"mechanism": "magic_stuff", "confidence": 0.99}'))
    ok &= check("不在枚举里 → 退回 page_derived", plan2["mechanism"] == "page_derived", plan2)
    plan3 = discover.ask(pack, chat=fake_chat("我不知道"))
    ok &= check("模型不回 JSON → 也退回 page_derived",
                plan3["mechanism"] == "page_derived", plan3)

    # 4) 三种机制都要能执行（不崩、有不有结果的说明）
    r1 = discover.apply_plan("page_derived", binp, tmp)
    ok &= check("page_derived 抽到 1 条", len(r1["routes"]) == 1, r1)
    ok &= check("带上了参数名", r1["routes"][0]["params"] == ["rootAPmac"], r1["routes"][0])
    r2 = discover.apply_plan("strings_goform", binp, tmp)
    ok &= check("strings_goform 抽到路径", len(r2["routes"]) >= 2, r2["routes"])
    ok &= check("strings 模式没有参数名（如实为空）",
                all(x["params"] == [] for x in r2["routes"]))
    r3 = discover.apply_plan("pointer_table", binp, tmp)
    ok &= check("需要 Ghidra 的机制交给 M2，不在这里硬做",
                r3["routes"] == [] and "Ghidra" in r3["note"], r3)

    # 5) 没有 rootfs 时，page_derived 要诚实地空手而归
    r4 = discover.apply_plan("page_derived", binp, None)
    ok &= check("没有 rootfs 就抽不到网页（不编）", r4["routes"] == [], r4)

    # 6) 探测验收：失败不能报成功
    out = discover.discover(binp, tmp, chat=fake_chat('{"mechanism":"page_derived"}'),
                            probe=lambda uris: {"checked": len(uris), "handler": 0},
                            log=lambda *_: None)
    ok &= check("discover 返回路由和计划", out["routes_count"] == 1 and out["plan"], out)
    ok &= check("探测结果原样带回（0 条可用）", out["probe"]["handler"] == 0, out["probe"])
    ok &= check("写了 profile 文件", os.path.exists(out["profile"]), out["profile"])

    import shutil

    shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("PASS（换固件也能自己找路由）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
