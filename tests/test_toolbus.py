"""工具总线的测试：规矩比数量重要。

这个模块的价值不在"支持了 10 个工具"，在**每个工具都说得出"我怎么算成功"**。
所以测的是纪律：

1. 没有成功判据的工具，注册要直接报错（宁可少一个）；
2. 工具没装时不许假装成功；
3. 验收失败时，退出码是 0 也不能算成功；
4. 按顺序试，第一个通过验收就停；
5. 全程留下 provenance（用了什么命令、哪个版本、耗时多少）。
"""

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import toolbus as TB  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def main() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="fwmap-bus-")
    src = os.path.join(tmp, "fw.bin")
    with open(src, "wb") as fh:
        fh.write(b"\x27\x05\x19\x56" + b"\x00" * 200)

    # 1) 铁律：没有 success 判据不许注册
    try:
        TB.Tool("bad", "unpack", ["true", "{src}"], None)
        ok &= check("没有成功判据 → 注册报错", False, "居然允许了")
    except ValueError as ex:
        ok &= check("没有成功判据 → 注册报错", "success" in str(ex), ex)

    try:
        TB.Tool("bad2", "不存在的分类", ["true"], lambda d: {"ok": True})
        ok &= check("未知能力分类 → 报错", False)
    except ValueError:
        ok &= check("未知能力分类 → 报错", True)

    # 2) 正常注册 + 编目
    def v_yes(d):
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "x"), "w").write("1")
        return {"ok": True, "detail": "看起来对"}

    def v_no(d):
        return {"ok": False, "detail": "解出来是垃圾"}

    MAKE = [sys.executable, "-c", "import os;os.makedirs(r'{out}',exist_ok=True);open(os.path.join(r'{out}','x'),'w').write('1')"]
    TB.register(TB.Tool("fake-ok", "unpack", MAKE, v_yes,
                        note="假的但会成功", needs=sys.executable))
    TB.register(TB.Tool("fake-no", "unpack", MAKE, v_no,
                        note="假的且验收失败", needs=sys.executable))
    cat = TB.catalog("unpack")
    ok &= check("编目里有它", {c["name"] for c in cat} >= {"fake-ok", "fake-no"}, cat)
    ok &= check("编目带 available 字段", all("available" in c for c in cat))

    # 3) 没装的工具：明确报"没装"，不是"失败"
    missing = TB.Tool("nonexistent-xyz", "unpack", ["definitely-not-here", "{src}"], v_yes)
    TB.register(missing)
    r = TB.run(missing, src, os.path.join(tmp, "o0"))
    ok &= check("没装就如实说没装", r["ok"] is False and "没装" in r.get("error", ""), r)

    # 4) 退出码 0 但验收不过 → 不算成功
    r2 = TB.run("fake-no", src, os.path.join(tmp, "o1"))
    ok &= check("验收不过就不算成功", r2["ok"] is False, r2)
    ok &= check("失败也留 provenance", r2["provenance"].get("exit") == 0, r2["provenance"])

    # 5) 成功路径 + provenance
    r3 = TB.run("fake-ok", src, os.path.join(tmp, "o2"))
    ok &= check("成功时 ok=True", r3["ok"] is True, r3)
    ok &= check("记下了用的命令", r3["provenance"].get("cmd"), r3["provenance"])
    ok &= check("记下了耗时", "seconds" in r3["provenance"])

    # 6) 按顺序试，第一个成功就停
    calls = []
    orig = TB.run
    TB.run = lambda tool, s, o, timeout=None: (calls.append(getattr(tool, "name", tool)),
                                              {"ok": getattr(tool, "name", tool) == "fake-ok",
                                               "tool": getattr(tool, "name", tool),
                                               "dir": o, "detail": ""})[1]
    try:
        chain = TB.run_chain(src, os.path.join(tmp, "o3"), ["fake-no", "fake-ok", "fake-no"])
        ok &= check("按顺序试到成功就停", calls == ["fake-no", "fake-ok"], calls)
        ok &= check("返回成功的那条", chain["ok"] and chain["tool"] == "fake-ok", chain)
    finally:
        TB.run = orig

    # 7) 全失败要如实
    TB.run = lambda tool, s, o, timeout=None: {"ok": False, "tool": getattr(tool, "name", ""),
                                               "error": "nope"}
    try:
        bad = TB.run_chain(src, os.path.join(tmp, "o4"), ["fake-no", "fake-ok"])
        ok &= check("全失败时不谎报", bad["ok"] is False and len(bad["tried"]) == 2, bad)
    finally:
        TB.run = orig

    # 8) choose() 兜底：模型不可用也要给出顺序
    order = TB.choose(src, capability="unpack", chat=None)
    ok &= check("没模型时也有兜底顺序", len(order) >= 1, order)
    ok &= check("兜底不包含没装的东西？不要求，但必须是已注册的",
                all(n in {t.name for t in TB.all_tools()} for n in order), order)

    # 9) 模型胡说（给出不存在的工具名）要被过滤
    bad_chat = lambda m, **k: '{"order": ["不存在的工具", "fake-ok"]}'   # noqa: E731
    order2 = TB.choose(src, capability="unpack", chat=bad_chat)
    ok &= check("过滤掉模型编的工具名", "不存在的工具" not in order2, order2)
    ok &= check("保留模型给的真工具", "fake-ok" in order2, order2)

    import shutil

    shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("PASS（工具总线）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
