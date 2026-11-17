"""经验飞轮的测试：记住、复用、不重复、不炸。

这套东西的价值不在"聪明"，在"别再踩同一个坑"。所以测的是：

1. 同一个厂商第二次跑，能命中上次的结论（跳过探索）；
2. 同一句经验只留一条（重复出现只加 hits，不刷屏）；
3. 记忆文件坏了不能让分析挂掉（当空的用）；
4. 成功率计数能累加 —— 以后"该先试哪种机制"就靠它。
"""

import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import knowledge as K  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def main() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="fwmap-know-")
    os.environ["FWMAP_KNOWLEDGE_DIR"] = os.path.join(tmp, "knowledge")
    K.reset()

    # 0) 空的时候要能用
    ok &= check("空库不炸", K.summary()["vendors"] == 0)
    ok &= check("空库默认目录会建出来", os.path.isdir(K.dir_path()))

    # 1) 厂商名推断：优先读固件自带的 VERSION
    root = os.path.join(tmp, "root")
    os.makedirs(root)
    with open(os.path.join(root, "VERSION"), "w", encoding="utf-8") as fh:
        fh.write("NAME:\t\tDIR_816LA1A\nVERSION:\t2.5.3\nSYSBUILDTIME:\t2015\n")
    key = K.vendor_key(root)
    ok &= check("从 VERSION 里认出型号", key == "dir-816l", key)
    ok &= check("没有 VERSION 时用目录名",
                K.vendor_key(os.path.join(tmp, "dlink_d615")) == "dlink_d615",
                K.vendor_key(os.path.join(tmp, "dlink_d615")))

    # 2) 记画像 + 复用
    prof = K.remember_vendor(key, mechanism="page_derived", web="busybox httpd + index.cgi",
                             validated=True, routes=188)
    ok &= check("画像写进去了", prof["mechanism"] == "page_derived", prof)
    ok &= check("runs 计数递增", prof["runs"] == 1, prof["runs"])
    again = K.vendor_profile(key)
    ok &= check("读回来的画像一致", again.get("routes") == 188, again)
    K.remember_vendor(key, routes=200)
    merged = K.vendor_profile(key)
    ok &= check("二次写入是合并、不覆盖其它字段",
                merged["mechanism"] == "page_derived" and merged["routes"] == 200, merged)
    ok &= check("runs 累加", merged["runs"] == 2, merged["runs"])

    # 3) 经验卡：去重 + hits
    ok &= check("第一次记经验返回 True",
                K.add_lesson("fwupdate.cgi 无条件崩 = 环境假象，别报", scope="dir-816l"))
    ok &= check("同一句再记返回 False（不新增）",
                K.add_lesson("fwupdate.cgi 无条件崩    = 环境假象，别报 ",
                             scope="dir-816l") is False)
    les = K.lessons_for("dir-816l")
    ok &= check("库里只有一条", len(les) == 1, les)
    ok &= check("hits 变成 2", les[0]["hits"] == 2, les[0]["hits"])
    ok &= check("按 scope 过滤能用", len(K.lessons_for("dir-816")) == 1)
    ok &= check("不相关的 scope 取不到", len(K.lessons_for("totolink")) == 0)

    # 4) 成功率计数
    K.bump("page_derived", key, True)
    K.bump("page_derived", key, True)
    st = K.bump("page_derived", key, False)
    ok &= check("成功/失败分别累加", st["ok"] == 2 and st["fail"] == 1, st)

    # 5) 记忆文件坏了要当空的用，而不是让分析挂掉
    with open(os.path.join(K.dir_path(), "vendors.json"), "w", encoding="utf-8") as fh:
        fh.write("{ 这不是 JSON")
    ok &= check("坏文件当空库", K.vendor_profile(key) == {})
    ok &= check("坏文件之后还能写", K.remember_vendor(key, mechanism="page_derived")["runs"] == 1)

    # 6) summary 对得上
    s = K.summary()
    ok &= check("summary 数字合理", s["vendors"] >= 1 and s["lessons"] == 1 and s["stats"] == 1, s)

    # 7) 上限保护：写很多条也不会无限增长
    for i in range(600):
        K.add_lesson(f"经验 {i}")
    ok &= check("超过上限会裁剪", len(K.lessons_for()) <= K._MAX_ITEMS,
                len(K.lessons_for()))

    import shutil

    os.environ.pop("FWMAP_KNOWLEDGE_DIR", None)
    shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("PASS（经验飞轮）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
