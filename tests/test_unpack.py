"""解包这层的测试：模型挑工具、代码执行、结果自证。

为什么值得单独测：**解不开的固件，后面所有分析都是零**。
而每一家的壳都不一样（squashfs 3/4、cramfs、UBI、私有加密），
所以这里测的不是"某个工具好用"，而是：

1. 模型说不该试（私有加密且没工具）时，程序不许硬试、更不许假装成功；
2. 模型给的顺序要被执行，而且**第一个成功的就停**；
3. 验收看的是「像不像 rootfs」（bin/etc/lib + 可执行文件），不是相信工具的退出码。
"""

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import unpack as U  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def fake_chat(reply):
    return lambda messages, **kw: reply


def main() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="fwmap-unpack-")

    # 假镜像：一个 cr6b 加密头（熵高）
    enc = os.path.join(tmp, "enc.bin")
    with open(enc, "wb") as fh:
        fh.write(b"cr6b" + bytes(range(256)) * 400)
    # 假镜像：squashfs 魔数
    sq = os.path.join(tmp, "sq.bin")
    with open(sq, "wb") as fh:
        fh.write(b"hsqs" + b"\x00" * 2000)

    # 1) 证据
    ev = U.evidence(enc)
    ok &= check("认出 cr6b 头", ev["head_ascii"].startswith("cr6b"), ev["head_ascii"])
    ok &= check("熵判定为加密", ev["entropy"] > 7.5, ev["entropy"])
    ok &= check("说明里点出私有加密", "cr6b" in ev["note"], ev["note"])
    ev2 = U.evidence(sq)
    ok &= check("认出 squashfs 魔数", any(m["magic"] == "hsqs" for m in ev2["magic_hits"]),
                ev2["magic_hits"])

    # 2) 模型说「解不了」→ 一个工具都不试
    p = U.plan(ev, chat=fake_chat(
        '{"attempts": [], "unsolvable": true, "reason": "cr6b 是 D-Link 私有加密，无公开工具"}'))
    ok &= check("模型说解不了 → 空方案", p == [], p)
    out = U.unpack(enc, os.path.join(tmp, "o1"), chat=fake_chat(
        '{"attempts": [], "unsolvable": true, "reason": "私有加密"}'), log=lambda *_: None)
    ok &= check("不硬试、如实报 unsolvable", out["unsolvable"] is True and out["rootfs"] is None,
                out)

    # 3) 模型给的顺序被执行，第一个成功就停
    calls = []

    def fake_run(tool, image, outdir, timeout=600):
        calls.append(tool)
        if tool == "7z":
            d = os.path.join(outdir, "root")
            for sub in ("bin", "etc", "lib"):
                os.makedirs(os.path.join(d, sub), exist_ok=True)
            open(os.path.join(d, "bin", "busybox"), "wb").write(b"\x7fELF")
            return {"ok": True, "dir": d,
                    "verdict": {"ok": True, "dirs": ["bin", "etc", "lib"], "elf_hint": 3}}
        return {"ok": False, "error": "假装解不开"}

    real = U._run_tool
    U._run_tool = fake_run
    try:
        out2 = U.unpack(sq, os.path.join(tmp, "o2"), chat=fake_chat(
            '{"attempts": [{"tool":"binwalk"},{"tool":"7z"},{"tool":"unsquashfs"}]}'),
            log=lambda *_: None)
        ok &= check("按模型的顺序试", calls == ["binwalk", "7z"], calls)
        ok &= check("成功就停（没继续试第三个）", "unsquashfs" not in calls, calls)
        ok &= check("返回能用的 rootfs", out2["ok"] and out2["tool"] == "7z", out2)
    finally:
        U._run_tool = real

    # 4) 验收：不像 rootfs 的目录必须判失败
    bad = os.path.join(tmp, "bad")
    os.makedirs(os.path.join(bad, "stuff"), exist_ok=True)
    open(os.path.join(bad, "stuff", "readme.txt"), "w").write("hi")
    v = U.looks_like_rootfs(bad)
    ok &= check("垃圾目录不算解包成功", v["ok"] is False, v)

    good = os.path.join(tmp, "good")
    for sub in ("bin", "etc", "sbin"):
        os.makedirs(os.path.join(good, sub), exist_ok=True)
    open(os.path.join(good, "bin", "busybox"), "wb").write(b"\x7fELF")
    ok &= check("标准目录 + 可执行 → 通过", U.looks_like_rootfs(good)["ok"] is True)
    ok &= check("目录不存在 → 不通过", U.looks_like_rootfs("/nonexistent")["ok"] is False)

    # 5) 工具不在机器上时要如实报，不是崩
    res = U._run_tool("ubireader", sq, os.path.join(tmp, "o3"))
    ok &= check("缺工具时给出原因", ("没有" in str(res.get("error"))) or res["ok"] is False, res)

    import shutil

    shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("PASS（解包这层）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
