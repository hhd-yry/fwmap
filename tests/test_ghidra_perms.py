"""Ghidra 跨平台搬运的两个坑（都在 VM 里踩到了）：

1. 启动脚本挑错：Windows 版目录里同时有 `analyzeHeadless.bat` 和 `analyzeHeadless`，
   Linux 上先试 `.bat` 就报 `Exec format error (errno 8)`。
2. 执行位丢失：从 Windows 打包 tar 过来，脚本和 `decompile`/`sleigh` 都没有 +x。
   反编译器的表现尤其坑 —— 不报错，只是**反编译 0 个函数**，看起来像「这个固件很干净」。
"""

import os
import stat
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import m2 as M  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def main() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="fwmap-perms-")

    # 造一个「从 Windows 拷过来」的 Ghidra 目录
    os.makedirs(os.path.join(tmp, "support"))
    os.makedirs(os.path.join(tmp, "Ghidra", "Features", "Decompiler", "os", "linux_x86_64"))
    headless = os.path.join(tmp, "support", "analyzeHeadless")
    decomp = os.path.join(tmp, "Ghidra", "Features", "Decompiler", "os",
                          "linux_x86_64", "decompile")
    for p in (headless, decomp):
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("#!/usr/bin/env bash\necho hi\n")
        os.chmod(p, 0o644)                      # 没有执行位，正是 Windows 打包的结果

    fixed = M.ensure_posix_perms(tmp, posix=True)
    ok &= check("补了执行位", len(fixed) >= 2, fixed)
    if os.name != "nt":
        # Windows 没有执行位这回事（chmod 只改只读属性），这几条只在 POSIX 上有意义
        ok &= check("启动脚本可执行", os.access(headless, os.X_OK))
        ok &= check("反编译器可执行（不然反编译 0 个函数）", os.access(decomp, os.X_OK))
    ok &= check("只补一次（第二次不再扫）", M.ensure_posix_perms(tmp, posix=True) == [])

    # 已经有执行位的不用动（同样只在 POSIX 上成立）
    other = tempfile.mkdtemp(prefix="fwmap-perms2-")
    os.makedirs(os.path.join(other, "support"))
    p2 = os.path.join(other, "support", "analyzeHeadless")
    open(p2, "w").write("#!/bin/sh\n")
    os.chmod(p2, 0o755)
    if os.name != "nt":
        ok &= check("已经是可执行的不重复改", M.ensure_posix_perms(other, posix=True) == [])
    ok &= check("非 POSIX 直接跳过",
                M.ensure_posix_perms(tempfile.mkdtemp(prefix="fwmap-perms3-"), posix=False) == [])

    # 启动脚本选择：Linux 上不能挑 .bat
    bat = os.path.join(tmp, "support", "analyzeHeadless.bat")
    open(bat, "w").write("@echo off\n")
    picked = M.headless_path(tmp)
    if os.name == "nt":
        ok &= check("Windows 上挑 .bat", picked.endswith(".bat"), picked)
    else:
        ok &= check("Linux 上挑无后缀脚本（不是 .bat）", not picked.endswith(".bat"), picked)

    import shutil

    shutil.rmtree(tmp, ignore_errors=True)
    shutil.rmtree(other, ignore_errors=True)

    print()
    print("PASS（Ghidra 跨平台搬运）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
