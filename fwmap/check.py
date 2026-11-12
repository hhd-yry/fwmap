"""
rootfs 自检。

存在的理由：解包不完整是最常见的坑，而且症状很隐蔽——工具照样跑，照样出报告，
只是报告是假的。所以必须有一个独立的检查步骤，在扫描之前告诉你"这个目录不对劲"。

检查的是结构合理性，不是文件内容正确性。
"""

from __future__ import annotations

import os
import re
from collections import Counter

REQUIRED_DIRS = ["bin", "sbin", "etc", "lib", "usr"]
# 强信号：这些扩展名不可能出现在正常 rootfs 里，出现即说明还有一层没解
STRONG_EXT = (".squashfs", ".sqsh", ".cpio", ".img", ".ubi", ".ubifs")
# 弱信号：包管理器/缓存/文档目录里的 tar.gz 是正常的，别误报
WEAK_EXT = (".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".zip", ".lzma", ".xz")
SKIP_DIRS = ("apk/db", "var/cache", "var/lib/dpkg", "share/doc", "share/man")
INIT_PATHS = ["etc/init.d", "etc/rc.d", "etc/init.d/rcS", "etc/inittab"]


def check(root: str, max_files: int = 200_000) -> dict:
    res: dict = {
        "root": os.path.abspath(root),
        "ok": False,
        "issues": [],      # 会导致结论不可信的问题
        "warnings": [],    # 值得注意但不致命
        "stats": {},
    }

    if not os.path.isdir(root):
        res["issues"].append("路径不是目录，或不存在")
        return res

    top = set(os.listdir(root))
    missing = [d for d in REQUIRED_DIRS if d not in top]
    if len(missing) >= 3:
        res["issues"].append(
            f"缺少关键目录 {missing}——大概率没解包完，或解到了上层目录"
        )
    elif missing:
        res["warnings"].append(f"缺少目录 {missing}（精简 rootfs 可能正常）")

    files = 0
    elfs = 0
    archs: Counter[str] = Counter()
    stripped = 0
    strong_archives: list[str] = []
    weak_archives: list[str] = []
    has_init = False
    total_size = 0
    zero_exec = 0

    from .elf import ELFError, read_elf

    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            files += 1
            if files > max_files:
                res["warnings"].append(f"文件数超过 {max_files}，已截断统计")
                break
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if any(rel.startswith(p) or p in rel for p in INIT_PATHS):
                has_init = True
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            total_size += size
            low = rel.lower()
            if size == 0 and low.startswith(("bin/", "sbin/", "usr/bin/", "usr/sbin/")):
                zero_exec += 1
            if low.endswith(STRONG_EXT):
                strong_archives.append(rel)
            elif low.endswith(WEAK_EXT) and size > 1024 * 1024 \
                    and not any(s in low for s in SKIP_DIRS):
                weak_archives.append(rel)
            if size < 64 or size > 40 * 1024 * 1024:
                continue
            try:
                with open(full, "rb") as fh:
                    if fh.read(4) != b"\x7fELF":
                        continue
                    fh.seek(0)
                    info = read_elf(fh.read())
            except (OSError, ELFError):
                continue
            elfs += 1
            archs[info.arch] += 1
            if not info.has_sections:
                stripped += 1

    res["stats"] = {
        "files": files,
        "elfs": elfs,
        "archs": dict(archs.most_common()),
        "stripped": stripped,
        "size_mb": round(total_size / 1048576, 1),
        "archives": len(strong_archives) + len(weak_archives),
    }

    if elfs == 0:
        res["issues"].append("一个 ELF 都没有——这不是可执行的 rootfs，检查解包层级")
    elif elfs < 5:
        res["warnings"].append(f"只有 {elfs} 个 ELF，样本过小，结论参考价值有限")

    if len(archs) > 1:
        res["warnings"].append(
            f"架构混杂 {dict(archs)}——可能是多平台固件，也可能解包混入了别的镜像"
        )

    if strong_archives:
        sample = ", ".join(strong_archives[:5])
        res["warnings"].append(
            f"发现 {len(strong_archives)} 个文件系统镜像/压缩包（如 {sample}）——"
            f"典型的多层嵌套固件，需要再解一层"
        )
    if weak_archives:
        sample = ", ".join(weak_archives[:3])
        res["warnings"].append(
            f"发现 {len(weak_archives)} 个大于 1MB 的归档（如 {sample}），确认是否需要解包"
        )

    if not has_init:
        res["warnings"].append(
            "没找到 init 脚本（etc/init.d 等）——无法判断哪些服务会真正启动，"
            "排序结果只能反映静态特征"
        )

    if elfs and stripped == elfs:
        res["warnings"].append("所有 ELF 都被 strip 了——后续反编译只能靠启发式恢复函数名")

    # bin 下的 0 字节文件：几乎一定是符号链接在解包时丢了。
    # 固件里 /bin/sh、/bin/echo 这类通常是 busybox 的软链接，丢了之后
    # 二进制里的 system() 一调用就 ENOEXEC —— 动态验证会全盘失败，
    # 而且症状极像「服务没跑起来」，很难往解包上想。
    if zero_exec >= 5:
        res["issues"].append(
            f"{zero_exec} 个 bin/sbin 下的文件是 0 字节——符号链接大概率在解包时丢了"
            "（在 Windows 上解 squashfs 的典型症状）。这些通常是 busybox 的软链接，"
            "丢了会让 system() 全部 ENOEXEC。请在 Linux 上用 unsquashfs 重新解包。")

    res["ok"] = not res["issues"]
    return res


def format_report(res: dict) -> str:
    s = res["stats"]
    lines = [f"rootfs: {res['root']}"]
    if s:
        lines.append(
            f"文件 {s['files']} · ELF {s['elfs']} · 总大小 {s['size_mb']} MB · "
            f"stripped {s['stripped']}"
        )
        if s["archs"]:
            arch_txt = ", ".join(f"{k}×{v}" for k, v in s["archs"].items())
            lines.append(f"架构: {arch_txt}")
    lines.append("")
    if res["issues"]:
        lines.append("✗ 阻断性问题")
        lines += [f"  - {i}" for i in res["issues"]]
    if res["warnings"]:
        lines.append("! 警告")
        lines += [f"  - {w}" for w in res["warnings"]]
    if res["ok"] and not res["warnings"]:
        lines.append("✓ 结构正常，可以扫描")
    elif res["ok"]:
        lines.append("✓ 可以扫描，但注意上面的警告")
    return "\n".join(lines)
