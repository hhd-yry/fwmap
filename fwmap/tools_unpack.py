"""把解包/解密类工具注册到总线。

规矩：每个工具都要有**自己的成功判据**。
解包类好办（解出来的目录像不像 rootfs），但像 gzip/tar/cpio 这种
"解开就是一堆文件"的，判据要放宽 —— 不能拿 rootfs 的标准去卡它。
"""

from __future__ import annotations

import os

from . import toolbus
from .toolbus import Tool

__all__ = ["register_all"]


def _rootfs_verdict(path: str) -> dict:
    from .unpack import looks_like_rootfs

    v = looks_like_rootfs(path)
    return {"ok": v["ok"],
            "detail": f"{'/'.join(v.get('dirs') or [])} · 疑似可执行 {v.get('elf_hint', 0)}"}


def _files_verdict(path: str, at_least: int = 1) -> dict:
    """只要解出文件就算成功（gzip/tar/cpio 这类没有 rootfs 结构）。"""
    n = 0
    for base, _dirs, files in os.walk(path):
        n += len(files)
        if n >= at_least:
            break
    return {"ok": n >= at_least, "detail": f"解出 {n} 个文件"}


def _repaired_rootfs(path: str) -> dict:
    """7z 的老毛病（符号链接变文本、执行位丢失）在这里自动修。"""
    from .unpack import fix_exec_bits, repair_symlinks

    sym = repair_symlinks(path)
    ex = fix_exec_bits(path)
    v = _rootfs_verdict(path)
    if sym["fixed"] or ex:
        v["detail"] = (v.get("detail", "") +
                       f" · 修复符号链接 {sym['fixed']} / 执行位 {ex}")
    return v


def register_all() -> int:
    """注册全部工具（幂等：已经注册过就跳过）。返回新注册的数量。"""
    have = {t.name for t in toolbus.all_tools()}
    n = 0

    def add(tool: Tool) -> None:
        nonlocal n
        if tool.name in have:
            return
        toolbus.register(tool)
        n += 1

    add(Tool("unblob", "unpack", ["unblob", "-e", "{out}", "{src}"],
             _rootfs_verdict,
             accepts=".bin/.img/任意固件",
             note="现代解包器，自带几十种格式（比 binwalk 更主动）",
             failure_hint="格式不在 unblob 的支持列表里",
             version_cmd=["unblob", "--version"]))

    add(Tool("binwalk", "unpack",
             ["binwalk", "-e", "-M", "--directory", "{out}", "{src}"],
             _rootfs_verdict,
             accepts="任意",
             note="签名扫描 + 递归提取，最通用也最慢",
             failure_hint="它只负责找签名，遇到私有容器就没辙",
             version_cmd=["binwalk", "--help"]))

    add(Tool("7z", "unpack", ["7z", "x", "-y", "-o{out}", "{src}"],
             _repaired_rootfs,
             accepts="squashfs 3/4、cramfs、cpio",
             note="唯一能读 squashfs 3.x 的常用工具（会丢符号链接和执行位）",
             failure_hint="遇到私有容器会解出一堆垃圾",
             version_cmd=["7z"]))

    add(Tool("unsquashfs", "unpack", ["unsquashfs", "-f", "-d", "{out}", "{src}"],
             _rootfs_verdict,
             accepts="squashfs 4.x",
             note="标准 squashfs 工具；3.x 会直接拒绝",
             failure_hint="版本不对（3.x 需要 sasquatch 或 7z）",
             version_cmd=["unsquashfs", "-version"]))

    add(Tool("sasquatch", "unpack", ["sasquatch", "-f", "-d", "{out}", "{src}"],
             _repaired_rootfs,
             accepts="squashfs 1.x-4.x",
             note="补丁版 unsquashfs，专门读老版本 squashfs（3.x）",
             failure_hint="没装（要自己编译）",
             version_cmd=["sasquatch", "-version"]))

    add(Tool("cramfsck", "unpack", ["cramfsck", "-x", "{out}", "{src}"],
             _rootfs_verdict,
             accepts="cramfs",
             note="老路由器常见的小文件系统",
             failure_hint="不是 cramfs",
             version_cmd=["cramfsck", "-h"]))

    add(Tool("ubireader", "unpack",
             ["ubireader_extract_images", "-o", "{out}", "{src}"],
             _rootfs_verdict,
             accepts="UBI/UBIFS",
             note="NAND 固件常见",
             failure_hint="不是 UBI，或需要 ubireader_extract_files 再解一层",
             version_cmd=["ubireader_extract_images", "--version"]))

    add(Tool("jefferson", "unpack", ["jefferson", "-d", "{out}", "{src}"],
             _rootfs_verdict,
             accepts="JFFS2",
             note="JFFS2 解包（需要 pip install jefferson）",
             failure_hint="不是 JFFS2",
             version_cmd=["jefferson", "--help"]))

    add(Tool("gzip", "unpack", ["sh", "-c",
                                "mkdir -p {out} && gzip -dc {src} > {out}/payload.bin"],
             lambda d: _files_verdict(d, 1),
             accepts="gzip",
             note="单层 gzip（内核/initramfs 常见）",
             failure_hint="不是 gzip 流"))

    add(Tool("cpio", "unpack", ["sh", "-c",
                                "mkdir -p {out} && cd {out} && cpio -idm < {src}"],
             _rootfs_verdict,
             accepts="cpio（initramfs）",
             note="initramfs 常见格式",
             failure_hint="不是 cpio 归档"))
    return n
