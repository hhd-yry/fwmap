"""decrypt / unwrap 类工具：把"看不懂的容器"剥成"看得懂的载荷"。

这一批和解包不同：解包是"把文件系统摊开"，这里是"先把外面那层壳去掉"。
壳有好几种性质，处理方式完全不同：

    纯偏移（uImage / TRX / .chk）   → 切掉头，载荷原样留着
    压缩流（gzip / xz / bzip2 / LZMA）→ 解压
    私有加密（cr6b / Zyxel / TP-Link）→ **公开算法各写各的**，只能靠外部脚本

前两类我们能自己实现，而且**验收特别干脆**：去掉壳之后，
里面必须能看到文件系统魔数（`hsqs`/`sqsh`/`shsq`/`CRAM`/`UBI#`），
看不到就是没成功 —— 没有"大概成功"这种说法。

第三类不硬编：留一个 **外部工具挂载点**（JSON 描述），
用户把厂商脚本放进来就能用，验收标准一样。
"""

from __future__ import annotations

import bz2
import gzip
import json
import lzma
import os
import struct
import zlib

from . import toolbus
from .toolbus import Tool

__all__ = ["register_all", "load_external", "MAGIC", "has_magic"]

# 去掉壳之后"应该看到什么"
MAGIC = {
    b"hsqs": "squashfs-le",
    b"sqsh": "squashfs-be",
    b"shsq": "squashfs-3",
    b"CRAM": "cramfs",
    b"UBI#": "ubi",
    b"\x1f\x8b\x08": "gzip",
    b"\xfd7zXZ": "xz",
    b"BZh": "bzip2",
}


def has_magic(path: str, limit: int = 4 * 1024 * 1024) -> tuple[bool, str]:
    """输出里有没有已知的文件系统/压缩魔数。这就是 decrypt 的验收标准。"""
    try:
        with open(path, "rb") as fh:
            blob = fh.read(limit)
    except OSError:
        return False, "读不出输出"
    for magic, name in MAGIC.items():
        if blob.find(magic) >= 0:
            return True, f"看到 {name}"
    return False, "没看到任何已知的文件系统魔数"


def _verdict_magic(outdir: str) -> dict:
    """验收：目录里任意一个文件带魔数就算成功。"""
    for base, _dirs, files in os.walk(outdir):
        for name in files:
            p = os.path.join(base, name)
            if os.path.getsize(p) < 1024:
                continue
            ok, why = has_magic(p)
            if ok:
                return {"ok": True, "detail": f"{name}: {why}"}
    return {"ok": False, "detail": "解出来的东西里没有文件系统魔数"}


# ---------------------------------------------------------------- 纯偏移类

def strip_uimage(src: str, outdir: str) -> None:
    """uImage：64 字节头 + 载荷（内核 + 可能跟一个 rootfs）。"""
    with open(src, "rb") as fh:
        head = fh.read(64)
        if head[:4] != b"\x27\x05\x19\x56":
            raise ValueError("不是 uImage")
        fh.seek(64)
        payload = fh.read()
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "payload.bin"), "wb") as fh:
        fh.write(payload)


def strip_trx(src: str, outdir: str) -> None:
    """Broadcom TRX：28 字节头（"HDR0"），载荷跟着。"""
    with open(src, "rb") as fh:
        head = fh.read(28)
        if head[:4] != b"HDR0":
            raise ValueError("不是 TRX")
        fh.seek(28)
        payload = fh.read()
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "payload.bin"), "wb") as fh:
        fh.write(payload)


def strip_netgear_chk(src: str, outdir: str) -> None:
    """Netgear .chk：头部（含校验和）后面才是真载荷。

    头部长度不固定，所以不按固定值切：扫前 1 MB 找文件系统魔数，
    从命中处切 —— 比猜头长度可靠。
    """
    with open(src, "rb") as fh:
        head = fh.read(1024 * 1024)
        if not head[:4] == b"\x2a\x23\x24\x5e" and b"chk " not in head[:8]:
            raise ValueError("不像 .chk")
        best = -1
        for magic in (b"hsqs", b"sqsh", b"shsq", b"CRAM", b"UBI#"):
            idx = head.find(magic)
            if idx > 0 and (best < 0 or idx < best):
                best = idx
        if best < 0:
            raise ValueError("没在头部之后找到文件系统")
        fh.seek(best)
        payload = fh.read()
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "payload.bin"), "wb") as fh:
        fh.write(payload)


# ---------------------------------------------------------------- 压缩流类

def _decompress_with(fn, src: str, outdir: str, name: str) -> None:
    with open(src, "rb") as fh:
        data = fh.read()
    out = fn(data)
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, name), "wb") as fh:
        fh.write(out)


def gunzip(src: str, outdir: str) -> None:
    _decompress_with(gzip.decompress, src, outdir, "payload.bin")


def bunzip2(src: str, outdir: str) -> None:
    _decompress_with(bz2.decompress, src, outdir, "payload.bin")


def unxz(src: str, outdir: str) -> None:
    _decompress_with(lzma.decompress, src, outdir, "payload.bin")


def unlzma(src: str, outdir: str) -> None:
    """裸 LZMA（uImage 的 kernel 常是这种，没有 xz 容器头）。"""
    with open(src, "rb") as fh:
        data = fh.read()
    for fmt in (lzma.FORMAT_ALONE, lzma.FORMAT_RAW):
        try:
            if fmt == lzma.FORMAT_RAW:
                out = lzma.decompress(data, format=fmt,
                                      filters=[{"id": lzma.FILTER_LZMA1,
                                                "dict_size": 8 * 1024 * 1024}])
            else:
                out = lzma.decompress(data, format=fmt)
        except Exception:                                  # noqa: BLE001
            continue
        os.makedirs(outdir, exist_ok=True)
        with open(os.path.join(outdir, "payload.bin"), "wb") as fh:
            fh.write(out)
        return
    raise ValueError("不像裸 LZMA 流")


def unzlib(src: str, outdir: str) -> None:
    _decompress_with(zlib.decompress, src, outdir, "payload.bin")


# ---------------------------------------------------------------- 外部脚本挂载点

def load_external(spec: str | dict | list) -> int:
    """挂载用户提供的厂商解密脚本。

    `spec` 可以是 JSON 文件路径、JSON 字符串，或者已经解析好的 list。
    每条形如：

        {"name": "dlink-cr6b",
         "cmd": ["python3", "/opt/cr6b.py", "{src}", "{out}"],
         "capability": "decrypt",
         "success": "magic",            # magic | rootfs
         "note": "D-Link 私有容器"}

    为什么用挂载而不是硬编：厂商算法各写各的、质量参差、还有版权问题。
    总线只负责**调它、验它**；验不过就是没成，绝不让它污染结论。
    """
    if isinstance(spec, str):
        if os.path.isfile(spec):
            with open(spec, encoding="utf-8") as fh:
                items = json.load(fh)
        else:
            items = json.loads(spec)
    else:
        items = spec

    n = 0
    for item in items if isinstance(items, list) else [items]:
        name = str(item.get("name") or "").strip()
        cmd = item.get("cmd") or []
        if not name or not cmd:
            continue
        kind = str(item.get("success") or "magic")
        if kind == "rootfs":
            from .unpack import looks_like_rootfs

            def validator(d, _v=looks_like_rootfs):
                v = _v(d)
                return {"ok": v["ok"], "detail": "/".join(v.get("dirs") or [])}
        else:
            validator = _verdict_magic
        try:
            toolbus.register(Tool(
                name, item.get("capability") or "decrypt", list(cmd), validator,
                accepts=item.get("accepts") or "",
                note=item.get("note") or "外部脚本",
                failure_hint=item.get("failure_hint") or "脚本没能解出可识别的东西"))
            n += 1
        except ValueError:
            continue                                   # 重名/非法就跳过
    return n


def register_all() -> int:
    """注册内置 unwrap 工具（幂等）。"""
    have = {t.name for t in toolbus.all_tools()}
    n = 0

    def add(tool: Tool) -> None:
        nonlocal n
        if tool.name in have:
            return
        toolbus.register(tool)
        n += 1

    add(Tool("uimage", "decrypt", None, _verdict_magic, python=strip_uimage,
             accepts="uImage（0x27051956）",
             note="切掉 64 字节 uImage 头，露出内核+rootfs"))
    add(Tool("trx", "decrypt", None, _verdict_magic, python=strip_trx,
             accepts="TRX（HDR0）",
             note="Broadcom TRX 容器，切 28 字节头"))
    add(Tool("netgear-chk", "decrypt", None, _verdict_magic, python=strip_netgear_chk,
             accepts="Netgear .chk",
             note="扫出头之后第一个文件系统位置再切"))
    add(Tool("gzip-stream", "decrypt", None, _verdict_magic, python=gunzip,
             accepts="gzip 流", note="单层 gzip"))
    add(Tool("xz-stream", "decrypt", None, _verdict_magic, python=unxz,
             accepts="xz 流", note="单层 xz"))
    add(Tool("bzip2-stream", "decrypt", None, _verdict_magic, python=bunzip2,
             accepts="bzip2 流", note="单层 bzip2"))
    add(Tool("lzma-stream", "decrypt", None, _verdict_magic, python=unlzma,
             accepts="裸 LZMA 流", note="uImage 内核常见的压缩方式"))
    add(Tool("zlib-stream", "decrypt", None, _verdict_magic, python=unzlib,
             accepts="zlib 流", note="很多私有壳内部就是 zlib"))
    return n
