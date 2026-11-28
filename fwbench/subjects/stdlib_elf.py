"""纯标准库的 ELF 头解析 —— 第二个被测工具（参考实现）。

存在的理由：证明**通用内核不依赖 fwmap**。
在没有安装 fwmap 的环境里，它照样能跑同一批用例、拿到同一份金标评分。

只读 52/64 字节的头，不解析节表；截断时明确报 `truncated`。
"""

from __future__ import annotations

import struct

from . import SubjectBase

__all__ = ["StdlibELF"]

ETYPES = {1: "rel", 2: "exec", 3: "dyn", 4: "core"}
MACHINES = {3: "x86", 8: "mips", 20: "ppc", 40: "arm", 62: "x86-64", 183: "aarch64"}


class StdlibELF(SubjectBase):
    subject_id = "stdlib"
    version = "1"
    capability = "elf-meta"
    requires = "无（标准库）"

    def inspect_elf(self, data: bytes) -> dict:
        if len(data) < 16:
            return {"ok": False, "error": "truncated", "fields": {}}
        magic = data[:4]
        if magic != b"\x7fELF":
            return {"ok": False, "error": "not_elf", "fields": {}}

        ei_class = data[4]          # 1=32 位, 2=64 位
        ei_data = data[5]           # 1=小端, 2=大端
        if ei_class not in (1, 2) or ei_data not in (1, 2):
            return {"ok": False, "error": "parse_error", "fields": {}}
        need = 52 if ei_class == 1 else 64
        if len(data) < need:
            return {"ok": False, "error": "truncated", "fields": {}}

        end = "<" if ei_data == 1 else ">"
        bits = 32 if ei_class == 1 else 64
        if bits == 32:
            e_type, e_machine = struct.unpack_from(end + "HH", data, 16)
        else:
            e_type, e_machine = struct.unpack_from(end + "HH", data, 16)
        return {"ok": True, "error": None,
                "fields": {"bits": bits,
                           "endian": "little" if ei_data == 1 else "big",
                           "etype": ETYPES.get(e_type, str(e_type)),
                           "machine_id": MACHINES.get(e_machine, str(e_machine))}}
