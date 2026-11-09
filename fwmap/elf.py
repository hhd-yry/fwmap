"""
零依赖 ELF 解析器 —— 只做固件初筛需要的那部分。

设计取舍：
  - 不解析重定位、不解析 program header 的加载语义（初筛用不到）
  - 必须支持 32/64 位 + 大小端（固件里 MIPS/ARM 大小端都有）
  - section header 缺失时退化为全文件字符串扫描（stripped 固件常见）

对外只暴露 read_elf() 和 ELFInfo。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

MACHINES = {
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    40: "ARM",
    42: "SuperH",
    50: "IA-64",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
}

ETYPES = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}

SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_DYNAMIC = 6
SHT_DYNSYM = 11
SHT_NOBITS = 8

DT_NEEDED = 1

PRINTABLE = set(range(0x20, 0x7F)) | {0x09}


class ELFError(Exception):
    pass


@dataclass
class Section:
    name: str
    type: int
    offset: int
    size: int


@dataclass
class ELFInfo:
    bits: int = 0
    endian: str = "<"
    machine_id: int = 0
    etype: int = 0
    entry: int = 0
    sections: list[Section] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    needed: list[str] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    has_sections: bool = True

    @property
    def arch(self) -> str:
        return MACHINES.get(self.machine_id, f"machine-{self.machine_id}")

    @property
    def kind(self) -> str:
        return ETYPES.get(self.etype, str(self.etype))


def extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    """从字节流里抽取可打印字符串，按出现顺序去重。"""
    out: list[str] = []
    seen: set[str] = set()
    buf = bytearray()
    for b in data:
        if b in PRINTABLE:
            buf.append(b)
        else:
            if len(buf) >= min_len:
                s = buf.decode("ascii", "replace")
                if s not in seen:
                    seen.add(s)
                    out.append(s)
            buf.clear()
    if len(buf) >= min_len:
        s = buf.decode("ascii", "replace")
        if s not in seen:
            out.append(s)
    return out


def _cstr(blob: bytes, off: int) -> str:
    if off < 0 or off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    if end < 0:
        end = len(blob)
    return blob[off:end].decode("ascii", "replace")


PT_LOAD = 1
PT_DYNAMIC = 2
DT_NEEDED = 1
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_SYMENT = 11


def _read_from_dynamic(data: bytes, info: "ELFInfo", bits: int, endian: str,
                       phoff: int, phentsize: int, phnum: int) -> None:
    """没有节头时，从 PT_DYNAMIC 里取导入符号和 DT_NEEDED。

    sstrip 会把节头表整个删掉（OpenWrt、很多厂商固件都这么干），但动态段还在。
    只读节头的实现在这类文件上会得到"零导入"，比解析错误更危险——报告看起来很干净。
    """
    loads: list[tuple[int, int, int]] = []
    dyn = None
    for i in range(phnum):
        base = phoff + i * phentsize
        try:
            if bits == 64:
                p_type, _flags, p_off, p_vaddr, _pa, p_filesz, _msz, _al = struct.unpack_from(
                    endian + "IIQQQQQQ", data, base)
            else:
                p_type, p_off, p_vaddr, _pa, p_filesz, _msz, _flags, _al = struct.unpack_from(
                    endian + "IIIIIIII", data, base)
        except struct.error:
            break
        if p_type == PT_LOAD:
            loads.append((p_vaddr, p_off, p_filesz))
        elif p_type == PT_DYNAMIC:
            dyn = (p_off, p_filesz)
    if dyn is None or not loads:
        return

    def v2o(vaddr: int):
        for v, off, size in loads:
            if v <= vaddr < v + size:
                return off + (vaddr - v)
        return None

    entsize = 16 if bits == 64 else 8
    tags: dict[int, list[int]] = {}
    for i in range(dyn[1] // entsize):
        off = dyn[0] + i * entsize
        try:
            if bits == 64:
                tag, val = struct.unpack_from(endian + "qQ", data, off)
            else:
                tag, val = struct.unpack_from(endian + "iI", data, off)
        except struct.error:
            break
        if tag == 0:
            break
        tags.setdefault(tag, []).append(val)

    def u32(off: int) -> int:
        try:
            return struct.unpack_from(endian + "I", data, off)[0]
        except struct.error:
            return 0

    # 依赖的 .so
    if DT_STRTAB in tags and DT_NEEDED in tags:
        str_off = v2o(tags[DT_STRTAB][0])
        if str_off is not None:
            for val in tags[DT_NEEDED]:
                nm = _cstr(data[str_off:], val)
                if nm and nm not in info.needed:
                    info.needed.append(nm)

    if DT_SYMTAB not in tags or DT_STRTAB not in tags:
        return
    sym_off = v2o(tags[DT_SYMTAB][0])
    str_off = v2o(tags[DT_STRTAB][0])
    if sym_off is None or str_off is None:
        return

    strsz = tags.get(DT_STRSZ, [0])[0]
    dynstr = data[str_off:str_off + strsz] if strsz else data[str_off:]

    # 符号个数：优先 DT_HASH 的 nchain；没有就用 (strtab - symtab) / syment 估。
    count = 0
    if DT_HASH in tags:
        hash_off = v2o(tags[DT_HASH][0])
        if hash_off is not None:
            count = u32(hash_off + 4)          # nbucket, nchain
    if not count:
        syment = tags.get(DT_SYMENT, [16 if bits == 32 else 24])[0] or (16 if bits == 32 else 24)
        count = max(0, (str_off - sym_off) // syment)
    if not count or count > 200000:
        return

    syment = 24 if bits == 64 else 16
    for i in range(count):
        base = sym_off + i * syment
        try:
            if bits == 64:
                st_name = struct.unpack_from(endian + "I", data, base)[0]
                st_shndx = struct.unpack_from(endian + "H", data, base + 6)[0]
            else:
                st_name, _st_value, _st_size, _st_info, _st_other, st_shndx = struct.unpack_from(
                    endian + "IIIBBH", data, base)
        except struct.error:
            break
        if st_shndx != 0:          # 只要未定义符号 = 外部依赖
            continue
        nm = _cstr(dynstr, st_name)
        if nm and nm not in info.imports:
            info.imports.append(nm)


def read_elf(data: bytes) -> ELFInfo:
    """解析 ELF。失败抛 ELFError。"""
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise ELFError("not an ELF file")

    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2):
        raise ELFError(f"bad EI_CLASS {ei_class}")
    if ei_data not in (1, 2):
        raise ELFError(f"bad EI_DATA {ei_data}")

    bits = 32 if ei_class == 1 else 64
    endian = "<" if ei_data == 1 else ">"
    info = ELFInfo(bits=bits, endian=endian)

    try:
        if bits == 64:
            (etype, machine, _ver, entry, phoff, shoff, _flags,
             _ehsize, phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from(
                endian + "HHIQQQIHHHHHH", data, 16)
        else:
            (etype, machine, _ver, entry, phoff, shoff, _flags,
             _ehsize, phentsize, phnum, shentsize, shnum, shstrndx) = struct.unpack_from(
                endian + "HHIIIIIHHHHHH", data, 16)
    except struct.error as e:
        raise ELFError(f"truncated header: {e}") from e

    info.machine_id = machine
    info.etype = etype
    info.entry = entry

    if shoff == 0 or shnum == 0:
        info.has_sections = False
        info.strings = extract_strings(data)
        # 被 sstrip 处理过的二进制（OpenWrt 和大多数厂商固件都是）没有节头表，
        # 但 PT_DYNAMIC 还在。不从这里补，导入就是空的，net/danger/nvram 三类
        # 信号会集体消失——这不是"信号少"，是"看错了世界"。
        _read_from_dynamic(data, info, bits, endian, phoff, phentsize, phnum)
        return info

    # 先读 section header 表
    raw_sections = []
    for i in range(shnum):
        base = shoff + i * shentsize
        try:
            if bits == 64:
                sh_name, sh_type, _flags, _addr, sh_off, sh_size, sh_link, _info2, _align, sh_entsize = struct.unpack_from(
                    endian + "IIQQQQIIQQ", data, base)
            else:
                sh_name, sh_type, _flags, _addr, sh_off, sh_size, sh_link, _info2, _align, sh_entsize = struct.unpack_from(
                    endian + "IIIIIIIIII", data, base)
        except struct.error:
            break
        raw_sections.append((sh_name, sh_type, sh_off, sh_size, sh_link, sh_entsize))

    # section 名字表
    shstr = b""
    if 0 <= shstrndx < len(raw_sections):
        _, _, off, size, _, _ = raw_sections[shstrndx]
        shstr = data[off:off + size]

    sections: list[Section] = []
    by_type: dict[int, list[Section]] = {}
    for sh_name, sh_type, sh_off, sh_size, _link, _ent in raw_sections:
        name = _cstr(shstr, sh_name) if shstr else ""
        sec = Section(name=name, type=sh_type, offset=sh_off, size=sh_size)
        sections.append(sec)
        by_type.setdefault(sh_type, []).append(sec)
    info.sections = sections

    # 动态符号表 -> 导入函数名
    dynsym = by_type.get(SHT_DYNSYM) or by_type.get(SHT_SYMTAB)
    strtab = by_type.get(SHT_STRTAB)
    if dynsym and strtab:
        dynstr = strtab[0]
        blob = data[dynstr.offset:dynstr.offset + dynstr.size]
        sym = dynsym[0]
        entsize = 24 if bits == 64 else 16
        count = sym.size // entsize
        seen = set()
        for i in range(count):
            base = sym.offset + i * entsize
            try:
                if bits == 64:
                    st_name, _st_info, _st_other, st_shndx = struct.unpack_from(
                        endian + "IBBH", data, base)
                else:
                    st_name, _st_value, _st_size, _st_info, _st_other, st_shndx = struct.unpack_from(
                        endian + "IIIBBH", data, base)
            except struct.error:
                break
            if st_shndx != 0:      # 只关心未定义符号 = 外部依赖
                continue
            nm = _cstr(blob, st_name)
            if nm and nm not in seen:
                seen.add(nm)
                info.imports.append(nm)

    # .dynamic -> DT_NEEDED（依赖哪些 .so）
    dyn = by_type.get(SHT_DYNAMIC)
    if dyn and strtab:
        blob = data[strtab[0].offset:strtab[0].offset + strtab[0].size]
        d = dyn[0]
        entsize = 16 if bits == 64 else 8
        count = d.size // entsize
        for i in range(count):
            base = d.offset + i * entsize
            try:
                if bits == 64:
                    tag, val = struct.unpack_from(endian + "qQ", data, base)
                else:
                    tag, val = struct.unpack_from(endian + "iI", data, base)
            except struct.error:
                break
            if tag == 0:
                break
            if tag == DT_NEEDED:
                nm = _cstr(blob, val)
                if nm:
                    info.needed.append(nm)

    # 字符串：优先 .rodata / .data / .comment
    chunks = []
    for want in (".rodata", ".data", ".comment", ".dynstr"):
        for sec in sections:
            if sec.name == want and sec.type != SHT_NOBITS:
                chunks.append(data[sec.offset:sec.offset + sec.size])
                break
    if not chunks:
        info.strings = extract_strings(data)
    else:
        merged = b"\x00".join(chunks)
        info.strings = extract_strings(merged)

    # 节头在、但 .dynsym 被剥掉了（部分厂商固件只保留节名做样子）——同样走动态段
    if not info.imports:
        _read_from_dynamic(data, info, bits, endian, phoff, phentsize, phnum)

    return info
