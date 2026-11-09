"""
生成一个合成的测试固件 rootfs —— 不需要下载真实固件就能验证工具链路。

为什么要这个：
  真实固件动辄几十上百 MB，且厂商样本有法律顾虑。用一个合成的 rootfs
  可以把"扫描逻辑"和"真实数据"解耦，改代码时能秒级回归。

它同时是一个 ELF 生成器：能造 32/64 位、大小端、带导入符号和 DT_NEEDED 的
合法 ELF，所以也能用来验证 elf.py 的解析正确性。
"""

from __future__ import annotations

import os
import struct
import sys

# ---------------------------------------------------------------- ELF 生成器

SHSTR = b"\x00.dynstr\x00.dynsym\x00.rodata\x00.dynamic\x00.shstrtab\x00"
SH_NAME = {
    ".dynstr": SHSTR.index(b".dynstr"),
    ".dynsym": SHSTR.index(b".dynsym"),
    ".rodata": SHSTR.index(b".rodata"),
    ".dynamic": SHSTR.index(b".dynamic"),
    ".shstrtab": SHSTR.index(b".shstrtab"),
}


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def build_elf(bits: int = 64, endian: str = "<", machine: int = 62, etype: int = 3,
              strings: tuple[str, ...] = (), imports: tuple[str, ...] = (),
              needed: tuple[str, ...] = ()) -> bytes:
    """造一个结构合法的 ELF。section 齐全，可被 readelf 识别。"""
    # --- .dynstr
    dynstr = bytearray(b"\x00")
    offs: dict[str, int] = {}
    for nm in list(imports) + list(needed):
        if nm in offs:
            continue
        offs[nm] = len(dynstr)
        dynstr += nm.encode() + b"\x00"

    # --- .dynsym（首项必须是全零的 null symbol）
    sym_ent = 24 if bits == 64 else 16
    dynsym = bytearray(sym_ent)
    for nm in imports:
        if bits == 64:
            dynsym += struct.pack(endian + "IBBHQQ", offs[nm], 0x12, 0, 0, 0, 0)
        else:
            dynsym += struct.pack(endian + "IIIBBH", offs[nm], 0, 0, 0x12, 0, 0)

    # --- .rodata
    rodata = bytearray()
    for s in strings:
        rodata += s.encode() + b"\x00"

    # --- .dynamic（DT_NEEDED + DT_NULL）
    dyn_ent = 16 if bits == 64 else 8
    fmt = endian + ("qQ" if bits == 64 else "iI")
    dynamic = bytearray()
    for nm in needed:
        dynamic += struct.pack(fmt, 1, offs[nm])
    dynamic += struct.pack(fmt, 0, 0)

    ehsize = 64 if bits == 64 else 52
    shentsize = 64 if bits == 64 else 40
    shnum = 6

    cur = ehsize
    off_dynstr = cur
    cur += len(dynstr)
    off_dynsym = _align(cur, 8)
    cur = off_dynsym + len(dynsym)
    off_rodata = cur
    cur += len(rodata)
    off_dynamic = _align(cur, 8)
    cur = off_dynamic + len(dynamic)
    off_shstr = cur
    cur += len(SHSTR)
    off_shoff = _align(cur, 8)
    total = off_shoff + shnum * shentsize

    buf = bytearray(total)

    # --- ELF header
    ei_class = 1 if bits == 32 else 2
    ei_data = 1 if endian == "<" else 2
    ident = b"\x7fELF" + bytes([ei_class, ei_data, 1, 0]) + b"\x00" * 8
    buf[0:16] = ident
    if bits == 64:
        hdr = struct.pack(endian + "HHIQQQIHHHHHH", etype, machine, 1, 0,
                          0, off_shoff, 0, ehsize, 0, 0, shentsize, shnum, 5)
    else:
        hdr = struct.pack(endian + "HHIIIIIHHHHHH", etype, machine, 1, 0,
                          0, off_shoff, 0, ehsize, 0, 0, shentsize, shnum, 5)
    buf[16:16 + len(hdr)] = hdr

    buf[off_dynstr:off_dynstr + len(dynstr)] = dynstr
    buf[off_dynsym:off_dynsym + len(dynsym)] = dynsym
    buf[off_rodata:off_rodata + len(rodata)] = rodata
    buf[off_dynamic:off_dynamic + len(dynamic)] = dynamic
    buf[off_shstr:off_shstr + len(SHSTR)] = SHSTR

    # --- section headers
    def sh(name_off, sh_type, off, size, link=0, entsize=0):
        if bits == 64:
            return struct.pack(endian + "IIQQQQIIQQ", name_off, sh_type, 0, 0,
                               off, size, link, 0, 8, entsize)
        return struct.pack(endian + "IIIIIIIIII", name_off, sh_type, 0, 0,
                           off, size, link, 0, 4, entsize)

    sections = [
        bytes(shentsize),                                            # NULL
        sh(SH_NAME[".dynstr"], 3, off_dynstr, len(dynstr)),           # STRTAB
        sh(SH_NAME[".dynsym"], 11, off_dynsym, len(dynsym), 1, sym_ent),
        sh(SH_NAME[".rodata"], 1, off_rodata, len(rodata)),           # PROGBITS
        sh(SH_NAME[".dynamic"], 6, off_dynamic, len(dynamic), 1, dyn_ent),
        sh(SH_NAME[".shstrtab"], 3, off_shstr, len(SHSTR)),
    ]
    blob = b"".join(sections)
    buf[off_shoff:off_shoff + len(blob)] = blob
    return bytes(buf)


# ---------------------------------------------------------------- 固件内容

FILES: list[tuple[str, bytes]] = [
    # 高危：典型 CGI 网关，含 HTTP 痕迹、多个端点、危险函数、nvram
    ("bin/httpd", build_elf(
        machine=8, endian=">",           # MIPS 大端，真实路由器最常见
        imports=("system", "popen", "strcpy", "sprintf", "recv", "listen",
                 "accept", "nvram_get", "websGetVar", "strlen"),
        needed=("libc.so.0", "libnvram.so"),
        strings=(
            "HTTP/1.1 200 OK", "HTTP/1.0 400 Bad Request",
            "Content-Type: text/html", "Content-Length: %d",
            "/apply.cgi", "/ntp_sync.cgi", "/wan_status.cgi", "/upgrade.cgi",
            "deviceName", "enable_ap_mode", "enable_sta_mode",
            "/sbin/insmod %s", "date -s %s", "NTPSyncWithHost.cgi",
            "Server: httpd/2.0",
        ),
    )),
    # 高危：UPnP 守护进程，SOAP 痕迹
    ("usr/sbin/upnpd", build_elf(
        machine=8, endian=">",
        imports=("system", "listen", "accept", "recvfrom", "strcpy"),
        needed=("libc.so.0",),
        strings=(
            "soap:", "SOAPAction", "urn:schemas-upnp-org:service:WANIPConnection:1",
            "AddPortMapping", "NewRemoteHost", "/rootDesc.xml",
        ),
    )),
    # 中危：telnet 服务
    ("bin/telnetd", build_elf(
        machine=8, endian=">",
        imports=("system", "listen", "accept", "fork"),
        needed=("libc.so.0",),
        strings=("/bin/sh", "login:", "Password: ", "telnetd: getpeername failed"),
    )),
    # 低危：普通工具
    ("bin/ntp_sync", build_elf(
        machine=8, endian=">",
        imports=("printf", "time", "sleep"),
        needed=("libc.so.0",),
        strings=("syncing time", "ntp server unreachable"),
    )),
    # 库：无危险函数
    ("lib/libc.so.0", build_elf(
        machine=8, endian=">", etype=3,
        imports=(),
        strings=("GNU C Library", "malloc: out of memory", "/etc/localtime"),
    )),
    # busybox：应被降权
    ("bin/busybox", build_elf(
        machine=8, endian=">",
        imports=("system", "strcpy", "sprintf", "printf"),
        needed=("libc.so.0",),
        strings=("BusyBox v1.31.1", "applet not found", "sh: can't access tty"),
    )),
    # 非 ELF，应被跳过
    ("etc/init.d/rcS", b"#!/bin/sh\n/bin/httpd -p 80 &\n/usr/sbin/upnpd &\n"),
    ("etc/passwd", b"root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000::/:/bin/sh\n"),
    ("etc_ro/web/index.html", b"<html><body>Router Admin</body></html>\n"),
    # 伪装成 ELF 但被截断，测试容错
    ("bin/truncated", b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8),
]


def make(root: str) -> str:
    for rel, data in FILES:
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
    return root


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "fixture_rootfs")
    make(target)
    n = sum(len(f) for _, _, f in os.walk(target))
    print(f"[+] 合成 rootfs: {target} ({n} 个文件)")
