"""
固件 rootfs 扫描与攻击面打分。

这一层的职责：把一个解包后的 rootfs 目录，变成一份"哪些二进制值得先看"的排序列表。
不做反编译、不做污点分析——那是下一层的事。

打分逻辑是显式的、可解释的：每个分数都能追到具体信号。
这对工具比"准"更重要——用户必须能推翻工具的判断。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .elf import ELFError, read_elf

# ---------------------------------------------------------------- 信号定义

HTTP_MARKERS = [
    b"HTTP/1.", b"HTTP/1.1", b"Content-Type:", b"Content-Length:",
    b"text/html", b"application/octet-stream", b"multipart/form-data",
]

# 端点路径不止一种形状。最初只认 Broadcom/Boa 的 `xxx.cgi`：
# 拿 Tenda AC15 的真实 httpd 一测，11 条 `/goform/*`、6 条 `/cgi-bin/*` 一条都没命中，
# 报告里最值钱的「暴露了哪些端点」整栏是空的。
# 这是 surface 信号（文件里确实存在这个串），扩召回不引入判断，只解决"有没有端点可看"。
ENDPOINT_RES = (
    # 任意深度、以 .cgi 结尾的路径：/apply.cgi、/cgi-bin/upgrade.cgi
    re.compile(rb"/(?:[A-Za-z0-9_\-]+/)*[A-Za-z0-9_\-]+\.cgi\b"),
    # 目录式端点：/goform/telnet（Realtek/Tenda）、/cgi-bin/upgrade（D-Link/Netgear）
    re.compile(rb"/(?:goform|cgi-bin)/(?:[A-Za-z0-9_\-]+/)*[A-Za-z0-9_\-]+"),
)
SOAP_HINT = [b"soap:", b"SOAPAction", b"urn:schemas-upnp-org"]

NETWORK_IMPORTS = {
    "listen", "bind", "accept", "recv", "recvfrom", "socket",
    "accept4", "getpeername",
}

DANGEROUS_IMPORTS = {
    "system": "命令执行",
    "popen": "命令执行",
    "execve": "命令执行",
    "doSystemCmd": "命令执行",
    "CsteSystem": "命令执行",
    "twsystem": "命令执行",
    "doSystem": "命令执行",
    "strcpy": "缓冲区溢出",
    "strcat": "缓冲区溢出",
    "sprintf": "缓冲区溢出",
    "vsprintf": "缓冲区溢出",
    "gets": "缓冲区溢出",
    "sscanf": "缓冲区溢出",
}

NVRAM_IMPORTS = {
    "nvram_get", "nvram_set", "nvram_bufget", "nvram_bufset",
    "acosNvramConfig_get", "acosNvramConfig_set", "getNvram",
    "websGetVar", "webGetVar", "get_cgi", "cgiFormString",
}

BUSYBOX_MARKERS = [b"BusyBox v", b"applet not found", b"busybox: applet"]


@dataclass
class Signal:
    """一条证据。

    kind 区分两类东西，这个区分是整个工具可信度的基础：
      surface —— 客观事实（有 HTTP 常量、有 CGI 路径、有 listen 导入）。
                 可以直接进结论，因为它是"文件里确实存在这个字符串"。
      hint    —— 启发式提示（引用了 system、引用了 nvram_get）。
                 只用来排序，不构成结论。"引用了危险函数"不等于"有漏洞"。
    """
    id: str
    label: str
    weight: int
    kind: str = "hint"


@dataclass
class Target:
    rel_path: str
    abs_path: str
    size: int
    arch: str = ""
    kind: str = ""
    role: str = "other"
    score: int = 0
    signals: list[Signal] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    needed: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    dangerous: list[str] = field(default_factory=list)
    sample_strings: list[str] = field(default_factory=list)
    stripped: bool = False
    error: str = ""
    # M2 的结果（可选，跑 --m2 才有）：{"strategy": str, "endpoints": [...]}
    m2: dict | None = None

    def to_dict(self) -> dict:
        return {
            "path": self.rel_path,
            "size": self.size,
            "arch": self.arch,
            "kind": self.kind,
            "role": self.role,
            "score": self.score,
            "signals": [{"id": s.id, "label": s.label, "weight": s.weight, "kind": s.kind}
                        for s in self.signals],
            "imports": self.imports[:80],
            "needed": self.needed,
            "endpoints": self.endpoints,
            "dangerous": self.dangerous,
            "strings": self.sample_strings[:60],
            "stripped": self.stripped,
            "error": self.error,
            "m2": self.m2,
        }


@dataclass
class ScanResult:
    root: str
    started_at: str
    files_seen: int = 0
    elf_count: int = 0
    targets: list[Target] = field(default_factory=list)
    non_elf_samples: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "started_at": self.started_at,
            "files_seen": self.files_seen,
            "elf_count": self.elf_count,
            "non_elf_samples": self.non_elf_samples[:40],
            "targets": [t.to_dict() for t in self.targets],
        }


# ---------------------------------------------------------------- 分析

def _analyze(rel: str, abs_path: str, data: bytes) -> Target | None:
    try:
        info = read_elf(data)
    except ELFError:
        return None

    t = Target(
        rel_path=rel,
        abs_path=abs_path,
        size=len(data),
        arch=info.arch,
        kind=info.kind,
        imports=info.imports,
        needed=info.needed,
        stripped=not info.has_sections,
    )

    strings_blob = b"\x00".join(s.encode("ascii", "replace") for s in info.strings)
    raw_strings = [s.encode() for s in info.strings]

    # 文件名/路径是强证据：.so 就是库，别因为符号少就误判。
    low = rel.lower().replace("\\", "/")
    base = low.rsplit("/", 1)[-1]
    looks_lib = ".so" in base or "/lib/" in low or low.startswith("lib/")

    # --- 信号 1：HTTP 协议痕迹
    http_hits = sum(1 for m in HTTP_MARKERS if m in strings_blob)
    if http_hits:
        w = min(30, 10 * http_hits)
        t.signals.append(Signal("http", f"HTTP 协议痕迹 ×{http_hits}", w, "surface"))

    # --- 信号 2：HTTP 端点（CGI / goform / cgi-bin）与 SOAP
    eps: list[str] = []
    for s in raw_strings:
        for rx in ENDPOINT_RES:
            for m in rx.finditer(s):
                p = m.group(0).decode("ascii", "replace")
                if p not in eps:
                    eps.append(p)
    # 三套正则会重叠：`/cgi-bin/upgrade.cgi` 同时命中 .cgi 和 /cgi-bin/ 两条规则。
    # 只保留更长的那个，别把同一个端点算成两个。
    eps = [e for e in eps if not any(e != o and e in o for o in eps)]
    if eps:
        w = 22 if len(eps) >= 3 else 12
        t.signals.append(Signal("cgi", f"HTTP 端点 ×{len(eps)}", w, "surface"))
    t.endpoints = eps[:60]

    if any(m in strings_blob for m in SOAP_HINT):
        t.signals.append(Signal("soap", "SOAP/UPnP 痕迹", 8, "surface"))

    # --- 信号 3：网络监听
    net = NETWORK_IMPORTS & set(info.imports)
    if net:
        t.signals.append(Signal("net", "网络监听调用", 15, "surface"))

    # --- 信号 4：危险函数
    dang = [i for i in info.imports if i in DANGEROUS_IMPORTS]
    t.dangerous = sorted(set(dang))
    if dang:
        w = min(20, 4 * len(set(dang)))
        t.signals.append(Signal("danger", f"危险函数引用 ×{len(set(dang))}", w, "hint"))

    # --- 信号 5：NVRAM / 输入获取
    nv = NVRAM_IMPORTS & set(info.imports)
    if nv:
        t.signals.append(Signal("nvram", f"配置/输入获取 ×{len(nv)}", 10, "hint"))

    # --- 信号 6：busybox 特征（降低优先级，它是工具箱不是服务）
    # 只用强特征。"busybox" 这个词太常见——apk 的字符串里有 "/bin/busybox"
    # 就被误判过，必须要求带版本号或 applet 报错串。
    if not looks_lib and any(m in strings_blob for m in BUSYBOX_MARKERS):
        t.role = "busybox"
        t.signals.append(Signal("busybox", "busybox 多合一二进制", -25, "hint"))

    # --- 角色判定
    has_http = http_hits >= 2
    has_net = bool(net)
    if t.role != "busybox":
        if looks_lib:
            # 库永远不是服务。它内部可能支持 HTTP（libcrypto 支持 OCSP over HTTP、
            # libapk 支持 HTTP 仓库），但自己不监听端口。这个判断必须无条件优先，
            # 否则 .so 会因为"有 HTTP 字符串"被排到服务前面。
            t.role = "library"
            t.signals.append(Signal("lib", "库文件，不直接对外服务", -35, "hint"))
        elif has_http or (eps and has_net):
            t.role = "http_server"
        elif has_net and dang:
            t.role = "network_service"
        elif eps:
            t.role = "cgi_binary"
        elif dang:
            t.role = "tool"
        elif info.imports:
            t.role = "tool"
        else:
            t.role = "other"

    t.score = max(0, min(100, sum(s.weight for s in t.signals)))

    # 保留有信息量的字符串（端点、路径、参数名），避免报告过大
    keep = [s for s in info.strings if s.startswith("/") or "%s" in s or len(s) > 12]
    t.sample_strings = keep[:60]
    return t


def scan(root: str, max_size: int = 40 * 1024 * 1024) -> ScanResult:
    """扫描 rootfs 目录（或单个文件）。"""
    res = ScanResult(
        root=os.path.abspath(root),
        started_at=datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
    )

    if os.path.isfile(root):
        candidates = [(os.path.basename(root), root)]
    else:
        candidates = []
        for dirpath, _dirnames, filenames in os.walk(root):
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                if os.path.islink(full):
                    continue
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                candidates.append((rel, full))

    for rel, full in candidates:
        res.files_seen += 1
        try:
            if not os.path.isfile(full):
                continue
            size = os.path.getsize(full)
            if size < 64 or size > max_size:
                continue
            with open(full, "rb") as fh:
                head = fh.read(4)
                if head != b"\x7fELF":
                    if len(res.non_elf_samples) < 40:
                        res.non_elf_samples.append(rel)
                    continue
                fh.seek(0)
                data = fh.read()
        except OSError as e:
            continue

        t = _analyze(rel, full, data)
        if t is not None:
            res.elf_count += 1
            res.targets.append(t)

    res.targets.sort(key=lambda x: (-x.score, x.rel_path))
    return res
