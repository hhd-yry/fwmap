"""analyze 类工具：给 Ghidra 之外再开一扇窗。

为什么需要第二个视角：Ghidra 很强但很慢（一次 M2 几分钟），而且它对
"没见过的 SDK" 常常抽不出 handler（Edimax 45 个端点 → 0 个 handler）。
这时候我们需要的不是"再等十分钟"，而是**几秒钟能拿到的另一种事实**：

    readelf / rabin2   —— 这个 ELF 到底是什么（架构、入口、符号、节）
    rizin              —— 函数列表、交叉引用（比 Ghidra 快一个数量级）
    lief（Python）     —— 用代码直接解析，能给后续步骤喂结构化数据

验收判据和别处一样硬：**必须真的解析出东西**（比如拿到"Machine: MIPS"
或者"函数 ≥ N 个"），而不是"命令跑完了"。
"""

from __future__ import annotations

import json
import os
import re

from . import toolbus
from .toolbus import Tool

__all__ = ["register_all", "parse_readelf", "parse_rizin_funcs"]


# ---------------------------------------------------------------- 解析器

def parse_readelf(text: str) -> dict:
    """从 readelf 输出里抽几个关键事实。抽不到就返回空 dict。"""
    info = {}
    m = re.search(r"Machine:\s*(.+)", text)
    if m:
        info["machine"] = m.group(1).strip()[:40]
    m = re.search(r"Class:\s*(\S+)", text)
    if m:
        info["class"] = m.group(1)
    m = re.search(r"Entry point address:\s*(0x[0-9a-fA-F]+)", text)
    if m:
        info["entry"] = m.group(1)
    m = re.search(r"Type:\s*(\S+)", text)
    if m:
        info["type"] = m.group(1)
    return info


def parse_rizin_funcs(text: str) -> list[str]:
    """rizin `afl` 的输出：每行以 0x 地址开头。"""
    out = []
    for line in text.splitlines():
        m = re.match(r"\s*0x[0-9a-fA-F]+\s+\d+\s+\d+\s+(\S+)", line)
        if m:
            out.append(m.group(1))
    return out


def parse_rabin2_json(text: str) -> dict:
    """rabin2 -Ij 输出 JSON；解析失败返回空。"""
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return {}
    try:
        return json.loads(m.group(0)) or {}
    except ValueError:
        return {}


# ---------------------------------------------------------------- 验收

def v_readelf(text: str) -> dict:
    info = parse_readelf(text or "")
    if not info.get("machine"):
        return {"ok": False, "detail": "没解析出 Machine 字段（不是 ELF？）"}
    return {"ok": True, "detail": f"{info.get('class', '?')} · {info['machine']}"
                                  f" · entry {info.get('entry', '?')}"}


def v_rabin2(text: str) -> dict:
    j = parse_rabin2_json(text or "")
    if not j.get("arch") and not j.get("bintype"):
        return {"ok": False, "detail": "rabin2 没给出可解析的 JSON"}
    return {"ok": True, "detail": f"{j.get('bintype', '?')} · {j.get('arch', '?')}"
                                  f" · bits {j.get('bits', '?')}"}


def v_rizin(min_funcs: int = 5):
    def _v(text: str) -> dict:
        funcs = parse_rizin_funcs(text or "")
        if len(funcs) < min_funcs:
            return {"ok": False,
                    "detail": f"只认出 {len(funcs)} 个函数（少于 {min_funcs}）"}
        return {"ok": True, "detail": f"认出 {len(funcs)} 个函数，如 {funcs[:3]}"}
    return _v


def _lief_parse(src: str):
    """兼容不同版本的 LIEF：老版本是 lief.parse，新版本挪到了类方法上。"""
    import lief

    fn = getattr(lief, "parse", None)
    if callable(fn):
        return fn(src)
    for name in ("Binary", "Parser"):
        cls = getattr(lief, name, None)
        if cls is not None and callable(getattr(cls, "parse", None)):
            return cls.parse(src)
    raise RuntimeError(f"lief {getattr(lief, '__version__', '?')} 没有可用的 parse 接口")


def _lief_run(src: str, outdir: str) -> None:
    """用 lief 解析 ELF，把结果写成 JSON（后续步骤能直接吃）。"""
    binary = _lief_parse(src)
    if binary is None:
        raise ValueError("lief 解析不了这个文件")
    info = {
        "format": str(getattr(binary, "format", "unknown")),
        "entry": hex(getattr(binary, "entrypoint", 0) or 0),
        "arch": str(getattr(binary.header, "machine_type", "")),
        "sections": len(getattr(binary, "sections", []) or []),
        "symbols": len(getattr(binary, "symbols", []) or []),
    }
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "lief.json"), "w", encoding="utf-8") as fh:
        json.dump(info, fh, ensure_ascii=False, indent=1)


def v_lief(outdir: str) -> dict:
    p = os.path.join(outdir, "lief.json")
    try:
        with open(p, encoding="utf-8") as fh:
            info = json.load(fh)
    except (OSError, ValueError):
        return {"ok": False, "detail": "没有 lief.json"}
    if not info.get("entry") or info["entry"] == "0x0":
        return {"ok": False, "detail": f"没拿到入口点：{info}"}
    return {"ok": True, "detail": f"{info.get('format')} · {info.get('arch')}"
                                  f" · entry {info['entry']} · 节 {info.get('sections')}"}


# ---------------------------------------------------------------- 注册

def register_all() -> int:
    have = {t.name for t in toolbus.all_tools()}
    n = 0

    def add(tool: Tool) -> None:
        nonlocal n
        if tool.name in have:
            return
        toolbus.register(tool)
        n += 1

    add(Tool("readelf", "analyze",
             ["readelf", "-h", "-l", "-S", "{src}"], None,
             stdout_success=v_readelf,
             accepts="ELF",
             note="binutils 自带，最快拿到架构/入口/节表",
             version_cmd=["readelf", "--version"]))

    add(Tool("rabin2", "analyze", ["rabin2", "-Ij", "{src}"], None,
             stdout_success=v_rabin2,
             accepts="ELF/Mach-O/PE",
             note="radare2 家族：一次给出类型/架构/位数/加固项",
             version_cmd=["rabin2", "-v"]))

    add(Tool("rizin", "analyze", ["rizin", "-q", "-c", "afl", "{src}"], None,
             stdout_success=v_rizin(5),
             accepts="ELF",
             note="几秒出函数表，比 Ghidra 快一个数量级（精度不如它）",
             version_cmd=["rizin", "-v"]))

    add(Tool("lief", "analyze", None, v_lief, python=_lief_run,
             accepts="ELF/PE/Mach-O",
             note="Python 库，直接把结构喂给后续步骤",
             failure_hint="需要 pip install lief"))
    return n
