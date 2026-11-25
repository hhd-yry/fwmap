"""工具总线：把「开源工具」变成可以放心自动调用的东西。

为什么需要它：工具只会越接越多（解包、解密、文件系统、静态分析、模糊……），
如果每接一个都要写一遍"怎么调、怎么判成功、失败怎么解释"，很快就乱了。

核心规矩只有一条 —— **没有成功判据的工具，不许注册。**

这条是血换来的：`fwupdate.cgi` 那次，工具（不是这里的工具，是固件里的 CGI）说
"我跑完了"，我们没验，差点把"环境崩溃"当成"漏洞"。从此以后：
每个工具必须能手把手回答「我怎么知道它真成了」，
由代码执行这个判据，而不是相信工具的退出码或输出。

模型只负责**排序**（先试哪个），不负责判断成功与否。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time

__all__ = ["Tool", "register", "all_tools", "catalog", "choose", "run", "run_chain",
           "CAPABILITIES"]

# 能力分类：LLM 选工具时按这个挑
CAPABILITIES = {
    "unpack": "把固件镜像解开成文件（解压/切分/递归）",
    "decrypt": "去掉厂商私有加密/校验壳",
    "mount": "把文件系统镜像挂出来或列内容",
    "analyze": "对二进制做静态分析（反汇编、符号、依赖）",
    "emulate": "把固件跑起来（模拟器）",
    "auth": "登录/默认口令（拿到会话才算成功）",
}


class Tool:
    """一个可自动调用的外部工具。

    `success(dir) -> dict` 是**必填**的：返回 {"ok": bool, "detail": str}。
    没有它，注册直接抛错 —— 宁可少一个工具，也不要一个会撒谎的工具。
    """

    def __init__(self, name: str, capability: str, cmd: list[str] | None, success,
                 *, accepts: str = "", failure_hint: str = "",
                 note: str = "", timeout: int = 600, needs: str | None = None,
                 version_cmd: list[str] | None = None, python=None,
                 stdout_success=None):
        if capability not in CAPABILITIES:
            raise ValueError(f"未知能力分类：{capability}")
        if not (callable(success) or callable(stdout_success)):
            raise ValueError(f"{name}: 必须提供 success 判据（不许只靠退出码）")
        self.name = name
        self.capability = capability
        self.cmd = cmd or []
        self.python = python          # 纯 Python 工具：python(src, out) -> dict
        self.success = success
        self.stdout_success = stdout_success   # 分析类工具：产物是 stdout，不是文件
        self.accepts = accepts
        self.failure_hint = failure_hint
        self.note = note
        self.timeout = timeout
        self.needs = needs or (cmd[0] if cmd else "")
        self.version_cmd = version_cmd

    def available(self) -> bool:
        return self.path() is not None

    def path(self) -> str | None:
        if self.python is not None:      # 内置 Python 工具，不依赖外部程序
            return "<python>"
        """找这个工具的可执行文件。

        不只看 PATH：Windows 上 7-Zip 默认装在 `C:\\Program Files\\7-Zip`，
        不进 PATH；Linux 上有些工具在 /usr/local/bin。找不到就返回 None。
        """
        hit = shutil.which(self.needs)
        if hit:
            return hit
        name = self.needs
        candidates = [
            rf"C:\Program Files\7-Zip\{name}.exe",
            rf"C:\Program Files (x86)\7-Zip\{name}.exe",
            f"/usr/local/bin/{name}",
            f"/usr/bin/{name}",
            f"/opt/homebrew/bin/{name}",
        ]
        for p in candidates:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
        return None

    def version(self) -> str:
        if not self.version_cmd:
            return ""
        try:
            out = subprocess.run(self.version_cmd, capture_output=True, timeout=15)
            text = (out.stdout or out.stderr).decode("latin-1", "replace")
            return text.splitlines()[0][:80] if text else ""
        except (OSError, subprocess.SubprocessError):
            return ""

    def entry(self) -> dict:
        return {"name": self.name, "capability": self.capability,
                "accepts": self.accepts, "note": self.note,
                "available": self.available()}


_REGISTRY: dict[str, Tool] = {}


def register(tool: Tool) -> Tool:
    if tool.name in _REGISTRY:
        raise ValueError(f"工具重名：{tool.name}")
    _REGISTRY[tool.name] = tool
    return tool


def all_tools(capability: str | None = None) -> list[Tool]:
    items = list(_REGISTRY.values())
    if capability:
        items = [t for t in items if t.capability == capability]
    return sorted(items, key=lambda t: (not t.available(), t.name))


def catalog(capability: str | None = None) -> list[dict]:
    return [t.entry() for t in all_tools(capability)]


def run(tool: Tool | str, src: str, outdir: str, *, timeout: int | None = None) -> dict:
    """跑一个工具并**当场验收**。返回值里带完整来龙去脉（provenance）。"""
    if isinstance(tool, str):
        if tool not in _REGISTRY:
            return {"ok": False, "tool": tool, "error": "没有这个工具"}
        tool = _REGISTRY[tool]

    exe = tool.path()
    if not exe:
        return {"ok": False, "tool": tool.name,
                "error": f"这台机器没装 {tool.needs}", "provenance": {}}

    os.makedirs(outdir, exist_ok=True)
    if tool.python is not None:                       # 内置工具：直接调函数
        t0 = time.time()
        try:
            tool.python(src, outdir)
        except Exception as ex:                       # noqa: BLE001
            return {"ok": False, "tool": tool.name, "error": f"{type(ex).__name__}: {ex}"[:160],
                    "provenance": {"seconds": round(time.time() - t0, 1)}}
        try:
            verdict = tool.success(outdir) or {}
        except Exception as ex:                       # noqa: BLE001
            verdict = {"ok": False, "detail": f"验收时出错：{ex}"}
        return {"ok": bool(verdict.get("ok")), "tool": tool.name,
                "capability": tool.capability, "dir": outdir,
                "detail": str(verdict.get("detail") or "")[:200], "verdict": verdict,
                "stdout": "", "stderr": "",
                "provenance": {"cmd": ["<python>", tool.name], "exit": 0,
                               "seconds": round(time.time() - t0, 1)}}
    cmd = [c.format(src=src, out=outdir) for c in tool.cmd]
    # 第一条命令用解析出来的真实路径（PATH 里没有、但装在固定目录的工具）
    if cmd and cmd[0] == tool.needs:
        cmd[0] = exe
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout or tool.timeout)
        code, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return {"ok": False, "tool": tool.name, "error": "超时",
                "provenance": {"cmd": cmd, "seconds": round(time.time() - t0, 1)}}
    except OSError as ex:
        return {"ok": False, "tool": tool.name, "error": str(ex)[:120],
                "provenance": {"cmd": cmd}}

    # ★ 验收：不看退出码，看东西对不对。
    # 解包类看产出目录；分析类的产物是 stdout，就用 stdout_success。
    try:
        if tool.stdout_success is not None:
            verdict = tool.stdout_success(
                (out or b"").decode("latin-1", "replace")) or {}
        else:
            verdict = tool.success(outdir) or {}
    except Exception as ex:                                   # noqa: BLE001
        verdict = {"ok": False, "detail": f"验收时出错：{ex}"}

    return {
        "ok": bool(verdict.get("ok")),
        "tool": tool.name,
        "capability": tool.capability,
        "dir": outdir,
        "detail": str(verdict.get("detail") or "")[:200],
        "verdict": verdict,
        "stdout": (out or b"").decode("latin-1", "replace")[-300:],
        "stderr": (err or b"").decode("latin-1", "replace")[-300:],
        "provenance": {"cmd": cmd, "exit": code, "seconds": round(time.time() - t0, 1),
                       "version": tool.version()},
    }


_PROMPT = """你要把一个固件镜像解开。已知信息：

{evidence}

可用工具（只能从这些里选，按你判断的先后顺序排）：
{tools}

只输出 JSON：
{{"order": ["工具名", ...], "reason": "一句话"}}

规则：
- 最多 4 个；不确定就把最通用的放前面；
- 不要发明工具名；
- 如果头是明显的厂商私有加密且没有任何 decrypt 工具可用，返回空 order。"""


# 魔数 → 该先试谁。没模型时靠它排序；有模型时只用来补漏。
_PREFER = {
    b"\x27\x05\x19\x56": ("uimage",),
    b"HDR0": ("trx",),
    b"hsqs": ("unsquashfs", "7z", "unblob", "binwalk"),
    b"sqsh": ("sasquatch", "7z", "unblob", "binwalk"),
    b"shsq": ("sasquatch", "7z", "unblob", "binwalk"),
    b"CRAM": ("cramfsck", "7z", "unblob"),
    b"UBI#": ("ubireader", "unblob"),
    b"\x1f\x8b\x08": ("gzip-stream", "gzip", "unblob"),
    b"\xfd7zXZ": ("xz-stream", "unblob"),
    b"BZh": ("bzip2-stream", "unblob"),
}


def preferred(src: str, names: set[str]) -> list[str]:
    """按文件头魔数给出"该先试谁"。这是没模型时的排序依据，也是模型漏选时的补丁。"""
    try:
        with open(src, "rb") as fh:
            head = fh.read(64)
    except OSError:
        return []
    for magic, order in _PREFER.items():
        if head.startswith(magic):
            return [n for n in order if n in names]
    return []


def choose(src: str, *, capability: str = "unpack", chat=None,
           evidence: dict | None = None, log=None) -> list[str]:
    """让模型排个序；模型不可用/胡说时按「装没装 + 认不认这个魔数」兜底。"""
    log = log or (lambda *a: None)
    tools = all_tools(capability)
    usable = [t for t in tools if t.available()]
    if not usable:
        return []

    advice = []
    if chat is not None:
        import json as _json
        import re as _re

        listing = "\n".join(f"- {t.name}: {t.note or t.accepts}" for t in usable)
        prompt = _PROMPT.format(
            evidence=_json.dumps(evidence or {"file": os.path.basename(src)},
                                 ensure_ascii=False)[:1500],
            tools=listing)
        try:
            reply = chat([{"role": "user", "content": prompt}], max_new_tokens=200) or ""
            m = _re.search(r"\{.*\}", reply, _re.S)
            if m:
                order = ( _json.loads(m.group(0)) or {}).get("order") or []
                advice = [n for n in order if isinstance(n, str)]
        except Exception as ex:                               # noqa: BLE001
            log(f"[toolbus] 模型排序失败，走兜底：{ex}")

    names = {t.name for t in usable}
    hinted = preferred(src, names)
    picked = [n for n in advice if n in names]
    if not picked:                                            # 模型没给可用顺序
        picked = list(hinted)
    else:
        # 模型给了顺序也把"魔数明显指向的那几个"提到前面 —— 证据优先于模型直觉
        picked = [n for n in hinted if n not in picked] + picked
    for t in usable:                                          # 兜底补齐
        if t.name not in picked:
            picked.append(t.name)
    return picked[:6]


_MAGICS = ((b"hsqs", "squashfs-le"), (b"sqsh", "squashfs-be"), (b"shsq", "squashfs-3"),
           (b"CRAM", "cramfs"), (b"UBI#", "ubi"))


def carve(src: str, tmpdir: str, *, limit: int = 8 * 1024 * 1024) -> list[dict]:
    """把固件里内嵌的文件系统「切」出来。

    固件通常长这样：``[uImage 头][LZMA 内核][ ... ][squashfs @ 0x100000]``。
    把整个 .bin 丢给 7z/squashfs 是解不开的（它看到的是 uImage 头）。
    真机上大家手工 ``dd skip=1M``，这里把这一步自动化：扫前 8 MB 找魔数，
    从命中处切出候选文件。
    """
    try:
        size = os.path.getsize(src)
        with open(src, "rb") as fh:
            head = fh.read(limit)
    except OSError:
        return []

    out = []
    for magic, name in _MAGICS:
        idx = head.find(magic)
        if idx <= 0:
            continue
        dst = os.path.join(tmpdir, f"{os.path.basename(src)}.at{idx:x}.{name}")
        try:
            os.makedirs(tmpdir, exist_ok=True)
            with open(dst, "wb") as out_fh, open(src, "rb") as in_fh:
                in_fh.seek(idx)
                while True:
                    chunk = in_fh.read(1 << 20)
                    if not chunk:
                        break
                    out_fh.write(chunk)
        except OSError:
            continue
        out.append({"path": dst, "offset": idx, "magic": name})
    return out


def run_chain(src: str, outdir: str, order: list[str], *, log=None,
              lessons_scope: str = "", with_carve: bool = True) -> dict:
    """按顺序试，**第一个通过验收的就停**；全失败也如实说。

    会先切出内嵌文件系统（见 carve）：先试原文件，再试切出来的候选。
    """
    log = log or (lambda *a: None)
    tried = []

    candidates = [{"path": src, "offset": 0, "magic": ""}]
    if with_carve:
        carved = carve(src, os.path.join(outdir, "_carve"))
        if carved:
            log("[toolbus] 镜像里发现 %d 个内嵌文件系统：%s"
                % (len(carved), "、".join(f"{c['magic']}@{c['offset']:#x}" for c in carved)))
        candidates += carved

    for cand in candidates:
        for name in order:
            tool = _REGISTRY.get(name)
            if not tool:
                continue
            tag = name if not cand["offset"] else f"{name}@{cand['offset']:#x}"
            log(f"[toolbus] 试 {tag} …")
            res = run(tool, cand["path"], os.path.join(outdir, tag.replace("@", "-")))
            tried.append({"tool": name, "offset": cand["offset"],
                          **{k: res.get(k) for k in ("ok", "detail", "error")}})
            if res["ok"]:
                log(f"[toolbus] {tag} 通过验收：{res['detail'] or res['dir']}")
                return {"ok": True, "tool": name, "dir": res["dir"], "result": res,
                        "offset": cand["offset"], "tried": tried}
            msg = res.get("error") or res.get("detail") or "验收没过"
            log(f"[toolbus] {tag} 没成：{msg[:80]}")
            if lessons_scope:                                # 失败也变成经验
                try:
                    from . import knowledge as kb

                    kb.add_lesson(f"{tag} 在 {lessons_scope} 上没成：{msg[:60]}",
                                  scope=lessons_scope)
                except Exception:                            # noqa: BLE001
                    pass
    return {"ok": False, "tool": "", "dir": "", "tried": tried}
