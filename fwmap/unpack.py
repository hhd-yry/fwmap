"""固件解包/拆壳：模型挑工具，跑完用「像不像一个 rootfs」来验收。

为什么单开一层：**解不开的固件，后面所有分析都是零**。
而现实是每一家、每一代都不一样：

    squashfs 4.x   → unsquashfs
    squashfs 3.x   → unsquashfs 拒绝，得用 7z / sasquatch
    cramfs         → cramfsck
    UBI            → ubireader
    JFFS2          → jefferson
    cr6b（D-Link） → 公开工具基本没有，得认输
    TRX / uImage   → 先 dd 出偏移，再解里面的 squashfs

规则写不完，所以还是老套路：**模型从工具清单里挑，代码执行，结果自证**。
「自证」= 解出来的目录里有没有 bin/ etc/ lib/、有多少个 ELF —— 这比相信工具的输出可靠。
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess

__all__ = ["TOOLS", "evidence", "ask", "looks_like_rootfs", "unpack", "plan"]

# 工具清单：name → 怎么用、认什么、会不会改原件
TOOLS = {
    "binwalk": {
        "desc": "通用扫描+提取，能自动识别 squashfs/cramfs/gzip/LZMA/uImage 等并递归解",
        "cmd": ["binwalk", "-e", "-M", "--run-as=root", "{image}"],
        "magic": ["所有"],
        "note": "最省事，但对 squashfs 3.x 也解不了（它内部还是调 unsquashfs）",
    },
    "unsquashfs": {
        "desc": "解 squashfs 4.x（最标准）",
        "cmd": ["unsquashfs", "-f", "-d", "{out}", "{image}"],
        "magic": ["hsqs", "sqsh"],
        "note": "遇到 3.x 会直接报错",
    },
    "7z": {
        "desc": "7-Zip 能读 squashfs 3.x（unsquashfs 4.x 砍掉的旧格式）、cramfs、cpio 等",
        "cmd": ["7z", "x", "-y", "-o{out}", "{image}"],
        "magic": ["hsqs", "shsq", "sqsh", "CRAM"],
        "note": "**会丢执行位**，解完要自己补 +x",
    },
    "cramfsck": {
        "desc": "解 cramfs",
        "cmd": ["cramfsck", "-x", "{out}", "{image}"],
        "magic": ["CRAM"],
        "note": "老路由器常见",
    },
    "ubireader": {
        "desc": "解 UBI 镜像（ubireader_extract_images）",
        "cmd": ["ubireader_extract_images", "-o", "{out}", "{image}"],
        "magic": ["UBI#"],
        "note": "NAND 固件常见",
    },
    "jefferson": {
        "desc": "解 JFFS2",
        "cmd": ["jefferson", "-d", "{out}", "{image}"],
        "magic": ["\x85\x19", "\x19\x85"],
        "note": "需要 pip install jefferson",
    },
}

PROMPT = """你在判断一个固件镜像该怎么解包。已知信息：

{evidence}

可用工具（只能从这里选，按你判断的先后顺序排）：
{tools}

只输出一个 JSON 对象，不要解释：
{{"attempts": [{{"tool": "工具名", "why": "一句话"}}], "unsolvable": false, "reason": ""}}

规则：
- 如果头是 cr6b / 熵接近 8 / 明显是厂商私有加密，且没有对应工具，就把 unsolvable 设成 true，
  并在 reason 里写清楚「为什么公开工具解不了」——**不许假装能解**；
- 拿不准就按 binwalk → 7z → unsquashfs 的顺序给，让程序自己试；
- 最多给 4 个。"""


def _read(path: str, n: int = 64) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def _entropy(path: str, chunk: int = 262144) -> float:
    try:
        with open(path, "rb") as fh:
            data = fh.read(chunk)
    except OSError:
        return 0.0
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def evidence(image: str) -> dict:
    """收集「该用什么工具」的依据。"""
    head = _read(image, 64)
    size = os.path.getsize(image) if os.path.exists(image) else 0
    ent = _entropy(image)

    magics = []
    for tool, spec in TOOLS.items():
        for m in spec["magic"]:
            if m in ("所有",):
                continue
            raw = m.encode("latin-1") if isinstance(m, str) else m
            if head.startswith(raw) or raw in head:
                magics.append({"tool": tool, "magic": m})

    # 镜像内部常见文件系统的出现位置（前 8 MB 找一遍）
    found = {}
    try:
        with open(image, "rb") as fh:
            blob = fh.read(8 * 1024 * 1024)
        for name, needle in (("squashfs_le", b"hsqs"), ("squashfs_be", b"sqsh"),
                             ("squashfs_3_le", b"shsq"), ("cramfs", b"CRAM"),
                             ("gzip", b"\x1f\x8b\x08"), ("ubi", b"UBI#")):
            idx = blob.find(needle)
            if idx >= 0:
                found[name] = idx
    except OSError:
        pass

    return {
        "image": os.path.basename(image),
        "size_kb": round(size / 1024),
        "head_hex": head[:16].hex(),
        "head_ascii": "".join(chr(c) if 32 <= c < 127 else "." for c in head[:16]),
        "entropy": round(ent, 2),
        "magic_hits": magics,
        "magic_offsets": found,
        "note": ("熵 > 7.9 通常说明整体加密；" if ent > 7.9 else "")
                + ("头是 cr6b（D-Link 私有加密容器）" if head.startswith(b"cr6b") else ""),
    }


def _json_of(text: str) -> dict:
    m = re.search(r"\{.*\}", text or "", re.S)
    if not m:
        return {}
    try:
        return json.loads(m.group(0))
    except ValueError:
        return {}


def ask(pack: dict, chat=None) -> dict:
    """让模型给出「按顺序试哪些工具」；它说解不了就听它的。"""
    if chat is None:
        from .agent import llm as llm_mod

        def chat(messages, **kw):                            # noqa: E306
            return llm_mod.chat(messages, **kw)

    tools_txt = "\n".join(f"- {n}: {v['desc']}（{v['note']}）" for n, v in TOOLS.items())
    prompt = PROMPT.format(evidence=json.dumps(pack, ensure_ascii=False, indent=1)[:2000],
                           tools=tools_txt)
    obj = _json_of(chat([{"role": "user", "content": prompt}], max_new_tokens=300))
    attempts = []
    for a in (obj.get("attempts") or [])[:4]:
        name = str((a or {}).get("tool") or "").strip()
        if name in TOOLS and name not in [x["tool"] for x in attempts]:
            attempts.append({"tool": name, "why": str(a.get("why") or "")[:120]})
    return {"attempts": attempts, "unsolvable": bool(obj.get("unsolvable")),
            "reason": str(obj.get("reason") or "")[:200]}


def plan(pack: dict, chat=None) -> list[dict]:
    """模型没给出可用方案时，按证据兜底排序。"""
    got = ask(pack, chat=chat)
    if got["attempts"]:
        return got["attempts"]
    if got["unsolvable"]:
        return []
    order = ["binwalk", "7z", "unsquashfs"]
    return [{"tool": t, "why": "模型没给方案，按兜底顺序"} for t in order
            if shutil.which(t) or t == "7z"]


def looks_like_rootfs(path: str) -> dict:
    """验收：解出来的东西像不像一个根文件系统。"""
    if not path or not os.path.isdir(path):
        return {"ok": False, "reason": "目录不存在"}
    dirs = {d.lower() for d in os.listdir(path) if os.path.isdir(os.path.join(path, d))}
    want = {"bin", "etc", "lib", "sbin", "usr"}
    hit = dirs & want
    elf = 0
    for base, _d, files in os.walk(path):
        for f in files:
            if f.endswith((".so", ".so.0")) or f in ("busybox", "sh", "init"):
                elf += 1
        if elf > 20:
            break
    ok = len(hit) >= 2 and elf > 0
    return {"ok": ok, "dirs": sorted(hit), "elf_hint": elf,
            "reason": "" if ok else f"只看到 {len(hit)} 个标准目录、{elf} 个疑似可执行"}


def repair_symlinks(root: str, max_size: int = 64) -> dict:
    """把 7z 写坏的符号链接还原。

    7z 解 squashfs/cramfs 时**不还原符号链接**，而是写成一个只有几十字节的小文件，
    内容是链接目标的名字（比如 `/bin/date` 里存着 `busybox`，
    `/lib/ld-uClibc.so.0` 里存着 `ld-uClibc-0.9.30.3.so`）。
    后果很致命：动态链接的程序全都起不来，报
    `mips-binfmt-P: /lib/ld-uClibc.so.0: Invalid ELF image for this architecture`
    —— 看起来像架构不对，其实是那个"文件"根本不是 ELF。

    判据要严：内容必须是纯路径/名字，而且**目标真的存在**，才敢替换。
    """
    fixed = skipped = 0
    for base, _dirs, files in os.walk(root):
        for name in files:
            path = os.path.join(base, name)
            try:
                st = os.lstat(path)
                if st.st_size == 0 or st.st_size > max_size:
                    continue
                with open(path, "rb") as fh:
                    raw = fh.read()
                if b"\x00" in raw:
                    continue
                text = raw.decode("ascii").strip()
            except (OSError, UnicodeDecodeError):
                continue
            if not re.fullmatch(r"[A-Za-z0-9_./+-]{1,60}", text or ""):
                continue
            if not (os.path.exists(os.path.join(base, text))
                    or os.path.exists(os.path.join(root, text.lstrip("/")))):
                skipped += 1
                continue
            try:
                os.remove(path)
                os.symlink(text, path)
                fixed += 1
            except OSError:
                pass
    return {"fixed": fixed, "skipped": skipped}


def fix_exec_bits(root: str) -> int:
    """7z 也不保留执行位：所有 ELF 补 +x（否则 chroot/qemu 直接 Permission denied）。"""
    n = 0
    for base, _dirs, files in os.walk(root):
        for name in files:
            path = os.path.join(base, name)
            try:
                if os.path.getsize(path) < 1024:
                    continue
                with open(path, "rb") as fh:
                    if fh.read(4) != b"\x7fELF":
                        continue
                if not os.access(path, os.X_OK):
                    os.chmod(path, os.stat(path).st_mode | 0o755)
                n += 1
            except OSError:
                pass
    return n


def _run_tool(tool: str, image: str, outdir: str, timeout: int = 300) -> dict:
    spec = TOOLS.get(tool)
    if not spec:
        return {"ok": False, "error": "未知工具"}
    exe = spec["cmd"][0]
    if shutil.which(exe) is None:
        return {"ok": False, "error": f"这台机器没有 {exe}"}
    os.makedirs(outdir, exist_ok=True)
    cmd = [c.format(image=image, out=outdir) for c in spec["cmd"]]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "超时"}
    except OSError as ex:
        return {"ok": False, "error": str(ex)[:120]}

    # binwalk 会自己在旁边建 _image.extracted/ 目录
    candidates = [outdir]
    for name in os.listdir(os.path.dirname(os.path.abspath(image)) or "."):
        if name.endswith(".extracted"):
            candidates.append(os.path.join(os.path.dirname(os.path.abspath(image)), name))
    best = {"ok": False}
    for cand in candidates:
        v = looks_like_rootfs(cand)
        if v["ok"]:
            return {"ok": True, "dir": cand, "verdict": v,
                    "stderr": proc.stderr.decode("latin-1", "replace")[-300:]}
        if v.get("elf_hint", 0) > best.get("elf_hint", -1):
            best = {**v, "dir": cand}
    return {"ok": False, "error": (proc.stderr.decode("latin-1", "replace") or "")[-200:],
            "verdict": best,
            "stdout": proc.stdout.decode("latin-1", "replace")[-200:]}


def unpack(image: str, outdir: str, *, chat=None, log=print, tools=None) -> dict:
    """完整流程：证据 → 模型选工具 → 依次试 → 验收（像不像 rootfs）。"""
    pack = evidence(image)
    log(f"[unpack] {pack['image']} {pack['size_kb']} KB · 头 {pack['head_ascii']!r} · "
        f"熵 {pack['entropy']} · 命中 {[m['magic'] for m in pack['magic_hits']]}"
        + (f" · {pack['note']}" if pack["note"] else ""))

    attempts = plan(pack, chat=chat)
    if not attempts:
        log("[unpack] 模型判断：公开工具解不了这层壳（如实记录，不硬试）")
        return {"image": image, "ok": False, "attempts": [], "rootfs": None,
                "evidence": pack, "unsolvable": True}

    tried = []
    for a in attempts:
        tool = a["tool"]
        log(f"[unpack] 试 {tool} —— {a.get('why', '')}")
        res = _run_tool(tool, image, os.path.join(outdir, tool), timeout=600)
        tried.append({"tool": tool, **{k: res.get(k) for k in ("ok", "dir", "error")}})
        if res["ok"]:
            log(f"[unpack] {tool} 成功 → {res['dir']}（{res['verdict']['dirs']}）")
            # 7z 的两个老毛病：符号链接变成小文本文件、执行位丢失。
            # 不补的话解出来的固件"能看不能跑"—— 动态链接的程序全都起不来。
            sym = repair_symlinks(res["dir"])
            ex = fix_exec_bits(res["dir"])
            if sym["fixed"] or ex:
                log(f"[unpack] 自动修复：还原符号链接 {sym['fixed']} 个、补执行位 {ex} 个")
            return {"image": image, "ok": True, "tool": tool, "rootfs": res["dir"],
                    "repaired": {"symlinks": sym["fixed"], "exec_bits": ex},
                    "attempts": tried, "evidence": pack, "unsolvable": False}
        log(f"[unpack] {tool} 没成：{str(res.get('error'))[:90]}")

    log("[unpack] 所有方案都没解开 —— 这台固件的壳目前处理不了")
    return {"image": image, "ok": False, "attempts": tried, "rootfs": None,
            "evidence": pack, "unsolvable": False}
