"""二进制身份绑定 —— 结果文件必须说清它对应的是哪一串字节。

我们以前的 `m2.json` / `flow.json` 只记路径（`binary: C:\\fw\\p5\\root\\bin\\webs`）。
后果是：换一版固件、或者同一路径被覆盖，**旧结果照样能接着用，而且不会有任何报错**。
这类错误是无声的 —— 链本身没毛病，只是它属于别的二进制。静态分析里这种错最难发现：
结论看着完全合理，只是对一个不存在的程序成立。

同学的 agent 用 sha256 挡这件事（结果 JSON、IDA 里打开的、输入三者必须是同一个）。
我们照抄这一条，但做得更宽容一点：

| 情况 | 处理 |
|---|---|
| 哈希对得上 | 静默通过 |
| 老结果文件里没有哈希 | 提示一次，不阻断（不能因为升级工具就把存量结果全废了） |
| 二进制已经不在那个路径 | 提示，不阻断（两机分工时路径本来就不一样） |
| **哈希对不上** | **默认拒绝继续**，除非显式 `--allow-stale` |

最后一行是重点：路径变了只是"没法核对"，哈希变了是"结论一定是错的"。
这两件事不能都算"警告"。
"""

from __future__ import annotations

import hashlib
import os

__all__ = ["sha256_of", "stamp", "status", "check"]

_CHUNK = 1 << 20

OK = "ok"
NO_HASH = "no-hash"
NO_BINARY = "no-binary"
MISMATCH = "mismatch"


def sha256_of(path: str) -> str:
    """算文件的内容哈希。读不动就抛 —— 算不了要说出来，不能返回空字符串装成算过了。"""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def stamp(obj: dict, binary: str) -> dict:
    """给要落盘的结果加 `binary_sha256` / `binary_size`（就地改并返回 obj）。

    二进制不在了就什么都不加 —— 宁可没有字段，也不要写个空字符串冒充"记过了"。
    """
    try:
        if binary and os.path.isfile(binary):
            obj["binary_sha256"] = sha256_of(binary)
            obj["binary_size"] = os.path.getsize(binary)
    except OSError:
        pass
    return obj


def status(obj: dict, binary: str | None = None) -> tuple[str, str]:
    """判断这份结果和二进制是不是同一个东西，返回 (状态, 人话)。"""
    expected = (obj or {}).get("binary_sha256") or ""
    path = binary or (obj or {}).get("binary") or ""
    if not expected:
        return NO_HASH, "结果里没有 binary_sha256（老版本工具产出的，没法核对）"
    if not path:
        return NO_BINARY, "结果里没记二进制路径"
    if not os.path.isfile(path):
        return NO_BINARY, f"二进制不在这个路径：{path}"
    try:
        got = sha256_of(path)
    except OSError as e:
        return NO_BINARY, f"读不了二进制：{e}"
    if got != expected:
        return MISMATCH, (f"哈希对不上：结果记的是 {expected[:16]}…，"
                          f"磁盘上是 {got[:16]}…")
    return OK, ""


def check(obj: dict, binary: str | None = None, allow_stale: bool = False,
          log=print, label: str = "") -> bool:
    """返回 True 表示可以继续。

    只有 `mismatch` 会返回 False（除非 allow_stale）。其余情况都是提示，
    因为它们只说明"核对不了"，不说明"结果是错的"。
    """
    st, detail = status(obj, binary)
    if st == OK:
        return True
    head = f"[{label}] " if label else ""
    if st == MISMATCH:
        if allow_stale:
            log(f"{head}[!] {detail}")
            log("    继续（--allow-stale）：这份结果可能是别的二进制算出来的，"
                "结论请自行斟酌。")
            return True
        log(f"{head}[x] {detail}")
        log("    拒绝继续：链是对的，只是它属于另一个二进制 —— 这种错误不会报错，"
            "只会让结论悄悄错掉。")
        log("    换正确的结果文件，或者（明知如此仍要跑）加 --allow-stale。")
        return False
    log(f"{head}[!] {detail}")
    return True


def report_of(obj: dict) -> dict:
    """给报告用的一行：这份结果的"出身"。"""
    return {
        "binary": (obj or {}).get("binary") or "",
        "binary_sha256": (obj or {}).get("binary_sha256") or "",
        "binary_size": (obj or {}).get("binary_size"),
    }
