"""emulate 类工具：把固件真的跑起来 —— 这一步以前一直是"卡住"的地方。

之前三天里，DIR-320、DIR-816L 卡在 `somovd` 守护进程，DIR-615 卡在 `login.cgi`，
`transmission`/`miniupnpd` 干脆不监听。根因只有一个：
**qemu-user 只模拟单个进程，跑不了需要内核、网络栈、守护进程的东西。**

真正的解法是全系统模拟（qemu-system）。但"配一台虚拟机"是脏活：
内核从哪来、rootfs 挂哪、网卡怎么桥、console 用什么。
所以这里不硬编某一台固件，只做两件事：

    1. 一个**通用的启动器**：按 profile 拼命令、跑起来、探端口、收串口日志、按时杀掉
    2. 一个**硬判据**：端口真的开了 / 串口里真的出现了 init 标记

profile 是 JSON（厂商/型号相关的部分），用户可以自己加：

    {"name": "dir-615",
     "cmd": ["qemu-system-mips", "-M", "malta", "-kernel", "{kernel}",
             "-hda", "{image}", "-append", "console=ttyS0 root=/dev/sda1",
             "-netdev", "user,id=n0,hostfwd=tcp::80-:80", "-nographic"],
     "ports": [80],
     "markers": ["init:", "login:", "Booting"]}

**跑不起来就是跑不起来** —— 判据不通过时，报告里只能写"没起来"，
绝不允许把"没起来"当成"没有漏洞"。
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time

from . import toolbus
from .toolbus import Tool

__all__ = ["Profile", "load_profile", "run_emulation", "register_all",
           "v_emulation", "profile_from_env"]

PROFILE_ENV = "FWMAP_EMU_PROFILE"


class Profile:
    """一次全系统模拟怎么启动。"""

    def __init__(self, data: dict):
        self.name = str(data.get("name") or "unknown")
        self.cmd = list(data.get("cmd") or [])
        self.ports = [int(p) for p in (data.get("ports") or [])]
        self.markers = [str(m) for m in (data.get("markers") or [])]
        self.wait = int(data.get("wait") or 25)
        self.arch = str(data.get("arch") or "")
        self.vars = dict(data.get("vars") or {})

    def render(self, image: str, outdir: str) -> list[str]:
        table = {"image": image, "out": outdir, **self.vars}
        return [piece.format(**table) for piece in self.cmd]


def load_profile(path: str) -> Profile:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return Profile(data if isinstance(data, dict) else {})


def profile_from_env() -> Profile | None:
    path = os.environ.get(PROFILE_ENV)
    if not path or not os.path.isfile(path):
        return None
    try:
        return load_profile(path)
    except (OSError, ValueError):
        return None


def _port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.6) -> bool:
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except OSError:
        return False


def run_emulation(image: str, outdir: str, profile: Profile) -> dict:
    """按 profile 启动，等到端口/标记出现就收工，超时就杀。

    返回值会被写进 `outdir/result.json`，验收函数只读这个文件 ——
    "跑过没有"由这里说了算，不靠调用方记性。
    """
    os.makedirs(outdir, exist_ok=True)
    cmd = profile.render(image, outdir)
    log_path = os.path.join(outdir, "serial.log")
    result_path = os.path.join(outdir, "result.json")
    result = {"ok": False, "profile": profile.name, "cmd": cmd,
              "ports": {p: False for p in profile.ports},
              "markers": [], "booted": False, "reason": ""}

    if not cmd:
        result["reason"] = "profile 里没有 cmd"
        _write(result_path, result)
        return result

    exe = cmd[0]
    if not (os.path.isfile(exe) or _which(exe)):
        result["reason"] = f"这台机器没有 {exe}"
        _write(result_path, result)
        return result

    t0 = time.time()
    try:
        with open(log_path, "wb") as log:
            proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT,
                                    stdin=subprocess.DEVNULL, start_new_session=True)
    except OSError as ex:
        result["reason"] = f"起不来：{ex}"
        _write(result_path, result)
        return result

    seen = set()
    try:
        deadline = time.time() + profile.wait
        while time.time() < deadline:
            for p in profile.ports:
                if not result["ports"][p] and _port_open(p):
                    result["ports"][p] = True
            for m in profile.markers:
                if m not in seen and _grep(log_path, m):
                    seen.add(m)
            if any(result["ports"].values()) or seen:
                break
            if proc.poll() is not None:            # 自己退出了，不用等
                break
            time.sleep(0.5)
    finally:
        _kill(proc)

    result["markers"] = sorted(seen)
    result["seconds"] = round(time.time() - t0, 1)
    result["exit"] = proc.returncode
    result["serial_tail"] = _tail(log_path)
    result["booted"] = bool(any(result["ports"].values()) or seen)
    if not result["booted"]:
        result["reason"] = (result["serial_tail"][-120:]
                            or "既没开端口，也没有 init 标记")
    result["ok"] = result["booted"]
    _write(result_path, result)
    return result


def _which(name: str) -> bool:
    from shutil import which

    return which(name) is not None


def _grep(path: str, needle: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return needle.encode() in fh.read()
    except OSError:
        return False


def _tail(path: str, n: int = 2000) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read()[-n:].decode("latin-1", "replace")
    except OSError:
        return ""


def _kill(proc) -> None:
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:                                      # noqa: BLE001
        try:
            proc.kill()
        except Exception:                                  # noqa: BLE001
            pass


def _write(path: str, obj: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=1)


def v_emulation(outdir: str) -> dict:
    """验收只看 result.json：端口开了或看到 init 标记才算起来。"""
    try:
        with open(os.path.join(outdir, "result.json"), encoding="utf-8") as fh:
            res = json.load(fh)
    except (OSError, ValueError):
        return {"ok": False, "detail": "没有 result.json（根本没跑）"}
    if not res.get("booted"):
        return {"ok": False, "detail": f"没起来：{res.get('reason', '')[:80]}"}
    ports = [p for p, up in (res.get("ports") or {}).items() if up]
    bits = []
    if ports:
        bits.append("端口 " + ",".join(ports))
    if res.get("markers"):
        bits.append("串口标记 " + ",".join(res["markers"][:3]))
    return {"ok": True, "detail": " · ".join(bits)}


def _runner(image: str, outdir: str) -> None:
    profile = profile_from_env()
    if profile is None:
        raise RuntimeError(f"没有 profile：设置 {PROFILE_ENV} 指向 JSON")
    res = run_emulation(image, outdir, profile)
    if not res["booted"]:
        raise RuntimeError(f"没起来：{res.get('reason', '')[:80]}")


def register_all() -> int:
    """注册常见架构的 qemu-system（幂等）。profile 通过环境变量传。"""
    have = {t.name for t in toolbus.all_tools()}
    n = 0
    targets = (("qemu-system-mips", "MIPS 大端"),
               ("qemu-system-mipsel", "MIPS 小端"),
               ("qemu-system-arm", "ARM"),
               ("qemu-system-aarch64", "ARM64"))
    for name, arch_note in targets:
        if name in have:
            continue
        toolbus.register(Tool(
            name, "emulate", None, v_emulation, python=_runner,
            accepts=f"{arch_note} 固件（需要 profile）",
            note=f"全系统模拟（{arch_note}）：按 profile 起内核+rootfs，探端口/串口",
            failure_hint="profile 不对，或缺内核/设备树"))
        n += 1
    return n
