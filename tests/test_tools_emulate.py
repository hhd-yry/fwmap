"""emulate 类工具的测试：判据只有一条 —— 服务真的起来了吗。

这是整套工具里最容易自欺的一类。qemu-system 启动失败有一百种表现
（内核 panic、rootfs 挂不上、网卡没配），但进程可能还活着，
于是"跑起来了"和"卡在启动中"看起来一样。

所以这里用一个**假的 qemu**（就是个 Python 脚本）来测：
- 会监听端口的 → 必须判成功；
- 起来就退出的 → 必须判失败，并写清原因；
- 没有 profile 的 → 必须直接报"没 profile"，不是"启动失败"。
"""

import json
import os
import sys
import tempfile
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import toolbus as TB  # noqa: E402
from fwmap import tools_emulate as TE  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


LISTEN_FAKE = textwrap.dedent('''
    import socket, sys, time
    port = int(sys.argv[1])
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(1)
    print("Booting Linux...", flush=True)
    time.sleep(30)
''')

EXIT_FAKE = textwrap.dedent('''
    import sys
    print("Kernel panic - not syncing: VFS: Unable to mount root fs", flush=True)
    sys.exit(1)
''')


def free_port() -> int:
    """动态要一个空闲端口 —— 别用固定端口：本机 7778 被厂商软件占着，
    会让"起不来"的用例假通过（这是实测踩到的坑）。"""
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def write_profile(tmp, cmd, ports, markers, wait=8, name="t"):
    p = os.path.join(tmp, "profile.json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"name": name, "cmd": cmd, "ports": ports,
                   "markers": markers, "wait": wait}, fh)
    return p


def main() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="fwmap-emu-")
    TE.register_all()

    listen = os.path.join(tmp, "qemu_listen.py")
    open(listen, "w", encoding="utf-8").write(LISTEN_FAKE)
    exitf = os.path.join(tmp, "qemu_exit.py")
    open(exitf, "w", encoding="utf-8").write(EXIT_FAKE)

    image = os.path.join(tmp, "fw.bin")
    open(image, "wb").write(b"\x00" * 1000)

    # 1) 会监听端口的假 qemu → 成功
    port_ok = free_port()
    prof = write_profile(tmp, [sys.executable, listen, str(port_ok)], [port_ok],
                         ["Booting"], wait=8, name="fake-ok")
    os.environ[TE.PROFILE_ENV] = prof
    r = TB.run("qemu-system-mips", image, os.path.join(tmp, "o1"))
    ok &= check("端口起来 → 判成功", r["ok"] is True, r)
    ok &= check("detail 里有端口号", str(port_ok) in (r.get("detail") or ""),
                r.get("detail"))
    res = json.load(open(os.path.join(tmp, "o1", "result.json")))
    ok &= check("串口标记也记下了", "Booting" in res.get("markers", []), res.get("markers"))
    ok &= check("记了耗时", "seconds" in res)

    # 2) 起来就退出 → 失败，且原因说得清
    prof2 = write_profile(tmp, [sys.executable, exitf], [free_port()], [],
                          wait=5, name="fake-bad")
    os.environ[TE.PROFILE_ENV] = prof2
    r2 = TB.run("qemu-system-mips", image, os.path.join(tmp, "o2"))
    ok &= check("起不来 → 判失败", r2["ok"] is False, r2)
    msg = ((r2.get("error") or "") + (r2.get("detail") or "")).lower()
    ok &= check("原因里能看到 panic 字样", "panic" in msg, msg[:120])
    v = TE.v_emulation(os.path.join(tmp, "o2"))
    ok &= check("验收函数也说失败", v["ok"] is False)

    # 3) 没 profile → 明确报「没有 profile」，而不是"启动失败"
    os.environ.pop(TE.PROFILE_ENV, None)
    r3 = TB.run("qemu-system-mips", image, os.path.join(tmp, "o3"))
    ok &= check("没 profile 就说没 profile", "profile" in (r3.get("error") or "").lower(), r3)

    # 4) profile 的 {image}/{out} 占位符要能替换
    p = TE.Profile({"name": "x", "cmd": ["{image}", "{out}"]})
    rendered = p.render("/tmp/a.bin", "/tmp/o")
    ok &= check("占位符替换", rendered == ["/tmp/a.bin", "/tmp/o"], rendered)

    # 5) 没有 result.json 时验收不能假装成功
    ok &= check("没 result.json → 失败", TE.v_emulation(os.path.join(tmp, "nope"))["ok"] is False)

    import shutil

    shutil.rmtree(tmp, ignore_errors=True)
    print()
    print("PASS（全系统模拟启动器）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
