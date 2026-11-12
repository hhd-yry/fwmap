"""动态验证：在模拟器里把目标二进制**真跑起来**，把 PoC 打进去，看它崩不崩。

静态分析只能证明「这条链在代码上存在」，`verify` 只能证明「别人报过类似的」。
这一步补的是最后一公里：**它现在真的会崩吗**。

做法是最小闭环：

    qemu-<arch> -L <rootfs> <binary>
        → 等端口起来
        → 发 HTTP 请求（poc.py 生成）
        → 看进程是正常退出、被信号打死、还是根本没起来

三种结论必须在报告里分清楚，不能混：

    crash        进程被信号打死 / 模拟器报 uncaught target signal —— 有崩溃证据
    no-crash     请求打完了，进程还活着或正常退出 —— 没有崩溃证据（不等于没有漏洞）
    no-listener  服务根本没起来（缺配置、端口被占、要 root 才能绑 80）—— **未验证**

把 no-listener 说成 no-crash 是这个环节最容易犯的错，所以状态里单独列出来。

当前环境没有 qemu-user 时，命令会退化成「只生成 PoC + 打印该在哪儿跑」，
不会假装跑过了。
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import time

ARCH_QEMU = {
    "mips": "qemu-mips", "mips32": "qemu-mips", "mipsbe": "qemu-mips",
    "mipsel": "qemu-mipsel", "mipsle": "qemu-mipsel",
    "arm": "qemu-arm", "armel": "qemu-arm", "aarch64": "qemu-aarch64",
    "armeb": "qemu-armeb",
    "x86": "qemu-i386", "i386": "qemu-i386", "x86_64": "qemu-x86_64",
    "ppc": "qemu-ppc", "powerpc": "qemu-ppc",
}
# 模拟器打出来的、能确认为崩溃的字样
CRASH_HINTS = ("uncaught target signal", "Segmentation fault", "Illegal instruction",
               "Bus error", "Aborted", "core dumped", "invalid memory access")


def find_runtime(arch: str, rootfs: str | None = None, binary: str = "") -> dict | None:
    """找一个能跑目标二进制的运行时，返回 {label, prefix, env, exe, cwd}；没有则 None。

    三种，优先级从高到低：

    1. **chroot + binfmt_misc**（Linux + root + 已注册）：最接近真机。
       固件里的 `/etc/boa`、`/dev/nvram` 都是绝对路径，`-L` 只重定向加载器、
       不重定向这些路径，所以 `-L` 跑法会 `Could not chdir to "/etc/boa"` 直接退出。
       chroot 之后 `/etc` 就是固件自己的 `/etc`，才能真的起来。
    2. **qemu-<arch>[-static]**：没有 root 权限时退回 `-L` 模式（路径会不完整）。
    3. **native**：架构与宿主机一致，直接跑。
    """
    key = (arch or "").lower()
    host = platform.machine().lower()
    native = ((key in ("x86_64", "amd64") and host in ("amd64", "x86_64")) or
              (key in ("x86", "i386") and host in ("amd64", "x86_64", "x86")))
    if native:
        return {"label": "native", "prefix": [], "env": {},
                "exe": binary, "cwd": os.path.dirname(binary) or "."}

    name = ARCH_QEMU.get(key)
    if not name:
        return None

    # 1) chroot + binfmt
    if (rootfs and binary and sys.platform.startswith("linux")
            and hasattr(os, "geteuid") and os.geteuid() == 0
            and os.path.exists(f"/proc/sys/fs/binfmt_misc/{name}")):
        root = os.path.abspath(rootfs)
        try:
            rel = os.path.relpath(os.path.abspath(binary), root)
        except ValueError:
            rel = None
        if rel and not rel.startswith(".."):
            return {"label": f"chroot+{name}", "prefix": ["chroot", root], "env": {},
                    "exe": "/" + rel.replace(os.sep, "/"), "cwd": root}

    # 2) qemu -L
    for cand in (name, name + "-static", name + ".exe"):
        exe = shutil.which(cand)
        if exe:
            env = {"QEMU_LD_PREFIX": rootfs} if rootfs else {}
            return {"label": cand, "prefix": [exe], "env": env,
                    "exe": binary, "cwd": os.path.dirname(binary) or "."}
    return None


def _wait_port(proc, port: int, deadline: float) -> bool:
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), 0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def run_request(req: dict, runtime: dict, timeout: float = 8.0,
                ready_timeout: float = 6.0) -> dict:
    """起服务 → 发一个请求 → 判状态。

    目标偶尔会因为「端口刚好被上一轮的 TIME_WAIT 占着」之类的原因起不来，
    所以起不来的情况重试一次；重试还起不来就如实报 no-listener。
    **绝不把 no-listener 当成 no-crash。**
    """
    res = _attempt(req, runtime, timeout, ready_timeout)
    if res["status"] == "no-listener" and "已被占用" not in res.get("detail", ""):
        time.sleep(0.5)
        res = _attempt(req, runtime, timeout, ready_timeout)
    return res


def _attempt(req: dict, runtime: dict, timeout: float, ready_timeout: float) -> dict:
    label = runtime["label"]

    # 端口已被占用：直接说明原因。否则目标 bind 失败会立刻退出，
    # 被记成「no-listener」，看起来像「服务起不来」，其实是上一次的实例没退干净。
    try:
        with socket.create_connection(("127.0.0.1", req["port"]), 0.3):
            return {"status": "no-listener",
                    "detail": f"端口 {req['port']} 已被占用（上一次的实例没退干净）",
                    "elapsed": 0}
    except OSError:
        pass

    full_env = dict(os.environ)
    full_env.update(runtime.get("env") or {})
    t0 = time.time()
    try:
        # start_new_session：目标如果 fork 出子进程，杀的时候要连子进程一起杀，
        # 否则它继续占着端口，后面每一条都会变成 no-listener。
        proc = subprocess.Popen(list(runtime["prefix"]) + [runtime["exe"]],
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=full_env, cwd=runtime.get("cwd") or ".",
                                start_new_session=True)
    except Exception as e:                              # noqa: BLE001
        return {"status": "no-listener", "detail": f"起不来：{e}", "elapsed": 0}

    sent = False
    resp = b""
    try:
        deadline = time.time() + ready_timeout
        while time.time() < deadline:
            try:
                s = socket.create_connection(("127.0.0.1", req["port"]), 0.5)
            except OSError:
                # 进程退出了要区分两种情况：
                #   ① 真的起不来（缺配置/没权限）→ 下面按「没监听」处理；
                #   ② fork 成守护进程后父进程退出 → 端口已经开了，再试一轮就通
                if proc.poll() is not None and not _port_open(req["port"]):
                    time.sleep(0.1)
                    break
                time.sleep(0.1)
                continue
            try:
                s.sendall(_render(req))
                s.settimeout(timeout)
                resp = s.recv(4096)
                sent = True
            except OSError:
                sent = True                 # 发出去之后对端没了，也算发过
            finally:
                s.close()
            break

        if not sent:
            out, err = _drain(proc, 2.0)
            return {"status": "no-listener",
                    "detail": "端口没起来（缺配置/要 root 绑 80/直接退出了）",
                    "exit": proc.returncode,
                    "stdout": out[:600], "stderr": err[:600],
                    "elapsed": round(time.time() - t0, 1)}

        # 判死活：只认「异常退出」。「正常的退出」不能当崩溃 ——
        # 单连接的服务打完一次请求就正常退出，把它算成 crash 就全错了。
        # 守护进程型的（父进程 fork 完就退）同样走这里：父进程 0 退出 = 没崩。
        crashed, code, out, err = _proc_state(proc, timeout)
        return {"status": "crash" if crashed else "no-crash", "exit": code,
                "elapsed": round(time.time() - t0, 1),
                "resp": resp[:300].decode("latin-1", "replace"),
                "stdout": out[:600], "stderr": err[:600], "runtime": label}
    finally:
        _kill(proc)
        _kill_guest(runtime["exe"])
        _kill_guest(runtime["exe"])


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), 0.3):
            return True
    except OSError:
        return False


def _render(req: dict) -> bytes:
    from .poc import render_http
    return render_http(req)


def _is_crash_code(code) -> bool:
    """崩溃退出码：POSIX 是被信号打死（负数），Windows 是 NTSTATUS（≥ 0x80000000）。"""
    if code is None:
        return False
    return code < 0 or code >= 0x80000000


def _proc_state(proc, timeout: float):
    """等进程结束；被信号打死或模拟器报崩溃都算 crash。"""
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # 超时说明它还活着（没崩），但也不能算「验证过」
        _kill(proc)
        return False, None, "", ""
    code = proc.returncode
    text = (out or b"").decode("latin-1", "replace") + (err or b"").decode("latin-1", "replace")
    crashed = _is_crash_code(code) or any(h in text for h in CRASH_HINTS)
    return crashed, code, (out or b"").decode("latin-1", "replace"), \
        (err or b"").decode("latin-1", "replace")


def _drain(proc, wait: float):
    try:
        out, err = proc.communicate(timeout=wait)
    except subprocess.TimeoutExpired:
        _kill(proc)
        return "", ""
    return (out or b"").decode("latin-1", "replace"), (err or b"").decode("latin-1", "replace")


def _kill_guest(exe: str) -> None:
    """按 /proc 里的 cmdline 杀掉 binfmt 拉起来的目标进程。

    为什么不能只 kill 进程组：`chroot <root> /bin/webs` 会被 binfmt_misc 转成
    `qemu-binfmt-P /bin/webs /bin/webs`，那个进程常常被 reparent 到 init(1)，
    进程组 kill 打不到它 —— 它继续占着端口，后面每一条都会变成「端口被占用」。
    """
    if not sys.platform.startswith("linux"):
        return
    me = os.getpid()
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return
    for pid in pids:
        if int(pid) == me:
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                parts = [p.decode("utf-8", "replace")
                         for p in fh.read().split(b"\0") if p]
        except OSError:
            continue
        if exe in parts and any("binfmt" in p or "qemu" in p for p in parts):
            try:
                os.kill(int(pid), signal.SIGKILL)
            except OSError:
                pass


def _kill(proc) -> None:
    """连进程组一起杀，并等端口真正释放。"""
    try:
        if proc.poll() is None:
            try:
                if hasattr(os, "killpg"):
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                else:
                    proc.kill()
            except Exception:                           # noqa: BLE001
                proc.kill()
            proc.wait(timeout=3)
    except Exception:                                   # noqa: BLE001
        pass
    time.sleep(0.2)                                     # 让内核把端口收回去


# ---------------------------------------------------------------- CLI
def _load(path: str):
    from .verify import _read_json
    return _read_json(path)


def run(args) -> int:
    from . import poc

    chains = [c for c in (_load(args.flow).get("chains") or [])
              if c.get("verdict", "keep") == "keep"]
    if args.only:
        chains = [c for c in chains if args.only.lower() in (c.get("function") or "").lower()]
    if not chains:
        print("[!] flow 里没有可用的链")
        return 1

    endpoints = []
    if getattr(args, "m2", None):
        endpoints = _load(args.m2).get("endpoints") or []
    ep_by_fn = {}
    for e in endpoints:
        fn = (e.get("handler_name") or "").strip()
        if fn and fn not in ep_by_fn:
            ep_by_fn[fn] = e
        for r in e.get("refs") or []:
            f = (r.get("in") or "").strip()
            if f and f not in ep_by_fn:
                ep_by_fn[f] = e

    arch = args.arch or _guess_arch(args.binary)
    runtime = find_runtime(arch, args.rootfs, args.binary)
    label = runtime["label"] if runtime else None
    print(f"[*] 目标 {os.path.basename(args.binary)} · 架构 {arch or '?'} · "
          f"运行时 {label or '无（只能生成 PoC）'}")

    results = []
    control = None
    if label and not args.dry_run:
        # 先打一发绝对无害的请求做对照。固件在模拟器里经常因为缺 NVRAM / 缺 /dev
        # 而「一请求就崩」，那种崩溃不是我们打出来的漏洞，必须先排除掉。
        print("    对照组（无害 GET /）… ", end="", flush=True)
        control = run_request(poc.control_request(args.port), runtime,
                              timeout=args.timeout)
        print(control["status"])
        if control["status"] == "crash":
            print("[!] 对照组也崩了 —— 这是环境问题（缺 NVRAM/缺设备），"
                  "不是漏洞。下面的结果只能当「未验证」。")

    env_broken = bool(control and control["status"] == "crash")
    for c in chains:
        reqs = poc.build_requests(c, ep_by_fn.get(c.get("function") or ""),
                                  port=args.port)
        rows = []
        for r in reqs[: args.max_payloads]:
            if args.dry_run or not label:
                rows.append({"req": r, "result": {"status": "not-run"}})
                continue
            if env_broken:
                rows.append({"req": r, "result": {"status": "env-broken"}})
                continue
            print(f"    {c.get('function')} · {r['param']}={len(r['value'])}B … ",
                  end="", flush=True)
            res = run_request(r, runtime, timeout=args.timeout)
            print(res["status"])
            rows.append({"req": r, "result": res})
            if res["status"] == "crash":
                break                     # 崩了就停，不用再加码
        results.append({"chain": c, "rows": rows})

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(_markdown(results, args, arch, label, control))
        print(f"[+] 报告：{args.out}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump([{k: v for k, v in r.items() if k != "chain"} | {"function":
                       r["chain"].get("function")} for r in results],
                      fh, ensure_ascii=False, indent=1)

    if not label:
        q = ARCH_QEMU.get((arch or "").lower(), "<arch>")
        print("[!] 这台机器没有能跑该架构的运行时（qemu-user），以上只是 PoC，没执行。")
        print("    在 Linux 上装 qemu-user-static 后重跑：")
        print(f"    {q} -L {args.rootfs or '<rootfs>'} {args.binary}")
        return 2
    if env_broken:
        print("[+] 全部标为「环境崩溃，未验证」——先修好运行环境（NVRAM/设备）再谈漏洞")
        return 3
    crashes = sum(1 for r in results for x in r["rows"] if x["result"]["status"] == "crash")
    print(f"[+] 崩溃 {crashes} 条 · 未崩溃 "
          f"{sum(1 for r in results for x in r['rows'] if x['result']['status'] == 'no-crash')} 条")
    return 0


def _guess_arch(binary: str) -> str:
    """ELF 机器号 + 字节序 → qemu 认的架构名。

    必须带上字节序：Edimax 的 webs 是 **LSB** MIPS，用 qemu-mips（大端）跑会直接
    退出 1 且不打印任何东西，看起来像「服务起不来」，其实只是用错了模拟器。
    """
    try:
        from .elf import read_elf

        with open(binary, "rb") as fh:
            info = read_elf(fh.read())
        arch = getattr(info, "arch", "") or ""
        le = getattr(info, "endian", "<") == "<"
        if arch == "MIPS":
            return "mipsel" if le else "mips"
        if arch == "ARM":
            return "armel" if le else "armeb"
        return arch
    except Exception:                                   # noqa: BLE001
        return ""


def _markdown(results, args, arch, label, control=None) -> str:
    from .poc import render_curl
    L = ["# fwmap dyn · 动态验证", ""]
    L.append(f"- 目标：`{args.binary}`")
    L.append(f"- 架构 / 运行时：{arch or '?'} / {label or '无（未执行）'}")
    L.append(f"- 端口：{args.port}")
    L.append("")
    L.append("> `no-listener` 表示服务没起来，**不是**「没有漏洞」；")
    L.append("> `no-crash` 表示打完了没崩，也不等于安全。")
    L.append("")
    if control is not None:
        st = control.get("status")
        L.append(f"**对照组（无害 `GET /`）：{st}**")
        L.append("")
        if st == "crash":
            L.append("> ⚠ 对照组也崩了 —— 目标是**因为环境不完整**（缺 NVRAM / 缺 /dev / ")
            L.append("> 缺配置）才崩的，下面的载荷结果**都不能算漏洞证据**。")
            L.append("")
        elif st == "no-listener":
            L.append("> ⚠ 对照组连端口都没起来，说明服务没跑起来，下面的结果无效。")
            L.append("")
    MARK = {"crash": "**崩溃**", "no-crash": "未崩溃", "no-listener": "未验证",
            "not-run": "未执行", "env-broken": "环境崩溃·未验证"}
    for r in results:
        c = r["chain"]
        L.append(f"## `{c.get('function')}` → {c.get('sink')}[{c.get('sink_category')}]")
        L.append("")
        L.append("| 载荷 | 结果 | 细节 |")
        L.append("|---|---|---|")
        for x in r["rows"]:
            q, res = x["req"], x["result"]
            val = q["value"].replace("|", "/").replace("`", "'")
            preview = val if len(val) <= 28 else f"{val[:14]}…（{len(val)}B）"
            detail = res.get("detail") or res.get("stderr", "")[:80] or ""
            code = res.get("exit")
            if not detail and isinstance(code, int):
                # 崩溃的退出码要写出来，否则报告里只有「崩溃」两个字，无法复核
                detail = (f"退出码 0x{code & 0xFFFFFFFF:08X}" if code >= 0
                          else f"被信号 {-code} 打死")
            L.append(f"| `{q['param']}` = `{preview}` | {MARK.get(res['status'], res['status'])} | "
                     f"{detail.replace('|', '/')} |")
        if r["rows"]:
            L.append("")
            L.append(f"```\n{render_curl(r['rows'][0]['req'])}\n```")
        L.append("")
    return "\n".join(L) + "\n"
