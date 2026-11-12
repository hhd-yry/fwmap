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
import socket
import subprocess
import time

ARCH_QEMU = {
    "mips": "qemu-mips", "mips32": "qemu-mips", "mipsbe": "qemu-mips",
    "mipsel": "qemu-mipsel", "mipsle": "qemu-mipsel",
    "arm": "qemu-arm", "armel": "qemu-arm", "aarch64": "qemu-aarch64",
    "x86": "qemu-i386", "i386": "qemu-i386", "x86_64": "qemu-x86_64",
    "ppc": "qemu-ppc", "powerpc": "qemu-ppc",
}
# 模拟器打出来的、能确认为崩溃的字样
CRASH_HINTS = ("uncaught target signal", "Segmentation fault", "Illegal instruction",
               "Bus error", "Aborted", "core dumped", "invalid memory access")


def find_runtime(arch: str, rootfs: str | None = None):
    """返回 (label, argv_prefix, env)。没有可用运行时返回 (None, None, None)。

    label 会写进报告：`native` 表示架构与宿主机一致、直接跑；
    `qemu-mipsel` 表示要用模拟器；None 表示这台机器跑不了。
    """
    key = (arch or "").lower()
    host = platform.machine().lower()
    native = ((key in ("x86_64", "amd64") and host in ("amd64", "x86_64")) or
              (key in ("x86", "i386") and host in ("amd64", "x86_64", "x86")))
    if native:
        return "native", [], {}
    name = ARCH_QEMU.get(key)
    if not name:
        return None, None, None
    exe = shutil.which(name) or shutil.which(name + ".exe")
    if not exe:
        return None, None, None
    env = {"QEMU_LD_PREFIX": rootfs} if rootfs else {}
    return name, [exe], env


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


def run_request(req: dict, binary: str, runtime, timeout: float = 8.0,
                ready_timeout: float = 6.0) -> dict:
    """起服务 → 发一个请求 → 判状态。

    不用「先连一次探端口」的做法：单线程 accept 的服务会把那次探测当成一个连接收走，
    真正的请求反而打不进去（实测假服务直接吃掉了探测连接然后退出，判成 no-crash）。
    改成边连边重试，连接被拒就等下一轮，第一个连上的连接就是用来发请求的。
    """
    label, prefix, env = runtime
    full_env = dict(os.environ)
    full_env.update(env or {})
    t0 = time.time()
    try:
        proc = subprocess.Popen(prefix + [binary], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=full_env, cwd=os.path.dirname(binary) or ".")
    except Exception as e:                              # noqa: BLE001
        return {"status": "no-listener", "detail": f"起不来：{e}", "elapsed": 0}

    sent = False
    resp = b""
    try:
        deadline = time.time() + ready_timeout
        while time.time() < deadline:
            if proc.poll() is not None:
                break                       # 进程自己退了，不会再有人监听
            try:
                s = socket.create_connection(("127.0.0.1", req["port"]), 0.5)
            except OSError:
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
                    "stdout": out[:600], "stderr": err[:600],
                    "elapsed": round(time.time() - t0, 1)}

        crashed, code, out, err = _proc_state(proc, timeout)
        return {"status": "crash" if crashed else "no-crash", "exit": code,
                "elapsed": round(time.time() - t0, 1),
                "resp": resp[:300].decode("latin-1", "replace"),
                "stdout": out[:600], "stderr": err[:600], "runtime": label}
    finally:
        _kill(proc)


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


def _kill(proc) -> None:
    try:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=3)
    except Exception:                                   # noqa: BLE001
        pass


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
    runtime = find_runtime(arch, args.rootfs)
    label = runtime[0] if runtime[0] else None
    print(f"[*] 目标 {os.path.basename(args.binary)} · 架构 {arch or '?'} · "
          f"运行时 {label or '无（只能生成 PoC）'}")

    results = []
    for c in chains:
        reqs = poc.build_requests(c, ep_by_fn.get(c.get("function") or ""),
                                  port=args.port)
        rows = []
        for r in reqs[: args.max_payloads]:
            if args.dry_run or not label:
                rows.append({"req": r, "result": {"status": "not-run"}})
                continue
            print(f"    {c.get('function')} · {r['param']}={len(r['value'])}B … ",
                  end="", flush=True)
            res = run_request(r, args.binary, runtime, timeout=args.timeout)
            print(res["status"])
            rows.append({"req": r, "result": res})
            if res["status"] == "crash":
                break                     # 崩了就停，不用再加码
        results.append({"chain": c, "rows": rows})

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(_markdown(results, args, arch, label))
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
    crashes = sum(1 for r in results for x in r["rows"] if x["result"]["status"] == "crash")
    print(f"[+] 崩溃 {crashes} 条 · 未崩溃 "
          f"{sum(1 for r in results for x in r['rows'] if x['result']['status'] == 'no-crash')} 条")
    return 0


def _guess_arch(binary: str) -> str:
    try:
        from .elf import read_elf

        with open(binary, "rb") as fh:
            info = read_elf(fh.read())
        return getattr(info, "arch", "") or ""
    except Exception:                                   # noqa: BLE001
        return ""


def _markdown(results, args, arch, label) -> str:
    from .poc import render_curl
    L = ["# fwmap dyn · 动态验证", ""]
    L.append(f"- 目标：`{args.binary}`")
    L.append(f"- 架构 / 运行时：{arch or '?'} / {label or '无（未执行）'}")
    L.append(f"- 端口：{args.port}")
    L.append("")
    L.append("> `no-listener` 表示服务没起来，**不是**「没有漏洞」；")
    L.append("> `no-crash` 表示打完了没崩，也不等于安全。")
    L.append("")
    MARK = {"crash": "**崩溃**", "no-crash": "未崩溃", "no-listener": "未验证",
            "not-run": "未执行"}
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
