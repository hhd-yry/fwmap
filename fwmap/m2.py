"""M2：端点 → handler 映射（调用 Ghidra headless）。

设计原则（和 M1 一致）：**能说"不知道"就说不知道**。
所以在没有把握的情况下，endpoint 会带着空 handler + `confidence: low` 返回，
而不是猜一个函数名塞进去——猜错一个 handler，人要在错误的地方读两小时代码。

策略由 Ghidra 脚本探测（见 ghidra_scripts/ExtractHandlers.java）：
  - strcmp-chain    端点字符串出现在比较链里
  - registration    数据段里有 (字符串, 函数) 相邻对
  - prefix          只有前缀常量，没有表

用法：
    python -m fwmap m2 <binary> [-o out.json]
环境：
    GHIDRA_HOME   Ghidra 安装目录（默认去常见位置找）
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

# Ghidra 安装位置：环境变量 → 这些常见位置 → 包旁边的 tools\ghidra* → 盘符根部扫
# 这里**只放通用位置**，不要写某台机器的绝对路径 —— 换台机器它就是一条废候选，
# 而真正该命中的是包内 tools/（便携包解压到哪都能用）。
DEFAULT_HOMES = [
    r"C:\ghidra",
    r"C:\tools\ghidra",
    "/opt/ghidra",
    "/usr/local/ghidra",
]
SCRIPT_NAME = "ExtractHandlers.java"


def _env_int(name: str, default: int) -> int:
    try:
        v = os.environ.get(name, "").strip()
        return int(v) if v else default
    except ValueError:
        return default


# Ghidra 单次调用的超时（秒）。
# 大二进制（>500 KB）在慢盘 / 开杀软的环境下会超过 15 分钟，用 FWMAP_GHIDRA_TIMEOUT 调大。
TIMEOUT = _env_int("FWMAP_GHIDRA_TIMEOUT", 1800)


def _ghidra_candidates() -> list[str]:
    """按优先级列出候选：环境变量 → 常见位置 → 包旁边的 tools\\ghidra* → 盘符下 ghidra*。"""
    out: list[str] = []
    for var in ("FWMAP_GHIDRA", "GHIDRA_HOME", "GHIDRA_INSTALL_DIR"):
        v = os.environ.get(var)
        if v:
            out.append(v)
    # 包目录（fwmap 包的上一级）旁边的 tools\ghidra*：fwmap setup 装的就放这，
    # 优先于系统里的旧版本，行为更可预期。
    pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for base in (os.path.join(pkg_root, "tools"),
                 os.path.join(os.path.dirname(pkg_root), "tools")):
        try:
            out.extend(sorted(glob.glob(os.path.join(base, "ghidra*"))))
        except Exception:
            pass
    out.extend(DEFAULT_HOMES)
    # Windows 上再扫一遍盘符根部，Linux 扫 /opt /usr/local
    if os.name == "nt":
        for drive in ("C:", "D:", "E:"):
            try:
                out.extend(sorted(glob.glob(os.path.join(drive + os.sep, "ghidra*"))))
            except Exception:
                pass
    else:
        out.extend(sorted(glob.glob("/opt/ghidra*")) + sorted(glob.glob("/usr/local/ghidra*")))
    return out


def find_ghidra(verbose: bool = False) -> str | None:
    """找一个可用的 Ghidra 目录（里面必须有 support/analyzeHeadless*）。"""
    tried: list[str] = []
    for home in _ghidra_candidates():
        if not home:
            continue
        tried.append(home)
        if not os.path.isdir(home):
            continue
        if (os.path.exists(os.path.join(home, "support", "analyzeHeadless.bat"))
                or os.path.exists(os.path.join(home, "support", "analyzeHeadless"))):
            return home
    if verbose:
        print("[!] 没找到 Ghidra，试过这些位置：")
        for t in tried:
            print("      " + t)
        print("    请设置环境变量 FWMAP_GHIDRA 指向 Ghidra 安装目录。")
    return None


def _script_dir() -> str:
    """找 ghidra_scripts：包目录上一级 / 上两级都试。"""
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (
        os.path.join(here, "ghidra_scripts"),
        os.path.join(os.path.dirname(here), "ghidra_scripts"),
        os.path.join(os.path.dirname(os.path.dirname(here)), "ghidra_scripts"),
    ):
        if os.path.isdir(cand):
            return cand
    return os.path.dirname(here)


def jdk_home() -> str:
    """找要用的 JDK：`FWMAP_JAVA_HOME` → 包内 `tools/jdk*` → 空字符串（交给系统 java）。

    为什么要有环境变量这一档：包内那份 JDK 可能被系统打过完整性标签、或者被杀软动过，
    换一份就行，不必动代码。Ghidra 12.2 要求 Java 25，系统里通常是 17。
    """
    env = os.environ.get("FWMAP_JAVA_HOME")
    if env and os.path.isdir(env):
        return env
    pkg = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tools = os.path.join(pkg, "tools")
    if not os.path.isdir(tools):
        return ""
    for name in sorted(os.listdir(tools)):
        p = os.path.join(tools, name)
        if name.lower().startswith("jdk") and os.path.isdir(p):
            return p
    return ""


_PERMS_FIXED: set[str] = set()


def ensure_posix_perms(home: str, posix: bool | None = None) -> list[str]:
    """从 Windows 拷过来的 Ghidra：脚本和原生程序**都没有执行位**。

    Linux 上的症状很迷惑人：
    - `analyzeHeadless` 跑不起来 → `Exec format error (errno 8)`
    - 反编译器 `decompile` / `sleigh` 没执行位 → 不报错，但反编译**0 个函数**
      （表现为「一条链都没有」，很容易被当成「这个固件很干净」）
    所以启动前自检一遍，缺了就补上。

    `posix` 只为测试留的（默认看 os.name）。
    """
    posix = (os.name != "nt") if posix is None else posix
    if not posix or home in _PERMS_FIXED:
        return []
    _PERMS_FIXED.add(home)
    fixed: list[str] = []
    targets: list[str] = []
    sup = os.path.join(home, "support")
    if os.path.isdir(sup):
        for name in os.listdir(sup):
            if name.startswith("analyzeHeadless") or name.endswith(".sh"):
                targets.append(os.path.join(sup, name))
    # 原生程序都放在 */os/linux*_*/* 里（decompile、sleigh、demangler…）
    for base, _dirs, files in os.walk(home):
        if f"{os.sep}os{os.sep}linux" in base:
            targets.extend(os.path.join(base, f) for f in files)
    for p in targets:
        try:
            mode = os.stat(p).st_mode
            if mode & 0o111:
                continue
            os.chmod(p, mode | 0o755)
            fixed.append(p)
        except OSError:
            pass
    return fixed


def headless_path(home: str) -> str:
    """按平台挑 Ghidra 的启动脚本。

    不要「先试 .bat，不存在再试无后缀」：把装了 Windows 版的 Ghidra 目录拷到 Linux
    （或者反过来）时两个文件都在，先试 .bat 会让 Linux 去执行批处理文件，
    报 `Exec format error（errno 8）` —— 看起来像 Ghidra 坏了，其实是挑错了启动脚本。
    """
    names = ("analyzeHeadless.bat", "analyzeHeadless") if os.name == "nt" else \
            ("analyzeHeadless", "analyzeHeadless.bat")
    fixed = ensure_posix_perms(home)
    if fixed:
        print(f"[!] Ghidra 里有 {len(fixed)} 个文件没有执行位（像是从 Windows 拷过来的），"
              f"已自动补上：{os.path.basename(fixed[0])} 等", flush=True)
    for name in names:
        p = os.path.join(home, "support", name)
        if os.path.exists(p):
            return p
    raise RuntimeError(f"Ghidra 目录里没有 analyzeHeadless：{os.path.join(home, 'support')}")


def _kill_tree(pid: int) -> None:
    """连子进程一起杀。analyzeHeadless.bat 会派 cmd → java，只杀 bat 会留下 java 占着工程锁。"""
    if os.name == "nt":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)],
                       capture_output=True, text=True, errors="replace")
    else:
        try:
            os.killpg(os.getpgid(pid), 9)
        except Exception:
            pass


def run_ghidra(cmd: list[str], timeout: int, label: str = "") -> str:
    """跑一次 Ghidra，返回 stdout。

    超时会杀掉整棵进程树（否则残留的 java 会锁住工程目录），并把 Ghidra 最后的
    输出带进异常里——不然只能看到一句 "timed out"，不知道它卡在哪。
    """
    # stdin 接空设备：Ghidra 的 .bat 失败后会 pause 等按键，后台调用时会把进程吊死。
    # Ghidra 往 java.io.tmpdir（$TEMP）写临时文件；受限环境里 %TEMP% 可能不可写，
    # 所以给它一个工程目录旁边的私有临时目录，不依赖系统设置。
    env = os.environ.copy()
    # 随包安装的 JDK（fwmap setup 装到 tools\jdk*）优先：
    # Ghidra 12.2 要求 Java 25，系统里若是 17/21 会拒绝启动。
    _jh = jdk_home()
    if _jh:
        env["JAVA_HOME"] = _jh
    try:
        tmp = os.path.join(os.path.dirname(cmd[1]), "ghidra-temp")
        os.makedirs(tmp, exist_ok=True)
        # Ghidra 启动第一件事是在 <TEMP> 下建它自己的临时目录，名字有两种写法：
        # <用户名>-ghidra（Launcher 走的那条）和 ghidra。某些 Windows 上它自己的
        # mkdirs 会返回 false（权限够、路径也短，就是建不出来），直接报
        # "Failed to create directory" 然后退出。目录已存在时它会跳过 mkdirs，
        # 所以这里两种都替它建好 —— 这是实测唯一稳定的绕法。
        _user = os.environ.get("USERNAME") or os.environ.get("USER") or "user"
        for _name in (f"{_user}-ghidra", "ghidra"):
            os.makedirs(os.path.join(tmp, _name), exist_ok=True)
        env["TEMP"] = env["TMP"] = tmp
    except Exception:
        pass
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, encoding="utf-8",
                            errors="replace", env=env)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc.pid)
        try:
            out, err = proc.communicate(timeout=30)
        except Exception:
            out, err = "", ""
        tail = ((out or "") + "\n" + (err or "")).strip()[-1200:]
        raise RuntimeError(
            f"Ghidra 超时（{timeout}s，{label or 'ghidra'}）。"
            f"大二进制或慢盘可设 FWMAP_GHIDRA_TIMEOUT=3600 后重试。\n"
            f"Ghidra 最后的输出：\n{tail or '(无输出)'}"
        )
    if proc.returncode != 0:
        tail = ((err or "") + "\n" + (out or "")).strip()[-1200:]
        raise RuntimeError(f"Ghidra 失败（exit {proc.returncode}）：\n{tail}")
    return out or ""


def extract(binary: str, ghidra_home: str | None = None, timeout: int = TIMEOUT) -> dict:
    """跑一次 Ghidra headless，返回 {'binary', 'strategy', 'endpoints', 'handlers'}。"""
    home = ghidra_home or find_ghidra()
    if not home:
        raise RuntimeError("找不到 Ghidra：设置 GHIDRA_HOME 环境变量")
    # 按平台挑启动脚本（见 headless_path 的说明）
    headless = headless_path(home)

    # Ghidra 不允许工程路径里出现 "." 开头的目录名，所以工作目录叫 fwmap-m2。
    # 每次用独立目录：triage 会在同一进程里连续跑多个二进制，
    # 共用 run-<pid> 会让上一次残留的工程锁把下一次卡死。
    base = os.environ.get("FWMAP_M2_DIR") or os.path.join(os.getcwd(), "fwmap-m2")
    os.makedirs(base, exist_ok=True)
    tag = hashlib.sha1(os.path.abspath(binary).encode("utf-8", "replace")).hexdigest()[:8]
    tmpdir = os.path.join(base, f"run-{os.getpid()}-{tag}")
    proj = os.path.join(tmpdir, "proj")
    os.makedirs(proj, exist_ok=True)
    cmd = [headless, proj, "m2", "-import", binary, "-overwrite",
           "-scriptPath", _script_dir(), "-postScript", SCRIPT_NAME]
    try:
        out = run_ghidra(cmd, timeout, label=os.path.basename(binary))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    rows = []
    dec = json.JSONDecoder()
    for line in out.splitlines():
        i = line.find('{"uri"')
        if i < 0:
            continue
        try:
            obj, _ = dec.raw_decode(line[i:])   # 行尾还有 " (GhidraScript)" 之类的尾巴
        except json.JSONDecodeError:
            continue
        rows.append(obj)

    # 注册表里存的是 form 名（"telnet"），URI 前缀是运行时拼的。
    # 判据：带扩展名的名字（apply.cgi）本身就是完整 URI，不能加前缀；
    # 不带扩展名的 ident（telnet、fast_setting_get）才是 form 名，补主导前缀。
    absolute = {r["uri"] for r in rows if r["uri"].startswith("/")}
    counts: dict[str, int] = {}
    for u in absolute:
        if u.count("/") >= 2:
            head = u.rsplit("/", 1)[0] + "/"
            counts[head] = counts.get(head, 0) + 1
    prefixes = sorted(counts, key=counts.get, reverse=True)

    def with_prefix(name: str) -> str:
        if name.startswith("/") or "." in name or not prefixes:
            return name
        for p in prefixes:
            if p + name in absolute:
                return p + name
        return prefixes[0] + name

    endpoints: dict[str, dict] = {}
    for r in rows:
        uri = with_prefix(r["uri"])
        e = endpoints.setdefault(uri, {"uri": uri, "refs": [], "handler": "", "handler_name": "",
                                       "strategy": r.get("strategy", "unknown"), "confidence": "low"})
        e["refs"].append({"at": r.get("ref", ""), "in": r.get("function", "")})
        if r.get("handler") and not e["handler"]:
            e["handler"] = r["handler"]
            e["handler_name"] = r.get("handler_name", "")
            e["confidence"] = r.get("confidence", "low")

    # 同一个端点可能以 "upgrade.cgi" 和 "/upgrade.cgi" 两种形式出现：
    # 带斜杠的那条才是规范形式，裸名只在没有对应路径时保留。
    for uri in list(endpoints):
        if not uri.startswith("/") and "/" + uri in endpoints:
            bare, canon = endpoints.pop(uri), endpoints["/" + uri]
            canon["refs"].extend(bare["refs"])
            if not canon["handler"] and bare["handler"]:
                canon["handler"] = bare["handler"]
                canon["handler_name"] = bare["handler_name"]
                canon["confidence"] = bare["confidence"]

    strategy = max((e["strategy"] for e in endpoints.values()), default="unknown",
                   key=lambda s: {"inventory": 0, "unknown": 0, "prefix": 1,
                                  "strcmp-chain": 2, "registration": 3}.get(s, 0))
    from . import integrity

    return integrity.stamp({
        "binary": binary,
        "strategy": strategy,
        "endpoints": sorted(endpoints.values(), key=lambda x: x["uri"]),
        "ghidra": home,
        "returncode": 0,
        "stderr_tail": "",
    }, binary)


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="fwmap m2", description="端点 → handler 映射（Ghidra）")
    ap.add_argument("binary", help="单个 ELF 文件")
    ap.add_argument("-o", "--output", help="输出 JSON")
    args = ap.parse_args(argv)

    res = extract(args.binary)
    print(f"[*] 策略: {res['strategy']}  端点: {len(res['endpoints'])}")
    for e in res["endpoints"]:
        h = f"{e['handler']} {e['handler_name']}" if e["handler"] else "(未定位)"
        print(f"  {e['uri']:<28} {h}   [{e['confidence']}]")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(res, fh, ensure_ascii=False, indent=2)
        print(f"[+] {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
