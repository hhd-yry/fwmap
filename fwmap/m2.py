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

# Ghidra 安装位置：环境变量 → 这些常见位置 → 包旁边的 tools\ghidra*
DEFAULT_HOMES = [
    r"C:\deepseek\tools\ghidra_12.2_PUBLIC",
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
    try:
        _pkg = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _tools = os.path.join(_pkg, "tools")
        if os.path.isdir(_tools):
            for _name in sorted(os.listdir(_tools)):
                _p = os.path.join(_tools, _name)
                if _name.lower().startswith("jdk") and os.path.isdir(_p):
                    env["JAVA_HOME"] = _p
                    break
    except Exception:
        pass
    try:
        tmp = os.path.join(os.path.dirname(cmd[1]), "ghidra-temp")
        os.makedirs(tmp, exist_ok=True)
        env["TEMP"] = env["TMP"] = tmp
    except Exception:
        pass
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", env=env)
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
    headless = os.path.join(home, "support", "analyzeHeadless.bat")
    if not os.path.exists(headless):
        headless = os.path.join(home, "support", "analyzeHeadless")

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
    return {
        "binary": binary,
        "strategy": strategy,
        "endpoints": sorted(endpoints.values(), key=lambda x: x["uri"]),
        "ghidra": home,
        "returncode": 0,
        "stderr_tail": "",
    }


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
