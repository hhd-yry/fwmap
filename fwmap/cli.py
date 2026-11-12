"""命令行入口。

用法：
    python -m fwmap scan <rootfs目录>            # 生成 report.html
    python -m fwmap scan <rootfs> -o out.html --json out.json --top 20
    python -m fwmap scan <单个ELF文件>
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .check import check, format_report
from .report import render_html
from .scan import scan

ROLE_LABEL = {
    "http_server": "HTTP服务",
    "network_service": "网络服务",
    "cgi_binary": "CGI",
    "library": "库",
    "tool": "工具",
    "busybox": "busybox",
    "other": "其他",
}


def _setup_console() -> None:
    """Windows 控制台默认走 GBK，打印 `✓` 和中文会直接 UnicodeEncodeError 崩掉
    （`fwmap check` 在 cmd/PowerShell 里必崩）。这里把代码页切到 UTF-8，
    并让 stdout/stderr 用 UTF-8 输出；真有编码问题也只会显示成替代字符，不会崩。
    """
    if os.name == "nt":
        try:
            import ctypes

            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _fmt(n: int) -> str:
    if n >= 1048576:
        return f"{n/1048576:.1f}M"
    if n >= 1024:
        return f"{n/1024:.0f}K"
    return f"{n}B"


def _pad(s: str, width: int) -> str:
    """按显示宽度补空格（中文算 2 列）。"""
    w = sum(2 if ord(c) > 0x2E80 else 1 for c in s)
    return s + " " * max(0, width - w)


def cmd_triage(args) -> int:
    from .triage import triage

    def log(m):
        print(m, file=sys.stderr, flush=True)

    out = triage(args.rootfs, args.outdir, binaries=args.binaries, limit=args.limit,
                 use_agent=args.agent, top_chains=args.top_chains, samples=args.samples,
                 force=args.force, use_auth=not args.no_auth,
                 use_verify=not args.no_verify, context=args.context or "",
                 log=log)
    # 全挂也要有非 0 退出码：否则 CI / 断网验收会把「四层一层都没跑成」当成通过。
    bins = out.get("binaries") or []
    dead = [b for b in bins if b.get("error") and not b.get("chain_list")]
    if bins and len(dead) == len(bins):
        print("[!] 所有二进制都分析失败，报告里的空结果不代表「没有漏洞」", file=sys.stderr)
        for b in dead[:3]:
            print(f"    {b.get('binary')}: {str(b.get('error'))[:100]}", file=sys.stderr)
        return 1
    return 0


def cmd_check(args) -> int:
    res = check(args.target)
    print(format_report(res))
    return 0 if res["ok"] else 1


def cmd_scan(args) -> int:
    if not os.path.exists(args.target):
        print(f"路径不存在: {args.target}", file=sys.stderr)
        return 2

    # 先自检：解包不完整时，扫描结果会"看起来很合理但其实是假的"
    if os.path.isdir(args.target):
        pre = check(args.target)
        if pre["issues"]:
            print("[!] rootfs 自检未通过，结果不可信：", file=sys.stderr)
            for i in pre["issues"]:
                print(f"    - {i}", file=sys.stderr)
            print("    运行 `fwmap check <rootfs>` 看完整报告", file=sys.stderr)

    print(f"[*] 扫描 {args.target} …", file=sys.stderr)
    res = scan(args.target, max_size=args.max_size * 1024 * 1024)
    print(f"[*] 文件 {res.files_seen} · ELF {res.elf_count}", file=sys.stderr)

    # 可选的 M2：对排名前 N 个二进制跑 Ghidra，把完整端点清单补进报告。
    # 每个二进制都要起一次 headless，很慢，所以默认关闭。
    if getattr(args, "m2", 0):
        from .m2 import extract

        for t in res.targets[: args.m2]:
            try:
                r = extract(t.abs_path)
                t.m2 = {"strategy": r["strategy"], "endpoints": r["endpoints"]}
                print(f"[*] M2 {t.rel_path}: {len(r['endpoints'])} 端点 "
                      f"({r['strategy']})", file=sys.stderr)
            except Exception as e:                      # noqa: BLE001
                t.m2 = {"strategy": "error", "endpoints": [], "error": str(e)}
                print(f"[!] M2 {t.rel_path} 失败: {e}", file=sys.stderr)

    out_html = args.output or os.path.join(
        os.path.dirname(os.path.abspath(args.target)) or ".",
        "fwmap-report.html",
    )
    render_html(res, out_html)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res.to_dict(), fh, ensure_ascii=False, indent=2)

    top = res.targets[: args.top]
    if top:
        print()
        print(f"{_pad('分数', 6)}{_pad('角色', 12)}{_pad('架构', 12)}{_pad('大小', 8)}路径")
        print("-" * 88)
        for t in top:
            print(f"{_pad(str(t.score), 6)}"
                  f"{_pad(ROLE_LABEL.get(t.role, t.role), 12)}"
                  f"{_pad(t.arch, 12)}"
                  f"{_pad(_fmt(t.size), 8)}"
                  f"{t.rel_path}")
    else:
        print("\n未发现 ELF 文件。检查解包路径是否正确。")

    print(f"\n[+] 报告: {os.path.abspath(out_html)}")
    if args.json:
        print(f"[+] JSON: {os.path.abspath(args.json)}")
    return 0


def cmd_m2(args) -> int:
    from .m2 import main as m2_main

    return m2_main([args.binary] + (["-o", args.output] if args.output else []))


def cmd_m3(args) -> int:
    from .m3 import main as m3_main

    argv = [args.binary, "--top", str(args.top)]
    if args.output:
        argv += ["-o", args.output]
    if getattr(args, "induce", False):
        argv.append("--induce")
    if getattr(args, "profile", None):
        argv += ["--profile", args.profile]
    if getattr(args, "flow", False):
        argv.append("--flow")
        if getattr(args, "limit", None):
            argv += ["--limit", str(args.limit)]
    return m3_main(argv)


def cmd_auth(args) -> int:
    from .auth import main as auth_main

    argv = [args.binary, "--limit", str(args.limit)]
    if args.input:
        argv += ["-i", args.input]
    if args.output:
        argv += ["-o", args.output]
    return auth_main(argv)


def main(argv: list[str] | None = None) -> int:
    _setup_console()
    p = argparse.ArgumentParser(prog="fwmap", description="固件攻击面地图")
    sub = p.add_subparsers(dest="cmd", required=True)

    tri = sub.add_parser("triage", help="一条命令跑完四层，出 HTML 报告")
    tri.add_argument("rootfs", help="解包后的 rootfs 目录")
    tri.add_argument("-o", "--outdir", default="fwmap-out", help="输出目录（默认 fwmap-out）")
    tri.add_argument("--binaries", type=int, default=2, help="对排名前 N 个二进制跑 M2/M3（默认 2）")
    tri.add_argument("--limit", type=int, help="M3 分析函数数上限（默认按大小自适应）")
    tri.add_argument("--agent", action="store_true", help="跑本地 LLM 复核")
    tri.add_argument("--top-chains", type=int, default=8, help="LLM 复核多少条链（默认 8）")
    tri.add_argument("--samples", type=int, default=3, help="每条链采样几次（默认 3）")
    tri.add_argument("--force", action="store_true", help="丢弃 profile 缓存，重新归纳")
    tri.add_argument("--no-auth", action="store_true", help="跳过 M2.5 端点鉴权检查")
    tri.add_argument("--no-verify", action="store_true",
                     help="跳过新颖性核对（默认会查 CVE 库，断网时用离线库）")
    tri.add_argument("--context", help="目标厂商/型号关键词，逗号分隔（如 Edimax,BR-6478AC）")
    tri.set_defaults(func=cmd_triage)

    s = sub.add_parser("scan", help="扫描已解包的 rootfs")
    s.add_argument("target", help="rootfs 目录，或单个 ELF 文件")
    s.add_argument("-o", "--output", help="HTML 报告路径")
    s.add_argument("--json", help="同时导出 JSON")
    s.add_argument("--top", type=int, default=15, help="控制台显示前 N 条（默认 15）")
    s.add_argument("--max-size", type=int, default=40, help="单文件大小上限 MB（默认 40）")
    s.add_argument("--m2", type=int, default=0,
                   help="对前 N 个二进制跑 M2（Ghidra，很慢），把完整端点清单写进报告")
    s.set_defaults(func=cmd_scan)

    c = sub.add_parser("check", help="解包后自检：结构是否合理、有没有嵌套压缩包")
    c.add_argument("target", help="rootfs 目录")
    c.set_defaults(func=cmd_check)

    d = sub.add_parser("doctor", help="环境自检：Ghidra / 模型 / 依赖 能不能找到")
    d.add_argument("--agent", action="store_true", help="连本地模型一起检查")
    d.set_defaults(func=cmd_doctor)

    v = sub.add_parser("verify", help="新颖性核对：按函数名 + 路由名查 CVE 库")
    v.add_argument("input", help="m3 --flow 的 flow.json，或 triage 的 report.json")
    v.add_argument("--m2", help="端点映射（输入是 flow.json 时需要）")
    v.add_argument("--out", "-o", help="输出 markdown（默认 <输入>.verify.md）")
    v.add_argument("--source", choices=["auto", "api", "online", "local"], default="auto",
                   help="检索源：auto=有网走 API、断网用离线库（默认）；api=强制联网；local=强制离线")
    v.add_argument("--db", help="离线库路径（默认 包目录/data/nvd/nvd.sqlite）")
    v.add_argument("--no-scan", action="store_true",
                   help="离线模式只做整词匹配，跳过子串兜底扫描（快，但可能漏）")
    v.add_argument("--update-index", action="store_true",
                   help="走完 API 后顺手把离线库刷到最新（只下变了的年包）")
    v.add_argument("--context", help="目标厂商/型号关键词，逗号分隔（如 Edimax,BR-6478AC）；"
                                     "命中里提到它的标【同厂商】")
    v.add_argument("--all-handlers", action="store_true",
                   help="把 M2 里所有 handler 都拉进来核对，不只核对出过链的函数")
    v.add_argument("--limit", type=int, default=0, help="只核对前 N 个函数")
    v.add_argument("--only", help="只核对函数名包含该子串的")
    v.add_argument("--delay", type=float, default=6.5, help="在线模式的请求间隔秒（NVD 无 key 有限流）")
    v.add_argument("--refresh", action="store_true", help="忽略缓存重新查询（仅在线模式）")
    v.add_argument("--dry-run", action="store_true", help="只列出关键词，不发请求")
    v.set_defaults(func=lambda a: __import__("fwmap.verify", fromlist=["run"]).run(a))

    nv = sub.add_parser("nvd", help="离线 NVD 索引：下载 / 建索引 / 查询（断网验收靠它）")
    nsub = nv.add_subparsers(dest="nvd_cmd")

    def _nvd_dir(p):
        p.add_argument("--dir", "-d", help="索引目录（默认 包目录/data/nvd）")
        return p

    nf = _nvd_dir(nsub.add_parser("fetch", help="下载 NIST 官方 CVE feed（约 240 MB）"))
    nf.add_argument("--from-year", dest="from_year", type=int, help="起始年份（默认 2002）")
    nf.add_argument("--to-year", dest="to_year", type=int, help="结束年份（默认今年）")
    nf.add_argument("--proxy", help="HTTP 代理，如 http://127.0.0.1:7897")

    _nvd_dir(nsub.add_parser("build", help="把年包合成 nvd.sqlite"))
    nu = _nvd_dir(nsub.add_parser("update", help="有网时增量更新：只下变了的年包，再重建"))
    nu.add_argument("--from-year", dest="from_year", type=int, help="从哪年起查（默认 2002）")
    nu.add_argument("--proxy", help="HTTP 代理，如 http://127.0.0.1:7897")

    nc = _nvd_dir(nsub.add_parser("check", help="只看有没有新数据，不下载"))
    nc.add_argument("--from-year", dest="from_year", type=int)
    nc.add_argument("--proxy")

    ns = _nvd_dir(nsub.add_parser("search", help="手工查一个关键词"))
    ns.add_argument("keywords", nargs="+")
    ns.add_argument("--limit", type=int, default=40)
    ns.add_argument("--db")
    ns.add_argument("--no-scan", action="store_true")

    _nvd_dir(nsub.add_parser("status", help="索引状态（条数 / 快照日期 / 大小）"))
    nv.set_defaults(func=lambda a: __import__("fwmap.nvd", fromlist=["run"]).run(a))

    dy = sub.add_parser("dyn", help="动态验证：把 PoC 打进模拟器里的二进制，看它崩不崩")
    dy.add_argument("flow", help="m3 --flow 的 flow.json")
    dy.add_argument("--m2", help="端点映射（用来确定打哪个 URL）")
    dy.add_argument("--binary", required=True, help="要跑的 ELF")
    dy.add_argument("--rootfs", help="解包后的 rootfs（给 qemu -L 用）")
    dy.add_argument("--arch", help="目标架构（默认从 ELF 头读）")
    dy.add_argument("--port", type=int, default=8080, help="服务端口（默认 8080）")
    dy.add_argument("--only", help="只验证函数名包含该子串的链")
    dy.add_argument("--cmd", help="命令注入类：要执行的 shell 命令（默认只发探测载荷）")
    dy.add_argument("--check", help="命令执行后去固件里查这个文件（如 /tmp/pwned）作为证据")
    dy.add_argument("--max-payloads", type=int, default=3, help="每条链最多试几个载荷")
    dy.add_argument("--timeout", type=float, default=8.0, help="单个请求等待秒数")
    dy.add_argument("--dry-run", action="store_true", help="只生成 PoC，不执行")
    dy.add_argument("-o", "--out", help="输出 markdown")
    dy.add_argument("--json", help="输出 JSON")
    dy.set_defaults(func=lambda a: __import__("fwmap.dyn", fromlist=["run"]).run(a))

    st = sub.add_parser("setup", help="下载安装 Ghidra / JDK（换机器后先跑这个）")
    st.add_argument("--ghidra", action="store_true", help="只装 Ghidra")
    st.add_argument("--jdk", action="store_true", help="只装 JDK")
    st.add_argument("--all", action="store_true", help="两个都装（默认）")
    st.add_argument("--dir", help="装到哪里（默认 包目录\\tools）")
    st.add_argument("--java", default="25", help="JDK 主版本（Ghidra 12.2 要求 25）")
    st.add_argument("--force", action="store_true", help="已存在也重装")
    st.add_argument("--dry-run", action="store_true", help="只打印计划，不下载")
    st.add_argument("--from", dest="from_zip", help="已手动下好的 Ghidra zip 路径（网络不通时用）")
    st.set_defaults(func=lambda a: __import__("fwmap.setup", fromlist=["run"]).run(a))

    m = sub.add_parser("m2", help="端点 → handler 映射（需要 Ghidra）")
    m.add_argument("binary", help="M1 排在前面的单个 ELF")
    m.add_argument("-o", "--output", help="输出 JSON")
    m.set_defaults(func=cmd_m2)

    m3 = sub.add_parser("m3", help="源/汇提取（需要 Ghidra）")
    m3.add_argument("binary", help="M1 排在前面的单个 ELF")
    m3.add_argument("-o", "--output", help="输出 JSON")
    m3.add_argument("--top", type=int, default=15)
    m3.add_argument("--induce", action="store_true", help="先做框架归纳，生成该固件的 source profile")
    m3.add_argument("--profile", help="使用已有的 source profile")
    m3.add_argument("--flow", action="store_true", help="跑 M3.2：数据流")
    m3.add_argument("--limit", type=int, default=40, help="数据流最多分析多少个函数（默认 40）")
    m3.set_defaults(func=cmd_m3)

    au = sub.add_parser("auth", help="端点鉴权检查：handler 及调用者里有没有认证（需要 Ghidra）")
    au.add_argument("binary", help="单个 ELF 文件")
    au.add_argument("-i", "--input", help="已有 M2 JSON（跳过 M2）")
    au.add_argument("-o", "--output", help="输出 JSON")
    au.add_argument("--limit", type=int, default=0, help="最多检查多少个已定位 handler（默认全部）")
    au.set_defaults(func=cmd_auth)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

def cmd_doctor(args) -> int:
    """把「换一台机器能不能跑」这件事变成一条命令。"""
    import os as _os
    import sys as _sys
    root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    ok_all = True

    def line(name, ok, detail="", soft=False):
        nonlocal ok_all
        mark = "[OK]  " if ok else ("[WARN]" if soft else "[MISS]")
        if not ok and not soft:
            ok_all = False
        print(f"{mark} {name:<10} {detail}")

    print(f"Python      {_sys.version.split()[0]}  ({_sys.executable})")
    line("包目录", _os.path.isdir(_os.path.join(root, "fwmap")), root)
    cat = _os.path.join(root, "fwmap", "data", "taint.txt")
    line("汇词表", _os.path.exists(cat), cat)

    from .m2 import find_ghidra
    g = find_ghidra()
    line("Ghidra", bool(g), g or "没找到（跑 py -3.13 -m fwmap setup）")

    # 随包 JDK（setup 装的）与系统 JDK 分开看：Ghidra 12.2 要求 25
    jdk_dir, jdk_ver = None, ""
    tools = _os.path.join(root, "tools")
    if _os.path.isdir(tools):
        for name in sorted(_os.listdir(tools)):
            p = _os.path.join(tools, name)
            if name.lower().startswith("jdk") and _os.path.isdir(p):
                jdk_dir = p
                rel = _os.path.join(p, "release")
                if _os.path.exists(rel):
                    for ln in open(rel, encoding="utf-8", errors="replace"):
                        if ln.startswith("JAVA_VERSION="):
                            jdk_ver = ln.split("=", 1)[1].strip().strip('"')
                break
    line("JDK", bool(jdk_dir), f"{jdk_ver}  {jdk_dir}" if jdk_dir else "没找到（setup 会装 Temurin 25）")

    # 离线 NVD 库：断网机器上 verify 全靠它，没有就明确报出来
    try:
        from .nvd import Index, find_db

        nd = find_db()
        if nd:
            _i = Index(nd)
            try:
                line("离线NVD", True,
                     f"{_i.count} 条 CVE，快照 {_i.built_at}，"
                     f"{_os.path.getsize(nd)/1048576:.0f} MB  {nd}")
            finally:
                _i.close()
        else:
            line("离线NVD", False,
                 "没有（verify 会回退联网；断网机器要跑 nvd fetch + nvd build）")
    except Exception as _e:                              # noqa: BLE001
        line("离线NVD", False, f"打不开：{_e}")

    if getattr(args, "agent", False):
        from .agent.llm import find_model
        m = find_model(verbose=True)
        line("本地模型", _os.path.isdir(m), m)
        try:
            import accelerate  # noqa: F401
            line("accelerate", True, accelerate.__version__)
        except Exception as ex:
            line("accelerate", False, f"{ex}（设 FWMAP_AGENT_LIBS 指向依赖目录）")

    print()
    print("结论：" + ("可以跑（M1 一定行；Ghidra 在的话 M2/M3 也行）" if ok_all
                     else "有缺项，见上面 MISS 行；M1（scan）仍可用"))
    return 0 if ok_all else 1
