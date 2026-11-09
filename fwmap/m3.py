"""M3.1：源/汇提取（调用 Ghidra headless）。

只做检索，不做判断：
  - 汇（sink）是符号问题，规则匹配接近 100%；
  - 源（source）只是候选，最终是不是外部可控，要 M3.2 的数据流和 M3.3 的语义来定。

用法：
    python -m fwmap m3 <binary> [-o out.json]
环境：
    GHIDRA_HOME   Ghidra 安装目录
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

from .m2 import find_ghidra, run_ghidra, _script_dir, TIMEOUT as _GHIDRA_TIMEOUT

SCRIPT_NAME = "ExtractSourceSink.java"


def catalog_path() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "data", "taint.txt")


def induce(binary: str, ghidra_home: str | None = None, min_calls: int = 3,
           min_distinct: int = 2, timeout: int = _GHIDRA_TIMEOUT) -> list[dict]:
    """框架归纳：找出"被很多调用点用不同字符串常量调用"的函数（取参 API 的形状）。

    阈值 (5, 3) —— **回滚过一次，别再降**。
    试过降到 (3, 2)：DIR-842 的表单取值函数 `FUN_0041c560` 确实能收进来
    （它只有 3 个调用点：ACTION / LOGINPASSWORD / USERNAME），DIR-842 的
    CVE 链也出来了。但代价是 M3.1 的候选池从 X 涨到 312，
    TP-Link 的 `FUN_00453c50` 从池内掉到 **137/800**、D-Link 的 genacgi_main、
    TOTOLINK 的 FUN_0042d3b4 同样被挤出 limit 40 —— 三个调参集正例全丢。
    结论：**降阈值不是"多收一点"，是重排整个池**。要收小函数，得改成
    "显式源跑完一遍、再用诱导源补第二轮"的取池，而不是直接放宽阈值。
    """
    home = ghidra_home or find_ghidra()
    if not home:
        raise RuntimeError("找不到 Ghidra：设置 GHIDRA_HOME 环境变量")
    headless = os.path.join(home, "support", "analyzeHeadless.bat")
    if not os.path.exists(headless):
        headless = os.path.join(home, "support", "analyzeHeadless")

    base = os.environ.get("FWMAP_M2_DIR") or os.path.join(os.getcwd(), "fwmap-m2")
    os.makedirs(base, exist_ok=True)
    tmpdir = os.path.join(base, f"induce-{os.getpid()}-{os.getpid() % 97}")
    proj = os.path.join(tmpdir, "proj")
    os.makedirs(proj, exist_ok=True)
    cmd = [headless, proj, "induce", "-import", binary, "-overwrite",
           "-scriptPath", _script_dir(), "-postScript", "InduceSources.java",
           str(min_calls), str(min_distinct)]
    try:
        out = run_ghidra(cmd, timeout, label=os.path.basename(binary))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    dec = json.JSONDecoder()
    rows = []
    for line in out.splitlines():
        i = line.find('{"api"')
        if i < 0:
            continue
        try:
            rows.append(dec.raw_decode(line[i:])[0])
        except json.JSONDecodeError:
            pass
    return rows


def induce_sinks(binary: str, ghidra_home: str | None = None, max_depth: int = 1,
                 timeout: int = _GHIDRA_TIMEOUT) -> list[dict]:
    """汇归纳：沿调用图反向找"直接/间接调用 system/popen/exec*"的函数。

    和 source 归纳对称：厂商固件普遍把 system 包一层（D-Link 的 lxmldbc_system、
    Realtek 的 doSystem），手写白名单换一家厂商就漏。

    默认只取深度 1（**直接**调用执行原语的函数）——深度 2 会把 handler 本身
    也当成汇（实测 D-Link 上 servicecgi_main / dlcfg_main 都被诱导出来），
    那样任何传给 handler 的污染都会报成命令注入，噪声不可接受。
    """
    home = ghidra_home or find_ghidra()
    if not home:
        raise RuntimeError("找不到 Ghidra：设置 GHIDRA_HOME 环境变量")
    headless = os.path.join(home, "support", "analyzeHeadless.bat")
    if not os.path.exists(headless):
        headless = os.path.join(home, "support", "analyzeHeadless")

    base = os.environ.get("FWMAP_M2_DIR") or os.path.join(os.getcwd(), "fwmap-m2")
    os.makedirs(base, exist_ok=True)
    tmpdir = os.path.join(base, f"sinks-{os.getpid()}")
    proj = os.path.join(tmpdir, "proj")
    os.makedirs(proj, exist_ok=True)
    cmd = [headless, proj, "sinks", "-import", binary, "-overwrite",
           "-scriptPath", _script_dir(), "-postScript", "InduceSinks.java",
           str(max_depth)]
    try:
        out = run_ghidra(cmd, timeout, label=os.path.basename(binary))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    dec = json.JSONDecoder()
    rows = []
    for line in out.splitlines():
        i = line.find('{"api"')
        if i < 0:
            continue
        try:
            rows.append(dec.raw_decode(line[i:])[0])
        except json.JSONDecodeError:
            pass
    return rows


def extract(binary: str, ghidra_home: str | None = None, timeout: int = _GHIDRA_TIMEOUT,
            profile: str | None = None) -> dict:
    home = ghidra_home or find_ghidra()
    if not home:
        raise RuntimeError("找不到 Ghidra：设置 GHIDRA_HOME 环境变量")
    headless = os.path.join(home, "support", "analyzeHeadless.bat")
    if not os.path.exists(headless):
        headless = os.path.join(home, "support", "analyzeHeadless")

    cat = catalog_path()
    if profile:
        # 目录 + 该固件归纳出来的 API，合并成临时文件给脚本
        merged = cat + ".merged.txt"
        with open(merged, "w", encoding="utf-8") as dh:
            dh.write(open(cat, encoding="utf-8").read())
            dh.write("\n# ---- induced profile ----\n")
            dh.write(open(profile, encoding="utf-8").read())
        cat = merged

    base = os.environ.get("FWMAP_M2_DIR") or os.path.join(os.getcwd(), "fwmap-m2")
    os.makedirs(base, exist_ok=True)
    tmpdir = os.path.join(base, f"m3-{os.getpid()}")
    proj = os.path.join(tmpdir, "proj")
    os.makedirs(proj, exist_ok=True)

    cmd = [headless, proj, "m3", "-import", binary, "-overwrite",
           "-scriptPath", _script_dir(),
           "-postScript", SCRIPT_NAME, cat, os.path.join(tmpdir, "out.jsonl")]
    jl = os.path.join(tmpdir, "out.jsonl")
    raw_lines: list[str] = []
    try:
        out = run_ghidra(cmd, timeout, label=os.path.basename(binary))
        if os.path.exists(jl):
            with open(jl, encoding="utf-8", errors="replace") as fh:
                raw_lines = fh.readlines()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    dec = json.JSONDecoder()
    rows = []
    summary = {}
    # 结果从文件读（脚本直接写），stdout 只用来取 SUMMARY
    for line in raw_lines:
        i = line.find('{"function"')
        if i < 0:
            continue
        try:
            rows.append(dec.raw_decode(line[i:])[0])
        except json.JSONDecodeError:
            pass
    for line in out.splitlines():
        j = line.find("SUMMARY ")
        if j >= 0:
            for kv in line[j + 8:].split(")")[0].split():
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    summary[k.strip()] = int(v) if v.isdigit() else v

    if not summary and rows:
        summary = {"funcs": len(rows)}

    both = [r for r in rows if r["sources"] and r["sinks"]]
    return {
        "binary": binary,
        "summary": summary,
        "functions": rows,
        "candidates": both,
        "returncode": 0,
        "stderr_tail": "",
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="fwmap m3", description="M3.1 源/汇提取（Ghidra）")
    ap.add_argument("binary", help="单个 ELF 文件")
    ap.add_argument("-o", "--output", help="输出 JSON")
    ap.add_argument("--top", type=int, default=15, help="控制台显示前 N 条候选（默认 15）")
    ap.add_argument("--induce", action="store_true", help="先做框架归纳，生成该固件的 source profile")
    ap.add_argument("--profile", help="使用已有的 source profile（taint 片段）")
    ap.add_argument("--flow", action="store_true", help="跑 M3.2：数据流")
    ap.add_argument("--limit", type=int, default=40,
                    help="数据流最多分析多少个函数（默认 40；调大能覆盖更多 handler，但很慢）")
    args = ap.parse_args(argv)

    profile = args.profile
    if args.induce:
        # 归纳阈值按二进制大小自适应。
        # 证据：DIR-842 cgibin（225 KB）里私有取值函数只有 3 个调用点，阈值 5 收不到，
        #       而 TP-Link wr940n（1.7 MB）一旦降到 3，候选池从 X 涨到 312，
        #       FUN_00453c50 从池内掉到 137/800，CVE 直接丢。
        # 稀释是池子大小的函数：小二进制没有这个问题，大二进制一降就翻车。
        size_kb = os.path.getsize(args.binary) // 1024
        mc, md = (3, 2) if size_kb < 512 else (5, 3)
        print(f"[*] 框架归纳中（{size_kb} KB -> 阈值 {mc}/{md}）…")
        rows = induce(args.binary, min_calls=mc, min_distinct=md)
        print(f"[*] 归纳出 {len(rows)} 个候选 API")
        if rows:
            print(f"    {'API':<22}{'调用':>6}{'不同字符串':>10}  样例")
            for r in rows[:10]:
                sample = ", ".join(r["strings"][:4])
                print(f"    {r['api']:<22}{r['calls']:>6}{r['distinct']:>10}  {sample[:60]}")
            profile = os.path.splitext(args.binary)[0] + ".taint.txt"
            with open(profile, "w", encoding="utf-8") as fh:
                fh.write("# 由 InduceSources / InduceSinks 归纳，人工复核后再当 source/sink 用\n")
                for r in rows:
                    # 配置键名通常带点（dhcp.dns.auto、ppoe.userid）；
                    # 表单字段名通常是驼峰（lanIp、startIp）——用这个粗略分流。
                    sample = r["strings"] or []
                    dotted = sum(1 for s in sample if "." in s)
                    # 归纳出来的源一律是"弱证据"：日志函数、错误上报、inet_ntop 包装
                    # 全都长成"被很多调用点用不同字符串调用"的样子。P2 实测新固件上
                    # 4/4 的强源假阳性都来自这里，所以单独记 source-induced，
                    # 不写进 source（强源），和 sink-ci-induced 对称。
                    kind = "source-weak" if sample and dotted > len(sample) / 2 else "source-induced"
                    fh.write(f"{kind} {r['api']}\n")
                # 汇归纳：直接调用 system/popen/exec* 的包装函数
                sink_rows = []
                try:
                    sink_rows = induce_sinks(args.binary)
                except Exception as e:                      # noqa: BLE001
                    print(f"[!] 汇归纳失败（忽略）：{e}")
                if sink_rows:
                    print(f"[*] 归纳出 {len(sink_rows)} 个命令执行包装函数（sink-ci）")
                    for r in sink_rows[:8]:
                        print(f"    {r['api']:<24} 距离={r.get('distance')} via={r.get('via')}")
                for r in sink_rows:
                    fh.write(f"sink-ci-induced {r['api']}\n")
            print(f"[+] profile: {profile}")

    r = extract(args.binary, profile=profile)
    s = r["summary"]
    print(f"[*] 函数 {s.get('funcs', '?')} · 有源 {s.get('with_source', '?')} · "
          f"有汇 {s.get('with_sink', '?')} · **同时有源和汇 {s.get('with_both', '?')}**")

    for f in r["candidates"][: args.top]:
        srcs = ", ".join(f"{x['api']}({x['param']})" if x["param"] else x["api"] for x in f["sources"])
        snks = ", ".join(f"{x['api']}[{x['category']}]" for x in f["sinks"])
        print(f"\n  {f['function']} @ {f['address']}")
        print(f"    源: {srcs}")
        print(f"    汇: {snks}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(r, fh, ensure_ascii=False, indent=2)
        print(f"\n[+] {args.output}")

    if args.flow:
        from .m3flow import run_flow, normalize_weak, _load_catalog

        print("\n[*] M3.2 数据流…")
        # 强源重判：getenv("REQUEST_URI") 这类是外部输入，不该按弱源处理。
        # 不重判的话，CGI 型固件的 handler（只有 getenv）永远进不了下面这个池。
        _src, _snk, _weak = _load_catalog(catalog_path())
        if profile and os.path.exists(profile):
            _s2, _k2, _w2 = _load_catalog(profile)
            _weak.update(_w2)
        _flipped = normalize_weak(r["functions"], _weak)
        if _flipped:
            print(f"    强源重判：{_flipped} 条 getenv(REQUEST_URI/HTTP_*) 由弱转强")
        # 候选池要包含"有强源但本函数没有汇"的函数——它们的 sink 在 helper 里
        # （实测 formSetMacFilterCfg 就是这样，只放 source+sink 的会直接漏掉）。
        pool = list(r["candidates"]) + [
            fn for fn in r["functions"]
            if fn["sources"] and not fn["sinks"]
            and any(not s["weak"] for s in fn["sources"])
        ]
        f = run_flow(args.binary, pool, profile=profile, limit=args.limit)
        chains = f["chains"]
        kept = [c for c in chains if c.get("verdict", "keep") == "keep"]
        demoted = [c for c in chains if c.get("verdict") == "demoted"]
        # 弱源（nvram_get 这类从配置读的）单独成组：它们不是远程输入，
        # 和 websGetVar/get_cgi 混在一起会让"待读清单"虚高。
        # 实测 TOTOLINK/Cisco 上弱源链占 40%~73%，剔掉之后链级精度 ~48% → ~82%。
        # 归纳出来的源（source-induced）同理：它是"形状像取参 API"，不是确认过的输入点。
        strong = [c for c in kept
                  if not c.get("weak") and not c.get("induced_sink")
                  and not c.get("induced_source")]
        weakc = [c for c in kept
                 if c.get("weak") or c.get("induced_sink") or c.get("induced_source")]
        print(f"    反编译 {f['decompiled']} 个函数，找到 {len(chains)} 条 source→sink 链")
        print(f"    规则去噪后保留 {len(kept)} 条（强源 {len(strong)} / 弱源 {len(weakc)}），"
              f"降级 {len(demoted)} 条"
              f"（1 跳 {sum(1 for c in kept if c['hops'] == 1)} / "
              f"多跳 {sum(1 for c in kept if c['hops'] > 1)}）")
        if strong:
            print("    ── 强源（远程可控，优先看）──")
            for c in strong[:10]:
                hop = f"×{c['hops']}跳" if c["hops"] > 1 else ""
                print(f"    {c['function']:<28} {c['source_api']}({c['source_param']}) "
                      f"-> {c['sink']}[{c['sink_category']}] {hop} [{c['confidence']}]")
        if weakc:
            print(f"    ── 弱源（配置值，需先确认能不能被写脏）共 {len(weakc)} 条，"
                  f"这里只列 5 条 ──")
            for c in weakc[:5]:
                print(f"    {c['function']:<28} {c['source_api']}({c['source_param']}) "
                      f"-> {c['sink']}[{c['sink_category']}]")
        f["summary"] = {"kept": len(kept), "strong": len(strong), "weak": len(weakc),
                        "demoted": len(demoted)}
        if args.output:
            jout = os.path.splitext(args.output)[0] + ".flow.json"
            with open(jout, "w", encoding="utf-8") as fh:
                json.dump(f, fh, ensure_ascii=False, indent=2)
            print(f"    [+] {jout}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
