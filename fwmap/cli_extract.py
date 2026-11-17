"""`fwmap extract`：用工具总线解包/拆壳（模型排顺序，验收决定成不成）。"""

import json
import os

from . import toolbus


def cmd_extract(args) -> int:
    from . import tools_unpack, tools_unwrap

    tools_unpack.register_all()
    tools_unwrap.register_all()
    if getattr(args, "external", None):
        n = tools_unwrap.load_external(args.external)
        print(f"挂载外部脚本 {n} 个：{args.external}")

    cap = args.capability
    cat = toolbus.catalog(cap)
    if not cat:
        print(f"[!] 没有注册任何 {cap} 类工具")
        return 2

    ready = [c for c in cat if c["available"]]
    print(f"{cap} 类工具 {len(cat)} 个，其中这台机器装了 {len(ready)} 个：")
    for c in cat:
        flag = "✓" if c["available"] else "·"
        print(f"  {flag} {c['name']:14s} {c['note'][:52]}")

    if not ready:
        print("\n[!] 一个都没装 —— 先装工具，或者换一台 Linux 机器跑")
        return 2

    chat = None
    if not args.no_llm:
        from .agent import llm

        def chat(messages, **kw):                       # noqa: E306
            return llm.chat(messages, **kw)

    evidence = {"file": args.image}
    try:                                                # 有解包模块就带上证据
        from . import unpack

        evidence = unpack.evidence(args.image)
    except Exception:                                   # noqa: BLE001
        pass

    order = toolbus.choose(args.image, capability=cap, chat=chat, evidence=evidence,
                           log=print)
    print(f"\n尝试顺序：{' → '.join(order)}")
    res = toolbus.run_chain(args.image, args.out, order, log=print,
                            lessons_scope=getattr(args, "scope", "") or "")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res, fh, ensure_ascii=False, indent=1, default=str)
        print(f"已写出：{args.json}")

    if not res["ok"]:
        print("\n[!] 按这个顺序都没通过验收 —— 记一条经验，下次换着试。")
        return 1
    print(f"\n[+] 通过验收：{res['tool']} → {res['dir']}")
    return 0


def cmd_analyze(args) -> int:
    """对一个二进制跑所有能用的静态分析工具，汇总成一份事实表。

    这不是"串联"（分析工具之间不是替代关系），而是"并行取证"：
    readelf 给架构/入口、rizin 给函数表、rabin2 给加固项，
    谁的输出过不了验收，就不采信谁。
    """
    from . import tools_analyze

    tools_analyze.register_all()
    tools = toolbus.all_tools("analyze")
    if args.tool:
        tools = [t for t in tools if t.name == args.tool]

    ready = [t for t in tools if t.available()]
    print(f"analyze 类工具 {len(tools)} 个，可用 {len(ready)} 个")
    if not ready:
        print("[!] 这台机器一个都没装（readelf/rabin2/rizin/lief）")
        return 2

    import tempfile

    # 不给 -o 就落到临时目录：绝不能在当前目录建 `lief/` 这种同名文件夹，
    # 否则 Python 会把它当成同名包，下次 import lief 直接拿到一个空模块。
    outroot = args.out or tempfile.mkdtemp(prefix="fwmap-analyze-")
    facts, results = {}, []
    for tool in ready:
        print(f"[analyze] {tool.name} …")
        res = toolbus.run(tool, args.binary, os.path.join(outroot, tool.name))
        results.append({"tool": tool.name, "ok": res["ok"],
                        "detail": res.get("detail") or res.get("error")})
        print(f"  {'✓' if res['ok'] else '·'} {res.get('detail') or res.get('error')}")
        if res["ok"]:
            facts[tool.name] = res.get("detail")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"binary": args.binary, "facts": facts, "results": results},
                      fh, ensure_ascii=False, indent=1)
        print(f"已写出：{args.json}")

    ok_n = sum(1 for r in results if r["ok"])
    print(f"\n{ok_n}/{len(results)} 个工具给出了可采信的事实")
    return 0 if ok_n else 1


def cmd_emulate(args) -> int:
    """全系统模拟：按 profile 起 qemu-system，探端口/串口，判"到底起来没有"。"""
    from . import tools_emulate as TE

    TE.register_all()
    prof = TE.load_profile(args.profile)
    print(f"profile: {prof.name} · 端口 {prof.ports or '无'} · 等待 {prof.wait}s")

    res = TE.run_emulation(args.image, args.out, prof)
    print(f"结果：{'起来了' if res['booted'] else '没起来'}（{res.get('seconds')}s）")
    for p, up in (res.get("ports") or {}).items():
        print(f"  端口 {p}: {'✓ 通' if up else '· 不通'}")
    if res.get("markers"):
        print(f"  串口标记: {', '.join(res['markers'])}")
    if not res["booted"] and res.get("serial_tail"):
        print("  串口最后几行：")
        for line in res["serial_tail"].strip().splitlines()[-5:]:
            print("   ", line[:110])

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res, fh, ensure_ascii=False, indent=1)
        print(f"已写出：{args.json}")
    return 0 if res["booted"] else 1
