"""`fwmap extract`：用工具总线解包/拆壳（模型排顺序，验收决定成不成）。"""

import json

from . import toolbus


def cmd_extract(args) -> int:
    from . import tools_unpack

    tools_unpack.register_all()

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
