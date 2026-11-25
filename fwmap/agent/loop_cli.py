"""`fwmap plan`：把 agent 循环接到命令行上。"""

import json
import os


def cmd_plan(args) -> int:
    from . import loop

    chat = None
    if not args.no_llm:
        from . import llm

        def chat(messages, **kw):                      # noqa: E306
            return llm.chat(messages, **kw)

    print(f"目标：{args.binary}")
    print(f"rootfs：{args.rootfs or '（无）'}   最大步数：{args.max_steps}"
          f"   模型：{'关' if args.no_llm else '开'}")

    res = loop.run(args.binary, args.rootfs, chat=chat, max_steps=args.max_steps,
                   arch=args.arch, log=print)

    print()
    print(f"跑了 {res['steps']} 步，抽到路由 {res['routes']} 条，"
          f"能应答 {res['handlers']} 条")
    print("动作序列：" + " → ".join(t.get("action", "?") for t in res["trace"]))

    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res["trace"], fh, ensure_ascii=False, indent=1)
        print(f"trace 已写出：{args.json}")
    return 0 if res["ok"] or res["trace"] else 1
