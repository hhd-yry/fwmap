"""`fwmap plan`：把 agent 循环接到命令行上。

关键在 `--probe`：打开之后，循环里的 probe 动作会**真的**把候选路由发给固件
（起 chroot + qemu-user 的 httpd，三对照判定 handler / not-found）。
端点清单交给模型挑 —— 这是"模型会不会挑端点"能被量化对比的前提。
"""

import json
import os


def _make_probe(args, log):
    """按需建探针。没有 qemu / 服务起不来就返回 None，让循环如实降级。"""
    if not getattr(args, "probe", False):
        return None
    if not args.rootfs:
        log("[!] 没有 --rootfs，起不了固件服务，probe 关掉")
        return None
    from .. import discover

    prob = discover.firmware_probe(args.binary, args.rootfs,
                                   port=int(getattr(args, "probe_port", 80) or 80),
                                   log=log)
    if prob is None:
        log("[!] 找不到能跑这个二进制的 qemu（或 chroot 起不来）—— probe 关掉")
        log("    这不影响静态部分，但「端点真不真」这次没有固件自证")
    return prob


def cmd_plan(args) -> int:
    from . import loop

    chat = None
    if not args.no_llm:
        from . import llm

        def chat(messages, **kw):                      # noqa: E306
            return llm.chat(messages, **kw)

    print(f"目标：{args.binary}")
    print(f"rootfs：{args.rootfs or '（无）'}   最大步数：{args.max_steps}"
          f"   模型：{'关' if args.no_llm else '开'}"
          f"   探针：{'开' if getattr(args, 'probe', False) else '关'}")

    probe = _make_probe(args, print)

    res = loop.run(args.binary, args.rootfs, chat=chat, max_steps=args.max_steps,
                   probe=probe, arch=args.arch, log=print)

    print()
    print(f"跑了 {res['steps']} 步，抽到路由 {res['routes']} 条，"
          f"能应答 {res['handlers']} 条")
    print("动作序列：" + " → ".join(t.get("action", "?") for t in res["trace"]))
    if res["probed"]:
        print("端点探测结果：")
        for uri, verdict in res["probed"].items():
            print(f"  {'✓' if verdict == 'handler' else '·'} {uri:44s} {verdict}")

    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"trace": res["trace"], "candidates": res["candidates"],
                       "probed": res["probed"], "handlers": res["handlers"]},
                      fh, ensure_ascii=False, indent=1)
        print(f"trace 已写出：{args.json}")
    return 0 if res["ok"] or res["trace"] else 1
