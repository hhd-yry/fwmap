"""把 unpack 接成命令：fwmap unpack <镜像> -o <目录> [--no-llm]"""
import json

from . import unpack as U


def cmd_unpack(args) -> int:
    from .agent import llm

    chat = None
    if getattr(args, "no_llm", False):
        def chat(messages, **kw):                       # noqa: E306
            # 不问模型：按 binwalk → 7z → unsquashfs 的兜底顺序
            return '{"attempts": [{"tool": "binwalk"}, {"tool": "7z"}, ' \
                   '{"tool": "unsquashfs"}], "unsolvable": false}'

    out = U.unpack(args.image, args.out, chat=chat, log=print)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False, indent=1)
        print(f"\n已写出：{args.json}")
    if not out["ok"]:
        print("\n[!] 没解开。这台固件的壳目前处理不了 ——"
              " 这不是「固件坏了」，是能力边界。")
        return 1
    print(f"\n[+] rootfs: {out['rootfs']}  （用 {out['tool']} 解出来的）")
    return 0
