"""`fwmap params`：给一个 URI，列出页面上的全部字段（静态 + 模型补的）。"""

import json
import os


def cmd_params(args) -> int:
    from . import param_llm

    chat = None
    if not args.no_llm:
        from . import llm

        def chat(messages, **kw):                      # noqa: E306
            return llm.chat(messages, **kw)

    res = param_llm.params_for_uri(args.rootfs, args.uri, chat=chat, log=print)

    print(f"URI: {res['uri']}")
    print(f"引用它的页面: {len(res['pages'])} 个")
    for p in res["pages"]:
        print("   ", os.path.relpath(p, args.rootfs))
    print(f"静态字段 {len(res['static'])} 个：{', '.join(res['static'][:12]) or '（无）'}")
    print(f"补全字段 {len(res['inferred'])} 个：{', '.join(res['inferred']) or '（无）'}")
    if res["dropped"]:
        print(f"被丢弃（页面里 grep 不到，判定模型编造）：{', '.join(res['dropped'])}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res, fh, ensure_ascii=False, indent=1)
        print(f"已写出：{args.json}")
    return 0 if (res["static"] or res["inferred"]) else 1
