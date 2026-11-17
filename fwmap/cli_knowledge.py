"""经验库的查看命令：把工具"记住的东西"摊开给人看。

为什么值得一个命令：经验库如果不可见，就等于没有 ——
你不知道它记了什么，也就不知道它下次为什么换了个判断。
"""

import json

from . import knowledge as kb


def cmd_knowledge(args) -> int:
    if getattr(args, "reset", None):
        kb.reset(args.reset)
        print(f"已清空：{args.reset}")

    if getattr(args, "json", False):
        data = {n: kb._load(n) for n in ("vendors", "lessons", "stats")}
        print(json.dumps(data, ensure_ascii=False, indent=1))
        return 0

    s = kb.summary()
    print(f"经验库：{s['dir']}")
    print(f"  厂商画像 {s['vendors']} 条 · 经验卡 {s['lessons']} 条 · "
          f"策略统计 {s['stats']} 条")

    vendors = kb._load("vendors")
    if vendors:
        print("\n== 厂商画像 ==")
        order = sorted(vendors.items(),
                       key=lambda kv: str((kv[1] or {}).get("updated_at", "")),
                       reverse=True)
        for key, v in order[:10]:
            bits = [f"跑过 {v.get('runs', 0)} 次"]
            if v.get("mechanism"):
                tail = "（验收通过）" if v.get("validated") else ""
                bits.append(f"机制 {v['mechanism']}{tail}")
            if v.get("routes"):
                bits.append(f"路由 {v['routes']} 条")
            if v.get("exec"):
                bits.append(f"命令执行 {v['exec']} 条")
            print(f"  {key:22s} " + " · ".join(bits))

    lessons = kb.lessons_for()
    if lessons:
        print("\n== 经验卡（按命中次数排序）==")
        for item in lessons[:10]:
            print(f"  [{item.get('hits', 1)}x] {item.get('text', '')[:90]}")

    stats = kb._load("stats")
    if stats:
        print("\n== 机制成功率 ==")
        ranked = sorted(stats.items(), key=lambda kv: int((kv[1] or {}).get("ok") or 0),
                        reverse=True)
        for _key, v in ranked[:10]:
            ok_n = int(v.get("ok") or 0)
            fail = int(v.get("fail") or 0)
            total = ok_n + fail
            print(f"  {str(v.get('mechanism', '?')):16s} @ {str(v.get('vendor', '?')):18s} "
                  f"{ok_n}/{total}")

    if not (vendors or lessons or stats):
        print("\n（还是空的：跑一次 triage 或 routes 就会开始攒）")
    return 0
