"""`fwmap plan`：把 agent 循环接到命令行上。

三件事在这里落地：

1. `--probe` 打开后，循环里的 probe 动作会**真的**把候选路由发给固件；
2. **完成状态**：有轨迹不等于做完了，退出码按 `status` 给，不再"跑过就返回 0"；
3. **交接文件**：无论正常结束还是中断，都写一份 `handoff.md` 给人接手。
"""

import json
import os
import time

# 退出码：调用方要能不读报告就区分"完成了"和"没完成"
EXIT_COMPLETED = 0
EXIT_INCOMPLETE = 2          # 预算用尽 / 无进展 / 一步没跑成
EXIT_DEP_MISSING = 3         # 请求了探针，但本机没有 qemu/chroot
EXIT_WRITE_FAILED = 4        # 结果写不出去

_STATUS_EXIT = {
    "completed": EXIT_COMPLETED,
    "budget_exhausted": EXIT_INCOMPLETE,
    "no_progress": EXIT_INCOMPLETE,
    "failed": EXIT_INCOMPLETE,
    "dependency_missing": EXIT_DEP_MISSING,
}


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


def _out_dir(args) -> str:
    """结果目录：--out-dir > --json 的父目录 > 当前目录。"""
    d = getattr(args, "out_dir", "") or ""
    if d:
        return os.path.abspath(d)
    if getattr(args, "json", ""):
        return os.path.dirname(os.path.abspath(args.json))
    return os.getcwd()


def _render_handoff(res: dict) -> str:
    h = res.get("handoff") or {}
    s = h.get("stats") or {}
    req = h.get("requested") or {}
    lines = [
        f"# 交接：{os.path.basename(h.get('binary') or '?')}"
        f"　{time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"- **完成状态**：`{h.get('status')}` —— {h.get('stop_reason')}",
        f"- **请求范围**：模型 {req.get('model')} · 探针 "
        f"{'开' if req.get('probe') else '关'} · 预算 {req.get('max_steps')} 步"
        f"{' · 候选匿名' if req.get('anonymize') else ''}",
        f"- **尚欠阶段**：{'、'.join(h.get('pending') or []) or '无'}",
        "",
    ]

    findings = h.get("findings") or []
    lines.append("## 已经确认的")
    if not findings:
        lines.append("- （没有形成任何结论）")
    for f in findings:
        strength = ("进程退出已确认" if f.get("support") == "process-exit"
                    else "仅观测到空响应，进程状态未确认")
        lines.append(f"- `{f.get('uri')}` {f.get('kind')}（{strength}）"
                     f"：{f.get('why') or '（无语由）'}")
        for e in f.get("evidence") or []:
            lines.append(f"  - 证据：`{e}`")

    lines.append("")
    lines.append("## 记录到的观测")
    ev = h.get("evidence") or {}
    if not ev:
        lines.append("- （没有探测记录）")
    for uri, d in ev.items():
        lines.append(f"- `{uri}` → {d.get('len')}B · {d.get('verdict')}"
                     + (f" · 首行 `{d['snippet']}`" if d.get("snippet") else ""))

    lines.append("")
    lines.append("## 归因")
    if s:
        lines.append(f"- 模型决定 {s.get('model_steps')} 步 / 主动规则 "
                     f"{s.get('rule_steps')} 步 / 兜底 {s.get('fallback_steps')} 步")
        if s.get("rejects"):
            kinds = "、".join(f"{k} {v}" for k, v in s["reject_kinds"].items())
            lines.append(f"- 模型被拒 {s['rejects']} 次：{kinds}")
        if s.get("verdict_tried"):
            lines.append(f"- 结论 {s.get('verdict_accepted')}/{s.get('verdict_tried')}")
        else:
            lines.append("- 结论：不适用（本轮没有尝试下结论）")

    lines.append("")
    lines.append("## 卡在哪 / 建议下一步")
    if h.get("status") == "completed":
        lines.append("- 本次按预期收工；若要继续，建议换更强的模型或扩候选来源")
    elif h.get("status") == "dependency_missing":
        lines.append("- 探针不可用：先确认本机有 qemu-user 且能 chroot 起服务")
    elif h.get("status") == "no_progress":
        lines.append("- 流程判定无进展而停：检查候选来源是否枯竭，"
                     "或换一种路由抽取机制")
    else:
        lines.append(f"- 未完成（{h.get('stop_reason')}）：可加预算重跑，"
                     "或先处理上面「尚欠阶段」")
    if h.get("pending"):
        lines.append(f"- 还没做到：{'、'.join(h['pending'])}")
    return "\n".join(lines) + "\n"


def cmd_plan(args) -> int:
    from . import loop

    chat = None
    temp = float(getattr(args, "temperature", 0.0) or 0.0)
    if not args.no_llm:
        from . import llm

        def chat(messages, **kw):                      # noqa: E306
            kw["temperature"] = temp        # 0=贪心（可复现），>0=采样（测鲁棒性）
            return llm.chat(messages, **kw)

    print(f"目标：{args.binary}")
    print(f"rootfs：{args.rootfs or '（无）'}   最大步数：{args.max_steps}"
          f"   模型：{'关' if args.no_llm else '开'}"
          f"   温度：{temp}"
          f"   探针：{'开' if getattr(args, 'probe', False) else '关'}"
          f"{'   候选匿名' if getattr(args, 'anonymize', False) else ''}")

    want_probe = bool(getattr(args, "probe", False))
    probe = _make_probe(args, print)

    res = loop.run(args.binary, args.rootfs, chat=chat, max_steps=args.max_steps,
                   probe=probe, arch=args.arch, log=print,
                   anonymize=bool(getattr(args, "anonymize", False)),
                   want_probe=want_probe)

    print()
    print(f"跑了 {res['steps']} 步，抽到路由 {res['routes']} 条，"
          f"能应答 {res['handlers']} 条")
    print("动作序列：" + " → ".join(t.get("action", "?") for t in res["trace"]))
    print(f"完成状态：{res['status']} —— {res['stop_reason']}")
    if res.get("pending"):
        print(f"尚欠阶段：{'、'.join(res['pending'])}")
    if res["probed"]:
        print("端点探测结果：")
        for uri, verdict in res["probed"].items():
            print(f"  {'✓' if verdict == 'handler' else '·'} {uri:44s} {verdict}")
    if res.get("findings"):
        print("模型下的结论（已过规则核验）：")
        for f in res["findings"]:
            strength = ("进程退出已确认" if f.get("support") == "process-exit"
                        else "仅观测到空响应")
            print(f"  [{f['kind']}/{strength}] {f['uri']} —— {f['why']}")
            for e in f.get("evidence") or []:
                print(f"        证据：{e}")

    s = res.get("stats") or {}
    if s:
        print()
        print(f"自评：{s['steps']} 步 —— 模型决定 {s['model_steps']} 步，"
              f"主动规则 {s['rule_steps']} 步，兜底 {s['fallback_steps']} 步"
              f"（模型参与 {s['model_share'] * 100:.0f}%）")
        if s.get("rejects"):
            kinds = "、".join(f"{k} {v}" for k, v in s["reject_kinds"].items())
            print(f"      模型被拒 {s['rejects']} 次：{kinds}")
        print(f"      探测 {s['probed']} 条端点：handler {s['handlers']} 条，"
              f"异常 {len(s['anomalies'])} 条")
        if s.get("verdict_tried"):
            print(f"      模型下结论 {s['verdict_tried']} 次，通过核验 "
                  f"{s['verdict_accepted']} 次"
                  f"（{s['verdict_accept_rate'] * 100:.0f}%）")
        else:
            print("      结论采纳率：不适用（本轮没有尝试下结论）")

    # 写结果：JSON 与交接文件都要能落地，写不出去要能从退出码看出来
    try:
        out_dir = _out_dir(args)
        os.makedirs(out_dir, exist_ok=True)
        if args.json:
            os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump({"trace": res["trace"], "status": res["status"],
                           "stop_reason": res["stop_reason"],
                           "pending": res["pending"],
                           "candidates": res["candidates"],
                           "probed": res["probed"], "handlers": res["handlers"],
                           "findings": res.get("findings") or [],
                           "evidence": res.get("evidence") or {},
                           "stats": res.get("stats") or {}},
                          fh, ensure_ascii=False, indent=1)
            print(f"trace 已写出：{args.json}")
        handoff_path = os.path.join(out_dir, "handoff.md")
        with open(handoff_path, "w", encoding="utf-8") as fh:
            fh.write(_render_handoff(res))
        print(f"交接文件：{handoff_path}")
    except OSError as exc:                              # noqa: BLE001
        print(f"[!] 结果写不出去：{exc}")
        return EXIT_WRITE_FAILED

    return _STATUS_EXIT.get(res["status"], EXIT_INCOMPLETE)
