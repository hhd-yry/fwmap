"""让本地模型参与「下一步调哪个工具」的决策。

为什么不是让模型全权做主：7B 在 8 GB 卡上做工具选择并不稳定，**选错一次的代价
是等 Ghidra 跑十分钟**。所以这里的分工是：

    模型提议 → 程序校验 → 不合格就退回规则 planner

校验是硬性的，不靠模型自觉：

- 工具名必须在注册表里；
- 必填参数必须给全（缺了就不执行，直接退规则）；
- 同一个 (工具, 参数) 不许连做两次（防原地打转）；
- 解析不出 JSON、或者模型直接答非所问，一律退规则。

这样即使模型今天状态很差，整个流程也不会比纯规则更糟。
"""

from __future__ import annotations

import json

PROMPT = """你在控制一个固件分析工具，每一步只能调用一个工具。

可用工具（名字 + 用途 + 参数）：
{catalog}

当前状态：
{state}

请选择下一步。判断原则：
1. 还没确认解包完整性 → check；还没选目标 → scan；
2. 有目标但没做端点映射 → m2；有端点但没出链 → m3；
3. 出了链但没核对过 → verify；有未命中的函数且能动态验证 → dyn；
4. 已经没什么可做，或者关键工具缺依赖 → 返回 done。

不要重复调用「刚才已经做过、参数也没变」的工具；「已经跑过」那一栏里的步骤直接跳过。

只输出一个 JSON 对象，二选一：
{{"tool": "工具名", "args": {{...}}, "why": "一句话说明为什么这一步"}}
{{"done": true, "why": "一句话说明为什么停"}}
"""


def _state_brief(state: dict) -> str:
    """把状态压成几行 —— 模型不需要看原始 JSON，只需要判断依据。"""
    lines = [f"- rootfs: {state.get('rootfs')}"]
    if state.get("skip_ghidra"):
        lines.append("- 模式: 只做不依赖 Ghidra 的步骤（m2/m3/dyn/bof 都不可用）")
    if state.get("checked"):
        lines.append(f"- 解包自检: {'通过' if state.get('check_clean') else '有阻断项'}")
    targets = state.get("targets") or []
    if targets:
        lines.append(f"- 已选目标: {targets[0].get('path')}（分数 {targets[0].get('score')}）")
    if state.get("endpoints"):
        lines.append(f"- 端点: {len(state['endpoints'])} 个")
    chains = state.get("chains") or []
    if chains:
        cats = {}
        for c in chains:
            k = c.get("sink_category", "?")
            cats[k] = cats.get(k, 0) + 1
        lines.append(f"- 链: {len(chains)} 条（{', '.join(f'{k}×{v}' for k, v in cats.items())}）")
    if state.get("verified"):
        st = state.get("verify_stat") or {}
        lines.append(f"- 新颖性: 已公开 {st.get('known', 0)} / 未命中 {st.get('unknown', 0)}")
        if state.get("unknown_fns"):
            lines.append(f"- 未命中函数: {', '.join(state['unknown_fns'][:6])}")
    done = sorted(state.get("plugins_done") or [])
    lines.append(f"- 插件调用过: {', '.join(done) or '（无）'}")
    # 已经跑过的内置工具必须写清楚：不写的话模型会反复提议同一个动作，
    # 每次都被规则拦下 —— 流程没错，但白烧 token、日志也难看。
    hist = state.get("history") or []
    if hist:
        ran = [f"{h['tool']}（{h.get('source', 'rule')}）→ {h['result'].get('summary', '')[:24]}"
               for h in hist[-4:]]
        lines.append("- 已经跑过: " + "；".join(ran))
    return "\n".join(lines)


def choose(state: dict, catalog: list[dict], model_path: str | None = None,
           log=None, hint: str = "") -> dict | None:
    """让模型选下一步。返回 {tool, kwargs, why, source: 'llm'} 或 None（表示 done/失败）。

    `hint` 用来告诉模型「你上一手被拒了，为什么」——小模型会重复同一个错误动作，
    给一次带原因的反馈，比直接退回规则更有机会纠正。
    """
    from . import llm as L

    prompt = PROMPT.format(
        catalog=json.dumps(catalog, ensure_ascii=False)[:3000],
        state=_state_brief(state))
    if hint:
        prompt += f"\n注意：{hint}"
    try:
        text = L.chat([{"role": "user", "content": prompt}],
                      max_new_tokens=200, temperature=0.0, model_path=model_path)
    except Exception as e:                                  # noqa: BLE001
        if log:
            log(f"     [llm] 不可用，退回规则：{str(e)[:80]}")
        return None

    obj = L.json_object(text)
    if not isinstance(obj, dict):
        if log:
            log(f"     [llm] 没解析出 JSON，退回规则：{text[:60]!r}")
        return None
    if obj.get("done"):
        return {"done": True, "why": str(obj.get("why") or "")[:120], "source": "llm"}

    name = obj.get("tool")
    names = {t["name"] for t in catalog}
    if name not in names:
        if log:
            log(f"     [llm] 选了不存在的工具 {name!r}，退回规则")
        return None

    spec = next(t for t in catalog if t["name"] == name)
    args = obj.get("args") if isinstance(obj.get("args"), dict) else {}
    # 只允许清单里声明过的参数，避免模型顺手发明字段
    allowed = set(spec.get("args") or {})
    kwargs = {k: v for k, v in args.items() if k in allowed}
    # 前面几步的产物由程序注入，不指望模型填对路径
    return {"tool": name, "kwargs": kwargs,
            "why": str(obj.get("why") or "")[:120], "source": "llm",
            "raw_args": args}


def allowed_by_state(act: dict, state: dict) -> tuple[bool, str]:
    """硬校验：模型选的这一步在当前状态下说不通吗？

    返回 (是否放行, 原因)。放行前只拦两类明显错误：
    - 重复同一个动作；
    - 依赖前置步骤的工具（比如没目标就跑 m2）。
    """
    tool = act["tool"]
    if state.get("skip_ghidra") and tool in ("m2", "m3", "dyn", "bof"):
        return False, "--skip-ghidra 模式下不跑需要 Ghidra/qemu 的工具"
    if tool == "check" and state.get("checked"):
        return False, "解包自检已经做过了"
    if tool == "scan" and state.get("targets"):
        return False, "目标已经选出来了"
    if tool in ("m2", "m3") and not state.get("binary"):
        return False, f"{tool} 需要先有目标二进制"
    if tool == "verify" and not (state.get("chains") or state.get("skip_ghidra")):
        return False, "还没有链可核对"
    key = (tool, json.dumps(act.get("kwargs") or {}, sort_keys=True, default=str))
    if key in (state.get("llm_seen") or set()):
        return False, "这一步刚刚做过"
    return True, ""
