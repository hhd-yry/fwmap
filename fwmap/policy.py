"""经验驱动的策略排序（L2：让"记住的成功率"真正影响决策）。

之前的问题：`knowledge.stats` 只记录不参与决策 —— 明知道某个机制在某厂商上
从来没成过，下次还是按同样的顺序再试一遍，白花一次探测（每次要点亮一次固件）。

这里的规则只有四条，都能被单测钉死：

1. **先验平滑**：没试过的机制给 0.5 分（不是 0，也不是 1）；
2. **连续失败惩罚**：每连败一次分数减半 —— 但清零，避免误杀；
3. **分层**：这家厂商有成功记录时，成功过的 > 没试过的 > 失败过的；
   一次都没成功过时，没试过的排最前（探索不能被饿死）；
4. **同层内**：魔数命中优先，其次历史分，最后看模型建议。

模型建议放在最后，是因为实测它会固执地选同一条（回环能兜住，但顺序不该由它定）。
"""

from __future__ import annotations

__all__ = ["prior", "score", "rank", "explain", "should_override"]


def prior(ok: int, fail: int, a: float = 1.0, b: float = 1.0) -> float:
    """拉普拉斯平滑的成功率：0 次尝试 = 0.5，1 成功 = 0.67，1 失败 = 0.33。"""
    ok, fail = max(0, int(ok)), max(0, int(fail))
    return (ok + a) / (ok + fail + a + b)


def score(mechanism: str, vendor: str, stats: dict | None = None) -> float:
    """机制在某厂商上的历史得分（0~1）。"""
    if stats is None:
        from . import knowledge as kb

        stats = kb._load("stats")
    rec = stats.get(f"{mechanism}@{vendor}") or {}
    base = prior(rec.get("ok", 0), rec.get("fail", 0))
    streak = int(rec.get("streak_fail") or 0)
    return base * (0.5 ** streak)


def _vendor_has_win(vendor: str, stats: dict) -> bool:
    suffix = f"@{vendor}"
    return any(int((v or {}).get("ok") or 0) > 0
               for k, v in stats.items() if k.endswith(suffix))


def rank(mechanisms: list[str], vendor: str, *, hinted=(), model_order=(),
         stats: dict | None = None) -> list[str]:
    """按经验给机制排序。`vendor` 为空时原样返回（等于关闭自适应）。"""
    if not vendor or not mechanisms:
        return list(mechanisms)
    if stats is None:
        from . import knowledge as kb

        stats = kb._load("stats")

    hinted_set = {h for h in (hinted or ()) if h}
    model_pos = {m: i for i, m in enumerate(model_order or ())}
    has_win = _vendor_has_win(vendor, stats)

    def tier(m: str) -> int:
        rec = stats.get(f"{m}@{vendor}") or {}
        tried = bool(rec)
        ok = int(rec.get("ok") or 0)
        if has_win:
            return 0 if ok > 0 else (1 if not tried else 2)
        return 0 if not tried else 1

    return sorted(
        mechanisms,
        key=lambda m: (tier(m),
                       0 if m in hinted_set else 1,
                       -score(m, vendor, stats),
                       model_pos.get(m, 99)),
    )


def explain(mechanisms: list[str], vendor: str, stats: dict | None = None) -> list[str]:
    """给日志用：说明每个机制为什么排在这个位置。"""
    if stats is None:
        from . import knowledge as kb

        stats = kb._load("stats")
    out = []
    for m in mechanisms:
        rec = stats.get(f"{m}@{vendor}") or {}
        ok, fail = int(rec.get("ok") or 0), int(rec.get("fail") or 0)
        streak = int(rec.get("streak_fail") or 0)
        out.append(f"{m}: 成功 {ok} / 失败 {fail}"
                   + (f" / 连败 {streak}" if streak else "")
                   + f" → {score(m, vendor, stats):.2f}")
    return out


def should_override(top_mech: str, cur_mech: str, vendor: str, *,
                    stats: dict | None = None, margin: float = 0.1) -> bool:
    """经验是否明显更好，值得推翻模型的选择。

    条件（两条都要满足）：
    1. 候选机制在这家厂商**真的成功过**（ok > 0）—— 没成功过的经验不算数；
    2. 分数至少高出 `margin`。

    为什么不能只比大小：未尝试的机制分数是 0.5，成功过一次是 0.67，
    差距不小但也不大；如果只比大小，任何"没试过"都会被判为更好，
    排序就退化成乱序。用 margin 是为了要求"经验优势足够明显"。
    """
    if not top_mech or top_mech == cur_mech:
        return False
    if stats is None:
        from . import knowledge as kb

        stats = kb._load("stats")
    rec = stats.get(f"{top_mech}@{vendor}") or {}
    if int(rec.get("ok") or 0) <= 0:
        return False
    return (score(top_mech, vendor, stats) - score(cur_mech, vendor, stats)) >= margin
