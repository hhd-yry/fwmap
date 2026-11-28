"""独立评分：从已落盘的提交与可见证据算通过标志。

三条硬约束：
1. 评分**不调模型**、不读未来事件、不读运行器内存；
2. 金标只在评分时加载，运行器全程看不到；
3. 引用必须满足：本轮**已读过** + 支持主张；追加与结论矛盾的引文要报错。
"""

from __future__ import annotations

import json
import os

__all__ = ["score_case", "score_run", "FAIL_REASONS"]

FAIL_REASONS = (
    "invalid_submission",      # 提交缺字段 / 格式不对
    "claim_mismatch",          # 结论与金标不符
    "no_citation",             # 有结论但没引用
    "citation_not_read",       # 引用了本轮没读过的记录
    "citation_unsupported",    # 引用的记录不支持这个主张
    "insufficient_evidence",   # 没有命中任何一组"充分证据"
    "abstain_not_allowed",     # 该例不允许弃权
    "missing_run",             # 没提交
)


def _load_json(path: str):
    try:
        with open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _supports(claim: dict, rec: dict) -> bool:
    """这条记录是否支持主张：主体、采样时间必须对得上；有 state 就必须一致。"""
    if not isinstance(rec, dict):
        return False
    if claim.get("subject") and rec.get("subject") != claim.get("subject"):
        return False
    if claim.get("sample_time") and rec.get("sample_time") != claim.get("sample_time"):
        return False
    if "state" in rec:
        return rec.get("state") == claim.get("claim")
    return False


def _score_lookup(case_dir: str, oracle_row: dict) -> dict:
    """A 层：按任务包约定的字段逐项核对；可选依赖缺失记 not_run。"""
    sub = _load_json(os.path.join(case_dir, "submission.json")) or {}
    err = sub.get("error")
    base = {"case_id": oracle_row["case_id"],
            "family": oracle_row.get("family"),
            "pair_id": oracle_row.get("pair_id") or "",
            "outcome": sub.get("outcome"), "claim": sub.get("fields"),
            "expected": oracle_row.get("expected_fields")
            or oracle_row.get("expect_error"),
            "citations": [], "served": [], "detail": []}
    if err == "not_run":
        return {**base, "passed": False, "failure": "not_run", "applicable": False}
    if oracle_row.get("expect_error"):
        ok = err == oracle_row["expect_error"]
        return {**base, "passed": ok, "applicable": True,
                "failure": None if ok else "wrong_error"}
    want = oracle_row.get("expected_fields") or {}
    got = sub.get("fields") or {}
    bad = [k for k, v in want.items() if got.get(k) != v]
    if err:
        return {**base, "passed": False, "applicable": True,
                "failure": "unexpected_error", "detail": [err]}
    return {**base, "passed": not bad, "applicable": True,
            "failure": None if not bad else "field_mismatch", "detail": bad}


def score_case(case_dir: str, oracle_row: dict) -> dict:
    if oracle_row.get("expected_fields") or oracle_row.get("expect_error"):
        return _score_lookup(case_dir, oracle_row)
    ev_path = os.path.join(case_dir, "events.jsonl")
    sub_path = os.path.join(case_dir, "submission.json")
    sub = _load_json(sub_path)

    served: set[str] = set()
    contents: dict[str, dict] = {}
    if os.path.exists(ev_path):
        with open(ev_path, encoding="utf-8-sig") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if ev.get("type") == "tool_result" and ev.get("ok"):
                    for rid in ev.get("evidence_ids") or []:
                        served.add(rid)
                        contents[rid] = ev.get("content") or {}

    failure = None
    detail = []
    if sub is None:
        failure = "missing_run"
    elif not isinstance(sub, dict) or "outcome" not in sub or "claim" not in sub:
        failure = "invalid_submission"
    elif sub.get("outcome") == "abstained":
        failure = None if oracle_row.get("allow_abstain") else "abstain_not_allowed"
    elif sub.get("outcome") != "answered":
        failure = "invalid_submission"
    else:
        cites = list(sub.get("citations") or [])
        if not cites:
            failure = "no_citation"
        elif any(c not in served for c in cites):
            failure = "citation_not_read"
            detail = [c for c in cites if c not in served]
        elif sub.get("claim") != oracle_row.get("expected"):
            failure = "claim_mismatch"
        elif not any(_supports(sub, contents.get(c, {})) for c in cites):
            failure = "citation_unsupported"
        else:
            allowed = [set(s) for s in oracle_row.get("acceptable_evidence_sets") or []]
            if allowed and not any(s <= set(cites) for s in allowed):
                failure = "insufficient_evidence"

    return {"case_id": oracle_row["case_id"],
            "family": oracle_row.get("family"),
            "pair_id": oracle_row.get("pair_id"),
            "applicable": True,
            "passed": failure is None,
            "failure": failure,
            "detail": detail,
            "outcome": (sub or {}).get("outcome"),
            "claim": (sub or {}).get("claim"),
            "expected": oracle_row.get("expected"),
            "citations": (sub or {}).get("citations") or [],
            "served": sorted(served)}


def score_run(run_dir: str, oracle: dict[str, dict]) -> dict:
    results = []
    cases_dir = os.path.join(run_dir, "cases")
    if not os.path.isdir(cases_dir):
        raise SystemExit(f"不是运行目录（缺 cases/）：{run_dir}")
    for cid in sorted(os.listdir(cases_dir)):
        row = oracle.get(cid)
        if not row:
            print(f"[!] 金标里没有 {cid}，跳过（不替它编）")
            continue
        results.append(score_case(os.path.join(cases_dir, cid), row))

    total = len(results)
    applicable = [r for r in results if r.get("applicable", True)]
    passed = sum(1 for r in applicable if r["passed"])
    not_run = total - len(applicable)
    answered = sum(1 for r in applicable if r["outcome"] == "answered")
    ungrounded = sum(1 for r in applicable
                     if r["outcome"] == "answered" and not r["passed"])
    pairs = {}
    for r in applicable:
        if not r.get("pair_id"):
            continue
        pairs.setdefault(r["pair_id"], []).append(r)
    pair_both = sum(1 for rs in pairs.values()
                    if len(rs) == 2 and all(x["passed"] for x in rs))

    return {"run_dir": run_dir, "results": results,
            "metrics": {
                "cases": total,
                "applicable": len(applicable),
                "not_run": not_run,
                "passed": passed,
                "pass_rate": (round(passed / len(applicable), 3)
                              if applicable else None),
                "answered": answered,
                "ungrounded_answered": ungrounded,
                "ungrounded_rate": (round(ungrounded / answered, 3)
                                    if answered else None),
                "pairs": len(pairs),
                "pairs_both_passed": pair_both,
                "pair_rate": round(pair_both / len(pairs), 3) if pairs else None,
            }}
