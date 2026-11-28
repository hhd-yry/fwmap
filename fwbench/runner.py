"""执行：预算、超时、断点续跑，落盘 manifest / events / submission。

硬规矩：
* `run` 落盘成功只表示**评测器**完成了工作，允许里面有失败任务；
* 预算按每例独立计算（decisions / tool_calls），用尽后仍可提交，但不能再看新材料；
* 达到预算后不得再读记录 —— 这一条在循环里强校验。
"""

from __future__ import annotations

import json
import os
import shutil

from . import SCHEMA_VERSION, __version__
from .adapters import make_policy
from .cases import Case, digest, load_fixture, load_suite
from .events import EventLog

__all__ = ["run_suite", "DEFAULT_LIMITS"]

DEFAULT_LIMITS = {"decisions": 6, "tool_calls": 4}


def _profile(path: str) -> dict:
    with open(path, encoding="utf-8-sig") as fh:
        prof = json.load(fh)
    prof.setdefault("policy", prof.get("name", "rule"))
    prof.setdefault("repeats", 1)
    prof.setdefault("limits", dict(DEFAULT_LIMITS))
    return prof


def _run_one(case: Case, fixtures_dir: str, profile: dict, out_dir: str,
             seed: int, repeat: int) -> dict:
    limits = dict(DEFAULT_LIMITS)
    limits.update(case.limits or {})
    limits.update(profile.get("limits") or {})

    records = load_fixture(fixtures_dir, case.fixture_ref)
    backend = _make_backend(records, seed)
    policy = make_policy(profile["policy"])
    policy.attach(case, backend)

    run_id = f"{case.case_id}-{profile['policy']}-r{repeat}"
    ev_path = os.path.join(out_dir, "events.jsonl")
    log = EventLog(ev_path, run_id=run_id, case_id=case.case_id, repeat=repeat)

    left = {"decisions": limits["decisions"], "tool_calls": limits["tool_calls"]}
    submission, stop_reason, step = None, "budget_exhausted", 0
    while left["decisions"] > 0:
        step += 1
        action = policy.act(step, left)
        log.decision = step
        if action.get("type") == "submit":
            submission = action.get("submission") or {}
            log.emit("decision", proposed_by=policy.name, action="submit",
                     executed_by_policy=policy.name)
            log.emit("submission", submission=submission,
                     proposed_by=policy.name)
            left["decisions"] -= 1
            stop_reason = "submitted"
            break
        if action.get("type") != "read":
            log.emit("decision", proposed_by=policy.name,
                     action=json.dumps(action, ensure_ascii=False)[:120],
                     ok=False, fallback_reason="invalid_action")
            left["decisions"] -= 1
            continue
        if left["tool_calls"] <= 0:
            log.emit("decision", proposed_by=policy.name, action="read",
                     ok=False, fallback_reason="tool_budget_exhausted")
            left["decisions"] -= 1
            continue

        rid = action.get("id")
        log.emit("decision", proposed_by=policy.name,
                 action=f"read:{rid}", executed_by_policy=policy.name)
        result = backend.dispatch(action)
        left["tool_calls"] -= 1
        log.emit("tool_result", tool=action.get("tool"), ok=bool(result.get("ok")),
                 evidence_ids=result.get("evidence_ids") or [],
                 error=result.get("error"), content=result.get("content"))
        policy.observe(action, result)
        left["decisions"] -= 1

    log.close()
    if submission is None:
        submission = {"outcome": "missing_run", "claim": None,
                      "subject": None, "sample_time": None, "citations": []}

    with open(os.path.join(out_dir, "submission.json"), "w",
              encoding="utf-8") as fh:
        json.dump(submission, fh, ensure_ascii=False, indent=1)

    return {"case_id": case.case_id, "family": case.family,
            "pair_id": case.pair_id, "run_id": run_id, "repeat": repeat,
            "policy": policy.name, "stop_reason": stop_reason,
            "decisions": step, "tool_calls_used": limits["tool_calls"] - left["tool_calls"],
            "served": sorted(backend.served),
            "submission": submission}


def _make_backend(records: dict, seed: int):
    from .adapters import backend_for
    return backend_for(records, seed=seed)


def _run_lookup(case: Case, fixtures_dir: str, subject, out_dir: str) -> dict:
    """A 层：把一份字节交给被测工具读，记下它给出的字段。"""
    import time as _t

    from .cases import load_blob

    data = load_blob(fixtures_dir, case.fixture_ref)
    run_id = f"{case.case_id}-{subject.subject_id}"
    log = EventLog(os.path.join(out_dir, "events.jsonl"), run_id=run_id,
                   case_id=case.case_id, repeat=1)
    log.decision = 1
    log.emit("decision", proposed_by=subject.subject_id,
             action=f"inspect_elf({len(data)}B)",
             executed_by_policy=subject.subject_id)
    t0 = _t.time()
    result = subject.inspect_elf(data)
    log.emit("tool_result", tool="inspect_elf", ok=bool(result.get("ok")),
             error=result.get("error"), content=result.get("fields") or {},
             elapsed_ms=int((_t.time() - t0) * 1000))
    sub = {"outcome": "answered" if result.get("ok") else str(result.get("error")),
           "fields": result.get("fields") or {},
           "error": result.get("error"),
           "subject": subject.subject_id, "subject_version": subject.version}
    log.emit("submission", submission=sub, proposed_by=subject.subject_id)
    log.close()
    with open(os.path.join(out_dir, "submission.json"), "w",
              encoding="utf-8") as fh:
        json.dump(sub, fh, ensure_ascii=False, indent=1)
    return {"case_id": case.case_id, "family": case.family, "pair_id": "",
            "run_id": run_id, "repeat": 1, "policy": subject.subject_id,
            "stop_reason": "submitted", "decisions": 1, "tool_calls_used": 1,
            "served": [], "submission": sub}


def _run_interactive_subject(case: Case, fixtures_dir: str, subject,
                             profile: dict, out_dir: str) -> dict:
    """C 层：由被测工具自己的决策循环跑一遍，事件原样落盘。"""
    limits = dict(DEFAULT_LIMITS)
    limits.update(case.limits or {})
    limits.update(profile.get("limits") or {})
    records = load_fixture(fixtures_dir, case.fixture_ref)
    backend = _make_backend(records, seed=0)

    run_id = f"{case.case_id}-{subject.subject_id}"
    out = subject.run_interactive(case, backend, limits, chat=None)

    log = EventLog(os.path.join(out_dir, "events.jsonl"), run_id=run_id,
                   case_id=case.case_id, repeat=1)
    for i, ev in enumerate(out["events"], 1):
        log.decision = i
        etype = ev.pop("type")
        log.emit(etype, **ev)
    log.close()
    sub = out["submission"]
    with open(os.path.join(out_dir, "submission.json"), "w",
              encoding="utf-8") as fh:
        json.dump(sub, fh, ensure_ascii=False, indent=1)
    return {"case_id": case.case_id, "family": case.family,
            "pair_id": case.pair_id, "run_id": run_id, "repeat": 1,
            "policy": subject.subject_id, "stop_reason": out["stop_reason"],
            "decisions": out["decisions"], "tool_calls_used": out["tool_calls"],
            "served": sorted(backend.served), "submission": sub}


def run_suite(suite_path: str, fixtures_dir: str, profile_path: str,
              out_dir: str, seed: int = 0, resume: bool = False,
              subject: str | None = None) -> dict:
    cases = load_suite(suite_path)
    profile = _profile(profile_path)
    subject_obj = None
    if subject:
        from .subjects import get as get_subject
        subject_obj = get_subject(subject)

    if os.path.isdir(out_dir) and not resume:
        if os.listdir(out_dir):
            raise SystemExit(f"输出目录已有内容：{out_dir}（换目录，或用 --resume）")
    os.makedirs(out_dir, exist_ok=True)

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "bench_version": __version__,
        "suite": os.path.basename(suite_path),
        "suite_digest": digest([c.case_id for c in cases]),
        "profile": profile,
        "seed": seed,
        "cases": len(cases),
        "subject": subject_obj.info() if subject_obj else None,
        "notes": "run 落盘成功只表示评测器完成了工作，允许其中存在失败任务",
    }
    with open(os.path.join(out_dir, "manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=1)

    rows = []
    for case in cases:
        if (getattr(subject_obj, "supports_interactive", False)
                and not case.is_lookup):
            case_dir = os.path.join(out_dir, "cases", case.case_id)
            if resume and os.path.exists(os.path.join(case_dir, "submission.json")):
                continue
            if os.path.isdir(case_dir):
                shutil.rmtree(case_dir)
            os.makedirs(case_dir, exist_ok=True)
            rows.append(_run_interactive_subject(case, fixtures_dir, subject_obj,
                                                 profile, case_dir))
            continue
        if case.is_lookup and subject_obj is not None:
            case_dir = os.path.join(out_dir, "cases", case.case_id)
            if resume and os.path.exists(os.path.join(case_dir, "submission.json")):
                continue
            if os.path.isdir(case_dir):
                shutil.rmtree(case_dir)
            os.makedirs(case_dir, exist_ok=True)
            rows.append(_run_lookup(case, fixtures_dir, subject_obj, case_dir))
            continue
        for repeat in range(1, int(profile.get("repeats", 1)) + 1):
            case_dir = os.path.join(out_dir, "cases", case.case_id)
            if resume and os.path.exists(os.path.join(case_dir, "submission.json")):
                continue
            if os.path.isdir(case_dir):
                shutil.rmtree(case_dir)
            os.makedirs(case_dir, exist_ok=True)
            rows.append(_run_one(case, fixtures_dir, profile, case_dir,
                                 seed, repeat))

    with open(os.path.join(out_dir, "results.jsonl"), "w",
              encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return {"manifest": manifest, "rows": rows}
