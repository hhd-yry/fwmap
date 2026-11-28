"""验收报告（2026-11-28）指出的三个会改变结论的缺陷 —— 回归用例。

三条都必须先失败、修完再通过：

1. 有执行轨迹就返回 0：空目录 + 一步预算，什么都没做成，CLI 仍返回 0；
2. 关掉模型仍记一次兜底：`fallback = 总步数 - 模型步数`，把"规则主动执行"也算成兜底；
3. 空响应 + 空引用仍能生成强结论：`evidence: []` 时循环体一次都不进，直接放行。
"""

import contextlib
import io
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap.agent import loop, loop_cli  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name
          + (("  " + str(detail)) if not cond else ""))
    return cond


def _fixture(tmp):
    """一个什么都没有的固件：空 rootfs + 占位二进制。"""
    rootfs = os.path.join(tmp, "root")
    os.makedirs(os.path.join(rootfs, "www"), exist_ok=True)
    binary = os.path.join(tmp, "httpd")
    with open(binary, "wb") as fh:
        fh.write(b"\x00" * 64)
    return binary, rootfs


def case_exit_code_needs_status(tmp) -> bool:
    """1) 一步预算、什么都没做成 → 退出码必须非 0。"""
    binary, rootfs = _fixture(os.path.join(tmp, "a"))
    args = type("A", (), {
        "binary": binary, "rootfs": rootfs, "arch": "", "max_steps": 1,
        "no_llm": True, "probe": False, "probe_port": 80, "temperature": 0.0,
        "anonymize": False, "json": "", "out_dir": "",
    })()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = loop_cli.cmd_plan(args)
    return check("一步失败后 CLI 不返回 0", rc != 0, f"rc={rc}")


def case_rule_steps_are_not_fallback(tmp) -> bool:
    """2) 主动关模型时，兜底次数必须是 0。"""
    binary, rootfs = _fixture(os.path.join(tmp, "b"))
    res = loop.run(binary, rootfs, chat=None, max_steps=1, log=lambda *_: None)
    s = res.get("stats") or {}
    ok = True
    ok &= check("关模型时 fallback_steps 为 0", s.get("fallback_steps") == 0, s)
    ok &= check("关模型时 rule_steps 计到 1", s.get("rule_steps") == 1, s)
    ok &= check("关模型时 model_steps 为 0", s.get("model_steps") == 0, s)
    return ok


def case_empty_evidence_rejected() -> bool:
    """3) 空引用 / 引用别的对象 → 不能形成结论。"""
    state = {"evidence": {"/x": {"verdict": "unknown", "len": 0, "status": None},
                          "/y": {"verdict": "handler", "len": 1818, "status": 200}}}
    ok = True
    r = loop._execute({"action": "verdict",
                       "args": {"uri": "/x", "kind": "crash", "evidence": []}},
                      state)
    ok &= check("空引用不能下结论", r["ok"] is False, r)
    ok &= check("空引用被拒时没有写进 findings", not state.get("findings"), state)

    r2 = loop._execute({"action": "verdict",
                        "args": {"uri": "/x", "kind": "crash",
                                 "evidence": ["/y 1818B handler"]}}, state)
    ok &= check("引用别的对象不能下结论", r2["ok"] is False, r2)

    r3 = loop._execute({"action": "verdict",
                        "args": {"uri": "/x", "kind": "crash",
                                 "evidence": ["/x 9999B unknown"]}}, state)
    ok &= check("引文数值与实测不符不能下结论", r3["ok"] is False, r3)

    r4 = loop._execute({"action": "verdict",
                        "args": {"uri": "/x", "kind": "crash",
                                 "evidence": ["/x 0B unknown"]}}, state)
    ok &= check("引用对得上才放行", r4["ok"] is True, r4)
    if r4["ok"]:
        f = (state.get("findings") or [{}])[0]
        ok &= check("证据强度被标成 observed-only（未确认进程退出）",
                    f.get("support") == "observed-only", f)

    # 允许带对照组：这是真实推理链（"别的 1818B，这条 0B"），不该被拒
    state2 = {"evidence": {"/x": {"verdict": "unknown", "len": 0, "status": None},
                           "/y": {"verdict": "handler", "len": 1818, "status": 200}}}
    r5 = loop._execute({"action": "verdict",
                        "args": {"uri": "/x", "kind": "crash",
                                 "evidence": ["/y 1818B handler",
                                              "/x 0B unknown"]}}, state2)
    ok &= check("带对照组的引用被接受", r5["ok"] is True, r5)
    if r5["ok"]:
        f2 = (state2.get("findings") or [{}])[0]
        ok &= check("主引用指向目标对象",
                    f2.get("primary_evidence") == "/x 0B unknown", f2)

    # 但夹带一条编造的证据仍然要拒
    r6 = loop._execute({"action": "verdict",
                        "args": {"uri": "/x", "kind": "crash",
                                 "evidence": ["/x 0B unknown",
                                              "/ghost.cgi 0B"]}}, state2)
    ok &= check("夹带编造证据仍被拒", r6["ok"] is False, r6)
    return ok


def _args(tmp, **kw):
    binary, rootfs = _fixture(tmp)
    base = {"binary": binary, "rootfs": rootfs, "arch": "", "max_steps": 2,
            "no_llm": True, "probe": False, "probe_port": 80,
            "temperature": 0.0, "anonymize": False, "json": "", "out_dir": ""}
    base.update(kw)
    return type("A", (), base)()


def case_status_variants(tmp) -> bool:
    """预算用尽 / 正常收工 / 依赖缺失，三种状态要能分开。"""
    ok = True

    # 预算用尽：一步预算，pages 跑完就没预算了，没有 done
    a = _args(os.path.join(tmp, "c"), max_steps=1)
    res = loop.run(a.binary, a.rootfs, chat=None, max_steps=1,
                   log=lambda *_: None)
    ok &= check("预算用尽 → budget_exhausted",
                res["status"] == "budget_exhausted", res["status"])

    # 正常收工（零发现也算完成）
    def done_chat(messages, **kw):
        return '{"action": "done", "args": {}, "why": "没得做"}'

    a2 = _args(os.path.join(tmp, "d"), no_llm=False)
    res2 = loop.run(a2.binary, a2.rootfs, chat=done_chat, max_steps=1,
                    log=lambda *_: None)
    ok &= check("模型收工 → completed", res2["status"] == "completed",
                res2["status"])
    ok &= check("零发现也算完成（ok=True）", res2["ok"] is True, res2["ok"])
    ok &= check("完成时退出码为 0",
                loop_cli._STATUS_EXIT.get(res2["status"]) == 0)

    # 请求了探针但没有 qemu
    a3 = _args(os.path.join(tmp, "e"), probe=True, max_steps=1)
    res3 = loop.run(a3.binary, a3.rootfs, chat=None, max_steps=1,
                    probe=None, want_probe=True, log=lambda *_: None)
    ok &= check("请求探针但不可用 → dependency_missing",
                res3["status"] == "dependency_missing", res3["status"])
    ok &= check("依赖缺失退出码为 3",
                loop_cli._STATUS_EXIT.get(res3["status"]) == 3)
    ok &= check("交接里写明尚欠 probe", "probe" in (res3["pending"] or []),
                res3["pending"])
    return ok


def case_write_failed(tmp) -> bool:
    """结果写不出去要能从退出码看出来。"""
    blocker = os.path.join(tmp, "not-a-dir")
    with open(blocker, "w", encoding="utf-8") as fh:
        fh.write("x")
    a = _args(os.path.join(tmp, "f"), out_dir=blocker)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = loop_cli.cmd_plan(a)
    return check("输出不可写 → 退出码 4", rc == 4, f"rc={rc}")


def case_handoff_written(tmp) -> bool:
    """跑完必须留下交接文件，且写明状态与证据强度。"""
    out = os.path.join(tmp, "out")
    a = _args(os.path.join(tmp, "g"), out_dir=out, max_steps=1)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        loop_cli.cmd_plan(a)
    path = os.path.join(out, "handoff.md")
    if not os.path.exists(path):
        return check("交接文件已生成", False, path)
    text = open(path, encoding="utf-8").read()
    ok = check("交接文件已生成", True)
    ok &= check("交接写明完成状态", "完成状态" in text and "budget_exhausted" in text,
                text[:120])
    ok &= check("交接写明尚欠阶段", "尚欠阶段" in text)
    return ok


def case_accept_rate_not_applicable(tmp) -> bool:
    """一次没试过结论，采纳率应为 None（显示"不适用"）。"""
    binary, rootfs = _fixture(os.path.join(tmp, "h"))
    res = loop.run(binary, rootfs, chat=None, max_steps=1, log=lambda *_: None)
    return check("没尝试过结论时采纳率为 None",
                 res["stats"]["verdict_accept_rate"] is None, res["stats"])


def main() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="fwmap-status-")
    ok &= case_exit_code_needs_status(tmp)
    ok &= case_rule_steps_are_not_fallback(tmp)
    ok &= case_empty_evidence_rejected()
    ok &= case_status_variants(tmp)
    ok &= case_write_failed(tmp)
    ok &= case_handoff_written(tmp)
    ok &= case_accept_rate_not_applicable(tmp)

    import shutil

    shutil.rmtree(tmp, ignore_errors=True)
    print()
    print("PASS（完成状态与证据强度）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
