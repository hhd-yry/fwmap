"""Agent 循环的测试：模型决定下一步，但纪律不能松。

四件事必须成立：
  1. 动作只能从白名单里选，非法动作要退回固定策略而不是直接执行；
  2. 有预算，超了就停（不能无限跑）；
  3. 每步结果写进 trace（可回放）；
  4. 没有模型时用固定策略，照样能跑完。
"""

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap.agent import loop  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def main() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="fwmap-loop-")
    rootfs = os.path.join(tmp, "root")
    os.makedirs(os.path.join(rootfs, "www"), exist_ok=True)
    with open(os.path.join(rootfs, "www", "a.asp"), "w", encoding="utf-8") as fh:
        fh.write('<form action="/goform/x"><input name="p1"></form>')
    binary = os.path.join(tmp, "webs")
    with open(binary, "wb") as fh:
        fh.write(b"\x7fELF" + b"\x00" * 500)

    # 1) 白名单校验
    okv, why = loop._validate({"action": "rm -rf /", "args": {}})
    ok &= check("非法动作被拒", not okv and "没有这个动作" in why, why)
    okv2, why2 = loop._validate({"action": "routes", "args": {"mechanism": "猜的"}})
    ok &= check("非法参数取值被拒", not okv2 and "不在允许取值" in why2, why2)
    okv3, _ = loop._validate({"action": "routes", "args": {"mechanism": "page_derived"}})
    ok &= check("合法动作通过", okv3)

    # 2) 没有模型：固定策略能跑完
    logs = []
    res = loop.run(binary, rootfs, chat=None, max_steps=4, log=logs.append)
    acts = [t.get("action") for t in res["trace"]]
    ok &= check("无模型时按固定策略执行", acts[:1] == ["pages"], acts)
    ok &= check("trace 有预算内步骤", 1 <= len(res["trace"]) <= 4, len(res["trace"]))
    ok &= check("pages 抓到了表单", res["routes"] >= 1, res.get("routes"))

    # 3) 模型给非法动作 → 退回固定策略
    def bad_chat(messages, **kw):
        return '{"action": "exec_shell", "args": {"cmd": "id"}}'

    res2 = loop.run(binary, rootfs, chat=bad_chat, max_steps=3, log=lambda *_: None)
    ok &= check("非法动作没有执行", all(t.get("action") != "exec_shell"
                                        for t in res2["trace"]), res2["trace"])
    ok &= check("退回后仍在白名单内", all(t.get("action") in loop.ACTIONS
                                          for t in res2["trace"]), res2["trace"])

    # 4) 模型说 done 就停
    def done_chat(messages, **kw):
        return '{"action": "done", "args": {}, "why": "收工"}'

    res3 = loop.run(binary, rootfs, chat=done_chat, max_steps=5, log=lambda *_: None)
    ok &= check("done 立即停止", len(res3["trace"]) == 1, res3["trace"])

    # 4.5) 模型重复同一个已成功的动作 → 换一个
    def repeat_chat(messages, **kw):
        return '{"action": "pages", "args": {}}'

    res_r = loop.run(binary, rootfs, chat=repeat_chat, max_steps=3, log=lambda *_: None)
    acts_r = [t.get("action") for t in res_r["trace"]]
    ok &= check("重复动作会被打断", acts_r.count("pages") <= 1, acts_r)

    # 5) 预算上限
    def spin_chat(messages, **kw):
        return '{"action": "analyze", "args": {"tool": "readelf"}}'

    res4 = loop.run(binary, rootfs, chat=spin_chat, max_steps=2, log=lambda *_: None)
    ok &= check("最多跑 max_steps 步", len(res4["trace"]) <= 2, len(res4["trace"]))

    # 6) 探针缺失时 probe 动作如实失败
    state = {"binary": binary, "rootfs": rootfs}
    r = loop._execute({"action": "probe", "args": {"uri": "/x"}}, state, probe=None)
    ok &= check("没有探针时 probe 失败", r["ok"] is False and "探针" in r["detail"], r)

    # 7) **模型主导试哪条端点** —— 这是这一版的重点
    #    模型说的 uri 必须原样送到固件前面，不能被执行层换成别的；
    #    固件给的裁决（handler / not-found）必须回填进状态，供下一步参考。
    sent = []

    def stub_probe(uris):
        sent.extend(uris)
        routes = {u: ("handler" if u == "/goform/x" else "not-found") for u in uris}
        return {"checked": len(uris),
                "handler": sum(1 for v in routes.values() if v == "handler"),
                "routes": routes, "control": {}}

    script = ['{"action": "pages", "args": {}}',
              '{"action": "probe", "args": {"uri": "/goform/x"}, "why": "表单的 action"}',
              '{"action": "done", "args": {}}']

    def scripted_chat(messages, **kw):
        return script.pop(0)

    res_p = loop.run(binary, rootfs, chat=scripted_chat, max_steps=3,
                     probe=stub_probe, log=lambda *_: None)
    ok &= check("模型挑的 uri 原样送到探针", sent == ["/goform/x"], sent)
    ok &= check("固件裁决回填进状态", res_p["probed"].get("/goform/x") == "handler",
                res_p["probed"])
    ok &= check("命中被计入 handlers", res_p["handlers"] == 1, res_p["handlers"])
    ok &= check("候选清单来自 pages", "/goform/x" in res_p["candidates"],
                res_p["candidates"])

    # 8) 探过的端点不再重复探（哪怕结果是 not-found）
    sent2 = []

    def stub_probe2(uris):
        sent2.extend(uris)
        return {"checked": len(uris), "handler": 0,
                "routes": {u: "not-found" for u in uris}, "control": {}}

    def stubborn_chat(messages, **kw):
        return '{"action": "probe", "args": {"uri": "/nope"}}'

    loop.run(binary, rootfs, chat=stubborn_chat, max_steps=2,
             probe=stub_probe2, log=lambda *_: None)
    ok &= check("同一条 not-found 不会反复探", sent2.count("/nope") == 1, sent2)

    # 9) uri 参数形态：只收绝对路径，允许数组
    ok &= check("相对路径被拒",
                loop._validate({"action": "probe", "args": {"uri": "goform/x"}})[0] is False)
    ok &= check("空 uri 被拒", loop._validate({"action": "probe", "args": {}})[0] is False)
    ok &= check("数组形态通过",
                loop._validate({"action": "probe",
                                "args": {"uri": ["/a", "/b"]}})[0] is True)
    ok &= check("候选写进 state_brief",
                "/goform/x" in loop.state_brief(res_p["state"]))

    import shutil

    shutil.rmtree(tmp, ignore_errors=True)
    print()
    print("PASS（agent 循环）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
