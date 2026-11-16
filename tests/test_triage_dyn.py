"""动态验证接进 triage：报告里要有「④ 动态验证」，而且要分清四种状态。

用户看完报告说「没有动态验证」——因为 `triage` 本来就不跑 dyn，
只有 `autopilot` 会跑。现在 `triage --dyn` 也能跑，报告里单列一节。
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import dyn as D  # noqa: E402
from fwmap import triage  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def chain(fn="formX", cat="ci", hops=1):
    return {"function": fn, "sink": "system", "sink_category": cat, "hops": hops,
            "verdict": "keep", "source_api": "websGetVar", "source_param": "cmd",
            "sink_args": "uVar1", "guard": "g"}


def main() -> int:
    ok = True

    # 1) 挑哪几条去打：命令注入优先（成功判定最硬），其次溢出、格式串
    mixed = [chain("fmt1", "fmt"), chain("bof1", "bof"), chain("ci1", "ci"),
             chain("ci2", "ci", hops=3)]
    picks = triage._pick_for_dyn(mixed, 3)
    ok &= check("命令注入排在前面", [p["function"] for p in picks[:2]] == ["ci1", "ci2"],
                [p["function"] for p in picks])
    ok &= check("只取 N 条", len(triage._pick_for_dyn(mixed, 2)) == 2)
    ok &= check("N=0 也至少给一条", len(triage._pick_for_dyn(mixed, 0)) == 1)

    # 2) run_dyn 在「没有 qemu」的机器上只出 PoC，不许假装验证过
    out = D.run_dyn([chain()], r"C:\nope\webs", rootfs=r"C:\nope",
                    dry_run=True, endpoints=[], log=lambda *_: None)
    ok &= check("dry-run 不执行", out["counts"].get("not-run", 0) >= 1, out["counts"])
    ok &= check("dry-run 没有 exec", "exec-confirmed" not in out["counts"])
    ok &= check("返回里有 chains 数", out["chains"] == 1)

    # 2.5) CLI 的 dyn 跑完要给出正确退出码（env-broken 是 3，正常是 0）
    #      这一段以前在 `run()` 里引用了 run_dyn 内部的变量，VM 上直接 NameError。
    import argparse
    import json
    import tempfile

    flow = {"binary": "bin/webs", "chains": [chain()]}
    tmp = tempfile.mkdtemp(prefix="fwmap-dyn-")
    flow_path = os.path.join(tmp, "flow.json")
    with open(flow_path, "w", encoding="utf-8") as fh:
        json.dump(flow, fh, ensure_ascii=False)

    def ns():
        return argparse.Namespace(flow=flow_path, binary="bin/webs", rootfs="/x", port=80,
                                  arch=None, cmd=None, check=None, only=None,
                                  max_payloads=1, timeout=1.0, dry_run=False, m2=None,
                                  out=None, json=None, allow_stale=True)

    real_run_dyn = D.run_dyn
    try:
        D.run_dyn = lambda *a, **k: {"arch": "mipsel", "label": "chroot+qemu",
                                     "control": {"status": "crash"}, "results": [],
                                     "counts": {}, "chains": 1, "env_broken": True,
                                     "settings": {}}
        ok &= check("对照组崩了 → 退出码 3", D.run(ns()) == 3)

        D.run_dyn = lambda *a, **k: {
            "arch": "mipsel", "label": "chroot+qemu", "control": {"status": "no-crash"},
            "results": [{"chain": chain(), "rows": [
                {"req": {"value": "x'\\nid\\n'"}, "result": {"status": "exec-confirmed",
                                                            "effect": "uid=0"}}]}],
            "counts": {"exec-confirmed": 1}, "chains": 1, "env_broken": False,
            "settings": {}}
        ok &= check("有 exec 命中 → 退出码 0", D.run(ns()) == 0)
    finally:
        D.run_dyn = real_run_dyn
        import shutil

        shutil.rmtree(tmp, ignore_errors=True)

    # 3) 报告渲染：有 dyn 数据时要出现 ④，且四种状态都有中文
    labels = triage._DYN_LABEL
    for st in ("exec-confirmed", "crash", "no-crash", "no-listener"):
        ok &= check(f"{st} 有中文说法", st in labels and labels[st], labels.get(st))

    res = {
        "rootfs": "/x", "time": "2026-11-15 21:00", "meta": {}, "agent": False,
        "dyn_requested": True,
        "stats": {"files": 1, "targets": 1, "elfs": 1, "high": 1, "oneline": "最小报告",
                  "kept": 1, "chains": 1, "known": 0},
        "agent_rows": [],
        "binaries": [{
            "name": "webs", "binary": "/x/bin/webs", "path": "bin/webs", "score": 87,
            "role": "web", "arch": "mipsel", "size": 991088, "chains": 1,
            "chain_list": [chain()], "endpoints": 1, "endpoint_list": [],
            "sink_verified": 0, "m2_strategy": "registration",
            "dyn": {"label": "chroot+qemu", "arch": "mipsel",
                    "control": {"status": "no-crash"},
                    "counts": {"exec-confirmed": 1, "no-crash": 2},
                    "results": [{
                        "chain": {"function": "formX", "sink": "system", "sink_category": "ci"},
                        "rows": [{"req": {"param": "cmd", "value": "x'\\nid\\n'"},
                                  "result": {"status": "exec-confirmed",
                                             "effect": "uid=0(root)"}}]}]},
        }],
    }
    html = triage.render(res)
    # 断言绑在「数据」上，不绑在文案上：报告标题怎么写是各人的事，
    # 只要动态验证的结果真的进了页面就行（改文案不用改测试）。
    ok &= check("页面里有动态验证这一节", "动态验证" in html, html[:200])
    ok &= check("写明了对照组", "对照组" in html)
    ok &= check("显示执行状态（用状态文案表判断）",
                triage._DYN_LABEL["exec-confirmed"] in html, triage._DYN_LABEL)
    ok &= check("把命令副产物贴出来了", "uid=0(root)" in html)

    # 4) 没有 dyn 数据（没开 --dyn）时，不能显示任何「已执行」状态
    res2 = dict(res)
    res2["binaries"] = [dict(res["binaries"][0])]
    res2["binaries"][0].pop("dyn")
    res2["dyn_requested"] = False
    html2 = triage.render(res2)
    ok &= check("没开动态验证时不显示执行状态",
                triage._DYN_LABEL["exec-confirmed"] not in html2)

    print()
    print("PASS（动态验证接进报告）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
