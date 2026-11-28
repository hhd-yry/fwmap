"""生成两份 plan 示例产物：正常零发现 / 未完成。

对应验收报告（2026-11-28）第五节 E："示例中至少有一个正常零发现和一个未完成案例，
读者只靠这两种输出就能区分结论范围。"

    py -3 lab/make_plan_examples.py
"""

import contextlib
import io
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap.agent import loop_cli  # noqa: E402

OUT = os.path.join(ROOT, "docs", "示例-2026-11-28")


def _fixture(tmp, with_form=False) -> tuple[str, str]:
    rootfs = os.path.join(tmp, "root")
    os.makedirs(os.path.join(rootfs, "www"), exist_ok=True)
    if with_form:
        with open(os.path.join(rootfs, "www", "a.asp"), "w",
                  encoding="utf-8") as fh:
            fh.write('<form action="/goform/x"><input name="p1"></form>')
    binary = os.path.join(tmp, "httpd")
    with open(binary, "wb") as fh:
        fh.write(b"\x00" * 64)
    return binary, rootfs


def _run(tag, binary, rootfs, out_dir, **kw) -> int:
    args = type("A", (), {
        "binary": binary, "rootfs": rootfs, "arch": "", "max_steps": 2,
        "no_llm": True, "probe": False, "probe_port": 80, "temperature": 0.0,
        "anonymize": False, "json": os.path.join(out_dir, "result.json"),
        "out_dir": out_dir, **kw})()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = loop_cli.cmd_plan(args)
    print(f"\n===== {tag} → 退出码 {rc} =====")
    print(buf.getvalue().strip().splitlines()[-6:])
    return rc


def main() -> int:
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    tmp = tempfile.mkdtemp(prefix="fwmap-example-")

    # ① 正常零发现：模型立刻收工
    def done_chat(messages, **kw):
        return '{"action": "done", "args": {}, "why": "没有更多可做的"}'

    b1, r1 = _fixture(os.path.join(tmp, "complete"))
    d1 = os.path.join(OUT, "正常零发现")
    os.makedirs(d1, exist_ok=True)
    from fwmap.agent import loop
    res1 = loop.run(b1, r1, chat=done_chat, max_steps=2, log=lambda *_: None)
    _write(d1, res1)
    print(f"\n① 正常零发现：status={res1['status']} 结论 {len(res1['findings'])} 条")

    # ② 未完成：预算一步，而且没有可抽取的页面
    b2, r2 = _fixture(os.path.join(tmp, "incomplete"))
    res2 = loop.run(b2, r2, chat=None, max_steps=1, log=lambda *_: None)
    d2 = os.path.join(OUT, "未完成")
    os.makedirs(d2, exist_ok=True)
    _write(d2, res2)
    print(f"② 未完成：status={res2['status']} 尚欠 {res2['pending']}")

    shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n产物目录：{OUT}")
    return 0


def _write(out_dir: str, res: dict) -> None:
    import json

    with open(os.path.join(out_dir, "result.json"), "w", encoding="utf-8") as fh:
        json.dump({"trace": res["trace"], "status": res["status"],
                   "stop_reason": res["stop_reason"], "pending": res["pending"],
                   "candidates": res["candidates"], "probed": res["probed"],
                   "handlers": res["handlers"], "findings": res["findings"],
                   "evidence": res["evidence"], "stats": res["stats"]},
                  fh, ensure_ascii=False, indent=1)
    with open(os.path.join(out_dir, "handoff.md"), "w", encoding="utf-8") as fh:
        fh.write(loop_cli._render_handoff(res))


if __name__ == "__main__":
    raise SystemExit(main())
