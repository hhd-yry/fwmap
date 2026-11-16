"""崩溃要说清楚「被什么打死的」，参数名不对也要说出来。

这两条都是今天在 VM 上被现实纠正过的：

1. `boom` 的两种死法含义完全不同：
   - SIGSEGV：访问越界（我们打出来的）
   - SIGABRT：程序自己 abort（boa 捕获段错误后自杀）
   都写成「崩了」会让报告没法复核。

2. **参数名不对时，「没崩」什么都不说明**。
   实测 `formiNICWdsEncrypt` 拿 `input=` 打，固件回 `<!--ERR_MSG-->` ——
   请求根本没走到 strcpy。这种 no-crash 必须标出来，不能被当成「这条链安全」。
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import dyn as D  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def main() -> int:
    ok = True

    # 1) 信号识别
    ok &= check("boa 的 'caught SIGSEGV' → SIGSEGV",
                D._signal_of("boa: caught SIGSEGV, dumping core in /tmp", None) == "SIGSEGV")
    ok &= check("qemu 的 'uncaught target signal 6 (Aborted)' → SIGABRT",
                D._signal_of("qemu: uncaught target signal 6 (Aborted)", None) == "SIGABRT")
    ok &= check("退出码 -11 → SIGSEGV", D._signal_of("", -11) == "SIGSEGV")
    ok &= check("退出码 -6 → SIGABRT", D._signal_of("", -6) == "SIGABRT")
    ok &= check("正常退出没有信号", D._signal_of("boa: starting server", 0) == "")

    # 2) 错误页 → 标注「参数名可能不对」，而不是留一个光秃秃的 no-crash
    real_run = D.run_request
    real_find = D.find_runtime

    def fake_run(req, runtime, timeout=8.0, ready_timeout=6.0):
        return {"status": "no-crash", "exit": None, "signal": "",
                "resp": "HTTP/1.0 200 OK\r\n\r\n<html><!--ERR_MSG--><head>",
                "elapsed": 0.1}

    try:
        D.run_request = fake_run
        D.find_runtime = lambda *a, **k: {"label": "fake", "prefix": [], "exe": "/bin/true",
                                          "env": {}, "cwd": "/tmp"}
        out = D.run_dyn([{"function": "formX", "sink": "strcpy", "sink_category": "bof",
                          "source_param": "input"}],
                        "/bin/true", rootfs="/tmp", port=80, dry_run=False,
                        log=lambda *_: None)
        row = out["results"][0]["rows"][0]
        ok &= check("错误页 → 结果带 note", "参数名" in (row["result"].get("note") or ""), row)
        ok &= check("状态仍是 no-crash（不伪造结论）", row["result"]["status"] == "no-crash")
    finally:
        D.run_request = real_run
        D.find_runtime = real_find

    print()
    print("PASS（崩溃信号 / 参数名提示）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
