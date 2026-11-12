"""PoC 生成 + 动态验证执行器的离线测试。

这里不碰真固件（那要 qemu + 具体 rootfs），只验证两件最容易写错的事：

1. **PoC 对不对**：URL、参数名、载荷类别是不是按链的信息填的；
2. **状态判定对不对**：崩溃 / 没崩 / 服务没起来 必须是三个不同结论。
   把 `no-listener` 说成 `no-crash` 是这一步最典型的错 —— 意思是
   「服务压根没跑起来」被读成「打了没崩，所以安全」。

执行器用一个 Python 假服务来验证管道：它在收到超长参数时自己 abort()，
这样能真实验证「进程被信号打死 → 判 crash」这条路径。
"""

import os
import socket
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import dyn, poc  # noqa: E402


def check(name, cond, detail=""):
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


CHAIN = {
    "function": "formStaDrvSetup",
    "source_api": "websGetVar", "source_param": "rootAPmac",
    "sink": "system", "sink_category": "ci", "sink_args": "cmd",
    "verdict": "keep",
}


def native_rt(exe: str) -> dict:
    """用一个 Python 解释器当「运行时」，跑脚本形式的假服务。"""
    return {"label": "native", "prefix": [sys.executable], "env": {},
            "exe": exe, "cwd": os.path.dirname(exe)}


def free_port() -> int:
    """拿一个当前空闲的端口：写死端口在反复跑测试时会撞上 TIME_WAIT 里的旧监听。"""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def fake_server(mode: str, port: int):
    """mode=crash：收到超过 300 字节就 abort()；mode=ok：正常响应不崩。"""
    code = f'''
import os, socket, sys
mode = {mode!r}
port = {port}
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port)); s.listen(1)
c, _ = s.accept()
data = c.recv(65536)
body = data.split(b"\\r\\n\\r\\n", 1)[-1]
if mode == "crash" and len(body) > 300:
    os.abort()
try:
    c.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nOK")
except OSError:
    pass
c.close(); s.close()
'''
    path = os.path.join(tempfile.mkdtemp(prefix="fwmap-dyn-"), "srv.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(code)
    return path


def main() -> int:
    ok = True

    # 1) PoC 生成
    reqs = poc.build_requests(CHAIN, {"uri": "/goform/formStaDrvSetup"}, port=18081)
    ok &= check("按真实 URI 生成", reqs and reqs[0]["path"] == "/goform/formStaDrvSetup",
                reqs[0]["path"] if reqs else None)
    ok &= check("参数名取 source_param", reqs[0]["param"] == "rootAPmac", reqs[0]["param"])
    ok &= check("ci 类别用命令注入载荷", reqs[0]["value"].startswith(";"),
                reqs[0]["value"])
    ok &= check("body 里带 urlencode", "rootAPmac=" in reqs[0]["body"], reqs[0]["body"])

    reqs2 = poc.build_requests({"function": "formX", "sink_category": "bof"},
                               None, port=18081)
    ok &= check("没有 URI 时按约定拼", reqs2[0]["path"] == "/goform/formX", reqs2[0]["path"])
    ok &= check("bof 载荷由短到长", len(reqs2[0]["value"]) < len(reqs2[-1]["value"]),
                [len(r["value"]) for r in reqs2])

    raw = poc.render_http(reqs[0])
    ok &= check("HTTP 报文以请求行开头", raw.startswith(b"POST /goform/formStaDrvSetup HTTP/1.1"))
    ok &= check("有 Content-Length", b"Content-Length:" in raw)

    # 2) 运行时探测：架构不匹配时不能返回 native
    rt = dyn.find_runtime("mips", None, "x")
    ok &= check("没有 qemu 时 mips → 无运行时", rt is None or "qemu" in rt["label"],
                rt)

    # 3) 真跑：崩 / 不崩 / 没起来
    py = sys.executable
    bof_chain = {"function": "formStaDrvSetup", "source_api": "websGetVar",
                 "source_param": "rootAPmac", "sink": "strcpy",
                 "sink_category": "bof", "verdict": "keep"}
    for mode, want, chain in (("crash", "crash", bof_chain),
                              ("ok", "no-crash", bof_chain)):
        port = free_port()
        srv = fake_server(mode, port)
        req = poc.build_requests(chain, {"uri": "/x"}, port=port)[-1]   # 最长的一档
        res = dyn.run_request(req, native_rt(srv), timeout=6)
        ok &= check(f"{mode} 场景判成 {want}", res["status"] == want, res)

    # 服务起不来（脚本直接报错退出）→ no-listener，绝不能是 no-crash
    dead = os.path.join(tempfile.mkdtemp(prefix="fwmap-dead-"), "dead.py")
    with open(dead, "w", encoding="utf-8") as fh:
        fh.write("raise SystemExit(3)\n")
    req = poc.build_requests(CHAIN, {"uri": "/x"}, port=free_port())[0]
    res = dyn.run_request(req, native_rt(dead), timeout=3, ready_timeout=1.5)
    ok &= check("服务没起来 → no-listener（不是 no-crash）",
                res["status"] == "no-listener", res)

    print()
    print("PASS（PoC 生成与动态验证）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
