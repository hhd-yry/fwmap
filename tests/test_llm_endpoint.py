"""远程模型服务测试：宿主有 GPU、虚拟机没有时，让 VM 用宿主的模型。

不加载真模型 —— 用一个假的 OpenAI 兼容服务，测「客户端会不会说人话、
服务端会不会把错误如实回传」。
"""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap.agent import llm  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def start_stub(reply: str = "OK", mode: str = "ok"):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = json.dumps({"object": "list", "data": [{"id": "stub"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(n)
            if mode == "error":
                body = json.dumps({"error": "CUDA out of memory"}).encode()
                self.send_response(500)
            elif mode == "weird":
                body = json.dumps({"nope": 1}).encode()
                self.send_response(200)
            else:
                body = json.dumps({"choices": [{"message": {"content": reply}}]}).encode()
                self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main() -> int:
    ok = True
    real = os.environ.pop("FWMAP_LLM_ENDPOINT", None)
    try:
        ok &= check("没设地址时 endpoint 为空", llm.endpoint() == "")

        srv = start_stub("模型答复")
        os.environ["FWMAP_LLM_ENDPOINT"] = f"http://127.0.0.1:{srv.server_port}/v1"
        ok &= check("设了地址就认出来", llm.endpoint().endswith("/v1"))
        text = llm.chat([{"role": "user", "content": "hi"}])
        ok &= check("远程模式能拿到回答", text == "模型答复", text)
        srv.shutdown()

        # 服务端 500：必须抛出来，不能当成「模型说没问题」
        bad = start_stub(mode="error")
        os.environ["FWMAP_LLM_ENDPOINT"] = f"http://127.0.0.1:{bad.server_port}/v1"
        try:
            llm.chat([{"role": "user", "content": "hi"}])
            ok &= check("服务端 500 要抛错", False, "没抛")
        except Exception as exc:                       # noqa: BLE001
            ok &= check("服务端 500 要抛错", "500" in str(exc) or "HTTP" in str(exc), exc)
        bad.shutdown()

        # 返回格式不对：要给看得懂的错，不是 KeyError
        weird = start_stub(mode="weird")
        os.environ["FWMAP_LLM_ENDPOINT"] = f"http://127.0.0.1:{weird.server_port}/v1"
        try:
            llm.chat([{"role": "user", "content": "hi"}])
            ok &= check("格式不对要报错", False, "没抛")
        except RuntimeError as exc:
            ok &= check("格式不对要报错", "格式不对" in str(exc), exc)
        weird.shutdown()
    finally:
        os.environ.pop("FWMAP_LLM_ENDPOINT", None)
        if real:
            os.environ["FWMAP_LLM_ENDPOINT"] = real

    print()
    print("PASS（远程模型服务）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
