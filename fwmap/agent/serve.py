"""把本机模型变成一个 OpenAI 兼容的 HTTP 服务，给别的机器（比如虚拟机）用。

场景很具体：VMware 里的 Ubuntu 没有 CUDA、只有 8 GB 内存，跑不了 7B；
但宿主机有 4060。让宿主跑这个服务，VM 里的 `triage --agent --dyn` 就能同时用
「宿主的显卡」和「VM 里的 qemu」。

只实现两个接口，够用就行：

    GET  /v1/models              -> 报一下模型名
    POST /v1/chat/completions    -> {"choices":[{"message":{"content": "..."}}]}

用法：

    # 宿主机（Windows，有 GPU）
    python -m fwmap serve --port 11434

    # 虚拟机里
    export FWMAP_LLM_ENDPOINT=http://<宿主机IP>:11434/v1
    python -m fwmap triage /path/to/rootfs -o out --agent --dyn
"""

from __future__ import annotations

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__all__ = ["serve", "run"]


def _handler(model_name: str):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):        # 别把每个请求都打到 stderr 上
            pass

        def _json(self, obj, code: int = 200) -> None:
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):                          # noqa: N802
            if self.path.rstrip("/").endswith("/v1/models"):
                self._json({"object": "list",
                            "data": [{"id": model_name, "object": "model"}]})
            else:
                self._json({"error": "not found"}, 404)

        def do_POST(self):                         # noqa: N802
            if not self.path.rstrip("/").endswith("/v1/chat/completions"):
                self._json({"error": "not found"}, 404)
                return
            try:
                n = int(self.headers.get("Content-Length") or 0)
                req = json.loads(self.rfile.read(n) or b"{}")
            except Exception as exc:               # noqa: BLE001
                self._json({"error": f"bad request: {exc}"}, 400)
                return

            from . import llm

            t0 = time.time()
            try:
                text = llm.chat(req.get("messages") or [],
                                 max_new_tokens=int(req.get("max_tokens") or 320),
                                 temperature=float(req.get("temperature") or 0.0))
            except Exception as exc:               # noqa: BLE001
                # 模型这边炸了要如实回 500，别让调用方以为"模型说了没风险"
                self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)
                return
            print(f"[serve] {time.time() - t0:.1f}s · {len(text)} 字符", flush=True)
            self._json({
                "id": "chatcmpl-local",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model_name,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                             "finish_reason": "stop"}],
            })

    return Handler


def serve(host: str = "127.0.0.1", port: int = 11434, model_path: str | None = None,
          log=print) -> int:
    from . import llm

    path = llm.find_model(model_path, verbose=True)
    name = os.path.basename(path.rstrip("/\\")) or "fwmap-local"
    if not os.path.isdir(path or ""):
        log(f"[!] 找不到模型：{path}")
        log("    先设 FWMAP_LLM_MODEL，或者把模型放进 tools/models/")
        return 2

    log(f"[serve] 模型 {name}")
    log(f"[serve] 监听 http://{host}:{port}/v1   （Ctrl+C 结束）")
    log(f"[serve] 别的机器这样用：export FWMAP_LLM_ENDPOINT=http://<本机IP>:{port}/v1")
    srv = ThreadingHTTPServer((host, port), _handler(name))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log("\n[serve] 已停止")
    finally:
        srv.server_close()
    return 0


def run(args) -> int:
    return serve(host=getattr(args, "host", "127.0.0.1"),
                 port=int(getattr(args, "port", 11434)),
                 model_path=getattr(args, "model", None))


if __name__ == "__main__":
    raise SystemExit(run(type("A", (), {"host": "127.0.0.1", "port": 11434, "model": None})()))
