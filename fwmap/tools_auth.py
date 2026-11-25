"""auth 类工具：默认口令 / 登录爆破 / 登录接口探测。

为什么放在工具总线里（而不是写死在别处）：
  不同固件的登录形态差别极大 —— 有的 POST 表单，有的先取验证码，
  有的 Basic Auth，有的带 CSRF token。**让模型按证据选工具**，
  代码只负责执行和验收，和 unpack/decrypt 是同一套规矩。

成功判据（auth 类的"成功"= 真的登进去了）：
  1. 响应里出现会话 Cookie（Set-Cookie 且名字像 session/sid/token）；
  2. 或者访问需要登录的页面不再返回登录页；
  3. 或者响应里出现管理页特征串（"logout"、"reboot" 等）。
只看到 "Login" 字样、或者 HTTP 200，都不算成功。

另外：**登录接口本身会崩**也是结论（我们实测 DIR-615 就是），
这种情况必须单独标出来，不能记成"口令错误"。
"""

from __future__ import annotations

import json
import os
import re
import socket

from . import toolbus
from .toolbus import Tool

__all__ = ["register_all", "probe_login", "DEFAULT_CREDS", "looks_like_success"]

DEFAULT_CREDS = [
    ("admin", ""), ("admin", "admin"), ("Admin", ""), ("Admin", "admin"),
    ("admin", "password"), ("admin", "1234"), ("admin", "12345"),
    ("root", ""), ("root", "root"), ("root", "admin"),
    ("user", "user"), ("guest", "guest"), ("support", "support"),
]

_ADMIN_MARKERS = ("logout", "log_out", "reboot", "restart", "syslog",
                  "wireless", "wan", "lan", "administrator")
_SESSION_COOKIE = re.compile(r"set-cookie:\s*([^=\r\n]+)=", re.I)


def looks_like_success(resp: str) -> dict:
    """判断一次登录尝试是否真的成功。返回 {ok, why}。"""
    head, _, body = (resp or "").partition("\r\n\r\n")
    low = resp.lower()

    m = _SESSION_COOKIE.search(head)
    cookie = m.group(1).strip() if m else ""
    if cookie and re.search(r"session|sid|token|auth|id", cookie, re.I):
        return {"ok": True, "why": f"拿到会话 Cookie: {cookie}"}

    hits = [w for w in _ADMIN_MARKERS if w in low]
    if len(hits) >= 3:
        return {"ok": True, "why": f"页面出现管理特征: {','.join(hits[:4])}"}

    if "login" in low and "password" in low and len(hits) < 2:
        return {"ok": False, "why": "仍然是登录页"}
    return {"ok": False, "why": "没有会话 Cookie，也没有管理页特征"}


def _http(port: int, method: str, path: str, body: str = "",
          timeout: float = 6.0) -> dict:
    head = [f"{method} {path} HTTP/1.0", "Host: 127.0.0.1",
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}", "Connection: close", "", ""]
    raw = ("\r\n".join(head) + body).encode()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout)
        s.sendall(raw)
        s.settimeout(timeout)
        data = b""
        while len(data) < 8192:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
    except OSError as ex:
        return {"resp": "", "error": type(ex).__name__}
    return {"resp": data.decode("latin-1", "replace"), "error": ""}


def probe_login(port: int = 80, *, path: str = "/login.cgi",
                user_field: str = "login_name", pass_field: str = "login_pass",
                extra: dict | None = None, creds=None, log=print) -> dict:
    """按默认口令表试一遍。**登录接口崩溃也算结论**，单独记。"""
    extra = dict(extra or {})
    creds = list(creds or DEFAULT_CREDS)
    results = []
    for user, pw in creds:
        body = "&".join([f"{user_field}={user}", f"{pass_field}={pw}"] +
                        [f"{k}={v}" for k, v in extra.items()] + ["Login=Login"])
        res = _http(port, "POST", path, body)
        if res["error"]:
            results.append({"user": user, "pass": pw, "verdict": "no-listener",
                            "detail": res["error"]})
            log(f"  {user}/{pw or '(空)'} → 连接失败 {res['error']}")
            continue
        if not res["resp"]:
            results.append({"user": user, "pass": pw, "verdict": "empty",
                            "detail": "空响应（服务可能被打死）"})
            log(f"  {user}/{pw or '(空)'} → 空响应")
            continue
        verdict = looks_like_success(res["resp"])
        rec = {"user": user, "pass": pw,
               "verdict": "success" if verdict["ok"] else "fail",
               "detail": verdict["why"]}
        results.append(rec)
        log(f"  {user}/{pw or '(空)'} → {rec['verdict']}（{verdict['why']}）")
        if verdict["ok"]:
            break

    crashed = [r for r in results if r["verdict"] in ("empty", "no-listener")]
    return {"port": port, "path": path, "tries": len(results),
            "success": any(r["verdict"] == "success" for r in results),
            "crashed": bool(crashed), "results": results}


# ---------------------------------------------------------------- 工具注册

def _runner_default_creds(src: str, outdir: str) -> None:
    """src 是 rootfs 或任意文件；真正连的是本机 80 端口的模拟服务。"""
    port = int(os.environ.get("FWMAP_AUTH_PORT") or 80)
    path = os.environ.get("FWMAP_AUTH_PATH") or "/login.cgi"
    res = probe_login(port, path=path, log=print)
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "auth.json"), "w", encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=1)
    if not res["success"]:
        raise RuntimeError(f"默认口令未成功（{res['tries']} 次，崩溃={res['crashed']}）")


def _validate_auth(outdir: str) -> dict:
    try:
        with open(os.path.join(outdir, "auth.json"), encoding="utf-8") as fh:
            res = json.load(fh)
    except (OSError, ValueError):
        return {"ok": False, "detail": "没有 auth.json"}
    if res.get("success"):
        hit = next((r for r in res["results"] if r["verdict"] == "success"), {})
        return {"ok": True, "detail": f"登录成功：{hit.get('user')}/{hit.get('pass')}"}
    if res.get("crashed"):
        return {"ok": False, "detail": "登录接口直接崩了（这本身是结论，不是口令问题）"}
    return {"ok": False, "detail": f"{res.get('tries')} 次都没成功"}


def register_all() -> int:
    have = {t.name for t in toolbus.all_tools()}
    n = 0

    if "default-creds" not in have:
        toolbus.register(Tool(
            "default-creds", "auth", None, _validate_auth,
            python=_runner_default_creds,
            accepts="已启动的固件 Web 服务（本机端口）",
            note="按常见默认口令表登录；成功判据是拿到会话 Cookie 或管理页特征",
            failure_hint="口令不对、或登录接口本身崩溃"))
        n += 1

    for name, note in (("hydra", "经典 HTTP 表单爆破（需自己给表单参数与成功串）"),
                       ("routersploit", "IoT 专用漏洞框架，自带厂商默认口令与利用模块")):
        if name in have:
            continue
        toolbus.register(Tool(
            name, "auth", [name, "--help"], lambda d: {"ok": False, "detail": "未配置"},
            accepts="需人工给参数", note=note, failure_hint="未安装或参数不全"))
        n += 1
    return n
