"""黑盒判断「这个 URL 在固件上到底存不存在」。

为什么需要：打漏洞打空，最常见的不是"没有漏洞"，而是**URL 猜错了**。
今天在 Edimax 上的实测：

    /goform/formStaDrvSetup + rootAPmac  -> 184 字节，正常页面（存在）
    /goform/formDNSProxyrules + input    -> 184 字节（存在）
    /goform/formiNICWdsEncrypt + input   -> 300 字节 ERR_MSG（存在，但参数名不对）
    /goform/not_a_real_handler           -> 300 字节跳转页（不存在）

前三条里有两类 300 字节，光看长度分不出来 —— 所以判定要靠**三个对照**：
  负对照：瞎编一个肯定不存在的路径
  正对照：`/`（服务器一定答得出来，用来确认服务真的起来了）
  候选  ：跟负对照比，响应"不一样"就是存在

判不出来就说不知道，绝不把"不知道"写成"不存在"。
"""

from __future__ import annotations

import random
import string

__all__ = ["classify", "probe", "signature"]

NOT_FOUND = "not-found"      # 和负对照一模一样 → 大概率没这个路由
HANDLER = "handler"          # 和负对照明显不同 → 路由存在
UNKNOWN = "unknown"          # 服务没起来 / 判不出来


def _req(path: str, port: int = 80, host: str = "127.0.0.1",
         method: str = "GET") -> dict:
    """构造一个探测请求。

    默认用 **GET**：探测的是"这个地址在不在"。用 POST 会让一部分固件的
    httpd 直接关掉连接（DIR-615 实测：GET /index.asp 返回 200，
    POST 同路径返回 0 字节），于是所有候选都被判成 unknown。
    需要 POST 的场景（有参动作）由调用方显式传 method="POST"。
    """
    body = "x=1" if method == "POST" else ""
    return {"method": method, "path": path, "host": host, "port": port,
            "headers": {"Host": f"{host}:{port}",
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Content-Length": str(len(body)),
                        "Connection": "close"},
            "body": body, "param": "x", "value": "1", "function": "<route-probe>"}


def signature(resp: str, full_len: int | None = None) -> tuple[int, str]:
    """把响应压成一个可比较的签名：长度 + 关键标记。

    只看长度会被"页面里带时间戳/随机数"骗到，所以再抽一个标记：
    404 页面通常带明确的 not found 字样或跳转脚本。
    """
    body = resp or ""
    low = body.lower()
    marks = []
    for word in ("not found", "404", "err_msg", "no such", "invalid url",
                 "location.assign", "document.location"):
        if word in low:
            marks.append(word)
    # 长度优先用完整响应长度（resp 可能被截到 300 字符，会把 184 和 300 判成一样）
    return (full_len if full_len is not None else len(body)), ",".join(marks)


def classify(candidate: str, negative: tuple[int, str], positive: tuple[int, str],
             got: tuple[int, str]) -> str:
    """三对照判定。允许 ±8 字节的长度抖动（有些页面带时间戳）。"""
    c_len, c_mark = got
    n_len, n_mark = negative
    if not c_len:
        return UNKNOWN
    if positive[0] == 0:
        return UNKNOWN                      # 正对照都答不出来 → 服务没起来
    same_as_neg = abs(c_len - n_len) <= 8 and c_mark == n_mark
    if same_as_neg:
        return NOT_FOUND
    return HANDLER


def probe(paths: list[str], run_request, runtime: dict, port: int = 80,
          timeout: float = 8.0, log=None) -> dict:
    """对一串路径做三对照探测，返回 {path: {verdict, len, mark}}。

    `run_request` 是 dyn.run_request（每次会起一次服务，约 8-10 秒）。
    """
    log = log or (lambda *a: None)
    bogus = "/" + "".join(random.choices(string.ascii_lowercase, k=12))

    neg_res = run_request(_req(bogus, port), runtime, timeout=timeout)
    neg = signature(neg_res.get("resp") or "", neg_res.get("resp_len"))
    # 正对照用 dyn 里那条「绝对无害的 GET /」—— 和动态验证用同一把尺子，
    # 免得两处对「服务活着」的判断标准不一致。
    from . import poc as _poc

    pos_res = run_request(_poc.control_request(port), runtime, timeout=timeout)
    pos = signature(pos_res.get("resp") or "", pos_res.get("resp_len"))
    log(f"[routes] 负对照 {bogus} → {neg[0]}B {neg[1]!r}；正对照 / → {pos[0]}B")

    out: dict[str, dict] = {}
    for p in paths:
        res = run_request(_req(p, port), runtime, timeout=timeout)
        sig = signature(res.get("resp") or "", res.get("resp_len"))
        verdict = classify(p, neg, pos, sig)
        out[p] = {"verdict": verdict, "len": sig[0], "mark": sig[1],
                  "status": res.get("status")}
        log(f"[routes] {p:40s} {sig[0]:5d}B -> {verdict}")
    return {"negative": {"path": bogus, "len": neg[0], "mark": neg[1]},
            "positive": {"path": "/", "len": pos[0]}, "routes": out}
