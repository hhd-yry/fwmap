"""端点提取的回归测试（零依赖，直接 `python tests/test_endpoints.py`）。

这里锁的是真实数据暴露过的问题：最初只认 `xxx.cgi`，Tenda AC15 的 httpd
里 11 条 `/goform/*`、6 条 `/cgi-bin/*` 全部漏掉。以后再加端点形状，
先在这里补一个用例，再改 scan.ENDPOINT_RES。
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from fwmap.scan import ENDPOINT_RES  # noqa: E402


def endpoints(text: str) -> list[str]:
    raw = text.encode()
    out: list[str] = []
    for rx in ENDPOINT_RES:
        for m in rx.finditer(raw):
            p = m.group(0).decode("ascii", "replace")
            if p not in out:
                out.append(p)
    # 规则之间会重叠（/cgi-bin/upgrade.cgi 同时命中两条），只保留更长的
    return [e for e in out if not any(e != o and e in o for o in out)]


CASES = [
    ("/apply.cgi", ["/apply.cgi"]),
    ("/cgi-bin/upgrade.cgi", ["/cgi-bin/upgrade.cgi"]),          # 两条规则重叠，取长的
    ("/goform/telnet", ["/goform/telnet"]),
    ("/cgi-bin/DownloadCfg", ["/cgi-bin/DownloadCfg"]),
    ("http://192.168.0.1/goform/setSysAdm?x=1", ["/goform/setSysAdm"]),
    ("/cgi-bin/luci/;stok=abc", ["/cgi-bin/luci"]),
    ("/goform/", []),                                            # 没有名字，不算端点
    ("/cgi-bin/", []),
    ("/goform", []),
    ("index.html", []),
    ("/etc/config/network", []),                                 # 普通路径不算端点
]


def main() -> int:
    failures = 0
    for text, want in CASES:
        got = endpoints(text)
        if got != want:
            failures += 1
            print(f"FAIL {text!r}: got {got}, want {want}")
        else:
            print(f"ok   {text!r} -> {got}")
    print(f"\n{len(CASES) - failures}/{len(CASES)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
