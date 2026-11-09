"""v2：鉴权语义实验——去掉截断、把问题收窄成二选一。

与 v1 的区别：
  1. 不再把 2000 行压成 80 行：按 300 行切块，块间 20 行重叠，最多 3 块/函数；
  2. 问题从「有没有鉴权」改成两个可判定的二选一：
       A) 这块代码里有没有调用鉴权/权限检查函数？
       B) 有没有读取 cookie / session / token？
  3. 汇总规则：任一块 A 或 B 为 1 → AUTHENTICATED；全部覆盖且均为 0 → UNAUTHENTICATED；
     未覆盖完整 → UNCLEAR。
  4. 证据行同样要求逐字命中。

用法：py -3.13 experiments/auth_semantics_v2.py [函数个数] [块数上限]
"""
import io
import json
import sys

sys.path.insert(0, r"C:\deepseek\fwmap-tool")
sys.path.insert(0, r"C:\deepseek\libs-bnb")

from fwmap.m3flow import decompile                      # noqa: E402
from fwmap.m2 import find_ghidra                        # noqa: E402
from fwmap.agent import llm as H                        # noqa: E402

BIN = r"C:\deepseek\fw\p5\root\bin\webs"
FLOW = r"C:\deepseek\fw\p5\webs_m3.flow.json"
OUT = r"C:\deepseek\fw\p5\auth_exp_v2.json"

PROMPT = """你在审计路由器 web 服务的一个请求处理函数。只回答两个二选一问题，不要推理全文。

A) 这段代码里有没有调用**鉴权/权限检查**函数（check_auth、verify_login、websSecurityHandler、
   check_permission、is_admin 之类）？
B) 这段代码里有没有**读取** cookie / session / token / Authorization 头？

只输出 JSON：
{"auth_call": 0 或 1, "cookie": 0 或 1, "evidence": "原样引用一行代码，没有就填空串"}
"""


def chunk(text: str, size: int = 120, overlap: int = 20, cap: int = 8):
    lines = [l.rstrip() for l in text.splitlines() if l.strip()]
    if len(lines) <= size:
        return ["\n".join(lines)], True
    out, i = [], 0
    while i < len(lines) and len(out) < cap:
        out.append("\n".join(lines[i:i + size]))
        i += size - overlap
    return out, i >= len(lines)


def ask(block: str):
    msg = [{"role": "user", "content": PROMPT + "\n\n```c\n" + block + "\n```"}]
    raw = H.chat(msg, max_new_tokens=120)
    s = raw[raw.find("{"): raw.rfind("}") + 1]
    j = json.loads(s)
    return int(j.get("auth_call") or 0), int(j.get("cookie") or 0), str(j.get("evidence") or "")


def main() -> int:
    nfn = int(sys.argv[1]) if len(sys.argv) > 1 else 4
    cap = int(sys.argv[2]) if len(sys.argv) > 2 else 8

    flow = json.load(io.open(FLOW, encoding="utf-8"))
    chains, order = {}, []
    for c in flow["chains"]:
        if c.get("verdict", "keep") != "keep":
            continue
        fn = c["function"]
        if fn not in chains:
            chains[fn] = []
            order.append(fn)
        chains[fn].append(c["sink"])
    order = order[:nfn]

    blocks = decompile(find_ghidra(), BIN, order)
    H.load()
    rows = []
    for i, fn in enumerate(order, 1):
        text = blocks.get(fn) or ""
        if not text:
            print("  [%d/%d] %-22s 反编译失败" % (i, len(order), fn))
            continue
        chunks, covered = chunk(text, cap=cap)
        a = ck = 0
        ev = ""
        ok = True
        for ch in chunks:
            try:
                x, y, e = ask(ch)
            except Exception as ex:
                print("      块失败:", str(ex)[:50])
                ok = False
                continue
            a, ck = a or x, ck or y
            ev = ev or e
        if a or ck:
            v = "AUTHENTICATED"
        elif covered and ok:
            v = "UNAUTHENTICATED"
        else:
            v = "UNCLEAR"
        real = bool(ev) and (" ".join(ev.split()) in " ".join(text.split()))
        print("  [%d/%d] %-22s %-15s auth=%d cookie=%d 块=%d%s 证据%s" % (
            i, len(order), fn, v, a, ck, len(chunks),
            "" if covered else "(未覆盖全)", "✓" if real else "✗"))
        rows.append({"function": fn, "verdict": v, "auth_call": a, "cookie": ck,
                     "covered": covered, "evidence": ev if real else "",
                     "sinks": chains[fn]})

    print("\n=== 交叉：未鉴权 + 危险函数 ===")
    for r in rows:
        if r["verdict"] == "UNAUTHENTICATED":
            print("  %-22s %s" % (r["function"], ", ".join(r["sinks"])))

    io.open(OUT, "w", encoding="utf-8").write(json.dumps(rows, ensure_ascii=False, indent=1))
    print("\n[+] %s" % OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
