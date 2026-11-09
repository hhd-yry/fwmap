"""实验：让 LLM 判断「这个 handler 有没有鉴权」，而不是判断「有没有守卫」。

与现有 agent 的区别：
  - 变的是问题（鉴权语义 vs 长度检查），不是数量；
  - 输出三态 + 证据行，证据必须能在反编译文本里找到（防编造）；
  - 最后把结果和 M3 的危险链交叉：未鉴权 + 可达危险函数 = 高危。

用法：py -3.13 auth_exp.py [函数个数]
"""
import io
import json
import os
import sys

sys.path.insert(0, r"C:\deepseek\fwmap-tool")
sys.path.insert(0, r"C:\deepseek\libs-bnb")

from fwmap.m3flow import decompile, _body, _normalize, _statements
from fwmap.m2 import find_ghidra
from fwmap.agent import llm as H

BIN = r"C:\deepseek\fw\p5\root\bin\webs"
FLOW = r"C:\deepseek\fw\p5\webs_m3.flow.json"
OUT = r"C:\deepseek\fw\p5\auth_exp.json"

PROMPT = """你是固件安全审计员。下面是一个路由器 web 服务的请求处理函数（反编译 C）。

任务：判断这个函数在执行敏感动作（命令执行 system/exec、文件写入、配置修改、重启）之前，
有没有校验调用者是否已登录或具备权限。

判定规则：
- AUTHENTICATED：调用了鉴权函数、或检查了 cookie/session/token、或先查了用户权限；
- UNAUTHENTICATED：直接执行敏感动作，看不到任何身份校验；
- UNCLEAR：代码被截断，或鉴权在别处、无法从本函数判断。

只输出 JSON，不要解释：
{"verdict":"AUTHENTICATED|UNAUTHENTICATED|UNCLEAR","evidence":"原样引用一行代码","why":"20 字以内"}
"""


def condense(text: str, head: int = 40, max_kw: int = 45) -> str:
    """函数可能有 2000 行，压成「头部 + 安全相关行」，控制模型输入。"""
    lines = [l.rstrip() for l in text.splitlines() if l.strip()]
    kw = ("websGetVar", "system", "exec", "strcpy", "sprintf", "getenv", "cookie",
          "session", "token", "auth", "login", "password", "apmib", "fopen", "write")
    picked = [l for l in lines[head:] if any(k.lower() in l.lower() for k in kw)]
    out = lines[:head] + ["/* ...省略... */"] + picked[:max_kw]
    return "\n".join(out)


def main() -> int:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    flow = json.load(io.open(FLOW, encoding="utf-8"))
    chains = {}
    order = []
    for c in flow["chains"]:
        if c.get("verdict", "keep") != "keep":
            continue
        fn = c["function"]
        if fn not in chains:
            chains[fn] = []
            order.append(fn)
        chains[fn].append("%s[%s] %s" % (c["sink"], c["sink_category"],
                                         "弱源" if c.get("weak") else "强源"))
    order = order[:limit]

    print("[*] 反编译 %d 个函数 …" % len(order))
    blocks = decompile(find_ghidra(), BIN, order)

    print("[*] 加载本地模型 …")
    H.load()
    rows = []
    for i, fn in enumerate(order, 1):
        text = blocks.get(fn) or ""
        if not text:
            print("  [%d/%d] %-22s 反编译失败" % (i, len(order), fn))
            continue
        stmts = text
        body = condense(stmts)
        msg = [{"role": "user", "content": PROMPT + "\n\n```c\n" + body + "\n```"}]
        try:
            raw = H.chat(msg, max_new_tokens=160)
        except Exception as e:
            print("  [%d/%d] %-22s LLM 失败 %s" % (i, len(order), fn, str(e)[:40]))
            continue
        v, ev, why = "UNCLEAR", "", ""
        try:
            s = raw[raw.find("{"): raw.rfind("}") + 1]
            j = json.loads(s)
            v = str(j.get("verdict", "UNCLEAR")).upper()
            ev = str(j.get("evidence", ""))[:120]
            why = str(j.get("why", ""))[:40]
        except Exception:
            why = "解析失败"
        # 证据必须在原文里出现，否则视为编造
        real = bool(ev) and (" ".join(ev.split()) in " ".join(stmts.split()))
        print("  [%d/%d] %-22s %-15s %s %s" % (
            i, len(order), fn, v, "证据✓" if real else "证据✗", why))
        rows.append({"function": fn, "verdict": v, "evidence": ev if real else "",
                     "why": why, "chains": chains[fn], "raw": raw[:200]})

    # 交叉：未鉴权 + 危险链
    print("\n=== 交叉结果（未鉴权 + 危险函数）===")
    for r in rows:
        if r["verdict"] == "UNAUTHENTICATED":
            print("  %-22s %s" % (r["function"], ", ".join(r["chains"])))

    io.open(OUT, "w", encoding="utf-8").write(
        json.dumps(rows, ensure_ascii=False, indent=1))
    print("\n[+] %s" % OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
