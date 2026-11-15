"""把同学的审查结论（Mango-Agent 的 report.json）并进我们这边核对。

为什么需要这一条：她那套 agent 的活是「拿 IDA 一条一条查证据」，查不到就老实写
`insufficient_evidence`。她查不到的东西里，有一部分**根本不用查代码** ——
函数名和路由名在 CVE 库里就有答案。

她 2026-11-06 那轮的真实结论是：`TendaTelnet` 从 NVRAM 取 `lan.ip` 拼进
`doSystemCmd("telnetd -b ...&")`，上游 `fromAdvSetLanip` 对 `lanIp` 没有任何校验，
但她**证不出** `TendaTelnet` 有没有被 `websFormDefine` 注册成 HTTP 处理函数，
于是停在 `insufficient_evidence`。

而 CVE-2025-1819 的描述里写得很清楚：`TendaTelnet`，`/goform/telnet`，参数 `lan_ip`，
命令注入。这一条不需要 IDA，0.3 秒就能查出来。

所以这个命令做三件事：
1. 读她的报告（`report.json` 或整个 run 目录），把她的结论原样保留；
2. 拿候选里的函数名去查 CVE 库（离线优先，和 verify 一致）；
3. 输出一份合并结论：**她缺的那条证据，库里有没有答案**。

绝不改写她的结论 —— 合并报告里她的 `insufficient_evidence` 一字不动。
"""

from __future__ import annotations

import json
import os
import re

__all__ = ["load_review", "candidate_names", "merge", "render", "run"]

# 反编译出来的占位名查不了，查了也只是噪音
_RE_PLACEHOLDER = re.compile(r"^(sub_|FUN_|loc_|j_|dword_|unk_)", re.I)
_RE_ROUTE = re.compile(r"/[A-Za-z][A-Za-z0-9_\-]*(?:/[A-Za-z0-9_\-.]+)*")
_RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)

# 这些名字在任何固件里都出现，查它的命中数只说明「这词很常见」，不能当新颖性依据
_GENERIC = {
    "system", "popen", "execve", "execl", "execv", "dosystemcmd", "dosystem",
    "sprintf", "snprintf", "strcpy", "strcat", "memcpy", "sscanf", "printf",
    "gets", "scanf", "main", "init", "start", "run", "handle", "handler", "process",
    "websgetvar", "websdefine", "websformdefine", "getvalue", "setvalue",
}


def load_review(path: str) -> dict:
    """接受 report.json，也接受一整个 run 目录。"""
    p = path
    if os.path.isdir(path):
        p = os.path.join(path, "report.json")
        if not os.path.exists(p):
            raise ValueError(f"{path} 里没有 report.json —— 这是她的 runs/<时间>-<id>/ 目录吗？")
    with open(p, encoding="utf-8-sig") as fh:
        rep = json.load(fh)
    if "candidate" not in rep or "review" not in rep:
        raise ValueError("不像是 Mango-Agent 的 report.json（缺 candidate / review）")
    rep.setdefault("_path", os.path.abspath(p))
    return rep


def candidate_names(cand: dict) -> tuple[list[str], list[str]]:
    """从候选里挑出「值得查库」的名字，返回 (要查的, 跳过的)。

    跳过分三类：反编译占位名（sub_415798）、通用函数名（system/sprintf）、
    以及带参数签名的长串。
    """
    raw: list[str] = []
    for step in cand.get("trace") or []:
        raw.append(str(step.get("function") or ""))
    raw.append(str((cand.get("sink") or {}).get("function") or ""))

    query, skipped = [], []
    for name in raw:
        name = name.strip()
        if not name:
            continue
        if (name.lower() in _GENERIC or _RE_PLACEHOLDER.match(name)
                or len(name) < 4 or len(name) > 40 or "(" in name or " " in name):
            if name not in skipped:
                skipped.append(name)
            continue
        if name not in query:
            query.append(name)
    return query, skipped


def _routes(desc: str) -> list[str]:
    """从 CVE 描述里抠出路由，比如 /goform/telnet。

    抠不到就算了 —— 宁可不给，也不能给个错的当证据。
    句末的句号、逗号要剪掉，否则会出 `/goform/telnet.` 这种带尾巴的。
    """
    out = []
    for m in _RE_ROUTE.findall(desc or ""):
        m = m.rstrip(".,;:")
        if m.lower().endswith((".c", ".h", ".so", ".bin", ".txt", ".html", ".htm")):
            continue
        if m not in out:
            out.append(m)
    return out


def merge(rep: dict, index, limit: int = 6, query_sink: bool = False) -> dict:
    """查库并把结果挂到报告上。index 可以是离线 Index，也可以是 None（只做结构解析）。"""
    cand = rep.get("candidate") or {}
    names, skipped = candidate_names(cand)
    find = {n: {"matched": [], "related": [], "routes": []} for n in names}
    sink = str((cand.get("sink") or {}).get("function") or "")

    if index is not None:
        for name in names:
            matched, related = index.search(name, limit=limit)
            find[name]["matched"] = matched
            find[name]["related"] = related
            seen = []
            for row in matched:
                for rt in _routes(row.get("desc") or ""):
                    if rt not in seen:
                        seen.append(rt)
            find[name]["routes"] = seen

    known = [n for n, v in find.items() if v["matched"]]
    return {
        "source": rep.get("_path", ""),
        "sha256": rep.get("binary_sha256", ""),
        "candidate": cand,
        "review": rep.get("review") or {},
        "names": find,
        "skipped": skipped,
        "sink": sink,
        "known": known,
        "routes": sorted({r for v in find.values() for r in v["routes"]}),
    }


def _verdict_of(m: dict) -> str:
    if m["known"]:
        return f"**已公开**（{len(m['known'])} 个函数名在 CVE 描述里出现）"
    if m["names"]:
        return "未命中（库里没有这些函数名）"
    return "无法检索（候选里全是 sub_/通用名）"


def render(m: dict, built_at: str = "") -> str:
    cand = m["candidate"]
    rev = m["review"]
    sink = cand.get("sink") or {}
    chain = " ← ".join(str(s.get("function")) for s in (cand.get("trace") or [])) or "（未记录）"
    inputs = (cand.get("inputs") or {}).get("likely") or []

    L = ["# 合并结论：她的审查 × 我们的新颖性核对", ""]
    L += ["| 项 | 值 |", "|---|---|"]
    L.append(f"| 目标 sha256 | `{m['sha256'] or '未记录'}` |")
    L.append(f"| 候选链 | {chain} → `{sink.get('function','?')}` @ {sink.get('ins_addr','?')} |")
    L.append(f"| 候选输入 | {', '.join(inputs) if inputs else '（未记录）'} |")
    L.append(f"| Mango 排名 | {cand.get('rank','-')}（不是概率） |")
    L.append(f"| 她的结论 | `{rev.get('status','?')}` |")
    L.append(f"| 新颖性 | {_verdict_of(m)} |")
    if built_at:
        L.append(f"| CVE 库快照 | {built_at} |")
    L.append("")

    L += ["## 她的结论（原样保留，不改写）", ""]
    L.append(f"**{rev.get('status','?')}** —— {rev.get('summary','')}".strip())
    L.append("")
    if rev.get("evidence"):
        L.append("她引用到的证据：")
        L.append("")
        for e in rev["evidence"]:
            L.append(f"- `{e.get('id','?')}` {e.get('claim','')}")
        L.append("")
    if rev.get("missing_evidence"):
        L.append("她明确说缺的：")
        L.append("")
        for x in rev["missing_evidence"]:
            L.append(f"- {x}")
        L.append("")

    L += ["## 我们查到的（离线 CVE 库）", ""]
    if not m["names"]:
        L.append("候选里没有可检索的函数名，这一步跳过。")
    for name, v in m["names"].items():
        rows = v["matched"]
        L.append(f"### `{name}` —— {len(rows)} 条命中")
        L.append("")
        if not rows:
            rel = v["related"]
            L.append("没有描述里原样出现该名字的 CVE。"
                     + (f"（分词级相关 {len(rel)} 条，仅供参考）" if rel else ""))
            L.append("")
            continue
        L += ["| CVE | 发布 | 等级 | 路由 | 描述 |", "|---|---|---|---|---|"]
        for r in rows:
            desc = " ".join((r.get("desc") or "").split())[:160].replace("|", "/")
            sev = f"{r.get('severity') or '-'} {r.get('score') or ''}".strip()
            L.append(f"| {r.get('cve_id') or r.get('id')} | {r.get('published','')} | {sev} "
                     f"| {', '.join(_routes(r.get('desc') or '')) or '—'} | {desc} |")
        L.append("")
    if m["skipped"]:
        L.append(f"> 跳过没查的：{', '.join(f'`{s}`' for s in m['skipped'])}"
                 "（占位名或通用汇点名，查了也是噪音）")
        L.append("")

    if m["known"] and m["routes"]:
        L += ["## 她那几条「缺失证据」，库里其实有答案", ""]
        L.append(f"她缺的第一条通常是「这个函数有没有注册成 HTTP 处理函数」。"
                 f"CVE 描述里给出的路由是：**{', '.join(m['routes'])}**。")
        L.append("")
        L.append("这条**不需要 IDA**：公开漏洞记录已经把「handler ↔ 路由」写死了。"
                 "换句话说，她的候选到这里就够判「已公开」了，"
                 "剩下的是「这个型号受不受影响」，那是版本问题，不是可达性问题。")
        L.append("")

    L += ["## 结论", ""]
    if m["known"]:
        L.append(f"- 这个候选**不是新的**：函数名 `{'`、`'.join(m['known'])}` 在已公开 CVE 里出现过。")
        L.append("- 她的 `insufficient_evidence` 是**对她手上的证据而言**正确，"
                 "但补上路由信息后，结论应当是「已公开的手法，需确认本型号/版本是否同样受影响」。")
    else:
        L.append("- 库里没有命中，**不等于新漏洞**：可能只是没人用这个函数名报过。"
                 "命不中时要靠动态验证或人工确认。")
    L.append("")
    L.append("> 本文件由 `fwmap merge --from mango` 生成。她的原始报告没有被修改。")
    return "\n".join(L)


def run(args) -> int:
    try:
        rep = load_review(args.input)
    except Exception as e:                              # noqa: BLE001
        print(f"[!] {e}")
        return 2

    index, built_at = None, ""
    if not getattr(args, "no_query", False):
        from .nvd import Index, find_db

        db = find_db(getattr(args, "db", None))
        if not db:
            print("[!] 没有离线库，只能做结构解析。先跑 nvd fetch / nvd build，"
                  "或者加 --no-query 显式跳过。")
            return 2
        index = Index(db)
        try:
            built_at = index.built_at
            m = merge(rep, index, limit=getattr(args, "limit", 6))
        finally:
            index.close()
    else:
        m = merge(rep, None, limit=getattr(args, "limit", 6))

    text = render(m, built_at)
    out = getattr(args, "output", None) or (
        os.path.splitext(rep["_path"])[0] + ".merged.md")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(text)

    rev = m["review"]
    print(f"[+] 她的结论：{rev.get('status','?')}")
    print(f"[+] 新颖性核对：{_verdict_of(m)}")
    for name, v in m["names"].items():
        print(f"    {name}: {len(v['matched'])} 条命中"
              + (f"，路由 {', '.join(v['routes'])}" if v["routes"] else ""))
    print(f"[+] 合并报告 → {out}")
    return 0
