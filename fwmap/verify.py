"""M4：新颖性核对 —— 判断工具报出来的线索「是不是已经被人报过」。

这一步不是静态分析，而是**公开库比对**。做法和人工一样，但固化成命令：

  1. 拿链上的**函数名**查 NVD（跨厂商召回的 CVE 常用函数名描述）；
  2. 再拿它对应的**路由名**查一次（很多公告只写 URL 不写函数名，
     只按函数名查会漏——实测 formDLNAserver 就是这样漏掉 CVE-2024-10661 的）；
  3. 命中后回读描述，确认关键字真的出现在里面，避免 NVD 全文检索的误召回。

输出三类结论：
  known    —— 命中已公开 CVE
  unknown  —— 没查到（**不等于**是新漏洞，只说明「按这个名字没查到」）
  manual   —— 名字是 FUN_xxxx / sub_xxxx 这类无法检索的，需人工

用法：
    python -m fwmap verify out/triage/report.json
    python -m fwmap verify out/3_m3.flow.json --m2 out/2_m2.json
"""

from __future__ import annotations

import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_PATH = os.path.join(os.path.expanduser("~"), ".fwmap", "nvd-cache.json")
CACHE_TTL = 7 * 24 * 3600
# 无 API key 时限流 5 次 / 30 秒，保守取 6.5 秒
DEFAULT_DELAY = 6.5

GENERIC = re.compile(r"^(FUN_|sub_|thunk_|LAB_|_|unknown)", re.I)


def _ctx():
    if os.environ.get("FWMAP_NO_VERIFY") == "1":
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        return c
    return ssl.create_default_context()


# ---------------------------------------------------------------- 输入
def load(path: str) -> tuple[list[dict], list[dict]]:
    """读 flow.json 或 triage 的 report.json，返回 (链, 端点)。"""
    obj = json.load(open(path, encoding="utf-8"))
    chains: list[dict] = []
    endpoints: list[dict] = []
    if "binaries" in obj:                      # triage report.json
        for b in obj["binaries"]:
            chains.extend(b.get("chain_list") or [])
            endpoints.extend(b.get("endpoint_list") or [])
    else:                                      # m3 --flow 的 *.flow.json
        chains = obj.get("chains") or []
    return chains, endpoints


def load_m2(path: str) -> list[dict]:
    obj = json.load(open(path, encoding="utf-8"))
    return obj.get("endpoints") or []


def route_name(uri: str) -> str:
    """'/goform/SetDlnaCfg' -> 'SetDlnaCfg'；'/addressNatList.asp' -> 'addressNatList'。"""
    tail = uri.rstrip("/").rsplit("/", 1)[-1]
    return tail.rsplit(".", 1)[0] if "." in tail else tail


def routes_by_function(endpoints: list[dict]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for e in endpoints:
        fn = (e.get("handler_name") or "").strip()
        if not fn:
            continue
        name = route_name(e.get("uri") or "")
        if name:
            out.setdefault(fn, [])
            if name not in out[fn]:
                out[fn].append(name)
    return out


# ---------------------------------------------------------------- NVD
def _load_cache(refresh: bool) -> dict:
    if refresh or not os.path.exists(CACHE_PATH):
        return {}
    try:
        return json.load(open(CACHE_PATH, encoding="utf-8"))
    except Exception:
        return {}


def _save_cache(cache: dict) -> None:
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        json.dump(cache, open(CACHE_PATH, "w", encoding="utf-8"), ensure_ascii=False)
    except Exception:
        pass


def nvd_search(keyword: str, cache: dict, refresh: bool = False) -> list[dict]:
    """返回 [{'id':..., 'desc':...}]。命中缓存则不发请求。"""
    now = time.time()
    hit = cache.get(keyword)
    if hit and not refresh and now - hit.get("at", 0) < CACHE_TTL:
        return hit.get("rows") or []

    url = (f"{NVD_API}?keywordSearch={urllib.parse.quote(keyword)}"
           f"&resultsPerPage=50")
    req = urllib.request.Request(url, headers={"User-Agent": "fwmap-verify"})
    data = None
    last_err = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, context=_ctx(), timeout=90) as r:
                data = json.load(r)
            break
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429:                      # 限流：等久一点再试
                time.sleep(30 + attempt * 15)
                continue
            if 500 <= e.code < 600:
                time.sleep(5 + attempt * 5)
                continue
            raise
        except Exception as e:                     # 超时 / 连接重置
            last_err = e
            time.sleep(5 + attempt * 5)
    if data is None:
        raise RuntimeError(f"NVD 查询失败：{last_err}")
    rows = []
    for v in data.get("vulnerabilities") or []:
        c = v.get("cve") or {}
        desc = " ".join(d.get("value", "") for d in (c.get("descriptions") or [])
                        if d.get("lang") == "en")
        rows.append({"id": c.get("id", ""), "desc": desc})
    cache[keyword] = {"at": now, "rows": rows}
    return rows


# ---------------------------------------------------------------- 判定
def judge_function(fn: str, routes: list[str], cache: dict,
                   refresh: bool, delay: float, dry: bool) -> dict:
    """对单个函数做双路检索，返回一行结论。"""
    keywords: list[str] = []
    if not GENERIC.match(fn):
        keywords.append(fn)
    for r in routes:
        if r and r not in keywords and not GENERIC.match(r):
            keywords.append(r)

    if not keywords:
        return {"function": fn, "routes": routes, "keywords": [],
                "verdict": "manual", "matched": [], "related": [],
                "note": "函数名不可检索（FUN_/sub_），需人工核对"}

    matched, related = [], []
    for kw in keywords:
        if dry:
            continue
        try:
            rows = nvd_search(kw, cache, refresh)
        except Exception as e:
            print(f"[!] {kw} 查询失败：{str(e)[:60]}")
            rows = []
        if delay:
            time.sleep(delay)
        low = kw.lower()
        for row in rows:
            item = dict(row, keyword=kw)
            if low in row["desc"].lower():
                matched.append(item)
            else:
                related.append(item)

    # 去重
    seen, uniq = set(), []
    for m in matched:
        if m["id"] not in seen:
            seen.add(m["id"])
            uniq.append(m)

    if uniq:
        verdict = "known"
        note = f"命中 {len(uniq)} 条已公开 CVE"
    elif related:
        verdict = "unknown"
        note = f"关键词有 {len(related)} 条无关命中，但描述里没提到它"
    else:
        verdict = "unknown"
        note = "按函数名/路由名都没查到（不等于新漏洞）"

    return {"function": fn, "routes": routes, "keywords": keywords,
            "verdict": verdict, "matched": uniq, "related": related,
            "note": note}


# ---------------------------------------------------------------- 渲染
MARK = {"known": "已公开", "unknown": "未命中", "manual": "需人工", "error": "查询失败"}


def to_markdown(rows: list[dict], source: str) -> str:
    L = ["# fwmap verify · 新颖性核对", ""]
    L.append(f"- 输入：`{source}`")
    L.append(f"- 检索源：NVD CVE API（函数名 + 路由名双路）")
    L.append(f"- 时间：{time.strftime('%Y-%m-%d %H:%M')}")
    L.append("")
    L.append("> **「未命中」不等于新漏洞**，只说明按这个名字在 NVD 里查不到。")
    L.append("> 很多固件漏洞从未申请 CVE，或公告只写型号不写函数。")
    L.append("")

    stat = {k: sum(1 for r in rows if r["verdict"] == k) for k in MARK}
    L.append(f"汇总：已公开 {stat['known']} · 未命中 {stat['unknown']} · 需人工 {stat['manual']}")
    L.append("")
    L.append("| 函数 | 路由 | 结论 | 说明 |")
    L.append("|---|---|---|---|")
    for r in rows:
        fn = r["function"]
        routes = ", ".join(r["routes"][:2]) or "—"
        L.append(f"| `{fn}` | {routes} | **{MARK[r['verdict']]}** | {r['note']} |")
    L.append("")

    known = [r for r in rows if r["verdict"] == "known"]
    if known:
        L.append("## 命中的 CVE")
        L.append("")
        for r in known:
            L.append(f"### `{r['function']}`  （关键词：{', '.join(r['keywords'])}）")
            for m in r["matched"][:6]:
                desc = (m["desc"] or "")[:220].replace("\n", " ")
                L.append(f"- **{m['id']}**（{m['keyword']}）— {desc}")
            L.append("")
    return "\n".join(L) + "\n"


def run(args) -> int:
    chains, endpoints = load(args.input)
    if args.m2:
        endpoints = load_m2(args.m2)

    if not chains:
        print("[!] 输入里没有链（是不是用的 scan 报告？verify 需要 m3 --flow 或 triage 的 report.json）")
        return 1

    fn_routes = routes_by_function(endpoints)
    # 按函数去重，保留出现次数，用于排序
    order, seen = [], {}
    for c in chains:
        if c.get("verdict", "keep") != "keep":
            continue
        fn = c.get("function") or ""
        if not fn:
            continue
        if fn not in seen:
            seen[fn] = 0
            order.append(fn)
        seen[fn] += 1

    if getattr(args, "only", None):
        order = [fn for fn in order if args.only.lower() in fn.lower()]
    if args.limit:
        order = order[: args.limit]

    print(f"[*] 输入 {os.path.basename(args.input)}：{len(order)} 个函数待核对")
    if endpoints:
        print(f"[*] 路由映射：{len(fn_routes)} 个函数有对应 URL")
    if args.dry_run:
        for fn in order:
            kws = ([fn] if not GENERIC.match(fn) else []) + fn_routes.get(fn, [])
            print(f"    {fn:<24} 关键词: {', '.join(kws) or '(无，需人工)'}")
        print("[dry-run] 未发起任何请求")
        return 0

    cache = _load_cache(args.refresh)
    rows = []
    for i, fn in enumerate(order, 1):
        routes = fn_routes.get(fn, [])
        print(f"  [{i}/{len(order)}] {fn:<24} ", end="", flush=True)
        try:
            row = judge_function(fn, routes, cache, args.refresh, args.delay, False)
        except Exception as e:
            row = {"function": fn, "routes": routes, "keywords": [],
                   "verdict": "error", "matched": [], "related": [],
                   "note": f"查询失败：{str(e)[:60]}"}
        _save_cache(cache)
        print(f"{MARK[row['verdict']]:<6} {row['note']}")
        rows.append(row)

    out_md = args.out or os.path.splitext(args.input)[0] + ".verify.md"
    with open(out_md, "w", encoding="utf-8") as fh:
        fh.write(to_markdown(rows, args.input))

    known = sum(1 for r in rows if r["verdict"] == "known")
    print()
    print(f"[+] 已公开 {known} · 未命中 {len(rows) - known}（不等于新漏洞）")
    print(f"[+] 报告：{out_md}")
    return 0
