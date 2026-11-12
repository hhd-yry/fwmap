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

检索源有两种，判定逻辑完全一样，只是数据从哪来：

  api    —— NVD CVE API。权威、当天最新；无 key 时限流 5 次/30 秒，要联网。
  local  —— 离线 NVD 库（`python -m fwmap nvd fetch/build` 建的 SQLite，
            NIST 官方 feed 全量）。零网络、亚秒级、结果冻结在某个快照日。

默认 `--source auto`：先探一下网络 —— 通就走 API，不通就退回本地库。
有网时加 `--update-index`，跑完顺手把本地库刷到最新（只下变了的年包），
这样下次断网还有新数据可用。

用法：
    python -m fwmap verify out/triage/report.json
    python -m fwmap verify out/3_m3.flow.json --m2 out/2_m2.json
    python -m fwmap verify out/3_m3.flow.json --source local
    python -m fwmap verify out/3_m3.flow.json --update-index
"""

from __future__ import annotations

import json
import os
import re
import ssl
import sys
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
_RE_CAMEL = re.compile(r"[A-Z]")
MAX_ROUTES = 4


def _add_route(out: dict[str, list[str]], fn: str, name: str) -> None:
    lst = out.setdefault(fn, [])
    if name not in lst and len(lst) < MAX_ROUTES:
        lst.append(name)


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
    """函数 → 路由名。

    优先用 handler_name（registration 策略能直接把 handler 解出来）；解不出来时
    （inventory 策略只记了「哪个函数引用了这个 URL 字符串」）退而用 refs ——
    准不准另说，但比完全没有路由名强：verify 是双路检索，多一路多一次命中机会。

    refs 只收「看起来像固件 handler」的名字（长度 ≥5 且含大写），否则
    /index.asp 这种通用页面会给几十个函数都挂上一个 "index" 的噪声关键词。
    """
    out: dict[str, list[str]] = {}
    for e in endpoints:
        name = route_name(e.get("uri") or "")
        if not name:
            continue
        fn = (e.get("handler_name") or "").strip()
        if fn:
            _add_route(out, fn, name)
            continue
        if len(name) < 5 or not _RE_CAMEL.search(name[1:]):
            continue
        for r in e.get("refs") or []:
            f = (r.get("in") or "").strip()
            if f and not GENERIC.match(f):
                _add_route(out, f, name)
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
            with urllib.request.urlopen(req, context=_ctx(), timeout=30) as r:
                data = json.load(r)
            break
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429:                      # 限流：等久一点再试
                time.sleep(20 + attempt * 10)
                continue
            if 500 <= e.code < 600:
                time.sleep(3 + attempt * 5)
                continue
            raise
        except Exception as e:                     # 超时 / 连接重置
            last_err = e
            time.sleep(3 + attempt * 5)
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
                   refresh: bool, delay: float, dry: bool,
                   searcher=None) -> dict:
    """对单个函数做双路检索，返回一行结论。

    `searcher(keyword) -> [{'id','desc',...}]` 是检索后端：默认走在线 API，
    离线模式下由 `nvd.Index.search` 提供。判定逻辑对两者完全一样 ——
    换的只是数据从哪来，不是判定标准。
    """
    if searcher is None:
        def searcher(kw):                      # noqa: E306  延迟绑定，便于测试替换
            return nvd_search(kw, cache, refresh)

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
            rows = searcher(kw)
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


def to_markdown(rows: list[dict], source: str, backend: dict | None = None) -> str:
    L = ["# fwmap verify · 新颖性核对", ""]
    L.append(f"- 输入：`{source}`")
    if backend and backend.get("kind") == "local":
        L.append(f"- 检索源：离线 NVD 库 `{os.path.basename(backend['db'])}`"
                 f"（{backend['count']} 条 CVE，{backend['years']} 年，"
                 f"快照 {backend['built_at']}）")
    else:
        L.append("- 检索源：NVD CVE API（在线，函数名 + 路由名双路）")
    L.append(f"- 时间：{time.strftime('%Y-%m-%d %H:%M')}")
    L.append("")
    L.append("> **「未命中」不等于新漏洞**，只说明按这个名字在 NVD 里查不到。")
    L.append("> 很多固件漏洞从未申请 CVE，或公告只写型号不写函数。")
    if backend and backend.get("kind") == "local":
        L.append(f"> 本报告基于 **{backend['built_at']}** 的 NVD 快照；"
                 "之后再公开的 CVE 不会出现在这里。")
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


def _make_searcher(args):
    """按 --source 选检索后端，返回 (searcher, info)；选不出来返回 (None, None)。

    auto（默认）：先探一下 NVD 通不通 ——
      通  → 走在线 API（权威、当天最新）
      不通 → 退回本地离线库（断网验收靠它）
    探一次只取几百字节的 .meta，不消耗 API 配额。
    """
    from . import nvd

    want = (getattr(args, "source", None) or "auto").lower()
    why = ""
    if want == "online":
        want = "api"
    if want == "auto":
        if os.environ.get("FWMAP_OFFLINE") == "1":
            want, why = "local", "FWMAP_OFFLINE=1"
        elif nvd.probe():
            want, why = "api", "网络可达"
        else:
            want, why = "local", "网络不可达"

    if want == "local":
        try:
            db = nvd.find_db(getattr(args, "db", None))
            if not db:
                print("[!] 没有离线 NVD 库。先跑 `python -m fwmap nvd fetch` + `nvd build`，"
                      "或加 --source api 联网查。", file=sys.stderr)
                return None, None
            idx = nvd.Index(db)
        except Exception as e:                       # noqa: BLE001
            print(f"[!] 离线库打不开：{e}", file=sys.stderr)
            return None, None
        deep = not getattr(args, "no_scan", False)
        info = {"kind": "local", "db": idx.path, "built_at": idx.built_at,
                "count": idx.count, "years": idx.years, "index": idx, "why": why}

        def local(kw):
            matched, related = idx.search(kw, deep=deep)
            return matched + related
        return local, info

    cache = _load_cache(getattr(args, "refresh", False))

    def online(kw):
        rows = nvd_search(kw, cache, getattr(args, "refresh", False))
        _save_cache(cache)                           # 逐词落盘，中断也不白跑
        return rows
    return online, {"kind": "api", "cache": CACHE_PATH, "why": why}


def run(args) -> int:
    chains, endpoints = load(args.input)
    if args.m2:
        endpoints = load_m2(args.m2)

    if not chains:
        print("[!] 输入里没有链（是不是用的 scan 报告？verify 需要 m3 --flow 或 triage 的 report.json）")
        return 1

    searcher, backend = _make_searcher(args)
    if searcher is None:
        return 2

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

    why = backend.get("why") or ""
    if backend["kind"] == "local":
        print(f"[*] 检索源：离线 NVD 库（{backend['count']} 条 CVE，"
              f"{backend['years']} 年，快照 {backend['built_at']}）"
              + (f" —— {why}" if why else ""))
    else:
        print(f"[*] 检索源：NVD 在线 API（请求间隔 {args.delay}s）"
              + (f" —— {why}" if why else ""))

    print(f"[*] 输入 {os.path.basename(args.input)}：{len(order)} 个函数待核对")
    if endpoints:
        print(f"[*] 路由映射：{len(fn_routes)} 个函数有对应 URL")
    if args.dry_run:
        for fn in order:
            kws = ([fn] if not GENERIC.match(fn) else []) + fn_routes.get(fn, [])
            print(f"    {fn:<24} 关键词: {', '.join(kws) or '(无，需人工)'}")
        print("[dry-run] 未发起任何请求")
        return 0

    delay = 0.0 if backend["kind"] == "local" else args.delay
    rows = []
    t_all = time.time()
    for i, fn in enumerate(order, 1):
        routes = fn_routes.get(fn, [])
        print(f"  [{i}/{len(order)}] {fn:<24} ", end="", flush=True)
        t0 = time.time()
        try:
            row = judge_function(fn, routes, {}, args.refresh, delay, False,
                                 searcher=searcher)
        except Exception as e:                       # noqa: BLE001
            row = {"function": fn, "routes": routes, "keywords": [],
                   "verdict": "error", "matched": [], "related": [],
                   "note": f"查询失败：{str(e)[:60]}"}
        print(f"{MARK[row['verdict']]:<6} {row['note']}  ({time.time()-t0:.1f}s)")
        rows.append(row)

    out_md = args.out or os.path.splitext(args.input)[0] + ".verify.md"
    with open(out_md, "w", encoding="utf-8") as fh:
        fh.write(to_markdown(rows, args.input, backend))

    known = sum(1 for r in rows if r["verdict"] == "known")
    print()
    print(f"[+] 已公开 {known} · 未命中 {len(rows) - known}（不等于新漏洞）"
          f" · 用时 {time.time()-t_all:.1f}s")
    print(f"[+] 报告：{out_md}")
    if backend["kind"] == "local" and backend.get("index"):
        idx = backend["index"]
        if idx._scans:
            print(f"[*] 其中 {idx._scans} 次整词未命中，落到子串扫描兜底")
        idx.close()
    else:
        _after_online(args)
    return 0


def _after_online(args) -> None:
    """走完 API 之后，顺手让离线库保持新鲜 —— 下次断网才有新数据可用。

    默认只提醒（更新一次要下年包 + 重建索引，不能偷偷跑）；加 --update-index 才真更新。
    """
    from . import nvd

    if getattr(args, "update_index", False):
        print("[*] 更新离线库（先比 .meta，只下变了的年包）…")
        try:
            r = nvd.update()
        except Exception as e:                       # noqa: BLE001
            print(f"[!] 离线库更新失败：{str(e)[:80]}")
            return
        if r["rebuilt"]:
            print(f"[+] 离线库已更新：{r['cve_count']} 条 CVE")
        else:
            print("[+] 离线库已是最新")
        return

    age = nvd.age_days(getattr(args, "db", None))
    if age is None:
        print("[*] 提示：还没有离线 NVD 库。跑 `python -m fwmap nvd update` 存一份，"
              "断网时 verify 直接用它")
    elif age > 7:
        print(f"[*] 提示：离线库快照已 {age:.0f} 天，跑 `python -m fwmap nvd update` 刷新"
              "（或本次加 --update-index）")
