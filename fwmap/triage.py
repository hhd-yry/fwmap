"""fwmap triage：一条命令跑完四层（挑文件 → 端点 → 出链 → LLM 复核），出一份 HTML。

用法：
    py -m fwmap triage <rootfs> -o out/ [--binaries 2] [--limit N] [--agent]

设计取舍：
  - M3 很慢（Ghidra），所以默认只对**前 2 个**二进制跑，且 profile 会缓存到
    <binary>.taint.txt，第二次跑同一个固件直接复用。
  - 任何一层失败都不中断：HTML 里如实记「这一层没跑/失败了」，而不是假装没有漏洞。
"""

from __future__ import annotations

import html
import json
import os
import time

from .m2 import extract as m2_extract
from .m3 import extract as m3_extract
from .m3 import induce, induce_sinks
from .m3flow import _load_catalog, normalize_weak, run_flow
from .m3 import catalog_path
from .scan import scan


# ---------------------------------------------------------------- 每层

_PROFILE_END = "# end-of-profile\n"


def _profile_for(binary: str, force: bool = False) -> str:
    """归纳出 profile（带缓存）。阈值按大小自适应，见 m3.py 里的说明。

    两个坑：① 以前直接往 rootfs 里写，写到一半被打断就留下半截文件，
    而下游只判「文件在不在」就复用 —— 之后所有链会静默变少，且一直缓存下去；
    ② rootfs 只读时整个 M3 会失败。现在先写临时文件再原子替换，并校验结束标记；
    真写不进去就返回空串，让 M3 用基础词表照常跑。
    """
    prof = os.path.splitext(binary)[0] + ".taint.txt"
    if os.path.exists(prof) and not force:
        try:
            with open(prof, encoding="utf-8") as fh:
                tail = fh.readlines()[-1:]
            if tail and tail[0].strip() == _PROFILE_END.strip():
                return prof
        except OSError:
            pass
        # 没有结束标记 = 上次被打断了，重建
    size_kb = os.path.getsize(binary) // 1024
    mc, md = (3, 2) if size_kb < 512 else (5, 3)
    rows = induce(binary, min_calls=mc, min_distinct=md)
    sink_rows = []
    try:
        sink_rows = induce_sinks(binary)
    except Exception:                                       # noqa: BLE001
        pass
    tmp = prof + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("# 由 InduceSources / InduceSinks 归纳，人工复核后再当 source/sink 用\n")
            for r in rows:
                sample = r["strings"] or []
                dotted = sum(1 for s in sample if "." in s)
                kind = "source-weak" if sample and dotted > len(sample) / 2 else "source-induced"
                fh.write(f"{kind} {r['api']}\n")
            for r in sink_rows:
                fh.write(f"sink-ci-induced {r['api']}\n")
            fh.write(_PROFILE_END)
        os.replace(tmp, prof)
    except OSError:
        # rootfs 只读之类：不阻断流程，只是这次不带 profile
        try:
            os.remove(tmp)
        except OSError:
            pass
        return ""
    return prof


def _m3(binary: str, limit: int, force: bool = False) -> dict:
    prof = _profile_for(binary, force=force)
    r = m3_extract(binary, profile=prof)
    _s, _k, weak = _load_catalog(catalog_path())
    if os.path.exists(prof):
        _s2, _k2, _w2 = _load_catalog(prof)
        weak.update(_w2)
    normalize_weak(r["functions"], weak)
    pool = list(r["candidates"]) + [
        fn for fn in r["functions"]
        if fn["sources"] and not fn["sinks"]
        and any(not s["weak"] for s in fn["sources"])
    ]
    flow = run_flow(binary, pool, profile=prof, limit=limit)
    return {"summary": r["summary"], "chains": flow["chains"],
            "decompiled": flow["decompiled"], "sink_verified": flow.get("sink_verified", 0)}


def _agent(binary: str, chains: list[dict], top: int, samples: int) -> list[dict]:
    from .agent import cli as agent_cli
    from .agent import extract as ex
    from .agent import judge as jd
    from .m3flow import decompile, _body, _normalize, _statements
    from .m2 import find_ghidra

    picks = agent_cli._pick_chains({"chains": chains}, top)
    if not picks:
        return []
    addrs = sorted({c["address"] for c in picks if c.get("address")})
    helpers = sorted({c["helper"] for c in picks if c.get("helper")})
    blocks = decompile(find_ghidra(), binary, addrs + helpers)
    out = []
    for c in picks:
        text = blocks.get(c["helper"]) if c.get("helper") else None
        text = text or blocks.get(c["function"])
        if not text:
            out.append({"chain": c, "facts": None, "evidence": {},
                        "judge": {"verdict": jd.UNPROVEN, "confidence": "none",
                                  "reason": "反编译失败"}})
            continue
        stmts = [" ".join(s.split()) for s in _statements(_body(_normalize(text)))]
        res = ex.extract(c, stmts, samples=samples)
        out.append({"chain": c, "facts": res.get("facts"),
                    "evidence": res.get("evidence"),
                    "agreement": res.get("agreement"),
                    "judge": jd.judge(c, res)})
    return out


# ---------------------------------------------------------------- 渲染

BADGE = {
    "CONFIRMED": ("#b42318", "#fee4e2"),
    "REVIEW": ("#b54708", "#fef0c7"),
    "REFUTED": ("#475467", "#f2f4f7"),
    "UNPROVEN": ("#475467", "#f9fafb"),
}


def _badge(v: str) -> str:
    fg, bg = BADGE.get(v, ("#344054", "#f2f4f7"))
    return (f'<span style="color:{fg};background:{bg};padding:1px 8px;'
            f'border-radius:10px;font-size:12px;font-weight:600">{html.escape(v)}</span>')


def _auth_cell(a: dict | None) -> str:
    if not a:
        return "<td>—</td>"
    e = html.escape
    tip = e(a.get("evidence") or a.get("reason", ""))
    line = e((a.get("line") or "")[:120])
    title = f"{tip} {line}".strip()
    st = a.get("status")
    if st == "protected":
        return (f'<td title="{title}"><span style="color:#027a48">有鉴权</span>'
                f'<span class="small"> {e(a.get("where", ""))}</span></td>')
    if st == "unprotected":
        return f'<td title="{title}"><b style="color:#b42318">未见鉴权</b></td>'
    return f'<td title="{title}"><span class="small">unknown</span></td>'


def _nov_cell(c: dict) -> str:
    """链的「新颖性」单元格。没有核对结果时显示 —，而不是伪造一个结论。"""
    nov = c.get("novelty")
    if not nov:
        return "—"
    v = nov.get("verdict")
    if v == "known":
        conf = {"high": " · 同厂商", "medium": " · 他厂商"}.get(nov.get("confidence") or "", "")
        ids = "、".join(html.escape(str(x.get("id"))) for x in (nov.get("cves") or [])[:2])
        return (f"<b style='color:#b45309'>已公开{conf}</b>"
                + (f" <span class='small'>{ids}</span>" if ids else ""))
    if v == "unknown":
        return "<span style='color:#64748b'>未命中</span>"
    if v == "manual":
        return "<span style='color:#64748b'>需人工</span>"
    return "<span style='color:#dc2626'>查询失败</span>"


def render(res: dict) -> str:
    e = html.escape
    L = []
    L.append("<!doctype html><meta charset='utf-8'><title>fwmap triage</title>")
    L.append("""<style>
body{font:14px/1.6 -apple-system,"Segoe UI",system-ui,sans-serif;margin:0;background:#f8f9fb;color:#101828}
.wrap{max-width:1180px;margin:0 auto;padding:28px 22px 80px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:34px 0 10px;padding-bottom:6px;border-bottom:1px solid #e4e7ec}
.sub{color:#667085;font-size:13px}
table{border-collapse:collapse;width:100%;background:#fff;border:1px solid #e4e7ec;border-radius:8px;overflow:hidden}
th{background:#f9fafb;text-align:left;font-weight:600;font-size:12px;color:#475467;padding:8px 10px;border-bottom:1px solid #e4e7ec}
td{padding:7px 10px;border-bottom:1px solid #f2f4f7;vertical-align:top}
tr:last-child td{border-bottom:0}
code{background:#f2f4f7;padding:1px 5px;border-radius:4px;font-size:12.5px}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}
.note{background:#eff8ff;border-left:3px solid #2e90fa;padding:10px 14px;border-radius:0 6px 6px 0;font-size:13px;color:#175cd3}
.warn{background:#fffaeb;border-left:3px solid #f79009;padding:10px 14px;border-radius:0 6px 6px 0;font-size:13px;color:#b54708}
.card{background:#fff;border:1px solid #e4e7ec;border-radius:8px;padding:14px 16px;margin:10px 0}
.small{font-size:12.5px;color:#667085}
</style>""")
    L.append("<div class='wrap'>")
    L.append(f"<h1>fwmap triage · {e(os.path.basename(res['rootfs']))}</h1>")
    L.append(f"<div class='sub'>{e(res['rootfs'])} · 生成于 {e(res['time'])}"
             f"{' · LLM 复核已开' if res.get('agent') else ' · 未开 LLM 复核'}</div>")

    st = res["stats"]
    L.append("<div class='card'><b>一句话</b>：" + e(st["oneline"]) + "</div>")

    # 第一层
    L.append("<h2>① 该先看哪些文件（M1）</h2>")
    L.append("<table><tr><th>#</th><th>分数</th><th>角色</th><th>架构</th><th>大小</th>"
             "<th>路径</th><th>端点</th><th>链</th></tr>")
    for i, b in enumerate(res["binaries"], 1):
        L.append(f"<tr><td>{i}</td><td><b>{b['score']}</b></td><td>{e(b['role'])}</td>"
                 f"<td>{e(b['arch'])}</td><td>{b['size']//1024}K</td>"
                 f"<td class='mono'>{e(b['path'])}</td>"
                 f"<td>{b.get('endpoints', '-')}</td><td>{b.get('chains', '-')}</td></tr>")
    L.append("</table>")
    L.append("<div class='small' style='margin-top:6px'>分数只表示“攻击面有多大”，不是“有没有漏洞”。</div>")

    # 每个二进制
    for b in res["binaries"]:
        L.append(f"<h2>② {e(b['path'])}</h2>")
        if b.get("error"):
            L.append(f"<div class='warn'>这一层失败：{e(b['error'])}</div>")
            continue
        eps = b.get("endpoint_list") or []
        L.append(f"<div class='small'>M2 策略 <code>{e(b.get('m2_strategy', '-'))}</code>，"
                 f"端点 {len(eps)} 个"
                 f"{'（前 8 个）' if len(eps) > 8 else ''}</div>")
        aus = b.get("auth_summary")
        if aus:
            L.append(f"<div class='small'>M2.5 鉴权：protected {aus['protected']} · "
                     f"unprotected {aus['unprotected']} · unknown {aus['unknown']}"
                     "（unprotected 是候选，不代表可利用）</div>")
        if b.get("auth_error"):
            L.append(f"<div class='warn'>鉴权检查失败：{e(b['auth_error'])}</div>")
        if eps:
            has_auth = any("auth" in x for x in eps)
            L.append("<table><tr><th>端点</th><th>handler</th><th>置信</th>"
                     + ("<th>鉴权</th>" if has_auth else "") + "</tr>")
            for x in eps[:8]:
                L.append(f"<tr><td class='mono'>{e(x['uri'])}</td>"
                         f"<td class='mono'>{e(x.get('handler') or '(未定位)')}</td>"
                         f"<td>{e(x.get('confidence', ''))}</td>"
                         + (_auth_cell(x.get("auth")) if has_auth else "") + "</tr>")
            L.append("</table>")
        # 未鉴权候选单独列出来：8 条截断的表格不能把它们埋掉
        unprot = [x for x in eps if (x.get("auth") or {}).get("status") == "unprotected"]
        if unprot:
            L.append("<div class='warn'><b>未鉴权端点候选（需人工确认）：</b><br>"
                     + "<br>".join(f"<span class='mono'>{e(x['uri'])}</span> "
                                   f"<span class='small'>{e(x.get('handler_name') or '')}</span>"
                                   for x in unprot[:10])
                     + (f"<br>…共 {len(unprot)} 个，完整清单见 report.json" if len(unprot) > 10 else "")
                     + "</div>")
        ch = b.get("chain_list") or []
        kept = [c for c in ch if c.get("verdict", "keep") == "keep"]
        sv = b.get("sink_verified") or 0
        L.append(f"<div class='small' style='margin-top:10px'>M3：找到 {len(ch)} 条链，"
                 f"保留 <b>{len(kept)}</b> 条"
                 + (f"，其中 {sv} 条诱导汇做过“形参到没到 system”的确认" if sv else "")
                 + "。</div>")
        if kept:
            L.append("<table><tr><th>函数</th><th>源</th><th>汇</th><th>跳</th>"
                     "<th>新颖性</th><th>说明</th></tr>")
            for c in kept[:15]:
                flags = []
                if c.get("weak"):
                    flags.append("弱源")
                if c.get("induced_source"):
                    flags.append("诱导源")
                if c.get("induced_sink"):
                    flags.append("诱导汇")
                L.append(f"<tr><td class='mono'>{e(c['function'])}</td>"
                         f"<td class='mono'>{e(c['source_api'])}({e(c.get('source_param') or '')})</td>"
                         f"<td class='mono'>{e(c['sink'])}<span class='small'> [{e(c.get('sink_category',''))}]</span></td>"
                         f"<td>{c.get('hops',1)}</td>"
                         f"<td class='small'>{_nov_cell(c)}</td>"
                         f"<td class='small'>{e('、'.join(flags)) or '—'}</td></tr>")
            L.append("</table>")
            ns = b.get("novelty_summary")
            if ns:
                L.append("<div class='small' style='margin-top:6px'>新颖性核对："
                         f"已公开 <b>{ns['known']}</b> · 未命中 {ns['unknown']}"
                         + (f" · 需人工 {ns['manual']}" if ns.get("manual") else "")
                         + (f" · 失败 {ns['error']}" if ns.get("error") else "")
                         + "。<b>未命中不等于新漏洞</b>，只说明按函数名/路由名在 NVD 里查不到。</div>")
            elif b.get("novelty_error"):
                L.append(f"<div class='warn small'>新颖性核对没跑成：{e(b['novelty_error'])}</div>")

    # 第四层
    if res.get("agent") and not res.get("agent_rows"):
        L.append("<h2>③ LLM 复核</h2>")
        errs = [b.get("agent_error") for b in res.get("binaries", []) if b.get("agent_error")]
        if errs:
            L.append("<div class='warn'><b>LLM 复核失败，本节没有结果。</b><br>"
                     f"<span class='mono'>{e('; '.join(errs)[:400])}</span><br>"
                     "常见原因：缺少 agent 依赖（accelerate / bitsandbytes）。"
                     "请先设 <span class='mono'>PYTHONPATH=C:\\deepseek\\libs-bnb</span> 再重跑。</div>")
        else:
            L.append("<div class='warn'>LLM 复核没有产出（没有可复核的候选链）。</div>")
    elif res.get("agent") and res.get("agent_rows"):
        L.append("<h2>③ LLM 复核</h2>")
        L.append("<div class='note'>LLM 只回答“危险调用前有没有真正的保护”，"
                 "并且必须引用语句编号（证据由我们取回，模型编不了）。裁决由规则给出。</div>")
        for r in res["agent_rows"]:
            c, j = r["chain"], r["judge"]
            L.append("<div class='card'>")
            L.append(f"<div>{_badge(j['verdict'])} "
                     f"<b class='mono'>{e(c['function'])}</b> "
                     f"<span class='mono'>{e(c['source_api'])}({e(c.get('source_param') or '')}) → {e(c['sink'])}</span></div>")
            L.append(f"<div style='margin-top:6px'>{e(j['reason'])}</div>")
            ev = r.get("evidence") or {}
            if ev.get("check"):
                L.append(f"<div class='small mono' style='margin-top:6px;background:#f9fafb;padding:6px 8px;"
                         f"border-radius:4px'>{e(ev['check'][:200])}</div>")
            L.append(f"<div class='small mono' style='margin-top:4px'>危险调用："
                     f"{e((c.get('sink_args') or '')[:160])}</div>")
            L.append("</div>")

    L.append("<h2>边界</h2><div class='warn'>"
             "① 分数只表示攻击面大小；② 链是“可疑”，不是“漏洞”；"
             "③ 引擎分不清“有界/无界”的所有写法，假阳性仍需人工核对；"
             "④ 只处理 ELF，PHP/lua 驱动的固件直接失明；"
             "⑤ “有鉴权”只说明存在鉴权动作，不证明实现正确；"
             "“未见鉴权”是候选，父级函数或前置代理鉴权无法完全排除。</div>")
    L.append("</div>")
    return "\n".join(L)


# ---------------------------------------------------------------- 主流程

def _novelty(chains: list[dict], endpoints: list[dict], ctx: list[str],
             source: str = "auto") -> dict | None:
    """对保留的链做新颖性核对（函数名 + 路由名双路查 CVE 库）。

    这一步原来是独立的 `fwmap verify` 命令，跑完一条命令的人根本不会记得再跑一次，
    报告里就永远缺「这是不是别人已经报过」这一栏。接到 triage 里之后，
    一条命令出来的报告自带这个结论。
    """
    from . import verify

    kept = [c for c in chains if c.get("verdict", "keep") == "keep"]
    if not kept:
        return None
    searcher, info = verify.open_backend(source=source)
    if searcher is None:
        return None
    delay = 6.5 if info.get("kind") == "api" else 0.0
    fn_routes = verify.routes_by_function(endpoints or [])
    rows: list[dict] = []
    cache: dict[str, dict] = {}
    try:
        for c in kept:
            fn = c.get("function") or ""
            if not fn:
                continue
            # 同一个函数常常出好几条链（不同汇/不同参数），只查一次
            if fn not in cache:
                try:
                    cache[fn] = verify.judge_function(
                        fn, fn_routes.get(fn, []), {}, False, delay, False,
                        searcher=searcher, context=ctx)
                except Exception as ex:                      # noqa: BLE001
                    cache[fn] = {"function": fn, "verdict": "error", "matched": [],
                                 "note": f"查询失败：{str(ex)[:60]}", "confidence": ""}
                rows.append(cache[fn])
            r = cache[fn]
            c["novelty"] = {
                "verdict": r["verdict"],
                "confidence": r.get("confidence", ""),
                "note": r["note"],
                "cves": [{"id": m.get("id"), "published": m.get("published", "")}
                         for m in (r.get("matched") or [])[:6]],
            }
    finally:
        if info.get("index"):
            info["index"].close()
    summary = {k: sum(1 for r in rows if r["verdict"] == k)
               for k in ("known", "unknown", "manual", "error")}
    return {"rows": rows, "summary": summary,
            "backend": {k: v for k, v in info.items() if k != "index"}}


def triage(rootfs: str, outdir: str, binaries: int = 2, limit: int | None = None,
           use_agent: bool = False, top_chains: int = 8, samples: int = 3,
           force: bool = False, use_auth: bool = True, use_verify: bool = True,
           context: str = "", log=print) -> dict:
    os.makedirs(outdir, exist_ok=True)
    t0 = time.time()

    log("[1/4] 扫描 rootfs …")
    res = scan(rootfs)
    cands = [t for t in res.targets][:binaries]

    out = {"rootfs": os.path.abspath(rootfs), "time": time.strftime("%Y-%m-%d %H:%M"),
           "agent": use_agent, "binaries": []}
    total_chains = total_kept = total_known = 0
    for i, t in enumerate(cands, 1):
        log(f"[2/4] {i}/{len(cands)} {t.rel_path}  —  M2 …")
        b = {"path": t.rel_path, "score": t.score, "role": t.role,
             "arch": t.arch, "size": t.size}
        try:
            m2 = m2_extract(t.abs_path)
            b["m2_strategy"] = m2["strategy"]
            b["endpoints"] = len(m2["endpoints"])
            b["endpoint_list"] = m2["endpoints"]
            if use_auth:
                from .auth import analyze as auth_analyze
                try:
                    log("        M2.5 鉴权检查 …")
                    a = auth_analyze(t.abs_path, m2=m2, log=log)
                    b["endpoint_list"] = a["endpoints"]
                    b["auth_summary"] = a["summary"]
                except Exception as ex:                          # noqa: BLE001
                    # 鉴权层失败不影响后面的 M3，报告里如实记一笔
                    b["auth_error"] = str(ex)
        except Exception as ex:                              # noqa: BLE001
            b["error"] = f"M2 失败：{ex}"
            out["binaries"].append(b)
            continue

        lim = limit or (140 if os.path.getsize(t.abs_path) > 512 * 1024 else 40)
        log(f"        M3（limit {lim}，慢，约几分钟）…")
        try:
            m3 = _m3(t.abs_path, lim, force=force)
            b["chain_list"] = m3["chains"]
            b["chains"] = sum(1 for c in m3["chains"] if c.get("verdict", "keep") == "keep")
            b["sink_verified"] = m3["sink_verified"]
            total_chains += len(m3["chains"])
            total_kept += b["chains"]
        except Exception as ex:                              # noqa: BLE001
            b["error"] = f"M3 失败：{ex}"
            out["binaries"].append(b)
            continue

        if use_agent:
            log(f"        LLM 复核（前 {top_chains} 条，每条 {samples} 次采样）…")
            try:
                b["agent_rows"] = _agent(t.abs_path, m3["chains"], top_chains, samples)
            except Exception as ex:                          # noqa: BLE001
                b["agent_error"] = str(ex)

        if use_verify:
            ctx = [c.strip().lower() for c in (context or "").split(",") if c.strip()]
            log("        新颖性核对（函数名 + 路由名查 CVE 库）…")
            try:
                nov = _novelty(m3["chains"], b.get("endpoint_list") or [], ctx)
                if nov:
                    b["novelty_summary"] = nov["summary"]
                    b["novelty_backend"] = nov["backend"]
                    total_known += nov["summary"]["known"]
                    log("        已公开 {known} · 未命中 {unknown} · 需人工 {manual}".format(
                        **nov["summary"]))
                else:
                    b["novelty_error"] = "没有可核对的链或没有可用检索源"
            except Exception as ex:                          # noqa: BLE001
                b["novelty_error"] = str(ex)[:200]
        out["binaries"].append(b)

    rows = []
    for b in out["binaries"]:
        rows.extend(b.get("agent_rows") or [])
    out["agent_rows"] = rows
    conf = sum(1 for r in rows if r["judge"]["verdict"] == "CONFIRMED")
    unprot_total = sum((b.get("auth_summary") or {}).get("unprotected", 0)
                       for b in out["binaries"])
    out["stats"] = {
        "oneline": (f"{len(cands)} 个二进制、{total_chains} 条候选链、保留 {total_kept} 条"
                    + (f"，其中 {total_known} 条对应的函数已出现在公开 CVE 里" if total_known else "")
                    + (f"，LLM 复核 {len(rows)} 条里 {conf} 条 CONFIRMED" if rows else "")
                    + (f"，未鉴权端点候选 {unprot_total} 个" if unprot_total else "")
                    + "。CONFIRMED 仍需人工核对后才能叫漏洞。"),
        "confirmed": conf, "kept": total_kept, "chains": total_chains,
        "known": total_known,
        "unprotected": unprot_total,
        "elapsed": round(time.time() - t0, 1),
    }

    with open(os.path.join(outdir, "report.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=1)
    html_path = os.path.join(outdir, "report.html")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(render(out))
    log(f"[4/4] 完成，用时 {out['stats']['elapsed']}s")
    log(f"      {html_path}")
    return out
