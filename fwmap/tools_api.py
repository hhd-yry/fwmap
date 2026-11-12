"""工具注册表：把 fwmap 的各个命令变成「可被智能体调用」的工具。

老师那句话点得对：大模型从零写个工具很快，但它**不会自动复用你已经有的东西**。
要让它复用，得先有一样东西——**每个工具的统一描述**：

    名字 / 干什么用 / 参数长什么样 / 返回什么摘要

有了这张表，planner 才能「看当前状态，决定下一步调哪个」，而不是每次从头写脚本。

两条设计约束，都是踩出来的：

1. **返回摘要，不返回原始数据**。`webs_m3.json` 有 16 MB，整包塞进模型上下文会当场爆掉。
   所以每个工具只回「一句话结论 + 几个数字 + 产物路径」，原始数据留在磁盘上。
2. **失败也要有结构化结果**。工具挂了不能抛异常穿透整个流程 ——
   给 `{ok: False, summary: "为什么没成"}`，planner 才有机会换个路子。
"""

from __future__ import annotations

import os
import subprocess
import sys

REGISTRY: dict[str, dict] = {}


def register(name: str, desc: str, args: dict):
    """注册一个工具。args 是 {参数名: 说明}，给 planner/模型看的。"""
    def deco(fn):
        REGISTRY[name] = {"name": name, "desc": desc, "args": args, "run": fn}
        return fn
    return deco


def catalog() -> list[dict]:
    """给模型看的工具清单（不含函数对象）。"""
    return [{"name": t["name"], "desc": t["desc"], "args": t["args"]}
            for t in REGISTRY.values()]


def call(name: str, **kwargs) -> dict:
    """统一调用入口：任何异常都变成结构化失败，不让它穿透。"""
    t = REGISTRY.get(name)
    if not t:
        return {"ok": False, "summary": f"没有这个工具：{name}"}
    try:
        return t["run"](**kwargs)
    except Exception as e:                                  # noqa: BLE001
        return {"ok": False, "summary": f"{name} 执行失败：{str(e)[:160]}"}


def _ok(summary: str, **data) -> dict:
    return {"ok": True, "summary": summary, **data}


# ---------------------------------------------------------------- 工具
@register("check", "校验 rootfs 解包是否完整（符号链接丢失、嵌套压缩包、无 ELF）",
          {"rootfs": "解包后的 rootfs 目录"})
def _check(rootfs: str) -> dict:
    from .check import check

    r = check(rootfs)
    issues = r.get("issues") or []
    warn = r.get("warnings") or []
    return _ok(f"解包自检：{'通过' if r.get('ok') else '有问题'} "
               f"（阻断 {len(issues)} 项 / 警告 {len(warn)} 项）",
               issues=issues[:3], warnings=warn[:3], ok_clean=bool(r.get("ok")),
               stats=r.get("stats") or {})


@register("scan", "按攻击面对 rootfs 里的 ELF 排序，出「先看哪个二进制」",
          {"rootfs": "解包后的 rootfs 目录", "top": "只看前 N 个（默认 5）"})
def _scan(rootfs: str, top: int = 5) -> dict:
    from .scan import scan

    res = scan(rootfs)
    picked = [{"path": t.rel_path, "score": t.score, "role": t.role,
               "arch": t.arch, "size": t.size}
              for t in res.targets[:top]]
    return _ok(f"扫描 {res.files_seen} 个文件 / {res.elf_count} 个 ELF，"
               f"最高分 {picked[0]['score']}（{picked[0]['path']}）" if picked
               else "没找到 ELF",
               targets=picked, rootfs=rootfs)


@register("m2", "解析端点 → 处理函数映射（需要 Ghidra，较慢）",
          {"binary": "单个 ELF 路径"})
def _m2(binary: str) -> dict:
    from .m2 import extract

    r = extract(binary)
    eps = r.get("endpoints") or []
    mapped = sum(1 for e in eps if (e.get("handler_name") or e.get("handler")))
    return _ok(f"端点 {len(eps)} 个，定位到 handler {mapped} 个"
               f"（策略 {r.get('strategy')}）",
               binary=binary, endpoints=eps, strategy=r.get("strategy"))


@register("m3", "源→汇数据流分析，产出候选链（需要 Ghidra，最慢）",
          {"binary": "单个 ELF 路径", "limit": "最多分析多少个函数（默认 20）",
           "profile": "可选，归纳出的 source profile 路径"})
def _m3(binary: str, limit: int = 20, profile: str | None = None) -> dict:
    from .m3 import catalog_path, extract as m3_extract
    from .m3flow import _load_catalog, normalize_weak, run_flow

    r = m3_extract(binary, profile=profile)
    _s, _k, weak = _load_catalog(catalog_path())
    if profile and os.path.exists(profile):
        _s2, _k2, _w2 = _load_catalog(profile)
        weak.update(_w2)
    normalize_weak(r["functions"], weak)
    pool = list(r["candidates"]) + [
        fn for fn in r["functions"]
        if fn["sources"] and not fn["sinks"]
        and any(not s["weak"] for s in fn["sources"])]
    flow = run_flow(binary, pool, profile=profile, limit=limit)
    kept = [c for c in flow.get("chains") or [] if c.get("verdict", "keep") == "keep"]
    cats = {}
    for c in kept:
        cats[c.get("sink_category", "?")] = cats.get(c.get("sink_category", "?"), 0) + 1
    return _ok(f"数据流：候选 {len(flow.get('chains') or [])} 条，保留 {len(kept)} 条"
               f"（{', '.join(f'{k}×{v}' for k, v in cats.items()) or '无'}）",
               chains=kept, binary=binary)


@register("verify", "核对链是否已被公开报告（离线 CVE 库，断网可用）",
          {"chains": "链列表", "context": "目标厂商/型号关键词，逗号分隔"})
def _verify(chains: list, context: str = "") -> dict:
    from . import verify as V

    kept = [c for c in chains if c.get("verdict", "keep") == "keep"]
    searcher, info = V.open_backend(source="auto")
    if searcher is None:
        return {"ok": False, "summary": "没有可用的 CVE 检索源"}
    ctx = [x.strip().lower() for x in (context or "").split(",") if x.strip()]
    rows, cache = [], {}
    try:
        for c in kept:
            fn = c.get("function") or ""
            if not fn or fn in cache:
                continue
            cache[fn] = V.judge_function(fn, [], {}, False, 0, False,
                                         searcher=searcher, context=ctx)
            rows.append(cache[fn])
    finally:
        if info.get("index"):
            info["index"].close()
    stat = {k: sum(1 for r in rows if r["verdict"] == k)
            for k in ("known", "unknown", "manual", "error")}
    unknown = [r["function"] for r in rows if r["verdict"] == "unknown"]
    return _ok(f"新颖性：已公开 {stat['known']} / 未命中 {stat['unknown']}"
               f" / 需人工 {stat['manual']}"
               + (f"；值得深挖：{', '.join(unknown[:5])}" if unknown else ""),
               summary_stat=stat, unknown=unknown,
               known=[{"function": r["function"],
                       "cves": [m.get("id") for m in (r.get("matched") or [])[:3]]}
                      for r in rows if r["verdict"] == "known"])


@register("dyn", "把链翻成 PoC 并在模拟器里真打（需要 qemu，Windows 上会跳过）",
          {"chains": "链列表", "binary": "ELF 路径", "rootfs": "rootfs 路径",
           "port": "端口", "cmd": "命令注入要执行的命令（可选）"})
def _dyn(chains: list, binary: str, rootfs: str, port: int = 80,
         cmd: str | None = None) -> dict:
    from . import dyn as D

    arch = D._guess_arch(binary)
    rt = D.find_runtime(arch, rootfs, binary)
    if not rt:
        return _ok(f"动态验证跳过：这台机器没有能跑 {arch or '?'} 的运行时"
                   f"（需要 Linux + qemu-user）", skipped=True)
    return _ok(f"动态验证：运行时 {rt['label']}（本工具在 MVP 里只报告可用性，"
               f"完整执行用 `fwmap dyn`）", runtime=rt["label"], skipped=True)


@register("bof", "二分测栈溢出的最小崩溃长度（需要 qemu）",
          {"binary": "ELF 路径", "rootfs": "rootfs 路径"})
def _bof(binary: str, rootfs: str) -> dict:
    from . import dyn as D

    arch = D._guess_arch(binary)
    rt = D.find_runtime(arch, rootfs, binary)
    if not rt:
        return _ok(f"阈值探测跳过：没有 {arch or '?'} 运行时", skipped=True)
    return _ok("阈值探测可用（完整执行用 `fwmap bof --threshold`）", skipped=True)


def run_cli(args: list[str], timeout: int = 1800) -> tuple[int, str]:
    """需要完整功能时，退回命令行调用（保证和手工跑完全一致）。"""
    cmd = [sys.executable, "-m", "fwmap"] + args
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or "") + (p.stderr or "")
