r"""fwmap setup：在对方机器上自动装 Ghidra + JDK。

包只带 1 MB 的工具本体，重的东西在这里按需下载：

    py -3.13 -m fwmap setup            # 检查并装缺的（Ghidra + JDK）
    py -3.13 -m fwmap setup --dry-run  # 只打印计划和候选地址，不下载
    py -3.13 -m fwmap setup --ghidra   # 只装 Ghidra
    py -3.13 -m fwmap setup --force    # 已存在也重装

装到 <包目录>\tools\ 下，find_ghidra() 会自动扫到，不需要配环境变量。
Ghidra 12.2 要求 **Java 25**（见 Ghidra/application.properties 的 application.java.min），
所以 JDK 也一并下；运行时由 run_ghidra() 把 JAVA_HOME 指过去。

下载源按顺序尝试（前面的失败会自动换下一个）：
    Ghidra: 官方 GitHub → ghproxy.net 镜像 → gh-proxy.com 镜像
    JDK   : 清华 TUNA 镜像 → Adoptium API

覆盖：FWMAP_GHIDRA_URL / FWMAP_JDK_URL 直接给地址；FWMAP_NO_VERIFY=1 跳过 TLS 校验。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import sys
import tempfile
import time
import urllib.request
import zipfile

PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GHIDRA_API = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
JDK_API = ("https://api.adoptium.net/v3/binary/latest/{v}/ga/windows/x64/jdk/"
           "hotspot/normal/eclipse")
TUNA = "https://mirrors.tuna.tsinghua.edu.cn/Adoptium/{v}/jdk/x64/windows/"
GH_MIRRORS = ["{url}", "https://ghproxy.net/{url}", "https://gh-proxy.com/{url}"]

IDLE_TIMEOUT = int(os.environ.get("FWMAP_IDLE_TIMEOUT", "60"))   # 多久没数据就放弃


def _ctx():
    if os.environ.get("FWMAP_NO_VERIFY") == "1":
        c = ssl.create_default_context()
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        return c
    return ssl.create_default_context()


def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "fwmap-setup"})
    with urllib.request.urlopen(req, context=_ctx(), timeout=30) as r:
        return json.load(r)


def _download_one(url: str, dest: str) -> str:
    """下一个 URL 到 dest，返回 sha256。长时间没数据就抛异常。"""
    h = hashlib.sha256()
    req = urllib.request.Request(url, headers={"User-Agent": "fwmap-setup"})
    with urllib.request.urlopen(req, context=_ctx(), timeout=IDLE_TIMEOUT) as r, open(dest, "wb") as fh:
        total = int(r.headers.get("Content-Length") or 0)
        got, last_print = 0, 0
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            fh.write(chunk)
            h.update(chunk)
            got += len(chunk)
            if got - last_print >= 32 << 20 or (total and got == total):
                pct = f"{int(got * 100 / total)}%" if total else "?"
                print(f"      {_human(got)} / {_human(total)}  {pct}", flush=True)
                last_print = got
    if got == 0:
        raise IOError("下载到 0 字节")
    print(f"      完成 {_human(got)}", flush=True)
    return h.hexdigest()


def _download(urls: list[str], dest: str) -> tuple[str, str]:
    """依次尝试候选地址，返回 (成功的 url, sha256)。"""
    errs = []
    for i, u in enumerate(urls, 1):
        if not u:
            continue
        print(f"  尝试源 {i}/{len(urls)}: {u[:100]}")
        try:
            sha = _download_one(u, dest)
            return u, sha
        except Exception as e:  # noqa: BLE001
            print(f"     失败：{type(e).__name__}: {str(e)[:80]}")
            errs.append(f"{u} -> {type(e).__name__}")
            try:
                if os.path.exists(dest):
                    os.remove(dest)
            except Exception:
                pass
    raise RuntimeError("所有下载源都失败：\n      " + "\n      ".join(errs))


def _install_zip(zip_path: str, target_dir: str, expect_prefix: str) -> str:
    os.makedirs(target_dir, exist_ok=True)
    with zipfile.ZipFile(zip_path) as z:
        top = {n.split("/")[0] for n in z.namelist() if n.strip()}
        z.extractall(target_dir)
    if len(top) == 1:
        return os.path.join(target_dir, top.pop())
    for t in sorted(top):
        if t.lower().startswith(expect_prefix.lower()):
            return os.path.join(target_dir, t)
    return target_dir


def _patch_launch_properties(ghidra_dir: str) -> list[str]:
    """官方 zip 里 launch.properties 写死了作者机器的绝对路径，换机器会指回去。"""
    p = os.path.join(ghidra_dir, "support", "launch.properties")
    if not os.path.exists(p):
        return [f"没找到 {p}"]
    changed, out = [], []
    for line in open(p, encoding="utf-8-sig", errors="replace").read().splitlines():
        s = line.strip()
        if s.startswith("JAVA_HOME_OVERRIDE=") or (
                s.startswith("VMARGS=") and
                ("application.settingsdir=" in s or "application.cachedir=" in s)):
            out.append("# [fwmap setup] 注释掉写死的绝对路径：" + line)
            changed.append(s[:90])
        else:
            out.append(line)
    open(p, "w", encoding="utf-8").write("\n".join(out) + "\n")
    return changed


def _find_dir(base: str, prefix: str) -> str | None:
    if not os.path.isdir(base):
        return None
    for name in sorted(os.listdir(base)):
        p = os.path.join(base, name)
        if name.lower().startswith(prefix.lower()) and os.path.isdir(p):
            return p
    return None


def _ghidra_plan() -> tuple[str, str, str | None, float]:
    """返回 (官方下载地址, 文件名, 期望 sha256, 大小)。"""
    rel = _get_json(GHIDRA_API)
    assets = [a for a in rel.get("assets", []) if a["name"].endswith(".zip")]
    if not assets:
        raise RuntimeError("这个 release 没有 zip 资产")
    a = assets[0]
    dg = a.get("digest") or ""
    sha = dg.split(":")[-1] if dg.startswith("sha256:") else None
    return a["browser_download_url"], a["name"], sha, float(a.get("size") or 0)


def _tuna_jdk_url(major: str) -> str | None:
    base = TUNA.format(v=major)
    try:
        req = urllib.request.Request(base, headers={"User-Agent": "fwmap-setup"})
        with urllib.request.urlopen(req, context=_ctx(), timeout=25) as r:
            html = r.read().decode("utf-8", "replace")
        zips = sorted(set(re.findall(r'([A-Za-z0-9._+-]+\.zip)', html)))
        for z in zips:
            if "jdk" in z.lower() and "windows" in z.lower():
                return base + z
    except Exception:
        return None
    return None


def install_ghidra(tools_dir: str, force: bool, dry: bool, from_zip: str | None = None) -> str | None:
    have = _find_dir(tools_dir, "ghidra")
    if have and not force:
        print(f"  Ghidra 已存在：{have}（重装加 --force）")
        return have

    # 1) 已手动下好 zip：完全不联网（国内网络最稳的一条路）
    if from_zip:
        if not os.path.exists(from_zip):
            print(f"  [!] 找不到文件：{from_zip}")
            return None
        print(f"  使用本地 zip：{from_zip}")
        gdir = _install_zip(from_zip, tools_dir, "ghidra")
        for c in _patch_launch_properties(gdir):
            print("  已修正： " + c)
        return gdir

    # 2) 解析下载源
    env_url = os.environ.get("FWMAP_GHIDRA_URL")
    if env_url:
        name, sha, size = env_url.rsplit("/", 1)[-1], None, 0.0
        cands = [env_url]
    else:
        print("  查询最新 release …")
        official, name, sha, size = _ghidra_plan()
        print(f"  {name}  {_human(size)}")
        cands = [m.format(url=official) for m in GH_MIRRORS]

    if dry:
        print("  [dry-run] 候选下载源：")
        for c in cands:
            print("      " + c)
        return have

    # 3) 下载 → 校验 → 解压 → 修正 launch.properties
    tmp = os.path.join(tempfile.gettempdir(), name)
    print("  下载 Ghidra：")
    _, got_sha = _download(cands, tmp)
    if sha and got_sha != sha:
        print(f"  [!] SHA256 不匹配，已删除\n      期望 {sha}\n      实际 {got_sha}")
        os.remove(tmp)
        return None
    if sha:
        print("      SHA256 校验通过")
    print("  解压 …")
    gdir = _install_zip(tmp, tools_dir, "ghidra")
    os.remove(tmp)
    for c in _patch_launch_properties(gdir):
        print("  已修正： " + c)
    return gdir



def install_jdk(tools_dir: str, force: bool, dry: bool, major: str = "25") -> str | None:
    have = _find_dir(tools_dir, "jdk")
    if have and not force:
        print(f"  JDK 已存在：{have}（重装加 --force）")
        return have

    env_url = os.environ.get("FWMAP_JDK_URL")
    cands: list[str] = []
    if env_url:
        cands.append(env_url)
    else:
        tuna = _tuna_jdk_url(major)
        if tuna:
            cands.append(tuna)
        cands.append(JDK_API.format(v=major))

    if dry:
        print("  [dry-run] 候选下载源：")
        for c in cands:
            print("      " + c)
        return have

    tmp = os.path.join(tempfile.gettempdir(), f"fwmap-jdk{major}.zip")
    print(f"  下载 JDK {major}（Temurin）：")
    src, sha = _download(cands, tmp)
    print(f"      来源 {src[:90]}")
    print(f"      SHA256 {sha[:16]}…")
    print("  解压 …")
    jdir = _install_zip(tmp, tools_dir, "jdk")
    os.remove(tmp)
    return jdir


def run(args) -> int:
    tools_dir = os.path.abspath(args.dir or os.path.join(PKG_ROOT, "tools"))
    do_ghidra = args.ghidra or args.all
    do_jdk = args.jdk or args.all
    if not (do_ghidra or do_jdk):
        do_ghidra = do_jdk = True

    print(f"安装目录：{tools_dir}")
    print(f"Python：{sys.version.split()[0]}")
    print()

    g = j = None
    if do_ghidra:
        print("[1/2] Ghidra")
        try:
            g = install_ghidra(tools_dir, args.force, args.dry_run, getattr(args, "from_zip", None))
        except Exception as e:  # noqa: BLE001
            print(f"  [!] 失败：{e}")
    if do_jdk:
        print("[2/2] JDK（Ghidra 12.2 要求 Java 25）")
        try:
            j = install_jdk(tools_dir, args.force, args.dry_run, args.java)
        except Exception as e:  # noqa: BLE001
            print(f"  [!] 失败：{e}")

    print()
    for label, path in (("Ghidra", g), ("JDK", j)):
        if path:
            print(f"{label}：{path}")
    print()
    print("下一步：py -3.13 -m fwmap doctor")
    print("模型（可选，14 GB）需自行下载，然后设 FWMAP_LLM_MODEL 指向模型目录")
    return 0 if (g or j or args.dry_run) else 1
