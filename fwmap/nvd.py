"""离线 NVD 索引：让 `fwmap verify` 在没有网络的机器上也能用。

`verify` 原本每核对一个函数就要联网查一次 NVD API，三个问题：

1. **验收机完全断网** —— 整个「新颖性核对」环节直接不可用；
2. 无 API key 时限流 5 次 / 30 秒 —— 30 个函数要跑三分钟以上；
3. 结果天天在变，报告不可复现。

这个模块把 NVD 官方的 CVE JSON feed（2002 年至今，按年打包）整包搬下来，
只抽 `(CVE 号 / 发布日期 / 严重级 / 英文描述)` 存进一个 SQLite 文件，
再建 FTS5 全文索引。之后 `verify --source local` 查本地库：零网络、
毫秒级、并且结果冻结在一个明确的时间点上（报告里写得出「基于哪天的快照」）。

数据来源是 NIST 官方 feed，不是自己拼的库：
    https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-<年>.json.gz

用法：
    python -m fwmap nvd fetch                # 下载（默认 2002-今年，约 240 MB）
    python -m fwmap nvd build                # 建索引 → data/nvd/nvd.sqlite
    python -m fwmap nvd status               # 索引状态（日期 / 条数 / 大小）
    python -m fwmap nvd search SetDlnaCfg    # 手工查一条
    python -m fwmap nvd search "Tenda AC15"
    python -m fwmap nvd update               # fetch + build（增量）

设计上的两点取舍：

* **解析必须流式**。2026 年那个包解压后 542 MB，`json.load` 峰值要几个 GB；
  这里用「按块读 + 正则跨过字符串」的方式逐条解析，内存恒定在几十 MB。
* **检索要两层**。FTS5 的 unicode61 分词会把 `formStaDrvSetup` 当成一个整词，
  所以「描述里出现完整标识符」这种最常见的情况是精确命中、极快；但公告里
  经常写更长的标识符（`formStaDrvSetup_0x1234`）或者把它拼进 URL，这时整词
  匹配不到，退化成 `LIKE '%x%'` 全表扫描兜底（90 MB 文本，几百毫秒），
  宁可慢一点也不能漏报。
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import sqlite3
import time
import urllib.error
import urllib.request

FEED = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
META = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.meta"

# 索引格式版本：改了抽取字段就 +1，旧库会被 build 拒绝（而不是静默出错）
SCHEMA_VERSION = 1
FIRST_YEAR = 2002

_UA = {"User-Agent": "fwmap-nvd/1.0 (+offline index builder)"}
_RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_RE_TOK = re.compile(r"[A-Za-z0-9_]+")
_RE_STRUCT = re.compile(r'["{}\[\]]')


# ---------------------------------------------------------------- 路径
def default_dir() -> str:
    """索引目录。默认放在包目录的 data/nvd（跟着文件夹一起拷走就能用）。"""
    env = os.environ.get("FWMAP_NVD_DIR")
    if env:
        return env
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "data", "nvd")


def default_db() -> str:
    env = os.environ.get("FWMAP_NVD_DB")
    if env:
        return env
    return os.path.join(default_dir(), "nvd.sqlite")


def raw_dir(ddir: str | None = None) -> str:
    return os.path.join(ddir or default_dir(), "raw")


def find_db(explicit: str | None = None) -> str | None:
    """找一个能用的库；找不到返回 None（verify 会退回在线）。

    显式给了路径就以显式为准：指定的文件不存在时直接算没有，
    不做「悄悄换成一个别的库」这种让人看不懂的事。
    """
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    for p in (os.environ.get("FWMAP_NVD_DB"), default_db()):
        if p and os.path.isfile(p):
            return p
    return None


# ---------------------------------------------------------------- 流式解析
class _Reader:
    """按块读文本，提供「跳到下一个结构字符」的快速扫描。

    不能逐字符 for 循环：总量 2 GB 以上，Python 逐字符要跑好几分钟。
    这里所有跨步都用 `str.find` / 正则（C 实现），只对结构字符做 Python 判断。
    """

    CHUNK = 1 << 20

    def __init__(self, fh):
        self.fh = fh
        self.buf = ""
        self.i = 0
        self.eof = False

    def _fill(self) -> bool:
        if self.eof:
            return False
        data = self.fh.read(self.CHUNK)
        if not data:
            self.eof = True
            return False
        self.buf = self.buf[self.i:] + data
        self.i = 0
        return True

    def ensure(self, n: int = 1) -> bool:
        while len(self.buf) - self.i < n:
            if not self._fill():
                return False
        return True

    def skip_ws(self) -> None:
        """跳过空白和分隔逗号；停在第一个有意义的字符上。"""
        while True:
            j = self.i
            n = len(self.buf)
            while j < n and self.buf[j] in " \t\r\n,":
                j += 1
            self.i = j
            if j < n:
                return
            if not self._fill():
                return

    def find_literal(self, lit: str) -> bool:
        keep = len(lit) - 1
        while True:
            j = self.buf.find(lit, self.i)
            if j >= 0:
                self.i = j + len(lit)
                return True
            self.i = max(self.i, len(self.buf) - keep)
            if not self._fill():
                return False

    def read_object(self) -> str | None:
        """从当前位置读一个花括号平衡的 JSON 对象原文；到 `]` 返回 None。

        buffer 会在中途被 _fill 换掉，所以用 acc 累积已消费片段，
        不能最后再 `buf[start:i]` 切片（那时 start 已经失效）。
        """
        self.skip_ws()
        if not self.ensure(1):
            return None
        if self.buf[self.i] != "{":
            return None
        acc: list[str] = []
        seg = self.i                      # 当前 buf 里尚未收集的起点
        depth = 1
        instr = False
        self.i += 1

        def flush() -> bool:
            nonlocal seg
            acc.append(self.buf[seg:self.i])
            if not self._fill():
                return False
            seg = 0
            return True

        while depth:
            if instr:
                j = self.buf.find('"', self.i)
                if j < 0:
                    self.i = len(self.buf)
                    if not flush():
                        raise ValueError("JSON 截断（字符串未闭合）")
                    continue
                # 数一下前面有几个反斜杠，奇数说明这个引号是转义出来的
                k, nb = j - 1, 0
                while k >= 0 and self.buf[k] == "\\":
                    nb += 1
                    k -= 1
                if nb % 2 == 0:
                    instr = False
                self.i = j + 1
            else:
                m = _RE_STRUCT.search(self.buf, self.i)
                if m is None:
                    self.i = len(self.buf)
                    if not flush():
                        raise ValueError("JSON 截断（对象未闭合）")
                    continue
                c = m.group()
                self.i = m.end()
                if c == '"':
                    instr = True
                elif c in "[{":
                    depth += 1
                else:
                    depth -= 1
        acc.append(self.buf[seg:self.i])
        return "".join(acc)


def iter_cves(path: str):
    """流式产出 feed 里 `vulnerabilities` 数组的每个元素（dict）。"""
    with gzip.open(path, "rb") as raw:
        with io.TextIOWrapper(raw, encoding="utf-8", errors="replace",
                              newline="") as fh:
            rd = _Reader(fh)
            if not rd.find_literal('"vulnerabilities"'):
                raise ValueError(f"{os.path.basename(path)}: 找不到 vulnerabilities 字段")
            while True:                       # 跳到数组的 '['
                if not rd.ensure(1):
                    raise ValueError("JSON 截断（没有数组）")
                c = rd.buf[rd.i]
                rd.i += 1
                if c == "[":
                    break
                if c in "{}":
                    raise ValueError("JSON 结构异常（vulnerabilities 不是数组）")
            while True:
                obj = rd.read_object()
                if obj is None:
                    return
                try:
                    yield json.loads(obj)
                except ValueError:
                    continue              # 单条坏了不要整包失败


# ---------------------------------------------------------------- 抽取
def _severity(metrics: dict) -> tuple[str, float | None]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for item in metrics.get(key) or []:
            data = item.get("cvssData") or {}
            score = data.get("baseScore")
            sev = data.get("baseSeverity") or item.get("baseSeverity") or ""
            if score is None:
                continue
            if not sev:                       # v2 没有 baseSeverity，按分数换算
                sev = ("LOW" if score < 4 else "MEDIUM" if score < 7
                       else "HIGH" if score < 9 else "CRITICAL")
            return sev.upper(), float(score)
    return "", None


def extract_row(vuln: dict):
    """{'cve': {...}} → (cve_id, published, severity, score, desc)；无用条目返回 None。"""
    cve = vuln.get("cve") or vuln
    cid = (cve.get("id") or "").strip()
    if not _RE_CVE.match(cid):
        return None
    desc = ""
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            desc = (d.get("value") or "").strip()
            if desc:
                break
    if not desc:                       # REJECT / 无英文描述的条目对检索没意义
        return None
    pub = (cve.get("published") or "")[:10]
    sev, score = _severity(cve.get("metrics") or {})
    return (cid, pub, sev, score, " ".join(desc.split()))


# ---------------------------------------------------------------- 下载
def _ctx():
    return None                        # 走系统默认证书；代理由 urllib 环境变量处理


def _open(url: str, proxy: str | None = None, timeout: int = 120):
    """proxy 为 None 时走系统/环境变量里的代理设置（和在线 API 那条路一致）。"""
    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    else:
        opener = urllib.request.build_opener()
    req = urllib.request.Request(url, headers=_UA)
    return opener.open(req, timeout=timeout)


def probe(timeout: int = 6) -> bool:
    """能不能到 NVD。只取一个几百字节的 .meta，不消耗 API 配额。"""
    year = time.localtime().tm_year
    url = META.format(year=year)
    proxies = [None]
    env = os.environ.get("FWMAP_PROXY")
    if env:
        proxies.append(env)
    for proxy in proxies:
        try:
            with _open(url, proxy, timeout) as r:
                if getattr(r, "status", 200) == 200:
                    return True
        except Exception:                            # noqa: BLE001
            continue
    return False


def parse_meta(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def _remote_meta(year: int, proxy: str | None, timeout: int = 60) -> dict:
    with _open(META.format(year=year), proxy, timeout) as r:
        return parse_meta(r.read().decode("utf-8", "replace"))


def _local_meta(year: int, ddir: str | None = None) -> dict:
    p = os.path.join(raw_dir(ddir), f"nvdcve-2.0-{year}.meta")
    if not os.path.isfile(p):
        return {}
    try:
        return parse_meta(open(p, encoding="utf-8", errors="replace").read())
    except OSError:
        return {}


def fetch(years: list[int], ddir: str | None = None, proxy: str | None = None,
          log=print) -> dict:
    """下载年包。已下且大小对得上的直接跳过（可重复执行）。"""
    d = raw_dir(ddir)
    os.makedirs(d, exist_ok=True)
    proxy = proxy or os.environ.get("FWMAP_PROXY") or ""
    got, skipped, failed = [], [], []
    for year in years:
        gz = os.path.join(d, f"nvdcve-2.0-{year}.json.gz")
        mp = os.path.join(d, f"nvdcve-2.0-{year}.meta")
        meta = {}
        try:
            with _open(META.format(year=year), proxy, 60) as r:
                meta = parse_meta(r.read().decode("utf-8", "replace"))
            with open(mp, "w", encoding="utf-8") as fh:
                fh.write("\n".join(f"{k}:{v}" for k, v in meta.items()))
        except Exception as e:                       # noqa: BLE001
            failed.append((year, f"meta: {str(e)[:60]}"))
            log(f"    {year} 取不到目录信息：{str(e)[:60]}")
            continue
        want = int(meta.get("gzSize") or 0)
        if os.path.isfile(gz) and want and os.path.getsize(gz) == want:
            skipped.append(year)
            log(f"    {year} 已存在（{want/1048576:.1f} MB）")
            continue
        tmp = gz + ".part"
        try:
            with _open(FEED.format(year=year), proxy, 900) as r, open(tmp, "wb") as fh:
                while True:
                    chunk = r.read(1 << 20)
                    if not chunk:
                        break
                    fh.write(chunk)
            size = os.path.getsize(tmp)
            if want and size != want:
                raise IOError(f"大小不符（{size} != {want}）")
            sha = meta.get("sha256")
            if sha:
                h = hashlib.sha256()
                with open(tmp, "rb") as fh:
                    for block in iter(lambda: fh.read(1 << 20), b""):
                        h.update(block)
                if h.hexdigest().upper() != sha.upper():
                    raise IOError("sha256 校验失败")
            os.replace(tmp, gz)
            got.append(year)
            log(f"    {year} 下载完成（{size/1048576:.1f} MB，sha256 校验通过）")
        except Exception as e:                       # noqa: BLE001
            failed.append((year, str(e)[:60]))
            log(f"    {year} 失败：{str(e)[:60]}")
            try:
                os.remove(tmp)
            except OSError:
                pass
    return {"downloaded": got, "skipped": skipped, "failed": failed}


def feed_files(ddir: str | None = None) -> list[tuple[int, str]]:
    d = raw_dir(ddir)
    out = []
    if not os.path.isdir(d):
        return out
    for name in os.listdir(d):
        m = re.match(r"nvdcve-2\.0-(\d{4})\.json\.gz$", name)
        if m:
            out.append((int(m.group(1)), os.path.join(d, name)))
    return sorted(out)


def _db_path(ddir: str | None = None) -> str:
    return os.environ.get("FWMAP_NVD_DB") or os.path.join(ddir or default_dir(), "nvd.sqlite")


def check_updates(years: list[int] | None = None, ddir: str | None = None,
                  proxy: str | None = None) -> dict:
    """只看 .meta（每个几百字节），判断哪些年包变了 —— 不下载正文。"""
    if years is None:
        years = list(range(FIRST_YEAR, time.localtime().tm_year + 1))
    d = raw_dir(ddir)
    out = {"changed": [], "missing": [], "same": [], "error": []}
    for year in years:
        gz = os.path.join(d, f"nvdcve-2.0-{year}.json.gz")
        try:
            meta = _remote_meta(year, proxy)
        except Exception as e:                       # noqa: BLE001
            out["error"].append((year, str(e)[:50]))
            continue
        if not os.path.isfile(gz):
            out["missing"].append(year)
            continue
        old = _local_meta(year, ddir)
        sha = (meta.get("sha256") or "").upper()
        want = int(meta.get("gzSize") or 0)
        changed = bool(want and os.path.getsize(gz) != want) or bool(
            sha and old.get("sha256") and old["sha256"].upper() != sha)
        (out["changed"] if changed else out["same"]).append(year)
    return out


def update(ddir: str | None = None, proxy: str | None = None, log=print,
           force: bool = False, years: list[int] | None = None) -> dict:
    """有网时把本地库刷到最新：先比 .meta，只下变了的年包，再重建索引。

    这是「有网就用网」的另一半 —— 联网时跑一遍，断网时才有一份新库可用。
    没有变化时不会重建（重建一次约 90 秒，不值得白跑）。
    """
    years = years or list(range(FIRST_YEAR, time.localtime().tm_year + 1))
    log("    比对各年包的 .meta …")
    chk = check_updates(years, ddir, proxy)
    if chk["error"] and len(chk["error"]) == len(years):
        raise RuntimeError(f"所有年包都取不到元信息：{chk['error'][0][1]}")
    todo = sorted(set(chk["missing"]) | set(chk["changed"]))
    downloaded: list[int] = []
    if todo:
        log(f"    需要下载：{', '.join(map(str, todo))}")
        downloaded = fetch(todo, ddir, proxy, log)["downloaded"]
    else:
        log("    年包都是最新的")

    db = _db_path(ddir)
    if not downloaded and os.path.isfile(db) and not force:
        log("    索引不用重建")
        return {"downloaded": [], "rebuilt": False, "db": db, "cve_count": None}

    log("    重建索引 …")
    built = build(ddir, log=log)
    return {"downloaded": downloaded, "rebuilt": True, "db": built["db"],
            "cve_count": built["cve_count"]}


def age_days(db: str | None = None) -> float | None:
    """离线库快照距今多少天；没有库返回 None。"""
    p = find_db(db)
    if not p:
        return None
    try:
        idx = Index(p)
        try:
            bt = idx.built_at
        finally:
            idx.close()
        t = time.mktime(time.strptime(bt, "%Y-%m-%d %H:%M:%S"))
    except Exception:                                # noqa: BLE001
        return None
    return max(0.0, (time.time() - t) / 86400.0)


# ---------------------------------------------------------------- 建索引
SCHEMA = """
PRAGMA journal_mode = OFF;
PRAGMA synchronous = OFF;
CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE cve (
    id        INTEGER PRIMARY KEY,
    cve_id    TEXT NOT NULL,
    published TEXT,
    severity  TEXT,
    score     REAL,
    desc      TEXT NOT NULL
);
CREATE VIRTUAL TABLE ft USING fts5(desc, content='cve', content_rowid='id');
CREATE INDEX idx_cve_id ON cve(cve_id);
"""


def build(ddir: str | None = None, log=print, keep_raw: bool = True) -> dict:
    """把 raw/*.json.gz 合成 nvd.sqlite。先写 .part，成功才原子替换。"""
    feeds = feed_files(ddir)
    if not feeds:
        raise FileNotFoundError(f"{raw_dir(ddir)} 里没有年包，先跑 `nvd fetch`")
    db = _db_path(ddir)
    os.makedirs(os.path.dirname(os.path.abspath(db)) or ".", exist_ok=True)
    tmp = db + ".part"
    for p in (tmp, tmp + "-journal", tmp + "-wal"):
        try:
            os.remove(p)
        except OSError:
            pass

    con = sqlite3.connect(tmp)
    con.executescript(SCHEMA)
    total, years, t0 = 0, [], time.time()
    batch: list[tuple] = []
    try:
        for year, path in feeds:
            n = 0
            for vuln in iter_cves(path):
                row = extract_row(vuln)
                if row is None:
                    continue
                batch.append((None,) + row)
                n += 1
                if len(batch) >= 20000:
                    con.executemany(
                        "INSERT INTO cve(id,cve_id,published,severity,score,desc)"
                        " VALUES(?,?,?,?,?,?)", batch)
                    batch.clear()
            total += n
            years.append(year)
            log(f"    {year}  {n:6d} 条")
            if batch:
                con.executemany(
                    "INSERT INTO cve(id,cve_id,published,severity,score,desc)"
                    " VALUES(?,?,?,?,?,?)", batch)
                batch.clear()
        con.commit()
        log(f"    建全文索引（{total} 条）…")
        con.execute("INSERT INTO ft(ft) VALUES('rebuild')")
        con.commit()
        meta = {
            "schema_version": str(SCHEMA_VERSION),
            "built_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "cve_count": str(total),
            "years": f"{min(years)}-{max(years)}" if years else "",
            "feeds": ",".join(str(y) for y in years),
            "source": FEED.format(year="<年>"),
        }
        con.executemany("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", list(meta.items()))
        con.commit()
        log("    VACUUM …")
        con.execute("VACUUM")
    finally:
        con.close()

    os.replace(tmp, db)
    dt = time.time() - t0
    size = os.path.getsize(db)
    log(f"    → {db}  {size/1048576:.0f} MB  {dt:.0f}s")
    return {"db": db, "cve_count": total, "years": years, "size": size,
            "seconds": round(dt, 1), "keep_raw": keep_raw}


# ---------------------------------------------------------------- 检索
class Index:
    """只读打开 nvd.sqlite。一个进程开一次，反复查。"""

    def __init__(self, path: str | None = None):
        self.path = find_db(path)
        if not self.path:
            raise FileNotFoundError(
                "没有离线 NVD 库。先跑 `python -m fwmap nvd fetch` + `nvd build`，"
                "或用 --source online 联网查。")
        self.con = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        self.con.row_factory = sqlite3.Row
        self.meta = {r["k"]: r["v"] for r in self.con.execute("SELECT k,v FROM meta")}
        got = self.meta.get("schema_version")
        if got and got != str(SCHEMA_VERSION):
            raise RuntimeError(
                f"离线库是旧格式（schema {got}，当前 {SCHEMA_VERSION}），"
                "跑 `python -m fwmap nvd build` 重建")
        has_fts = self.con.execute(
            "SELECT 1 FROM sqlite_master WHERE name='ft'").fetchone()
        if not has_fts:
            raise RuntimeError("离线库里没有全文索引（ft 表），索引已损坏，请重建")
        self.count = self.con.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
        self._scans = 0

    # -- 元信息
    @property
    def built_at(self) -> str:
        return self.meta.get("built_at", "?")

    @property
    def years(self) -> str:
        return self.meta.get("years", "?")

    def close(self) -> None:
        try:
            self.con.close()
        except Exception:                              # noqa: BLE001
            pass

    # -- 单条查询
    def _fts(self, tokens: list[str], limit: int) -> list[sqlite3.Row]:
        if not tokens:
            return []
        q = " ".join(f'"{t}"' for t in tokens)
        # 故意不 try/except：库坏了就要报出来。吞成 [] 会让每个函数都显示「未命中」，
        # 看起来像「查过了、没有公开记录」，其实一条都没查成。
        return self.con.execute(
            "SELECT c.cve_id,c.published,c.severity,c.score,c.desc"
            " FROM ft JOIN cve c ON c.id=ft.rowid"
            " WHERE ft MATCH ? ORDER BY rank LIMIT ?", (q, limit)).fetchall()

    def _like(self, keyword: str, limit: int) -> list[sqlite3.Row]:
        esc = keyword.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        self._scans += 1
        return self.con.execute(
            "SELECT cve_id,published,severity,score,desc FROM cve"
            " WHERE desc LIKE ? ESCAPE '\\'"
            " ORDER BY published DESC LIMIT ?", (f"%{esc}%", limit)).fetchall()

    def search(self, keyword: str, limit: int = 40, deep: bool = True) -> tuple[list, list]:
        """返回 (matched, related)。

        matched —— 描述里确实出现了这个关键词（verify 判定「已公开」只认这个）；
        related —— 只有分词级命中（比如公告里出现了同系列的另一半名字），
                   给「未命中但可能有关系」提供线索。
        """
        kw = (keyword or "").strip()
        if not kw:
            return [], []
        if _RE_CVE.match(kw):                        # 直接查 CVE 号
            rows = self.con.execute(
                "SELECT cve_id,published,severity,score,desc FROM cve"
                " WHERE cve_id=? COLLATE NOCASE", (kw,)).fetchall()
            return [dict(r, id=r["cve_id"]) for r in rows], []

        low = kw.lower()
        tokens = [t for t in _RE_TOK.findall(kw) if len(t) >= 3] or \
                 _RE_TOK.findall(kw)

        matched: dict[str, dict] = {}
        related: dict[str, dict] = {}
        for r in self._fts(tokens, limit * 4):
            d = dict(r)
            d["id"] = d.get("cve_id", "")          # 和在线 API 的行对齐，上层不用分叉
            (matched if low in d["desc"].lower() else related)[d["cve_id"]] = d

        if not matched and deep:                     # 整词匹配不到 → 子串兜底
            for r in self._like(kw, limit):
                d = dict(r)
                d["id"] = d.get("cve_id", "")
                matched[d["cve_id"]] = d

        def rank(rows):
            return sorted(rows.values(), key=lambda d: d.get("published") or "",
                          reverse=True)[:limit]

        return rank(matched), rank(related)


# ---------------------------------------------------------------- 输出
def _fmt_row(d: dict) -> str:
    sev = d.get("severity") or "-"
    score = f"{d['score']:.1f}" if d.get("score") else "-"
    desc = " ".join((d.get("desc") or "").split())[:240]
    return f"  {d.get('cve_id','?'):<16} {d.get('published','----------')}  {sev:<8} {score:>4}  {desc}"


def status(ddir: str | None = None) -> dict:
    db = find_db()
    if not db:
        print(f"[!] 没有离线库（找过 {default_dir()}）")
        print("    先跑：python -m fwmap nvd fetch && python -m fwmap nvd build")
        return {"ok": False}
    idx = Index(db)
    try:
        size = os.path.getsize(db)
        print(f"[+] 库文件   {db}")
        print(f"    条数     {idx.count} 条 CVE")
        print(f"    覆盖     {idx.years}")
        print(f"    构建于   {idx.built_at}")
        print(f"    大小     {size/1048576:.0f} MB")
        raw = feed_files(ddir)
        if raw:
            rsize = sum(os.path.getsize(p) for _, p in raw)
            print(f"    原始包   {len(raw)} 个年包 / {rsize/1048576:.0f} MB（{raw_dir(ddir)}）")
        return {"ok": True, "db": db, "count": idx.count, "years": idx.years,
                "built_at": idx.built_at, "size": size}
    finally:
        idx.close()


# ---------------------------------------------------------------- CLI
def _years_from(args) -> list[int]:
    y0 = getattr(args, "from_year", None) or FIRST_YEAR
    y1 = getattr(args, "to_year", None) or time.localtime().tm_year
    return list(range(y0, y1 + 1))


def run(args) -> int:
    cmd = getattr(args, "nvd_cmd", None) or "status"
    ddir = getattr(args, "dir", None)
    if cmd == "fetch":
        years = _years_from(args)
        print(f"[*] 下载 NVD CVE feed {years[0]}-{years[-1]}（{len(years)} 个年包）")
        r = fetch(years, ddir, proxy=getattr(args, "proxy", None))
        print(f"[+] 新下载 {len(r['downloaded'])} · 已有 {len(r['skipped'])} · "
              f"失败 {len(r['failed'])}")
        if r["failed"]:
            for y, why in r["failed"]:
                print(f"    {y}: {why}")
            return 1
        return 0

    if cmd == "build":
        if not feed_files(ddir):
            print(f"[!] {raw_dir(ddir)} 里没有年包，先跑 `python -m fwmap nvd fetch`")
            return 1
        print("[*] 解析年包 → SQLite")
        r = build(ddir)
        print(f"[+] 完成：{r['cve_count']} 条 CVE，{r['size']/1048576:.0f} MB")
        return 0

    if cmd == "update":
        print("[*] 检查 NVD 年包是否有更新（只比 .meta）")
        try:
            r = update(ddir, proxy=getattr(args, "proxy", None),
                       years=_years_from(args))
        except Exception as e:                       # noqa: BLE001
            print(f"[!] 更新失败：{e}")
            return 1
        if r["rebuilt"]:
            print(f"[+] 已更新：{r['cve_count']} 条 CVE → {r['db']}")
            if r["downloaded"]:
                print(f"    新下载年包：{', '.join(map(str, r['downloaded']))}")
        else:
            print(f"[+] 已是最新，没重建（{r['db']}）")
        return 0

    if cmd == "check":
        chk = check_updates(_years_from(args), ddir, getattr(args, "proxy", None))
        same = ", ".join(map(str, chk["same"])) or "—"
        print(f"[+] 最新：{same}")
        for key, label in (("changed", "有更新"), ("missing", "本地缺")):
            if chk[key]:
                print(f"[*] {label}：{', '.join(map(str, chk[key]))}")
        for y, why in chk["error"]:
            print(f"[!] {y} 取不到元信息：{why}")
        chk["has_update"] = bool(chk["changed"] or chk["missing"])
        return 0 if not chk["error"] else 1

    if cmd == "search":
        idx = Index(find_db(getattr(args, "db", None)))
        try:
            kws = getattr(args, "keywords", None) or []
            for kw in kws:
                m, rel = idx.search(kw, limit=getattr(args, "limit", 40),
                                    deep=not getattr(args, "no_scan", False))
                print(f"\n[{kw}]  精确命中 {len(m)} 条，相关 {len(rel)} 条")
                for d in m:
                    print(_fmt_row(d))
                if rel and not m:
                    print("  —— 只有分词级相关（描述里没有原样出现）：")
                    for d in rel[:5]:
                        print(_fmt_row(d))
            if not kws:
                print("[!] 给个关键词，例如：nvd search SetDlnaCfg")
                return 2
            return 0
        finally:
            idx.close()

    return 0 if status(ddir)["ok"] else 1
