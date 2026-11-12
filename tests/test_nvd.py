"""离线 NVD 索引的离线测试（不联网、不依赖真实的大库）。

用一个几十行的合成 feed 覆盖这些点：
  - 流式解析能吃下 NVD 的真实 JSON 结构（含转义引号、嵌套数组）
  - 抽取规则：非英文描述 / 空描述的条目要丢掉，不能进库
  - cvss v3 有 baseSeverity，v2 没有，要按分数换算
  - 检索两层：整词命中（FTS5）和子串兜底（LIKE）都算「已公开」
  - 库里查得到 → verify 判 known；库里有但描述没提到它 → 不能算 known
  - `--source local` 没库时要明确失败，不能静默回退联网
"""

import argparse
import gzip
import json
import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import nvd, verify  # noqa: E402


def check(name, cond, detail=""):
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


FEED = {
    "resultsPerPage": 5,
    "vulnerabilities": [
        {"cve": {
            "id": "CVE-2026-10127",
            "published": "2026-07-14T10:00:00.000",
            "descriptions": [{"lang": "en", "value":
                              'Edimax BR-6478AC 1.23 has a stack buffer overflow in '
                              'formStaDrvSetup via the "station" parameter.'}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8,
                                                        "baseSeverity": "CRITICAL"}}]},
        }},
        {"cve": {
            "id": "CVE-2024-10661",
            "published": "2024-11-02T00:00:00.000",
            "descriptions": [{"lang": "en", "value":
                              "Tenda AC15 15.03.05.19 SetDlnaCfg has a stack overflow "
                              "via the scanList parameter."}],
            # v2 没有 baseSeverity，要按分数换算
            "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]},
        }},
        {"cve": {   # 只有中文描述 → 丢掉
            "id": "CVE-2025-0002",
            "descriptions": [{"lang": "es", "value": "desbordamiento de pila en formFoo"}],
        }},
        {"cve": {"id": "CVE-2025-0003", "descriptions": []}},      # 空描述 → 丢掉
        {"cve": {"id": "not-a-cve", "descriptions": [{"lang": "en", "value": "x"}]}},
        {"cve": {
            "id": "CVE-2025-0004",
            "published": "2025-03-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value":
                              "formStaDrvSetup_extra in some router has \\\"weird\\\" "
                              "escaping [and brackets] in it."}],
        }},
    ],
}


def make_feed(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with gzip.open(path, "wb") as fh:
        fh.write(json.dumps(FEED, ensure_ascii=False).encode("utf-8"))


def main() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="fwmap-nvd-")
    db = os.path.join(tmp, "nvd.sqlite")
    old_env = os.environ.get("FWMAP_NVD_DB")
    os.environ["FWMAP_NVD_DB"] = db
    try:
        feed = os.path.join(nvd.raw_dir(tmp), "nvdcve-2.0-2026.json.gz")
        make_feed(feed)

        # 1) 流式解析 + 抽取
        items = list(nvd.iter_cves(feed))
        ok &= check("流式解析条数", len(items) == 6, len(items))
        rows = [nvd.extract_row(v) for v in items]
        rows = [r for r in rows if r]
        ok &= check("过滤非英文/空描述/非法 CVE 号", len(rows) == 3, len(rows))
        by = {r[0]: r for r in rows}
        ok &= check("cvss v3 严重级",
                    by["CVE-2026-10127"][2] == "CRITICAL", by["CVE-2026-10127"][2])
        ok &= check("cvss v2 无 baseSeverity → 按分数换算",
                    by["CVE-2024-10661"][2] == "MEDIUM", by["CVE-2024-10661"][2])
        ok &= check("发布日期取到",
                    by["CVE-2026-10127"][1] == "2026-07-14", by["CVE-2026-10127"][1])

        # 2) 建库
        r = nvd.build(tmp, log=lambda *a: None)
        ok &= check("建库条数", r["cve_count"] == 3, r["cve_count"])
        ok &= check("库文件存在", os.path.isfile(db), db)

        idx = nvd.Index(db)
        try:
            ok &= check("元信息条数", idx.count == 3, idx.count)
            ok &= check("快照日期有记录", idx.built_at != "?", idx.built_at)

            m, _ = idx.search("formStaDrvSetup")
            # 两条都真含这个字符串（一条是 _extra 后缀），都该算命中
            ok &= check("整词命中（FTS5）",
                        {d["cve_id"] for d in m} == {"CVE-2026-10127", "CVE-2025-0004"},
                        [d["cve_id"] for d in m])
            ok &= check("整词命中的没走扫描兜底", idx._scans == 0, idx._scans)

            m, _ = idx.search("SetDlnaCfg")
            ok &= check("路由名命中", [d["cve_id"] for d in m] == ["CVE-2024-10661"],
                        [d["cve_id"] for d in m])

            # 描述里是 formStaDrvSetup_extra，整词匹配不到 → 必须靠子串兜底
            m, _ = idx.search("StaDrvSetup_ext")
            ok &= check("子串兜底（LIKE）", [d["cve_id"] for d in m] == ["CVE-2025-0004"],
                        [d["cve_id"] for d in m])
            ok &= check("确实走了扫描", idx._scans >= 1, idx._scans)

            m, _ = idx.search("CVE-2024-10661")
            ok &= check("按 CVE 号直查", len(m) == 1 and m[0]["cve_id"] == "CVE-2024-10661", m)

            m, rel = idx.search("formNoSuchThing")
            ok &= check("库里没有的名字 → 空", not m and not rel, (m, rel))

            n_before = idx._scans
            idx.search("ScAnLiSt", deep=False)
            ok &= check("deep=False 不扫描", idx._scans == n_before, idx._scans)
        finally:
            idx.close()

        # 3) verify 接上离线库
        ns = argparse.Namespace(source="local", db=db, no_scan=False,
                                refresh=False, delay=0)
        searcher, binfo = verify._make_searcher(ns)
        ok &= check("后端是 local", binfo and binfo["kind"] == "local", binfo and binfo["kind"])
        row = verify.judge_function("formStaDrvSetup", [], {}, False, 0, False,
                                    searcher=searcher)
        ok &= check("离线判定 known", row["verdict"] == "known", row["verdict"])
        ok &= check("命中 CVE-2026-10127",
                    row["matched"] and row["matched"][0]["id"] == "CVE-2026-10127",
                    row["matched"])
        row = verify.judge_function("formNoSuchThing", ["NoSuchRoute"], {}, False, 0, False,
                                    searcher=searcher)
        ok &= check("查不到 → unknown（不是新漏洞）", row["verdict"] == "unknown", row["verdict"])

        # 4) 没有库时 --source local 必须明确失败，不能偷偷联网
        ns2 = argparse.Namespace(source="local", db=os.path.join(tmp, "nope.sqlite"),
                                 no_scan=False, refresh=False, delay=0)
        old = os.environ.pop("FWMAP_NVD_DB", None)
        try:
            s2, i2 = verify._make_searcher(ns2)
        finally:
            if old:
                os.environ["FWMAP_NVD_DB"] = old
        ok &= check("没库时 local 返回 None", s2 is None and i2 is None, i2)

        # 5) 报告里写清快照来源
        md = verify.to_markdown([row], "x.flow.json",
                                {"kind": "local", "db": db, "count": 3,
                                 "years": "2026-2026", "built_at": "2026-11-12 10:00"})
        ok &= check("报告写明离线快照",
                    "离线 NVD 库" in md and "快照 2026-11-12" in md, md[:200])

        # 6) auto 路由：有网走 API，断网退本地（用户要的就是这个顺序）
        ns3 = argparse.Namespace(source="auto", db=db, no_scan=False,
                                 refresh=False, delay=0, update_index=False)
        orig_probe = nvd.probe
        try:
            nvd.probe = lambda timeout=6: True
            _, i5 = verify._make_searcher(ns3)
            ok &= check("auto + 有网 → api", i5 and i5["kind"] == "api", i5 and i5["kind"])
            nvd.probe = lambda timeout=6: False
            _, i6 = verify._make_searcher(ns3)
            ok &= check("auto + 断网 → local", i6 and i6["kind"] == "local", i6 and i6["kind"])
            ok &= check("记下为什么选它", i6.get("why") == "网络不可达", i6.get("why"))
            # FWMAP_OFFLINE=1 时不探测，强制本地
            os.environ["FWMAP_OFFLINE"] = "1"
            try:
                _, i7 = verify._make_searcher(ns3)
            finally:
                os.environ.pop("FWMAP_OFFLINE", None)
            ok &= check("FWMAP_OFFLINE=1 强制本地",
                        i7 and i7["kind"] == "local" and i7.get("why") == "FWMAP_OFFLINE=1", i7)
        finally:
            nvd.probe = orig_probe

        # 7) 快照年龄可算（auto 模式靠它决定要不要提示更新）
        age = nvd.age_days(db)
        ok &= check("刚建的库年龄 < 1 天", age is not None and age < 1, age)
    finally:
        if old_env is not None:
            os.environ["FWMAP_NVD_DB"] = old_env
        else:
            os.environ.pop("FWMAP_NVD_DB", None)
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("PASS（离线 NVD 索引）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
