"""经验库在报告里的呈现：别让读者以为这轮是凭空猜的。"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import triage  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def base_res(kn=None):
    r = {
        "rootfs": "/x", "time": "2026-11-17 20:00", "meta": {}, "agent": False,
        "dyn_requested": False,
        "stats": {"files": 1, "targets": 1, "elfs": 1, "high": 1, "oneline": "最小报告",
                  "kept": 0, "chains": 0, "known": 0},
        "agent_rows": [],
        "binaries": [{"name": "httpd", "binary": "/x/sbin/httpd", "path": "sbin/httpd",
                      "score": 60, "role": "web", "arch": "MIPS", "size": 1000,
                      "chains": 0, "chain_list": [], "endpoints": 0,
                      "endpoint_list": [], "sink_verified": 0, "m2_strategy": "inventory"}],
    }
    if kn:
        r["knowledge"] = kn
    return r


def main() -> int:
    ok = True

    html = triage.render(base_res())
    ok &= check("没有经验库字段时不报错", "<h2>" in html and "经验库" not in html)

    html2 = triage.render(base_res({
        "vendor": "dir-615c2", "hit": True, "runs": 3, "new": 2,
        "dir": "/home/u/.fwmap/knowledge"}))
    ok &= check("命中经验时写清厂商", "dir-615c2" in html2)
    ok &= check("写出是第几次跑", "第 4 次" in html2, html2[html2.find("经验库"):][:160])
    ok &= check("写出新增经验条数", "新增经验 2 条" in html2)
    ok &= check("带了知识库路径", ".fwmap" in html2)

    html3 = triage.render(base_res({"vendor": "dir-816l", "hit": False, "runs": 0,
                                    "new": 0, "dir": "/tmp/k"}))
    ok &= check("没命中时不吹牛", "命中历史" not in html3 and "dir-816l" in html3)

    print()
    print("PASS（经验库报告）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
