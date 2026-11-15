"""合并测试：把她的 report.json 并进来，补上「新颖性」这一层。

这里不解真实 CVE 库（换了机器可能没有），用一个假 Index 顶替 ——
测的是**取名字、抠路由、判定、不改写她的结论**这几件事。
真实数据的效果见 docs/评估-Mango-Agent.md。
"""

import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import merge_mango as M  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


REPORT = {
    "schema": "mango-review/1",
    "status": "completed",
    "mode": "api",
    "candidate": {
        "trace": [{"function": "TendaTelnet", "ins_addr": "0x498798"}],
        "sink": {"function": "doSystemCmd", "ins_addr": "0x498890"},
        "inputs": {"likely": ["lan.ip"]},
        "rank": 0.7,
    },
    "review": {
        "action": "finish",
        "status": "insufficient_evidence",
        "summary": "证不出 TendaTelnet 有没有注册成 HTTP 处理函数。",
        "evidence": [{"id": "E0013", "claim": "fromAdvSetLanip 未过滤 lanIp"}],
        "missing_evidence": ["TendaTelnet 是否被 websFormDefine 注册"],
        "next_steps": [],
    },
    "dynamic_validation": "not_performed",
    "binary_sha256": "6887f4676af57e8eb74d289d4e1e3d256a615d3ff03bd6bc25b8fa765eb98af7",
}

HITS = {
    "TendaTelnet": ([{
        "cve_id": "CVE-2025-1819", "published": "2025-03-02",
        "severity": "MEDIUM", "score": 5.3,
        "desc": ("A vulnerability was found in Tenda AC7 1200M 15.03.06.44. Affected is the "
                 "function TendaTelnet of the file /goform/telnet. The manipulation of the "
                 "argument lan_ip leads to os command injection."),
    }], []),
}


class StubIndex:
    built_at = "2026-11-12 10:02:09"

    def search(self, keyword, limit=40):
        return HITS.get(keyword, ([], []))


def main() -> int:
    ok = True

    # 1) 输入：目录 / 文件 / 错东西
    tmp = tempfile.mkdtemp(prefix="fwmap-merge-")
    with open(os.path.join(tmp, "report.json"), "w", encoding="utf-8") as fh:
        json.dump(REPORT, fh, ensure_ascii=False)
    rep = M.load_review(tmp)
    ok &= check("能直接读整个 run 目录", rep["review"]["status"] == "insufficient_evidence")
    ok &= check("也能读单个 report.json",
                M.load_review(os.path.join(tmp, "report.json"))["binary_sha256"][:8] == "6887f467")
    bad = os.path.join(tmp, "bad.json")
    with open(bad, "w", encoding="utf-8") as fh:
        json.dump({"hello": 1}, fh)
    try:
        M.load_review(bad)
        ok &= check("不是她的报告就报错", False, "没报错")
    except ValueError as e:
        ok &= check("不是她的报告就报错", "candidate" in str(e) or "review" in str(e), e)

    # 2) 挑名字：占位名和通用汇点名不该拿去查库
    names, skipped = M.candidate_names(REPORT["candidate"])
    ok &= check("留下 handler 名", names == ["TendaTelnet"], names)
    ok &= check("汇点名被跳过（查了也是噪音）", "doSystemCmd" in skipped, skipped)
    names2, skipped2 = M.candidate_names(
        {"trace": [{"function": "sub_415798"}, {"function": "FUN_000aaa"}],
         "sink": {"function": "system"}})
    ok &= check("全是占位名时一个都不查", names2 == [], names2)

    # 3) 路由：句号要剪掉，源码文件名不要
    ok &= check("句末句号剪掉", M._routes("of the file /goform/telnet. The manipulation") == ["/goform/telnet"],
                M._routes("of the file /goform/telnet. The manipulation"))
    ok &= check("跳过源码文件名", M._routes("in httpd.c and /goform/x") == ["/goform/x"],
                M._routes("in httpd.c and /goform/x"))
    ok &= check("没有路由就返回空（不能编）", M._routes("Tenda M3 command execution") == [])

    # 4) 合并 + 渲染
    m = M.merge(rep, StubIndex())
    ok &= check("判定为已公开", m["known"] == ["TendaTelnet"], m["known"])
    ok &= check("路由被汇总", m["routes"] == ["/goform/telnet"], m["routes"])
    text = M.render(m, "2026-11-12 10:02:09")
    ok &= check("她的结论原样出现", "insufficient_evidence" in text and "证不出 TendaTelnet" in text)
    ok &= check("她的缺失证据也被抄下来（不替她删）", "是否被 websFormDefine 注册" in text)
    ok &= check("报告里有 CVE 号", "CVE-2025-1819" in text)
    ok &= check("报告里有路由", "/goform/telnet" in text)
    ok &= check("明说不是新漏洞", "不是新的" in text)
    ok &= check("明说她的结论没被改写", "不改写" in text or "没有被修改" in text)

    # 5) 查不到时不许说「是新的」
    m2 = M.merge(rep, StubIndex().__class__())   # 空表
    m2["names"] = M.merge(rep, None)["names"]
    t2 = M.render(M.merge(rep, None))
    ok &= check("查不到时不给「新漏洞」结论", "不等于新漏洞" in t2, t2[-200:])

    print()
    print("PASS（合并她的审查结论）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
