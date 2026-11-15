"""二进制身份绑定测试 —— 结果文件必须对得上它分析的那串字节。

这条是照同学的 agent 抄的：她那边的规则是「Mango 结果 / IDA 库 / 输入」三者
必须是同一个二进制，对不上直接拒绝。我们以前只记路径，换个版本静默复用。

测四件事：
- 写的时候真的记了哈希；
- 读的时候四种情况分得清（对得上 / 没哈希 / 二进制不在 / 哈希变了）；
- 只有「哈希变了」会拦，其余只提示（不能因为换工具就把存量结果全废了）；
- verify / dyn 真的会在哈希对不上时拒绝继续。
"""

import argparse
import hashlib
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import integrity as I  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def quiet(*_a, **_k):
    pass


def main() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="fwmap-integrity-")

    # 1) 哈希算得对
    binary = os.path.join(tmp, "bin")
    with open(binary, "wb") as fh:
        fh.write(b"fwmap-integrity" * 100)
    want = hashlib.sha256(b"fwmap-integrity" * 100).hexdigest()
    ok &= check("sha256 算得对", I.sha256_of(binary) == want, I.sha256_of(binary)[:16])

    # 2) 写：stamp 会加上哈希和大小；文件不在就什么都不加（不能写空串冒充记过了）
    obj = I.stamp({"binary": binary, "chains": []}, binary)
    ok &= check("stamp 记了哈希", obj.get("binary_sha256") == want)
    ok &= check("stamp 记了大小", obj.get("binary_size") == 1500, obj.get("binary_size"))
    missing = I.stamp({"binary": "/nope/x"}, "/nope/x")
    ok &= check("二进制不在时不写空哈希", "binary_sha256" not in missing, missing)

    # 3) 读：四种情况分得清
    ok &= check("对得上 → ok", I.status(obj, binary)[0] == I.OK, I.status(obj, binary))
    ok &= check("老结果没哈希 → no-hash",
                I.status({"binary": binary}, binary)[0] == I.NO_HASH)
    ok &= check("二进制不在 → no-binary",
                I.status(obj, os.path.join(tmp, "gone"))[0] == I.NO_BINARY)
    other = os.path.join(tmp, "other")
    with open(other, "wb") as fh:
        fh.write(b"a different firmware")
    st, detail = I.status(obj, other)
    ok &= check("哈希变了 → mismatch", st == I.MISMATCH, st)
    ok &= check("mismatch 的提示里有哈希前几位", "…" in detail, detail)

    # 4) 只有 mismatch 会拦
    ok &= check("对得上 → 放行", I.check(obj, binary, log=quiet) is True)
    ok &= check("没哈希 → 提示但放行", I.check({"binary": binary}, binary, log=quiet) is True)
    ok &= check("二进制不在 → 提示但放行",
                I.check(obj, os.path.join(tmp, "gone"), log=quiet) is True)
    ok &= check("哈希变了 → 拒绝", I.check(obj, other, log=quiet) is False)
    ok &= check("哈希变了 + allow_stale → 放行",
                I.check(obj, other, allow_stale=True, log=quiet) is True)

    # 5) verify / dyn 真的会拦住
    flow = os.path.join(tmp, "x.flow.json")
    with open(flow, "w", encoding="utf-8") as fh:
        json.dump({"binary": other, "binary_sha256": want,
                   "chains": [{"function": "formSetX", "verdict": "keep",
                               "sink": "system", "source_param": "a"}]}, fh)

    from fwmap import verify

    ns = argparse.Namespace(input=flow, allow_stale=False, m2=None, dry_run=True,
                            source="local", db=None, context=None, all_handlers=False,
                            only=None, limit=0, out=None, no_scan=True, refresh=False,
                            delay=0, update_index=False)
    rc = verify.run(ns)
    ok &= check("verify 对着错版本的链拒绝跑", rc == 3, rc)

    from fwmap import dyn

    ns2 = argparse.Namespace(flow=flow, binary=other, allow_stale=False)
    ok &= check("dyn 把链打给另一个二进制时拒绝跑", dyn.run(ns2) == 3)

    # 6) triage 的 report.json 形状也要能查（每个 binary 一条）
    rep = os.path.join(tmp, "report.json")
    with open(rep, "w", encoding="utf-8") as fh:
        json.dump({"binaries": [{"binary": other, "binary_sha256": want,
                                 "chain_list": []}]}, fh)
    ns3 = argparse.Namespace(allow_stale=False)
    ok &= check("triage 报告里的多个二进制逐个核对",
                verify._stale_ok(ns3, rep, log=quiet) is False)
    ns3.allow_stale = True
    ok &= check("allow_stale 对 triage 报告同样生效",
                verify._stale_ok(ns3, rep, log=quiet) is True)

    print()
    print("PASS（二进制身份绑定）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
