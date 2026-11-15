"""导出测试：我们的链 → 别人的工具能直接吃的 Mango 结果格式。

这条线是给「融合」用的，所以测的不是分析对不对，而是**壳对不对**：
- 她的 `agent.py list` 只读 `closures[].sink.{function,ins_addr}` / `rank` / `depth`；
- 她的 `review` 还要 `sha256` 跟 IDA 里打开的二进制对上；
- 地址必须是 hex 字符串（她那边 `int(x, 16)` 会直接解析）。
"""

import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import export_mango as E  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


FLOW = {
    "binary": "C:/fw/p3/tenda19/bin/httpd",
    "chains": [
        {"function": "formWifiBasicSet", "address": "0009135c", "sink": "doSystemCmd",
         "sink_category": "ci", "source_api": "FUN_0008f234", "source_param": "wl5g.ssidxx",
         "sink_args": '"cfm post %d",3,uVar3', "guard": "if (local_38 == 0)", "hops": 1,
         "confidence": "low", "verdict": "keep", "weak": False},
        {"function": "FUN_000aaa", "address": "000aaaaa", "sink": "strcpy",
         "sink_category": "bof", "source_api": "websGetVar", "source_param": "ssid",
         "sink_args": "local_38, uVar3", "guard": "x" * 900, "hops": 3,
         "confidence": "high", "verdict": "keep", "weak": False},
        {"function": "FUN_000bbb", "address": "000bbbbb", "sink": "printf",
         "sink_category": "fmt", "source_api": "GetValue", "source_param": "name",
         "sink_args": "uVar1", "guard": "", "hops": 1,
         "confidence": "low", "verdict": "demoted", "weak": True},
    ],
}


def main() -> int:
    ok = True

    out = E.to_mango(FLOW)
    cl = out["closures"]
    ok &= check("默认只导 keep（demoted 被挡掉）", len(cl) == 2, [c["sink"]["function"] for c in cl])
    ok &= check("名字对上 Mango 的 closures 结构",
                all({"rank", "depth", "sink"} <= set(c) for c in cl), cl[0].keys())
    ok &= check("sink 里是 function + ins_addr",
                all(set(c["sink"]) == {"function", "ins_addr"} for c in cl), cl[0]["sink"])
    ok &= check("ins_addr 带 0x（她那边 int(x,16)）",
                all(int(c["sink"]["ins_addr"], 16) >= 0 for c in cl), cl[0]["sink"])
    ok &= check("可信度高的排在前面", cl[0]["sink"]["function"] == "strcpy",
                cl[0]["sink"]["function"])
    ok &= check("rank 从 1 起", [c["rank"] for c in cl] == [1, 2], [c["rank"] for c in cl])
    ok &= check("depth 取的是链上跳数", cl[0]["depth"] == 3, cl[0]["depth"])
    ok &= check("她的 prompt 会看到 handler 和参数名",
                cl[0]["fwmap"]["handler"] == "FUN_000aaa"
                and cl[0]["fwmap"]["source_param"] == "ssid", cl[0]["fwmap"])
    ok &= check("超长守卫要截断（别把上下文吃掉）",
                len(cl[0]["fwmap"]["guard"]) <= E._MAX_TEXT + 1, len(cl[0]["fwmap"]["guard"]))
    ok &= check("写明 rank 不是概率",
                "不是漏洞概率" in out["generator"]["note"], out["generator"]["note"])

    out_all = E.to_mango(FLOW, include_demoted=True)
    ok &= check("--all 时把降级的也带上", len(out_all["closures"]) == 3,
                len(out_all["closures"]))

    top = E.to_mango(FLOW, top=1)
    ok &= check("--top 生效", len(top["closures"]) == 1, len(top["closures"]))

    # sha256：对方拿它跟 IDA 里打开的库比对，算错就等于没接上
    tmp = tempfile.mkdtemp(prefix="fwmap-export-")
    blob = os.path.join(tmp, "bin")
    with open(blob, "wb") as fh:
        fh.write(b"fwmap" * 1000)
    import hashlib
    ok &= check("sha256 算得对", E.sha256_of(blob) == hashlib.sha256(b"fwmap" * 1000).hexdigest())

    # 落盘用 run()：默认文件名、缺 chains 时的报错
    src = os.path.join(tmp, "flow.json")
    with open(src, "w", encoding="utf-8") as fh:
        json.dump(FLOW, fh, ensure_ascii=False)
    args = type("A", (), {"input": src, "output": None, "binary": blob,
                          "top": 0, "all": False})()
    rc = E.run(args)
    dst = os.path.splitext(src)[0] + ".mango.json"
    ok &= check("run() 写出 <输入>.mango.json", rc == 0 and os.path.exists(dst), dst)
    if os.path.exists(dst):
        saved = json.load(open(dst, encoding="utf-8"))
        ok &= check("落盘后 sha256 在里面", len(saved.get("sha256", "")) == 64,
                    saved.get("sha256"))

    bad = os.path.join(tmp, "notflow.json")
    with open(bad, "w", encoding="utf-8") as fh:
        json.dump({"nope": 1}, fh)
    args2 = type("A", (), {"input": bad, "output": None, "binary": None,
                           "top": 0, "all": False})()
    ok &= check("不是 flow.json 就明确报错", E.run(args2) == 2)

    print()
    print("PASS（导出到 Mango 格式）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
