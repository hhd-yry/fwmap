"""工具注册表与决策循环的离线测试。

重点不是「能不能跑」，而是三件事：

1. 工具返回的是**摘要**，不是几 MB 的原始 JSON（否则塞进模型上下文会爆）；
2. 工具失败要变成**结构化结果**，不能让异常穿透整个智能体；
3. 结论必须区分「没跑」和「跑了没有」—— 0 条链时不能写成「这个固件很干净」。
"""

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import planner, tools_api as T  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)                      # cond 可能是字符串（and 的返回值），统一成布尔
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def main() -> int:
    ok = True

    # 1) 注册表
    cat = T.catalog()
    names = {t["name"] for t in cat}
    ok &= check("注册了 7 个工具", len(cat) == 7, names)
    ok &= check("关键工具都在",
                {"check", "scan", "m2", "m3", "verify", "dyn"} <= names, names)
    ok &= check("每个工具都有用途说明", all(t["desc"] for t in cat))

    # 2) 未知工具 / 工具内部异常 → 结构化失败，不抛
    r = T.call("no_such_tool")
    ok &= check("未知工具返回 ok=False", r["ok"] is False, r)
    r = T.call("scan", rootfs="C:\\definitely\\not\\exist\\路径")
    ok &= check("不存在的 rootfs 不抛异常", isinstance(r, dict) and "ok" in r, r)

    # 3) 真实工具：check 在空目录上应报缺失，且返回摘要而不是大对象
    tmp = tempfile.mkdtemp(prefix="fwmap-empty-")
    r = T.call("check", rootfs=tmp)
    ok &= check("check 有摘要", isinstance(r.get("summary"), str) and r["summary"], r)
    ok &= check("check 报出问题", r.get("ok_clean") is False, r.get("ok_clean"))

    # 4) 决策：一开始必须先做 check
    act = planner.decide({"rootfs": tmp})
    ok &= check("第一步是 check", act and act["tool"] == "check", act)
    # 做完 check、还没 scan
    act = planner.decide({"rootfs": tmp, "checked": True})
    ok &= check("第二步是 scan", act and act["tool"] == "scan", act)
    # 有目标、跳过 ghidra、无链 → 应收敛
    act = planner.decide({"rootfs": tmp, "checked": True, "scan_ok": True,
                          "targets": [{"path": "bin/x"}], "skip_ghidra": True})
    ok &= check("skip-ghidra 且无链 → 收敛", act is None, act)
    # 有链 → 去 verify
    act = planner.decide({"rootfs": tmp, "checked": True, "scan_ok": True,
                          "targets": [{"path": "bin/x"}], "skip_ghidra": True,
                          "chains": [{"function": "f"}]})
    ok &= check("有链就去 verify", act and act["tool"] == "verify", act)

    # 5) 结论措辞：0 条链不能写成「研究过了」
    rep = planner._report({"history": [], "chains": [], "verified": False,
                           "skip_ghidra": True, "binary": "bin/x"}, 1.0)
    joined = " ".join(rep["lines"])
    ok &= check("0 条链不冒充「已研究过」",
                "已经被研究过" not in joined and "没跑" in joined, rep["lines"])
    rep = planner._report({"history": [], "chains": [{"function": "f"}],
                           "verified": True, "unknown_fns": [],
                           "verify_stat": {"known": 3, "unknown": 0, "manual": 0},
                           "binary": "bin/x"}, 1.0)
    ok &= check("确实核对完才说「有公开记录」",
                "已出现在公开 CVE 里" in " ".join(rep["lines"]), rep["lines"])
    # 全部需人工时，不能冒充「核对过」
    rep2 = planner._report({"history": [], "chains": [{"function": "FUN_1"}],
                            "verified": True, "unknown_fns": [],
                            "verify_stat": {"known": 0, "unknown": 0, "manual": 22},
                            "binary": "bin/x"}, 1.0)
    joined2 = " ".join(rep2["lines"])
    ok &= check("全需人工时说明「没核对过」",
                "没有核对过" in joined2 and "已出现在公开 CVE" not in joined2, rep2["lines"])

    print()
    print("PASS（工具注册表与决策循环）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
