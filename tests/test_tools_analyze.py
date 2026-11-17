"""analyze 类工具的测试：解析要真能抽出事实，而不是"命令跑完了"。

这批工具最容易出假阳性：`readelf` 在非 ELF 上会往 stderr 打一句
"Error: Not an ELF file"，退出码可能还是 0。如果我们只信退出码，
就会拿"没解析出任何东西"当"分析成功"。
"""

import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import toolbus as TB  # noqa: E402
from fwmap import tools_analyze as TA  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


READELF = """ELF Header:
  Class:                             ELF32
  Data:                              2's complement, little endian
  Type:                              EXEC (Executable file)
  Machine:                           MIPS R3000
  Entry point address:               0x400b20
"""

RIZIN = """0x00400a00    40    32 sym.main
0x00400b20   120    48 sym.cgi_handler
0x00400c80    64    40 sym.upload
0x00400d00    32    24 sym.foo
0x00400d40    16    16 sym.bar
"""

RABIN2 = json.dumps({"arch": "mips", "bintype": "elf", "bits": 32})


def main() -> int:
    ok = True
    TA.register_all()

    # 1) readelf 解析 + 验收
    info = TA.parse_readelf(READELF)
    ok &= check("解析出 Machine", info.get("machine", "").startswith("MIPS"), info)
    ok &= check("解析出入口", info.get("entry") == "0x400b20", info)
    v = TA.v_readelf(READELF)
    ok &= check("readelf 验收通过", v["ok"] is True, v)
    ok &= check("非 ELF 输出 → 验收失败",
                TA.v_readelf("Error: Not an ELF file")["ok"] is False)

    # 2) rizin 函数表
    funcs = TA.parse_rizin_funcs(RIZIN)
    ok &= check("认出 5 个函数", len(funcs) == 5, funcs)
    ok &= check("名字对", funcs[1] == "sym.cgi_handler", funcs)
    ok &= check("函数太少 → 失败", TA.v_rizin(5)("0x0 1 1 a")["ok"] is False)
    ok &= check("函数够 → 通过", TA.v_rizin(5)(RIZIN)["ok"] is True)

    # 3) rabin2 JSON
    ok &= check("rabin2 JSON 解析", TA.parse_rabin2_json(RABIN2)["arch"] == "mips")
    ok &= check("rabin2 验收", TA.v_rabin2(RABIN2)["ok"] is True)
    ok &= check("rabin2 没 JSON → 失败", TA.v_rabin2("usage: rabin2")["ok"] is False)

    # 4) 走总线的路径：做一对假的执行器验证 stdout 验收
    calls = []

    def fake_run(cmd, capture_output=True, timeout=None):
        calls.append(cmd)

        class R:
            returncode = 0
            stdout = READELF.encode()
            stderr = b""
        return R()

    import subprocess

    real = subprocess.run
    subprocess.run = fake_run
    try:
        tmp = tempfile.mkdtemp(prefix="fwmap-ana-")
        src = os.path.join(tmp, "f")
        open(src, "wb").write(b"\x7fELF")
        r = TB.run("readelf", src, os.path.join(tmp, "o"))
        ok &= check("总线跑 readelf 并验收通过", r["ok"] is True, r)
        ok &= check("记下命令与耗时", r["provenance"].get("cmd")
                    and "seconds" in r["provenance"], r["provenance"])
        ok &= check("detail 里带架构", "MIPS" in r["detail"], r["detail"])
    finally:
        subprocess.run = real

    # 5) lief：没装就明确失败，不假装
    tmp2 = tempfile.mkdtemp(prefix="fwmap-ana2-")
    r2 = TB.run("lief", src, os.path.join(tmp2, "o"))
    ok &= check("lief 不可用时如实失败", r2["ok"] is False, r2)
    ok &= check("失败原因说得清", bool(r2.get("error") or r2.get("detail")), r2)

    # 6) lief 结果验收（用假 json）
    d = os.path.join(tmp2, "fake")
    os.makedirs(d, exist_ok=True)
    json.dump({"format": "ELF", "entry": "0x400b20", "arch": "MIPS",
               "sections": 12, "symbols": 40}, open(os.path.join(d, "lief.json"), "w"))
    ok &= check("lief.json 存在且合法 → 验收通过", TA.v_lief(d)["ok"] is True, TA.v_lief(d))
    json.dump({"format": "ELF", "entry": "0x0"}, open(os.path.join(d, "lief.json"), "w"))
    ok &= check("没有入口点 → 不算成功", TA.v_lief(d)["ok"] is False)

    import shutil

    shutil.rmtree(tmp2, ignore_errors=True)
    print()
    print("PASS（静态分析工具）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
