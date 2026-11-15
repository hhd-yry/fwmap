"""插件接口测试：外部工具用一份 JSON 描述就能接进来，双方都不改代码。

覆盖这几个容易出事的点：
- manifest 缺字段要被拒绝，而不是带着半成品去调外部程序；
- `{参数}` 替换要能工作；
- 外部工具超时 / 非零退出 / 输出坏 JSON，都要变成结构化失败，不能抛穿；
- 外部输出只取摘要，不要把几十 MB 原样塞回来；
- Windows 上子进程输出要按 UTF-8 解（默认 GBK 会让中文直接崩）。
"""

import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import plugins as P  # noqa: E402
from fwmap import tools_api as T  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def write_tool(dirpath: str, body: str, name: str = "ext.py") -> str:
    p = os.path.join(dirpath, name)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(body)
    return p


def q(p: str) -> str:
    return p.replace("\\", "/")


def main() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="fwmap-plugin-")

    # 1) 好工具：回一段 JSON（含中文，验证编码）
    good = write_tool(tmp, (
        "import sys\n"
        "import json\n"
        "print(json.dumps({'n': 3, 'msg': '中文输出', 'items': list(range(10000))}))\n"
    ))
    m = {"name": "t_good", "desc": "好工具", "cmd": [sys.executable, q(good)],
         "args": {}, "output": "json"}
    name = P.register_manifest({**m, "_path": "x"})
    r = T.call(name)
    ok &= check("外部工具能被调用", r.get("ok") is True, r)
    ok &= check("中文输出不炸（UTF-8）", "中文" in json.dumps(r, ensure_ascii=False), r.get("summary"))
    ok &= check("摘要里带字段值", "n=3" in (r.get("summary") or ""), r.get("summary"))
    blob = json.dumps(r.get("data") or {}, ensure_ascii=False)
    ok &= check("大结果只取摘要（data < 500 字节）", len(blob) < 500, len(blob))

    # 2) 参数替换
    echo = write_tool(tmp, (
        "import sys, json\n"
        "print(json.dumps({'target': sys.argv[2] if len(sys.argv) > 2 else ''}))\n"
    ), "echo.py")
    m2 = {"name": "t_echo", "desc": "回显参数",
          "cmd": [sys.executable, q(echo), "--target", "{target}"],
          "args": {"target": "目标"}, "output": "json"}
    name2 = P.register_manifest({**m2, "_path": "x"})
    r = T.call(name2, target="/some/rootfs")
    ok &= check("参数替换生效", "/some/rootfs" in json.dumps(r, ensure_ascii=False), r.get("summary"))

    # 3) 缺少参数 → 结构化失败（不是抛异常）
    r = T.call(name2)
    ok &= check("缺参数返回 ok=False", r.get("ok") is False, r)

    # 4) 非零退出
    bad = write_tool(tmp, "import sys; sys.stderr.write('boom'); sys.exit(3)\n", "bad.py")
    name3 = P.register_manifest({"name": "t_bad", "desc": "会失败",
                                 "cmd": [sys.executable, q(bad)], "output": "json",
                                 "_path": "x"})
    r = T.call(name3)
    ok &= check("非零退出 → ok=False 且带原因",
                r.get("ok") is False and "退出码" in (r.get("summary") or ""), r)

    # 5) 坏 JSON → 摘要说明「不是合法 JSON」，不崩
    junk = write_tool(tmp, "print('not json at all')\n", "junk.py")
    name4 = P.register_manifest({"name": "t_junk", "desc": "坏输出",
                                 "cmd": [sys.executable, q(junk)], "output": "json",
                                 "_path": "x"})
    r = T.call(name4)
    ok &= check("坏 JSON 也能给出摘要", r.get("ok") is True and "JSON" in r.get("summary", ""), r)

    # 6) manifest 校验
    badm = os.path.join(tmp, "bad.json")
    with open(badm, "w", encoding="utf-8") as fh:
        json.dump({"desc": "没有 name 和 cmd"}, fh)
    try:
        P.load_manifest(badm)
        ok &= check("缺字段的 manifest 必须报错", False, "没报错")
    except ValueError as e:
        ok &= check("缺字段的 manifest 必须报错", "缺少必填字段" in str(e), e)

    # 7) 目录批量加载
    with open(os.path.join(tmp, "ok1.json"), "w", encoding="utf-8") as fh:
        json.dump({"name": "t_dir1", "cmd": [sys.executable, q(good)]}, fh)
    loaded = P.load([tmp], log=lambda *_: None)
    ok &= check("目录批量加载", "plugin.t_dir1" in loaded, loaded)

    # 8) 模板生成 + 自测（对方拿到手的第一分钟）
    tdir = os.path.join(tmp, "template")
    r = P.init_template(tdir, name="t_template", desc="模板测试")
    ok &= check("init 生成三个文件",
                all(os.path.exists(x) for x in (r["manifest"], r["tool"],
                                                os.path.join(tdir, "README.md"))),
                r)
    ok &= check("生成的 manifest 合法", P.load_manifest(r["manifest"])["name"] == "t_template")
    rc = P.test_manifest(r["manifest"], tmp, log=lambda *_: None)
    ok &= check("plugin test 自测通过", rc == 0, rc)

    # 9) 裸中文必须真的按 UTF-8 出来。
    #    注意：json.dumps 默认 ensure_ascii=True，第 1 条测的中文其实是 \u4e2d 转义，
    #    根本没走编码这条路 —— 这条才测得到。Windows 上 Python 子进程默认按 GBK 写管道，
    #    不补 PYTHONUTF8 就会变成一串 \ufffd。
    zh = write_tool(tmp, (
        "import sys\n"
        "sys.stdout.write('{\"msg\": \"无法连接接口\"}')\n"
    ), "zh.py")
    name5 = P.register_manifest({"name": "t_zh", "cmd": [sys.executable, q(zh)],
                                 "output": "json", "_path": "x"})
    r = T.call(name5)
    blob = json.dumps(r, ensure_ascii=False)
    ok &= check("裸中文不乱码（GBK 默认编码已兜住）", "无法连接接口" in blob, blob[:160])

    # 10) manifest 能把环境变量传给外部工具（很多工具靠这个开关行为）
    envtool = write_tool(tmp, (
        "import os, json\n"
        "print(json.dumps({'v': os.environ.get('FWMAP_TEST_MARK', '')}))\n"
    ), "env.py")
    name6 = P.register_manifest({"name": "t_env", "cmd": [sys.executable, q(envtool)],
                                 "env": {"FWMAP_TEST_MARK": "hello-env"},
                                 "output": "json", "_path": "x"})
    r = T.call(name6)
    ok &= check("manifest 的 env 传得到子进程", "hello-env" in json.dumps(r), r.get("summary"))

    # 11) Python 外部工具默认拿到 UTF-8 的 stdout
    enc = write_tool(tmp, (
        "import sys, json\n"
        "print(json.dumps({'enc': sys.stdout.encoding}))\n"
    ), "enc.py")
    name7 = P.register_manifest({"name": "t_enc", "cmd": [sys.executable, q(enc)],
                                 "output": "json", "_path": "x"})
    r = T.call(name7)
    ok &= check("Python 子进程 stdout 是 utf-8", "utf-8" in json.dumps(r).lower(),
                r.get("summary"))

    print()
    print("PASS（插件接口）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
