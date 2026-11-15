"""界面测试 —— 只测「命令拼得对不对」和「路径判断对不对」。

GUI 里能点的东西没法断言，但**命令拼错**一定会出事（参数名打错、路径没引号、
- o 少个横线），所以这两块单独抽成纯函数来测。
窗口本身只在有图形环境时才建，没有就跳过。
"""

import os
import sys
import tempfile
import types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import app  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def main() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="fwmap-app-")

    # 1) 三种模式拼出来的命令
    auto = app.build_cmd("auto", r"C:\fw\root", r"C:\out\x", port=9090)
    ok &= check("一键分析 = autopilot", "autopilot" in auto and r"C:\fw\root" in auto, auto)
    ok &= check("端口传下去了", "--port" in auto and "9090" in auto, auto)
    ok &= check("调查日志写进输出目录",
                auto[-1].endswith("survey.json") and r"C:\out\x" in auto[-1], auto[-1])
    ok &= check("没勾模型就不加 --llm", "--llm" not in auto, auto)
    auto2 = app.build_cmd("auto", "r", "o", binary="bin/webs", llm=True, limit=30)
    ok &= check("指定二进制", "--binary" in auto2 and "bin/webs" in auto2, auto2)
    ok &= check("勾了模型才加 --llm", "--llm" in auto2, auto2)
    ok &= check("limit 能透传", "--limit" in auto2 and "30" in auto2, auto2)

    rep = app.build_cmd("report", r"C:\fw\root", r"C:\out\y")
    ok &= check("完整报告 = triage", "triage" in rep and r"C:\out\y" in rep, rep)
    ok &= check("报告模式默认不带 --agent", "--agent" not in rep, rep)
    ok &= check("报告模式勾模型加 --agent", "--agent" in app.build_cmd("report", "r", "o", llm=True))

    doc = app.build_cmd("doctor", "", "")
    ok &= check("检查环境 = doctor", "doctor" in doc, doc)

    try:
        app.build_cmd("nope", "r", "o")
        ok &= check("未知模式要报错", False, "没报错")
    except ValueError as e:
        ok &= check("未知模式要报错", "未知模式" in str(e), e)

    # 2) 路径判断：别让人对着一个压缩包点半天
    rootfs = os.path.join(tmp, "root")
    os.makedirs(os.path.join(rootfs, "bin"))
    os.makedirs(os.path.join(rootfs, "etc"))
    ok &= check("有 bin/etc 的目录 = rootfs", app.looks_like_rootfs(rootfs)[0] is True)

    empty = os.path.join(tmp, "empty")
    os.makedirs(empty)
    got, why = app.looks_like_rootfs(empty)
    ok &= check("空目录不算 rootfs", got is False and "bin/" in why, why)

    z = os.path.join(tmp, "fw.zip")
    open(z, "wb").write(b"PK\x03\x04")
    got, why = app.looks_like_rootfs(z)
    ok &= check("压缩包要提示先解包", got is False and "解包" in why, why)
    ok &= check("提示里说清 Windows 解不了", "Windows" in why, why)

    ok &= check("路径不存在要报出来", app.looks_like_rootfs(os.path.join(tmp, "nope"))[0] is False)

    # 3) 子进程环境：不带 UTF-8 就会出乱码（这个坑踩过）
    env = app.child_env()
    ok &= check("子进程带 PYTHONUTF8", env.get("PYTHONUTF8") == "1")
    ok &= check("子进程带 PYTHONIOENCODING", env.get("PYTHONIOENCODING") == "utf-8")
    ok &= check("PYTHONPATH 指向包目录", str(ROOT) in env.get("PYTHONPATH", ""))

    # 3.5) 模型目录：选对了才让勾模型
    mdl = os.path.join(tmp, "model")
    os.makedirs(mdl)
    ok &= check("空目录不算模型", app.looks_like_model(mdl)[0] is False)
    with open(os.path.join(mdl, "config.json"), "w", encoding="utf-8") as fh:
        fh.write("{}")
    ok &= check("有 config.json 但没权重 → 不算", app.looks_like_model(mdl)[0] is False)
    with open(os.path.join(mdl, "model-00001.safetensors"), "wb") as fh:
        fh.write(b"\0" * (300 * 1024))
    ok &= check("权重太小 → 提示没下完", "没下完" in app.looks_like_model(mdl)[1],
                app.looks_like_model(mdl))
    with open(os.path.join(mdl, "model-00001.safetensors"), "wb") as fh:
        fh.truncate(300 * 1024 * 1024)          # 稀疏文件，不占磁盘
    got, msg = app.looks_like_model(mdl)
    ok &= check("完整模型目录能认出来", got is True and "GB" in msg, msg)

    env2 = app.child_env(mdl)
    ok &= check("选了模型就传给子进程", env2.get("FWMAP_LLM_MODEL") == mdl)
    ok &= check("没选模型就不设这个变量", "FWMAP_LLM_MODEL" not in app.child_env())
    auto3 = app.build_cmd("auto", "r", "o", llm=True, model=mdl)
    ok &= check("勾了模型就带 --llm-model", "--llm-model" in auto3 and mdl in auto3, auto3)
    ok &= check("没勾模型就不带", "--llm-model" not in app.build_cmd("auto", "r", "o"),
                app.build_cmd("auto", "r", "o"))

    # 配置能存能读（下次打开不用重选）
    cfg_path = os.path.join(tmp, "config.json")
    old = app.CFG_FILE
    app.CFG_FILE = __import__("pathlib").Path(cfg_path)
    try:
        app.save_config({"model": mdl})
        ok &= check("选过的模型记下来了", app.load_config().get("model") == mdl)
        app.CFG_FILE = __import__("pathlib").Path(os.path.join(tmp, "broken.json"))
        with open(app.CFG_FILE, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        ok &= check("配置坏了也不崩", app.load_config() == {})
    finally:
        app.CFG_FILE = old

    # 4) 找报告：只在真存在时才让按钮可点
    fake = types.SimpleNamespace(last_outdir=tmp)
    ok &= check("没有 html 就返回空", app.App._find_report(fake) == "")
    deep = os.path.join(tmp, "sub")
    os.makedirs(deep)
    html = os.path.join(deep, "report.html")
    open(html, "w", encoding="utf-8").write("<html></html>")
    ok &= check("能找到子目录里的 report.html", app.App._find_report(fake) == html,
                app.App._find_report(fake))

    print()
    print("PASS（图形界面）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
