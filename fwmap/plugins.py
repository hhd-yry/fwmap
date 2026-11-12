"""插件接口：把别人的工具接进来，双方都不用改对方代码。

老师的「融合」要求，落到技术上最难的是**边界**：两套工具各自迭代，
谁也不想为了合体去改自己的工程。所以这里只约定一件事——**一份 JSON 描述**：

```json
{
  "name": "otherscan",
  "desc": "某某做的端点扫描器",
  "cmd": ["python", "C:/tools/otherscan.py", "--target", "{target}"],
  "args": {"target": "解包后的 rootfs 目录"},
  "output": "json",
  "timeout": 600
}
```

框架负责：替换 `{参数}` → 起子进程 → 收输出 → 压成**摘要**塞回工具注册表。
对方的工具仍然是一个普通命令行程序，可以独立运行、独立发版。

三条约束和内置工具保持一致：

1. **只回摘要**：外部工具可能吐几十 MB，不能直接进上下文；
2. **失败结构化**：超时/非零退出/坏 JSON 都变成 `{ok: False, ...}`；
3. **不猜语义**：摘要只写「跑出来了 / 多少条 / 前几项」，不做价值判断。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from . import tools_api as T

MANIFEST_KEYS = ("name", "cmd")


def _summarize(output: str, mode: str, limit: int = 400) -> tuple[str, dict]:
    """把外部输出压成「一句话 + 小数据」。不猜语义，只报事实。"""
    text = (output or "").strip()
    if not text:
        return "没有输出", {}
    if mode == "json":
        try:
            obj = json.loads(text)
        except ValueError:
            return f"输出不是合法 JSON（{len(text)} 字节）", {"raw_head": text[:limit]}
        if isinstance(obj, list):
            head = obj[:3]
            return f"返回 {len(obj)} 条", {"count": len(obj), "head": head}
        if isinstance(obj, dict):
            keys = list(obj)[:6]
            scalars = [(k, v) for k, v in obj.items()
                       if isinstance(v, (int, float, str, bool))][:3]
            detail = "、".join(f"{k}={str(v)[:20]}" for k, v in scalars)
            # head 只带标量，嵌套结构一律不往里塞 —— 否则外部工具吐一个大列表，
            # 摘要就不再是摘要了。
            head = {k: (str(v)[:80] if isinstance(v, str) else v) for k, v in scalars}
            return (f"返回对象{'（' + detail + '）' if detail else ''}",
                    {"keys": keys, "head": head})
        return f"返回 {type(obj).__name__}", {"head": obj}
    first = text.splitlines()[0][:limit]
    n = len(text.splitlines())
    return f"{n} 行输出，首行：{first[:80]}", {"lines": n, "head": text[:limit]}


def load_manifest(path: str) -> dict:
    """读一个 manifest 并校验必填字段。"""
    with open(path, encoding="utf-8-sig") as fh:
        m = json.load(fh)
    if not isinstance(m, dict):
        raise ValueError("manifest 必须是 JSON 对象")
    for k in MANIFEST_KEYS:
        if not m.get(k):
            raise ValueError(f"manifest 缺少必填字段：{k}")
    if not isinstance(m["cmd"], list) or not all(isinstance(x, str) for x in m["cmd"]):
        raise ValueError("cmd 必须是字符串数组（不要用 shell 字符串）")
    m.setdefault("desc", "外部工具")
    m.setdefault("args", {})
    m.setdefault("output", "json")
    m.setdefault("timeout", 600)
    m["_path"] = os.path.abspath(path)
    return _normalize(m)


def _normalize(m: dict) -> dict:
    """补默认值。不管是走 load_manifest 还是直接传 dict 注册，都要先过这一步。"""
    m.setdefault("desc", "外部工具")
    m.setdefault("args", {})
    m.setdefault("output", "json")
    m.setdefault("timeout", 600)
    m.setdefault("cmd", [])
    return m


def register_manifest(m: dict) -> str:
    """把一个 manifest 变成工具注册表里的条目，返回注册名。"""
    m = _normalize(m)
    name = f"plugin.{m['name']}"

    def run(**kwargs) -> dict:
        argv = []
        for part in m["cmd"]:
            try:
                argv.append(part.format(**kwargs))
            except KeyError as e:
                return {"ok": False, "summary": f"参数没提供：{e}"}
        try:
            # 必须显式指定 utf-8：Windows 上 text=True 默认按 GBK 解码，
            # 外部工具一输出中文就 UnicodeDecodeError（还是发生在读取线程里，很难查）。
            p = subprocess.run(argv, capture_output=True, text=True,
                               encoding="utf-8", errors="replace",
                               timeout=float(m["timeout"]),
                               cwd=m.get("cwd") or None)
        except subprocess.TimeoutExpired:
            return {"ok": False, "summary": f"{m['name']} 超时（>{m['timeout']}s）"}
        except FileNotFoundError:
            return {"ok": False, "summary": f"找不到程序：{argv[0]}"}
        except Exception as e:                          # noqa: BLE001
            return {"ok": False, "summary": f"执行失败：{str(e)[:120]}"}
        if p.returncode != 0:
            tail = (p.stderr or p.stdout or "")[-200:].replace("\n", " ")
            return {"ok": False,
                    "summary": f"{m['name']} 退出码 {p.returncode}：{tail}"}
        summary, data = _summarize(p.stdout, m["output"])
        return {"ok": True, "summary": f"[外部] {m['name']}：{summary}",
                "plugin": m["name"], "data": data}

    T.REGISTRY[name] = {"name": name, "desc": m["desc"], "args": m["args"], "run": run}
    return name


def load(paths: list[str], log=print) -> list[str]:
    """加载插件：路径可以是 manifest 文件，也可以是目录（取里面所有 .json）。"""
    loaded = []
    for p in paths:
        files = []
        if os.path.isdir(p):
            files = sorted(os.path.join(p, f) for f in os.listdir(p)
                           if f.lower().endswith(".json"))
        else:
            files = [p]
        for f in files:
            try:
                m = load_manifest(f)
                loaded.append(register_manifest(m))
                log(f"[plugin] 已加载 {m['name']}：{m['desc']}")
            except Exception as e:                      # noqa: BLE001
                log(f"[plugin] 跳过 {os.path.basename(f)}：{e}")
    return loaded


def example_manifest() -> dict:
    """给别人的样板：照这个填就能接进来。"""
    return {
        "name": "my_tool",
        "desc": "一句话说明这个工具干什么",
        "cmd": [sys.executable, "C:/path/to/my_tool.py", "--target", "{target}"],
        "args": {"target": "解包后的 rootfs 目录"},
        "output": "json",
        "timeout": 600,
    }
