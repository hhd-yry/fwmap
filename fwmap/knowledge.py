"""经验飞轮：让工具用过一次就记住，下次别再从头踩。

为什么不是"训练模型"：我们手上的样本只有个位数固件、几百条链，
既没有 ground truth（哪条链真可利用），也没有规模。**训练在这里只会过拟合。**
真正稀缺的不是模型容量，是**记忆**——今天的四个坑（cr6b 能解、7z 坏链接、
CGI 要 cd 到模板目录、fwupdate 假崩溃）明天还要再踩一遍，因为工具跑完就忘了。

所以这里只做三件事：

    vendors.json   厂商画像：用哪种机制找路由、Web 是什么架构、解包配方
    lessons.json   经验卡：被证伪的判断（"无条件崩 = 环境假象，别报"）
    stats.json     机制 × 厂商 的成功/失败计数

全部是明文 JSON、可人工编辑、可删。**没有模型，没有训练，只有记性。**
"""

from __future__ import annotations

import json
import os
import re
import time

__all__ = ["dir_path", "vendor_key", "vendor_profile", "remember_vendor",
           "add_lesson", "lessons_for", "bump", "summary", "reset"]

DEFAULT_DIR = os.path.join(os.path.expanduser("~"), ".fwmap", "knowledge")
_MAX_ITEMS = 500          # 每个库的条数上限，防止无限增长


def dir_path() -> str:
    d = os.environ.get("FWMAP_KNOWLEDGE_DIR") or DEFAULT_DIR
    os.makedirs(d, exist_ok=True)
    return d


def _file(name: str) -> str:
    return os.path.join(dir_path(), f"{name}.json")


def _load(name: str) -> dict:
    """读一个库。文件坏了就当空的 —— 记忆坏了不能让分析跑不动。"""
    try:
        with open(_file(name), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(name: str, data: dict) -> None:
    """原子写：先写临时文件再改名，避免半截 JSON。"""
    path = _file(name)
    if len(data) > _MAX_ITEMS:
        # 保留最近更新的那批
        keep = sorted(data.items(), key=lambda kv: str(
            (kv[1] or {}).get("updated_at", "")), reverse=True)[:_MAX_ITEMS]
        data = dict(keep)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M")


# ---------------------------------------------------------------- 厂商画像

_GENERIC_DIRS = {"root", "rootfs", "squashfs-root", "fs", "filesystem",
                 "output", "out", "tmp", "firmware"}
_VERSION_FILES = ("VERSION", "etc/VERSION", "etc/version", "etc/version.txt")
_RE_NAME = re.compile(r"^\s*NAME\s*[:=]\s*(\S+)", re.I | re.M)
_RE_MODEL = re.compile(r"DIR[-_]?(\d{3,4})([A-Z]?)", re.I)


def _read_version(rootfs: str) -> dict:
    for rel in _VERSION_FILES:
        p = os.path.join(rootfs, rel)
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(4000)
        except OSError:
            continue
        info = {}
        m = _RE_NAME.search(text)
        if m:
            info["name"] = m.group(1)
        for key in ("VERSION", "VERSION:", "SYSBUILDTIME"):
            for line in text.splitlines():
                if line.upper().startswith(key.split(":")[0]) and ":" in line:
                    info.setdefault("version", line.split(":", 1)[1].strip())
                    break
        if info:
            info["file"] = rel
            return info
    return {}


def vendor_key(rootfs: str = "", model: str = "") -> str:
    """给一台固件起一个"厂商/型号"的名字。

    优先读固件自带的 VERSION 文件（D-Link 有 `NAME: DIR_816LA1A`），
    读不到就用目录名。这个键以后决定"要不要复用上次的经验"。

    **目录名不能用泛称**：解包出来的目录常叫 `root` / `rootfs` / `squashfs-root`，
    拿它当键会让所有固件撞在一起 —— 那样"经验"就变成了互相污染。
    遇到泛称就往上找一层（`.../d615/root` → `d615`）。
    """
    if model:
        return model.strip().lower()[:60]
    info = _read_version(rootfs) if rootfs else {}
    name = (info.get("name") or "").strip()
    if name:
        m = _RE_MODEL.search(name)
        if m:
            return f"dir-{m.group(1).lower()}{m.group(2).lower()}"[:60]
        return name.lower()[:60]
    path = os.path.abspath(rootfs or "")
    base = os.path.basename(path) or "unknown"
    if base.lower() in _GENERIC_DIRS:
        parent = os.path.basename(os.path.dirname(path))
        if parent:
            base = parent
    return base.lower()[:60]


def vendor_profile(key: str) -> dict:
    return _load("vendors").get(key or "", {}) or {}


def remember_vendor(key: str, **fields) -> dict:
    """记一条厂商画像（合并式写入：不覆盖已有字段，除非显式传）。"""
    if not key:
        return {}
    data = _load("vendors")
    cur = data.get(key) or {}
    cur.update({k: v for k, v in fields.items() if v is not None})
    cur["runs"] = int(cur.get("runs") or 0) + 1
    cur["updated_at"] = _now()
    data[key] = cur
    _save("vendors", data)
    return cur


# ---------------------------------------------------------------- 经验卡

def _norm(text: str) -> str:
    return re.sub(r"\s+", "", (text or "")).lower()[:80]


def add_lesson(text: str, *, scope: str = "", evidence: str = "") -> bool:
    """记一条经验。同一句话（归一化后）只留一条，返回是否新增。"""
    text = (text or "").strip()
    if not text:
        return False
    data = _load("lessons")
    key = _norm(text)
    if key in data:
        item = data[key]
        item["hits"] = int(item.get("hits") or 1) + 1
        item["updated_at"] = _now()
        _save("lessons", data)
        return False
    data[key] = {"text": text[:200], "scope": scope[:60], "evidence": evidence[:200],
                 "hits": 1, "created_at": _now(), "updated_at": _now()}
    _save("lessons", data)
    return True


def lessons_for(scope: str = "") -> list[dict]:
    """取经验卡；给 scope 时只返回相关的那批（scope 为空 = 全部）。"""
    items = list(_load("lessons").values())
    if scope:
        s = scope.lower()
        items = [x for x in items if s in (x.get("scope") or "").lower()
                 or s in (x.get("text") or "").lower()]
    return sorted(items, key=lambda x: int(x.get("hits") or 0), reverse=True)


# ---------------------------------------------------------------- 策略成功率

def bump(mechanism: str, vendor: str, ok: bool) -> dict:
    """记一次「用某机制在某厂商上」的结果。多臂老虎机式的先验就是从这里来的。

    除了成功/失败计数，还维护两个决策要用的字段：
    `streak_fail`（连续失败次数，成功即清零）和 `last_ok/last_fail`（时间戳）。
    没有它们，排序只能看总成功率，分不清"偶尔失败"和"一直失败"。
    """
    data = _load("stats")
    key = f"{mechanism}@{vendor}"
    cur = data.get(key) or {"mechanism": mechanism, "vendor": vendor,
                            "ok": 0, "fail": 0, "streak_fail": 0}
    if ok:
        cur["ok"] = int(cur.get("ok") or 0) + 1
        cur["streak_fail"] = 0
        cur["last_ok"] = _now()
    else:
        cur["fail"] = int(cur.get("fail") or 0) + 1
        cur["streak_fail"] = int(cur.get("streak_fail") or 0) + 1
        cur["last_fail"] = _now()
    cur["updated_at"] = _now()
    data[key] = cur
    _save("stats", data)
    return cur


def summary() -> dict:
    v, l, s = _load("vendors"), _load("lessons"), _load("stats")
    return {"vendors": len(v), "lessons": len(l), "stats": len(s),
            "dir": dir_path()}


def reset(what: str = "all") -> None:
    """清空记忆（调试/测试用）。"""
    for name in (("vendors", "lessons", "stats") if what == "all" else (what,)):
        try:
            os.remove(_file(name))
        except OSError:
            pass
