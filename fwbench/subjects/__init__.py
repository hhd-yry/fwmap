"""被测工具适配器（subject）。

契约（实施计划第 9 节）：
* 每个适配器声明 **工具 ID、版本、支持的任务、所需输入、可观察输出**；
* 适配器只做「入参转换 + 输出映射」，不替被测工具推测它做过什么；
* **通用内核不得 import fwmap** —— 内核只认这里的接口。

目前三个：
  fwmap    生产入口（fwmap.elf.read_elf）
  stdlib   纯标准库参考实现（不需要 fwmap、不需要第三方库，用来证明内核可独立运行）
  elftools 第三方只读库（可选依赖，未安装时标记 not_run）
"""

from __future__ import annotations

__all__ = ["REGISTRY", "get", "available_subjects", "SubjectBase"]


class SubjectBase:
    """适配器基类：只暴露"检查一份字节能得到什么"。"""

    subject_id = "base"
    version = "0"
    capability = "elf-meta"
    requires = ""

    @classmethod
    def available(cls) -> tuple[bool, str]:
        return True, ""

    def inspect_elf(self, data: bytes) -> dict:
        """返回 {ok, fields:{...}, error} —— 字段由任务包约定。"""
        raise NotImplementedError

    def info(self) -> dict:
        ok, why = self.available()
        return {"subject_id": self.subject_id, "version": self.version,
                "capability": self.capability, "available": ok,
                "unavailable_reason": why, "requires": self.requires}


def _load():
    from . import elftools_elf, fwmap_elf, stdlib_elf

    return {c.subject_id: c for c in (fwmap_elf.FwmapELF,
                                      stdlib_elf.StdlibELF,
                                      elftools_elf.ElftoolsELF)}


REGISTRY = _load()


def get(name: str) -> SubjectBase:
    """取一个被测工具实例。

    不可用时**不抛错**：按计划要求，产物标 `not_run`，由评分与报告体现，
    而不是让整批运行失败。
    """
    if name not in REGISTRY:
        raise SystemExit(f"未知被测工具：{name}（可选 {', '.join(REGISTRY)}）")
    cls = REGISTRY[name]
    inst = cls()
    ok, why = cls.available()
    if not ok:
        print(f"[!] 被测工具 {name} 不可用：{why} —— 本批将标为 not_run")
    return inst


def available_subjects() -> list[dict]:
    return [cls().info() for cls in REGISTRY.values()]
