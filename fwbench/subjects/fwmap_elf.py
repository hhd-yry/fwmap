"""fwmap 适配器：调用生产入口 `fwmap.elf.read_elf`。

字段映射（只在适配器里做，内核不认识 fwmap 的类型）：

| fwmap.ELFInfo | 任务包字段 |
|---|---|
| `bits`        | `bits` |
| `endian`      | `endian` |
| `etype`       | `etype` |
| `machine_id`  | `machine_id` |
| 抛异常        | `error`（类别按异常类型归一） |

**不做推测**：fwmap 没有给出的字段，适配器不补。
"""

from __future__ import annotations

from . import SubjectBase


class FwmapELF(SubjectBase):
    subject_id = "fwmap"
    capability = "elf-meta"
    requires = "fwmap（本仓库）"

    @classmethod
    def available(cls) -> tuple[bool, str]:
        try:
            import fwmap.elf  # noqa: F401
            return True, ""
        except Exception as exc:                             # noqa: BLE001
            return False, f"导入 fwmap 失败：{type(exc).__name__}"

    @property
    def version(self) -> str:                                # type: ignore[override]
        try:
            from fwmap import __version__ as v
            return str(v)
        except Exception:                                    # noqa: BLE001
            return "unknown"

    def inspect_elf(self, data: bytes) -> dict:
        from fwmap import elf as felf

        from .stdlib_elf import ETYPES, MACHINES
        try:
            info = felf.read_elf(data)
        except Exception as exc:                             # noqa: BLE001
            return {"ok": False, "error": _classify(exc), "fields": {}}
        etype = getattr(info, "etype", None)
        machine = getattr(info, "machine_id", None)
        endian = getattr(info, "endian", None)
        # 任务包统一用 big/little；fwmap 内部用 >/<，归一在适配器里做
        endian = {">": "big", "<": "little"}.get(str(endian), endian)
        return {"ok": True, "error": None,
                "fields": {
                    "bits": getattr(info, "bits", None),
                    "endian": endian,
                    # 任务包用字符串；整型到名字的归一**在适配器里做**
                    "etype": ETYPES.get(etype, str(etype)),
                    "machine_id": MACHINES.get(machine, str(machine))}}


def _classify(exc: Exception) -> str:
    """把异常归一成任务包认识的类别，不把异常文案当结论。"""
    text = f"{type(exc).__name__}: {exc}".lower()
    if "truncat" in text or "short" in text or "out of range" in text:
        return "truncated"
    if "magic" in text or "not an elf" in text or "not elf" in text:
        return "not_elf"
    return "parse_error"
