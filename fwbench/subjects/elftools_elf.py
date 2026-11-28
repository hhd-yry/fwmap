"""第三方只读库适配器（可选依赖 pyelftools）。

未安装时 `available()` 返回 False，运行产物标 `not_run`，
**不拿别的实现冒充它**（计划第 9 节：工具没提供的内容记不可观察）。
"""

from __future__ import annotations

from . import SubjectBase


class ElftoolsELF(SubjectBase):
    subject_id = "elftools"
    version = "0"
    capability = "elf-meta"
    requires = "pyelftools"

    @classmethod
    def available(cls) -> tuple[bool, str]:
        try:
            import elftools  # noqa: F401
            return True, ""
        except Exception:                                    # noqa: BLE001
            return False, "未安装 pyelftools"

    @property
    def version(self) -> str:                                # type: ignore[override]
        try:
            import elftools
            return str(getattr(elftools, "__version__", "unknown"))
        except Exception:                                    # noqa: BLE001
            return "0"

    def inspect_elf(self, data: bytes) -> dict:
        if not self.available()[0]:
            return {"ok": False, "error": "not_run", "fields": {}}
        import io

        from elftools.common.exceptions import ELFError
        from elftools.elf.elffile import ELFFile
        try:
            with ELFFile(stream=io.BytesIO(data)) as ef:     # type: ignore[arg-type]
                hdr = ef.header
                return {"ok": True, "error": None,
                        "fields": {
                            "bits": 64 if ef.elfclass == 64 else 32,
                            "endian": "little" if ef.little_endian else "big",
                            "etype": str(hdr["e_type"]).replace("ET_", "").lower(),
                            "machine_id": str(hdr["e_machine"]).replace("EM_", "").lower()}}
        except ELFError as exc:
            text = str(exc).lower()
            kind = "truncated" if ("truncat" in text or "EOF" in str(exc)) else "not_elf"
            return {"ok": False, "error": kind, "fields": {}}
        except Exception:                                    # noqa: BLE001
            return {"ok": False, "error": "parse_error", "fields": {}}
