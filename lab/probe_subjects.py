"""开发期小工具：看两个 subject 对三份 ELF 各自读出什么。

    py -3 lab/probe_subjects.py
"""

import sys

ROOT = r"C:\deepseek\fwmap-tool"
sys.path.insert(0, ROOT)

from fwbench.subjects import get  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> int:
    for name in ("stdlib", "fwmap", "elftools"):
        s = get(name)
        ok, why = type(s).available()
        print(f"\n[{name}] available={ok} {why} version={s.version}")
        if not ok:
            continue
        for ref in ("elf-a", "elf-b", "elf-t"):
            path = f"{ROOT}/bench/fixtures/{ref}/input.bin"
            with open(path, "rb") as fh:
                data = fh.read()
            r = s.inspect_elf(data)
            print(f"  {ref:6s} ok={str(r['ok']):5s} err={r['error']} "
                  f"fields={r['fields']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
