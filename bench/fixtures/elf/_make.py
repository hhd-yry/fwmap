"""生成 A 层用的三个 ELF 夹具（正常 / 另一字节序 / 截断）。

都是**构造出来的最小 ELF 头**，不含任何真实固件内容：
  · elf-a   32 位大端，e_type=2(exec)，e_machine=8(mips)
  · elf-b   32 位小端，e_type=3(dyn)， e_machine=40(arm)
  · elf-t   取 elf-a 的前 30 字节（头都读不全）

    py -3 bench/fixtures/elf/_make.py
"""

import os
import struct

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # -> bench/fixtures


def build(bits: int, endian: str, etype: int, machine: int) -> bytes:
    """造一个只有 ELF 头的文件：头的其余部分填 0，长度按 32/64 位补齐。"""
    fmt = "<" if endian == "little" else ">"
    ei_class = 1 if bits == 32 else 2
    ei_data = 1 if endian == "little" else 2
    ident = b"\x7fELF" + bytes([ei_class, ei_data, 1, 0]) + b"\x00" * 8
    body = struct.pack(fmt + "HHIIIIIHHHHHH",
                       etype, machine, 1, 0, 0, 0, 0,
                       52 if bits == 32 else 64, 0, 0, 0, 0, 0)
    total = 52 if bits == 32 else 64
    data = ident + body
    return data + b"\x00" * max(0, total - len(data))


CASES = {
    "elf-a": build(32, "big", 2, 8),
    "elf-b": build(32, "little", 3, 40),
}


def main() -> int:
    for name, data in CASES.items():
        d = os.path.join(HERE, name)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "input.bin"), "wb") as fh:
            fh.write(data)
        print(f"{name}: {len(data)} 字节")
    d = os.path.join(HERE, "elf-t")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "input.bin"), "wb") as fh:
        fh.write(CASES["elf-a"][:30])
    print("elf-t: 30 字节（截断）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
