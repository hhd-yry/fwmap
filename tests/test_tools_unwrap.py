"""decrypt/unwrap 类工具的测试：壳去掉之后必须"看得见东西"。

这批工具比解包更容易自欺 —— 一个解密脚本「跑完了」但输出是垃圾，
不比「跑失败」好多少。所以这里全部围绕一个判据：

    去掉壳之后，里面必须能看到文件系统魔数（hsqs/sqsh/CRAM/...）。

看不到就是没成。没有"大概解开了"。
"""

import bz2
import gzip
import lzma
import os
import struct
import sys
import tempfile
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import toolbus as TB  # noqa: E402
from fwmap import tools_unwrap as TU  # noqa: E402


def check(name, cond, detail=""):
    cond = bool(cond)
    print(("ok   " if cond else "FAIL ") + name + (("  " + str(detail)) if not cond else ""))
    return cond


def main() -> int:
    ok = True
    tmp = tempfile.mkdtemp(prefix="fwmap-unwrap-")
    TU.register_all()

    squash = b"hsqs" + b"\x00" * 4000

    # 1) 魔数判定：这就是验收标准本身
    p1 = os.path.join(tmp, "a.bin")
    open(p1, "wb").write(b"\x00" * 100 + squash)
    okk, why = TU.has_magic(p1)
    ok &= check("能认出藏在中间的 squashfs", okk and "squashfs" in why, why)
    p2 = os.path.join(tmp, "b.bin")
    open(p2, "wb").write(b"garbage" * 200)
    ok &= check("垃圾不算", TU.has_magic(p2)[0] is False)

    # 2) uImage 去头
    ui = os.path.join(tmp, "fw.img")
    open(ui, "wb").write(b"\x27\x05\x19\x56" + b"\x00" * 60 + squash)
    r = TB.run("uimage", ui, os.path.join(tmp, "o-ui"))
    ok &= check("uImage 去头后验收通过", r["ok"] is True, r.get("detail"))
    ok &= check("记了 provenance", r["provenance"].get("cmd"), r["provenance"])

    # 3) 不是 uImage 要老实报错
    r2 = TB.run("uimage", p2, os.path.join(tmp, "o-ui2"))
    ok &= check("不是 uImage 就失败", r2["ok"] is False and "uImage" in str(r2.get("error")), r2)

    # 4) TRX 去头
    trx = os.path.join(tmp, "fw.trx")
    open(trx, "wb").write(b"HDR0" + struct.pack(">I", 28) + b"\x00" * 20 + squash)
    ok &= check("TRX 去头成功", TB.run("trx", trx, os.path.join(tmp, "o-trx"))["ok"] is True)

    # 5) 压缩流
    gz = os.path.join(tmp, "fw.gz")
    open(gz, "wb").write(gzip.compress(squash))
    ok &= check("gzip 解开并由魔数验收",
                TB.run("gzip-stream", gz, os.path.join(tmp, "o-gz"))["ok"] is True)

    xzp = os.path.join(tmp, "fw.xz")
    open(xzp, "wb").write(lzma.compress(squash, format=lzma.FORMAT_XZ))
    ok &= check("xz 解开", TB.run("xz-stream", xzp, os.path.join(tmp, "o-xz"))["ok"] is True)

    bzp = os.path.join(tmp, "fw.bz2")
    open(bzp, "wb").write(bz2.compress(squash))
    ok &= check("bzip2 解开", TB.run("bzip2-stream", bzp, os.path.join(tmp, "o-bz"))["ok"] is True)

    zl = os.path.join(tmp, "fw.zlib")
    open(zl, "wb").write(zlib.compress(squash))
    ok &= check("zlib 解开", TB.run("zlib-stream", zl, os.path.join(tmp, "o-zl"))["ok"] is True)

    lz = os.path.join(tmp, "fw.lzma")
    open(lz, "wb").write(lzma.compress(squash, format=lzma.FORMAT_ALONE))
    ok &= check("裸 LZMA 解开", TB.run("lzma-stream", lz, os.path.join(tmp, "o-lz"))["ok"] is True)

    # 6) 解出来但没有魔数 → 验收失败（关键：不许自欺）
    plain = os.path.join(tmp, "plain.gz")
    open(plain, "wb").write(gzip.compress(b"this is not firmware" * 100))
    r3 = TB.run("gzip-stream", plain, os.path.join(tmp, "o-plain"))
    ok &= check("解出垃圾也不算成功", r3["ok"] is False, r3.get("detail"))

    # 7) 外部脚本挂载：合法能进，非法跳过
    spec = [
        {"name": "vendor-dec", "cmd": [sys.executable, "-c",
                                       "import sys,os;os.makedirs(sys.argv[2],exist_ok=True);"
                                       "open(os.path.join(sys.argv[2],'p'),'wb').write(b'hsqs'+b'0'*2000)",
                                       "{src}", "{out}"],
         "capability": "decrypt", "success": "magic", "note": "假的厂商解密"},
        {"name": "bad-no-cmd"},
    ]
    n = TU.load_external(spec)
    ok &= check("外部脚本注册成功 1 个", n == 1, n)
    ok &= check("外部脚本出现在编目里",
                "vendor-dec" in {c["name"] for c in TB.catalog("decrypt")})
    r4 = TB.run("vendor-dec", p2, os.path.join(tmp, "o-ext"))
    ok &= check("外部脚本也要过验收", r4["ok"] is True, r4)
    ok &= check("重复挂载不会重名报错", TU.load_external(spec) == 0)

    # 8) 内部工具不依赖外部程序
    ok &= check("内置工具标成 <python>", TB._REGISTRY["uimage"].path() == "<python>")

    import shutil

    shutil.rmtree(tmp, ignore_errors=True)

    print()
    print("PASS（去壳/解密）" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
