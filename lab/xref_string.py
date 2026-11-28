"""用 m2 自己的 Ghidra 调用方式跑 FindStringRef —— 复用它能成功的那套环境。

为什么不再手工拼 analyzeHeadless：手拼三次分别死在 JDK 路径、缓存目录权限、
import 拒绝访问；而 `fwmap m2` 对同一个文件是**能跑通**的，差别就在
`m2.run_ghidra()` 里设的 TEMP/APPDATA 和 ghidra-temp 目录布局。
所以这里直接 import 它，只换 postScript。

    py -3 lab/xref_string.py "graph_id"
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from fwmap import m2  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> int:
    needle = sys.argv[1] if len(sys.argv) > 1 else "graph_id"
    binary = os.path.join(ROOT, "tmp-d615-httpd")
    if not os.path.exists(binary):
        print("先跑 lab/fetch_binary.py 把 httpd 取回来")
        return 2

    home = m2.find_ghidra()
    if not home:
        print("找不到 Ghidra")
        return 2
    headless = m2.headless_path(home)
    print(f"Ghidra: {headless}")

    base = os.environ.get("FWMAP_M2_DIR") or os.path.join(os.getcwd(), "fwmap-m2")
    os.makedirs(base, exist_ok=True)
    tmpdir = os.path.join(base, f"xref-{os.getpid()}")
    proj = os.path.join(tmpdir, "proj")
    os.makedirs(proj, exist_ok=True)

    cmd = [headless, proj, "xref", "-import", binary, "-overwrite",
           "-scriptPath", m2._script_dir(),
           "-postScript", "FindStringRef.java", needle]
    print("命令:", " ".join(cmd))
    try:
        out = m2.run_ghidra(cmd, 1800, label=f"xref {needle}")
    except RuntimeError as exc:
        print(f"[!] {exc}")
        return 1

    hits = [ln for ln in out.splitlines()
            if needle in ln or "FUNC" in ln or "0x" in ln]
    print(f"\n=== 含 {needle!r} / 地址 / 函数的输出行（{len(hits)} 行）===")
    for ln in hits[:60]:
        print(" ", ln)
    with open(os.path.join(ROOT, "docs", f"xref-{needle}.txt"), "w",
              encoding="utf-8") as fh:
        fh.write(out)
    print(f"\n完整输出已写入 docs/xref-{needle}.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
