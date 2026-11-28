"""把当前仓库打包同步到实验虚拟机（会**清空**目标目录后重铺）。

连接参数见 `vmcfg.py`。目标目录来自 `FWMAP_LAB_ROOT`。

安全约束（2026-11-28 加）：这条命令会 `sudo rm -rf` 目标目录，
所以只允许删 `/home/<user>/` 下面的路径；路径不合规直接拒绝，
避免改错一个环境变量就把别的东西清掉了。

    py -3 lab/vm_sync.py            # 同步到 FWMAP_LAB_ROOT（默认 /home/ubuntu/fwmap-run）
    py -3 lab/vm_sync.py --dry-run  # 只打包，不动远端
"""
import os
import re
import sys
import tarfile

import paramiko

try:
    from vmcfg import HOST, PWD, USER, require, VM_ROOT
except ImportError:
    from .vmcfg import HOST, PWD, USER, require, VM_ROOT  # type: ignore

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TGZ = os.environ.get("FWMAP_LAB_TGZ", "/tmp/fwmap-sync.tgz")
SKIP = {".git", "__pycache__", "ghidra-temp", "out", ".pytest_cache",
        "node_modules", "data", "experiments"}


def _safe_target(path: str) -> str:
    """只允许清空 /home/<user>/ 下面的目录。"""
    p = (path or "").rstrip("/")
    if not re.fullmatch(r"/home/[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+", p):
        raise SystemExit(f"拒绝同步：目标目录 {path!r} 不在 /home/<user>/ 下")
    if ".." in p:
        raise SystemExit(f"拒绝同步：目标目录含 .. —— {path!r}")
    return p


def pack() -> int:
    n = 0
    with tarfile.open(TGZ, "w:gz") as tf:
        for root, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in SKIP]
            for f in files:
                p = os.path.join(root, f)
                if f.endswith((".pyc", ".log")):
                    continue
                tf.add(p, arcname=os.path.relpath(p, ROOT))
                n += 1
    return n


def main() -> int:
    dry = "--dry-run" in sys.argv
    dest = _safe_target(VM_ROOT)
    n = pack()
    print(f"打包 {n} 个文件，{os.path.getsize(TGZ) / 1024:.0f} KB → {dest}")
    if dry:
        print("（--dry-run：不动远端）")
        return 0

    require()

    c = paramiko.SSHClient()
    require()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PWD, timeout=20)
    s = c.open_sftp()
    s.put(TGZ, "/tmp/fwmap-sync.tgz")
    s.close()
    # 上一轮是用 sudo 跑的，目录里全是 root 的文件，先 sudo 清干净再铺
    cmd = (f"echo {PWD} | sudo -S rm -rf {dest} && mkdir -p {dest} && "
           f"tar xzf /tmp/fwmap-sync.tgz -C {dest} && "
           f"ls {dest} | head -5 && du -sh {dest}")
    _i, out, err = c.exec_command(cmd, timeout=600)
    print(out.read().decode("utf-8", "replace"))
    e = err.read().decode("utf-8", "replace")
    if e.strip():
        print("stderr:", e[:400])
    c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())