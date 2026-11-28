"""把 VM 上的 /tmp/p3（agent 端到端跑出来的产物）取回归档。"""

import os
import sys

import paramiko

try:
    from vmcfg import HOST, PWD, USER
except ImportError:
    from .vmcfg import HOST, PWD, USER  # type: ignore

import vm

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEST = os.path.join(ROOT, "docs", "示例-2026-11-28", "端到端-模型跑")

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> int:
    # /tmp/p3 由 root 创建，先放开读权限
    vm.run("chmod -R a+rX /tmp/p3 && ls /tmp/p3", timeout=60, sudo=True)

    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PWD, timeout=20)
    s = c.open_sftp()
    os.makedirs(DEST, exist_ok=True)
    n = 0
    for name in s.listdir("/tmp/p3"):
        remote = f"/tmp/p3/{name}"
        try:
            with s.open(remote) as fh:
                data = fh.read()
        except OSError:
            continue
        with open(os.path.join(DEST, name), "wb") as out:
            out.write(data)
        print(f"  {name}  {len(data)} 字节")
        n += 1
    s.close()
    c.close()
    print(f"\n共 {n} 个文件 → {DEST}")
    return 0 if n else 1


if __name__ == "__main__":
    sys.exit(main())
