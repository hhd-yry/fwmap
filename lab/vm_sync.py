"""把当前仓库打包同步到 VM 的 /home/ubuntu/fwmap-run（覆盖）。"""
import os
import subprocess
import sys
import tarfile

import paramiko

HOST, USER, PWD = "192.168.8.137", "ubuntu", "ubuntu"
SRC = r"C:\deepseek\fwmap-tool"
DST = "/home/ubuntu/fwmap-run"
TGZ = r"C:\deepseek\tmp\fwmap-sync.tgz"
SKIP = {".git", "__pycache__", "ghidra-temp", "out", ".pytest_cache", "node_modules",
        "data", "experiments"}


def pack():
    n = 0
    with tarfile.open(TGZ, "w:gz") as tf:
        for root, dirs, files in os.walk(SRC):
            dirs[:] = [d for d in dirs if d not in SKIP]
            for f in files:
                p = os.path.join(root, f)
                rel = os.path.relpath(p, SRC)
                if f.endswith((".pyc", ".log")):
                    continue
                tf.add(p, arcname=rel)
                n += 1
    return n


def main():
    n = pack()
    size = os.path.getsize(TGZ) / 1024
    print(f"打包 {n} 个文件，{size:.0f} KB")
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PWD, timeout=15)
    s = c.open_sftp()
    s.put(TGZ, "/tmp/fwmap-sync.tgz")
    s.close()
    # 上一轮是用 sudo 跑的，目录里全是 root 的文件，先 sudo 清干净再铺
    cmd = (f"echo {PWD} | sudo -S rm -rf {DST} && mkdir -p {DST} && "
           f"tar xzf /tmp/fwmap-sync.tgz -C {DST} && "
           f"ls {DST} | head -5 && du -sh {DST}")
    _i, out, err = c.exec_command(cmd, timeout=600)
    print(out.read().decode("utf-8", "replace"))
    e = err.read().decode("utf-8", "replace")
    if e.strip():
        print("stderr:", e[:400])
    c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
