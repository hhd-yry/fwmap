"""把本地脚本放到 VM 再跑（绕开 heredoc 和引号问题）。

    py -3 vm_put_run.py <本地文件> [远程命令]

输出会存成 <本地文件>.out（UTF-8），控制台只打尾部几行，避免 GBK 报错。
"""
import os
import sys

import paramiko

HOST, USER, PWD = "192.168.8.137", "ubuntu", "ubuntu"

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def main():
    local = sys.argv[1]
    prefix = " ".join(sys.argv[2:]) or "python3"
    remote = "/tmp/" + os.path.basename(local)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PWD, timeout=15)
    s = c.open_sftp()
    s.put(local, remote)
    s.close()
    _i, out, err = c.exec_command(f"{prefix} {remote}", timeout=3600)
    text = out.read().decode("utf-8", "replace")
    e = err.read().decode("utf-8", "replace")
    rc = out.channel.recv_exit_status()
    c.close()

    dest = local + ".out"
    with open(dest, "w", encoding="utf-8") as fh:
        fh.write(text)
        if e.strip():
            fh.write("\n--- stderr ---\n" + e)
    print(f"[rc={rc}] 输出 {len(text)} 字符 → {dest}")
    print("\n".join(text.splitlines()[-12:]))
    return rc


if __name__ == "__main__":
    sys.exit(main())
