"""把 httpd 从 VM 拷到宿主机（rootfs 是 root 权限，先 sudo 复制到 /tmp 再取）。"""

import os
import sys

import paramiko

try:
    from vmcfg import HOST, PWD, USER
except ImportError:
    from .vmcfg import HOST, PWD, USER  # type: ignore

import vm

DST = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "tmp-d615-httpd")
src = "/home/ubuntu/lab/d615/root/sbin/httpd"


def main() -> int:
    vm.run(f"cp {src} /tmp/httpd-d615 && chmod 644 /tmp/httpd-d615", timeout=60,
           sudo=True)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PWD, timeout=20)
    s = c.open_sftp()
    s.get("/tmp/httpd-d615", DST)
    s.close()
    c.close()
    print(f"已取回：{DST}  {os.path.getsize(DST)} 字节")
    return 0


if __name__ == "__main__":
    sys.exit(main())
