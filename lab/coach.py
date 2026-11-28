"""教练脚本：start / req / status / stop，用于手敲复现。

    py -3 lab/coach.py start
    py -3 lab/coach.py req /index.asp
    py -3 lab/coach.py status
    py -3 lab/coach.py stop

设计上的两个约束（都是踩过坑换来的）：
  * 清理进程只用 `pkill -x httpd`：`-f 'sbin/httpd'` 会匹配到自己这层 shell；
  * 请求客户端写成远端文件再执行，不把 heredoc 塞进 sudo 管道（密码会被吃掉）。
"""

import os
import sys

import paramiko

try:
    from vmcfg import HOST, PWD, USER, require
except ImportError:
    from .vmcfg import HOST, PWD, USER, require  # type: ignore

import vm

ROOT = "/home/ubuntu/lab/d615/root"
CLIENT_PATH = "/tmp/coach_req.py"

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CLIENT = '''import socket, sys
path = sys.argv[1] if len(sys.argv) > 1 else "/"
s = socket.create_connection(("127.0.0.1", 80), 5)
s.sendall(("GET %s HTTP/1.0\\r\\nHost: 127.0.0.1\\r\\n\\r\\n" % path).encode())
d = b""
try:
    while True:
        c = s.recv(8192)
        if not c:
            break
        d += c
except OSError:
    pass
s.close()
first = d.split(b"\\r\\n")[0].decode("latin-1") if d else "(空响应，连接被关闭)"
print(f"  请求 {path}")
print(f"  收到 {len(d)} 字节   首行: {first}")
'''


def _upload_client() -> None:
    require()
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PWD, timeout=20)
    s = c.open_sftp()
    with s.open(CLIENT_PATH, "w") as fh:
        fh.write(CLIENT)
    s.close()
    c.close()


def cmd_start() -> None:
    script = (
        f"pkill -9 -x httpd 2>/dev/null; sleep 0.6; "
        f"( chroot {ROOT} /sbin/httpd -h /www -p 80 >/tmp/coach.log 2>&1 & ); "
        f"for i in $(seq 1 25); do "
        f"(echo > /dev/tcp/127.0.0.1/80) >/dev/null 2>&1 && break; sleep 0.2; done; "
        f"echo \"  服务已启动：$(pgrep -x httpd | head -1)  "
        f"端口: $( (echo > /dev/tcp/127.0.0.1/80) >/dev/null 2>&1 && echo 通 || echo 不通)\""
    )
    _rc, out, _err = vm.run(script, timeout=120, sudo=True)
    sys.stdout.write(out)


def cmd_req(path: str) -> None:
    _upload_client()
    _rc, out, _err = vm.run(f"python3 {CLIENT_PATH} {path}", timeout=60)
    sys.stdout.write(out)


def cmd_status() -> None:
    script = ("echo \"  进程: $(pgrep -x httpd >/dev/null && echo up || echo down)\"; "
              "echo \"  日志末行: $(tail -1 /tmp/coach.log 2>/dev/null)\"")
    _rc, out, _err = vm.run(script, timeout=60, sudo=True)
    sys.stdout.write(out)


def cmd_stop() -> None:
    _rc, out, _err = vm.run("pkill -9 -x httpd 2>/dev/null; sleep 0.3; "
                            "echo '  已清理'", timeout=60, sudo=True)
    sys.stdout.write(out)


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 2
    cmd, rest = args[0], args[1:]
    if cmd == "start":
        cmd_start()
    elif cmd == "req":
        if not rest:
            print("用法：py -3 lab/coach.py req <路径>")
            return 2
        cmd_req(rest[0])
    elif cmd == "status":
        cmd_status()
    elif cmd == "stop":
        cmd_stop()
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
