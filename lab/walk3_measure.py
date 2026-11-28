"""重新测一遍标准对照表（一次跑完，数字以这次为准）。

顺序很重要：会让服务退出的那条放最后，中间每打一条都重启服务。
"""

import sys

import vm

ROOT = "/home/ubuntu/lab/d615/root"
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SCRIPT = f"""
set -u
run_one() {{
  pkill -9 -x httpd 2>/dev/null; sleep 0.4
  ( chroot {ROOT} /sbin/httpd -h /www -p 80 >/tmp/h.log 2>&1 & )
  for i in 1 2 3 4 5 6 7 8 9 10; do
    (echo > /dev/tcp/127.0.0.1/80) >/dev/null 2>&1 && break
    sleep 0.3
  done
  python3 - "$1" <<'PY'
import socket, sys
path = sys.argv[1]
s = socket.create_connection(("127.0.0.1", 80), 5)
s.sendall(("GET %s HTTP/1.0\\r\\nHost: 127.0.0.1\\r\\n\\r\\n" % path).encode())
d = b""
try:
    while True:
        c = s.recv(8192)
        if not c: break
        d += c
except OSError: pass
s.close()
head = d.split(b"\\r\\n")[0].decode("latin-1") if d else "(空响应)"
body = d.split(b"\\r\\n\\r\\n", 1)[-1] if b"\\r\\n\\r\\n" in d else b""
print(f"{{path:34s}} {{len(d):6d}} 字节   {{head:22s}} 正文 {{len(body)}} 字节  首行={{body.split(chr(10).encode())[0][:40]!r}}")
PY
  sleep 0.6
  echo "      进程=$(pgrep -x httpd >/dev/null && echo up || echo down)"
}}

run_one /index.asp
run_one /apply.cgi
run_one /login.cgi?graph_id=1
run_one /zzqxvbnm1234
run_one /login.cgi
echo
echo "服务端最后一行："
tail -1 /tmp/h.log 2>/dev/null
pkill -9 -x httpd 2>/dev/null
exit 0
"""


def main() -> int:
    _rc, out, err = vm.run(SCRIPT, timeout=600, sudo=True)
    sys.stdout.write(out)
    if err.strip():
        sys.stderr.write("\n--- stderr ---\n" + err[-300:])
    return 0


if __name__ == "__main__":
    sys.exit(main())
