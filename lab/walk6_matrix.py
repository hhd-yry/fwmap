"""触发条件矩阵：到底什么情况下才崩。

已验：`graph_id=`（空值）不崩 → 服务端区分"参数缺失"和"参数为空串"。
把边界钉死，汇报时"根因"那一问就有实据。
"""

import sys

import vm

ROOT = "/home/ubuntu/lab/d615/root"
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SCRIPT = r"""
set -u

cat > /tmp/mx.py <<'PY'
import socket, sys
method, path = sys.argv[1], sys.argv[2]
body = sys.argv[3] if len(sys.argv) > 3 else ""
s = socket.create_connection(("127.0.0.1", 80), 5)
if method == "GET":
    req = f"GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"
else:
    req = (f"POST {path} HTTP/1.0\r\nHost: 127.0.0.1\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\n\r\n{body}")
s.sendall(req.encode())
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
first = d.split(b"\r\n")[0].decode("latin-1") if d else "(空响应)"
print(f"      {method} {path}  body={body!r}  -> {len(d)} 字节  {first}")
PY

probe() {
  local method="$1" path="$2" body="${3:-}"
  pkill -9 -x httpd 2>/dev/null; sleep 0.5
  ( chroot /home/ubuntu/lab/d615/root /sbin/httpd -h /www -p 80 >/tmp/m.log 2>&1 & )
  for i in $(seq 1 20); do
    (echo > /dev/tcp/127.0.0.1/80) >/dev/null 2>&1 && break
    sleep 0.2
  done
  echo "== $4 =="
  python3 /tmp/mx.py "$method" "$path" "$body"
  sleep 0.8
  echo "      进程=$(pgrep -x httpd >/dev/null && echo up || echo down)   崩溃日志=$(grep -c SIGSEGV /tmp/m.log 2>/dev/null)"
}

probe GET /login.cgi "" "1. GET /login.cgi（已知崩）"
probe GET "/login.cgi?graph_id=1" "" "2. 带值"
probe GET "/login.cgi?graph_id=" "" "3. 空值"
probe GET "/login.cgi?graph_id" "" "4. 只有名字没有等号"
probe GET "/login.cgi?x=1" "" "5. 换个参数名"
probe GET "/login.cgi?graph_code=1" "" "6. 另一个 graph 参数"
probe POST /login.cgi "" "7. POST 空 body"
probe POST /login.cgi "graph_id=" "8. POST 空值"
pkill -9 -x httpd 2>/dev/null
exit 0
"""

_rc, out, err = vm.run(SCRIPT, timeout=900, sudo=True)
sys.stdout.write(out)
if err.strip():
    sys.stderr.write("\n--- stderr ---\n" + err[-400:])
