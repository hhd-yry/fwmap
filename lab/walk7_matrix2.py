"""触发条件矩阵（第二轮）：到底是"缺 graph_id"还是"查询串为空"。

第一轮结果推翻了原假设：
  GET  /login.cgi            → 崩
  GET  /login.cgi?graph_id=  → 不崩（空值）
  GET  /login.cgi?graph_id   → 不崩（没有等号）
  GET  /login.cgi?x=1        → 不崩（不相干的参数）
所以不是"缺 graph_id"，而更像"GET 没带查询串"。
这一轮验证：任意查询串都行吗？POST 侧呢？别的 .cgi 会不会也这样？
"""

import sys

import vm

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
  local method="$1" path="$2" body="${3:-}" label="$4"
  pkill -9 -x httpd 2>/dev/null; sleep 0.5
  ( chroot /home/ubuntu/lab/d615/root /sbin/httpd -h /www -p 80 >/tmp/m2.log 2>&1 & )
  for i in $(seq 1 20); do
    (echo > /dev/tcp/127.0.0.1/80) >/dev/null 2>&1 && break
    sleep 0.2
  done
  echo "== $label =="
  python3 /tmp/mx.py "$method" "$path" "$body"
  sleep 1.2
  echo "      进程=$(pgrep -x httpd >/dev/null && echo up || echo down)  SIGSEGV=$(grep -c SIGSEGV /tmp/m2.log 2>/dev/null)"
}

probe GET "/login.cgi?" "" "A. 光一个问号"
probe GET "/login.cgi?&" "" "B. 问号加与号"
probe GET "/login.cgi?x" "" "C. 只有名字"
probe POST "/login.cgi" "x=1" "D. POST 不相干参数"
probe POST "/login.cgi" "graph_id=1" "E. POST 正常值"
probe GET "/apply.cgi" "" "F. 别的 .cgi 空查询（对照）"
probe GET "/ping_response.cgi" "" "G. 另一个 .cgi 空查询（对照）"
pkill -9 -x httpd 2>/dev/null
exit 0
"""

_rc, out, err = vm.run(SCRIPT, timeout=900, sudo=True)
sys.stdout.write(out)
if err.strip():
    sys.stderr.write("\n--- stderr ---\n" + err[-300:])
