"""抓崩溃现场：qemu 带 gdbstub 起 httpd，gdb 断在 SIGSEGV，打印 PC/调用栈/出错指令。

静态那边（Ghidra FindStringRef）只找到字符串、没有函数引用它，MIPS 的 $gp 相对寻址
没被解析出来。所以改走动态：崩溃现场是事实，不需要猜。

注意：gdb-multiarch 连 qemu-mips 的 stub 时**必须**先 file + set architecture mips，
否则报 "Truncated register 39 in remote 'g' packet"。

    py -3 lab/crash_gdb.py
"""

import sys

import vm

ROOT = "/home/ubuntu/lab/d615/root"
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SCRIPT = r"""
set -u
R=/home/ubuntu/lab/d615/root

if [ ! -x $R/usr/bin/qemu-mips-static ]; then
  mkdir -p $R/usr/bin
  cp /usr/bin/qemu-mips-static $R/usr/bin/qemu-mips-static
  chmod +x $R/usr/bin/qemu-mips-static
fi

pkill -9 -x httpd 2>/dev/null; pkill -9 -x qemu-mips-static 2>/dev/null; sleep 0.6
rm -f /tmp/gdb.out /tmp/g.log

( chroot $R /usr/bin/qemu-mips-static -g 1234 /sbin/httpd -h /www -p 80 >/tmp/g.log 2>&1 & )
sleep 2

cat > /tmp/gdb.cmd <<'EOF'
set confirm off
set pagination off
set width 0
file /home/ubuntu/lab/d615/root/sbin/httpd
set architecture mips
target remote 127.0.0.1:1234
continue
echo \n===== 命中信号 =====\n
info registers pc ra sp a0 a1
echo \n===== 调用栈 =====\n
bt
echo \n===== PC 附近的指令 =====\n
x/10i $pc-16
echo \n===== PC 属于哪个符号 =====\n
info symbol $pc
kill
quit
EOF

( gdb-multiarch -q -batch -x /tmp/gdb.cmd >/tmp/gdb.out 2>&1 & )
sleep 4

python3 - <<'PY'
import socket, time
for attempt in range(6):
    try:
        s = socket.create_connection(("127.0.0.1", 80), 5)
        s.sendall(b"GET /login.cgi HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        d = s.recv(4096)
        print(f"  第 {attempt+1} 次发送成功，收到 {len(d)} 字节")
        break
    except Exception as e:
        print(f"  第 {attempt+1} 次连不上（{type(e).__name__}），1 秒后重试")
        time.sleep(1)
PY

sleep 6
echo
echo "################ gdb 输出 ################"
cat /tmp/gdb.out
echo "#########################################"
pkill -9 -x httpd 2>/dev/null; pkill -9 -x qemu-mips-static 2>/dev/null
exit 0
"""

_rc, out, err = vm.run(SCRIPT, timeout=600, sudo=True)
sys.stdout.write(out)
if err.strip():
    sys.stderr.write("\n--- stderr ---\n" + err[-400:])
