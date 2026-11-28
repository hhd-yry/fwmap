"""第三阶段：找到调 vsscanf 的那个函数（就在 httpd 里）。

已知：崩在 libc 的 strlen，调用者是 libc 的 vsscanf，且 vsscanf 的字符串参数是 NULL。
也就是说某处写了 `sscanf(NULL, ...)`。现在在 vsscanf 入口下条件断点，
只看"从 httpd（0x004xxxxx）返回"的那次调用，打印返回地址并解析函数名。

    py -3 lab/crash_gdb3.py
"""

import sys

import vm

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
rm -f /tmp/gdb3.out /tmp/g3.log

( chroot $R /usr/bin/qemu-mips-static -g 1234 /sbin/httpd -h /www -p 80 >/tmp/g3.log 2>&1 & )
sleep 2

cat > /tmp/gdb3.cmd <<'EOF'
set confirm off
set pagination off
set width 0
set sysroot /home/ubuntu/lab/d615/root
set solib-search-path /home/ubuntu/lab/d615/root/lib:/home/ubuntu/lab/d615/root/usr/lib
file /home/ubuntu/lab/d615/root/sbin/httpd
set architecture mips
target remote 127.0.0.1:1234
set breakpoint pending on
sharedlibrary
break sscanf if $a0 == 0
continue
echo \n===== 命中：httpd 里调 sscanf 的地方 =====\n
info registers ra a0 a1 sp
echo \n===== 返回地址属于 =====\n
info symbol $ra
echo \n===== 调用点附近 =====\n
x/10i $ra-28
echo \n===== a0（被当格式串/输入串的那个指针）=====\n
print/x $a0
echo \n===== a1（格式串）=====\n
x/s $a1
kill
quit
EOF

( gdb-multiarch -q -batch -x /tmp/gdb3.cmd >/tmp/gdb3.out 2>&1 & )
sleep 4

python3 - <<'PY'
import socket, time
for i in range(6):
    try:
        s = socket.create_connection(("127.0.0.1", 80), 5)
        s.sendall(b"GET /login.cgi HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        print("  发送成功，收到", len(s.recv(4096)), "字节")
        break
    except Exception:
        time.sleep(1)
PY

sleep 6
echo
echo "################ gdb 输出 ################"
cat /tmp/gdb3.out
echo "#########################################"
pkill -9 -x httpd 2>/dev/null; pkill -9 -x qemu-mips-static 2>/dev/null
exit 0
"""

_rc, out, err = vm.run(SCRIPT, timeout=600, sudo=True)
sys.stdout.write(out)
if err.strip():
    sys.stderr.write("\n--- stderr ---\n" + err[-300:])
