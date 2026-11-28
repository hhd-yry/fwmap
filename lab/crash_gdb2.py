"""第二阶段：追调用者 —— 崩溃的 strlen 是谁调的。

第一阶段拿到了 pc=0x3fd407d0 / a0=0 / ra=0x3fd39070。
这一轮让 gdb 认识 rootfs 里的共享库（set sysroot + solib-search-path），
再看 ra 属于哪个库、调用点附近是什么、a1 指向什么字符串。

    py -3 lab/crash_gdb2.py
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
rm -f /tmp/gdb2.out /tmp/g2.log

( chroot $R /usr/bin/qemu-mips-static -g 1234 /sbin/httpd -h /www -p 80 >/tmp/g2.log 2>&1 & )
sleep 2

cat > /tmp/gdb2.cmd <<'EOF'
set confirm off
set pagination off
set width 0
set sysroot /home/ubuntu/lab/d615/root
set solib-search-path /home/ubuntu/lab/d615/root/lib:/home/ubuntu/lab/d615/root/usr/lib
file /home/ubuntu/lab/d615/root/sbin/httpd
set architecture mips
target remote 127.0.0.1:1234
continue
echo \n===== 信号 =====\n
info registers pc ra sp a0 a1 a2 a3
echo \n===== 已加载的共享库 =====\n
info sharedlibrary
echo \n===== pc 属于 =====\n
info symbol $pc
echo \n===== ra 属于 =====\n
info symbol $ra
echo \n===== ra 附近 =====\n
x/8i $ra-20
echo \n===== a1 指向 =====\n
x/s $a1
echo \n===== 栈顶 32 个字（找返回地址）=====\n
x/32wx $sp
echo \n===== 回溯 =====\n
set heuristic-fence-post 400
bt
kill
quit
EOF

( gdb-multiarch -q -batch -x /tmp/gdb2.cmd >/tmp/gdb2.out 2>&1 & )
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
cat /tmp/gdb2.out
echo "#########################################"
pkill -9 -x httpd 2>/dev/null; pkill -9 -x qemu-mips-static 2>/dev/null
exit 0
"""

_rc, out, err = vm.run(SCRIPT, timeout=600, sudo=True)
sys.stdout.write(out)
if err.strip():
    sys.stderr.write("\n--- stderr ---\n" + err[-300:])
