"""反汇编前的现场检查：Ghidra / JDK / 旧的 m2 产物还在不在。"""

import sys

import vm

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CMD = r"""
echo "== JDK =="
ls -d /home/ubuntu/fwmap-run/tools/jdk* 2>/dev/null | head -3
java -version 2>&1 | head -2
echo
echo "== Ghidra =="
ls -d /home/ubuntu/fwmap-run/tools/ghidra* 2>/dev/null | head -3
echo
echo "== 旧产物 =="
ls -d /home/ubuntu/fwmap-m2 /home/ubuntu/fwmap-run/fwmap-m2 /tmp/d615* 2>/dev/null | head -5
ls -l /home/ubuntu/*.json 2>/dev/null | head -5
echo
echo "== 目标二进制 =="
ls -l /home/ubuntu/lab/d615/root/sbin/httpd
file /home/ubuntu/lab/d615/root/sbin/httpd 2>/dev/null | cut -c1-120
"""

_rc, out, err = vm.run(CMD, timeout=120)
sys.stdout.write(out)
if err.strip():
    print("stderr:", err[-200:])
