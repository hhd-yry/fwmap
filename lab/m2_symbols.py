"""定位 /login.cgi 的 handler：先看符号表里有没有 `login`，再决定用哪个反汇编器。"""

import sys

import vm

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CMD = r"""
B=/home/ubuntu/lab/d615/root/sbin/httpd
echo "== 可用工具 =="
for t in rizin rabin2 objdump readelf nm ghidraRun; do
  printf "%-10s %s\n" "$t" "$(command -v $t || echo '(没有)')"
done
echo
echo "== 符号表里带 login 的 =="
readelf -sW $B 2>/dev/null | grep -i login | head -10
echo
echo "== 带 graph 的字符串 =="
strings -a $B | grep -i "^graph" | head -10
echo
echo "== 带 QUERY / websGetVar 的字符串 =="
strings -a $B | grep -E "QUERY_STRING|websGetVar|HTTP_" | head -10
"""

_rc, out, err = vm.run(CMD, timeout=180, sudo=True)
sys.stdout.write(out)
