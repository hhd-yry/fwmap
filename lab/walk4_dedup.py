"""阶段 5/6：跨版本 rootfs 是否在、离线 NVD 查重怎么跑。"""

import sys

import vm

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CMD = r"""
echo "=== 可用的 DIR-615 rootfs ==="
for d in /home/ubuntu/lab/d615/root /home/ubuntu/fw/reve/root; do
  if [ -d "$d" ]; then
    printf "%-34s httpd=%s 字节\n" "$d" "$(stat -c%s $d/sbin/httpd 2>/dev/null || echo '?')"
  else
    printf "%-34s 不存在\n" "$d"
  fi
done
echo
echo "=== 离线 NVD 库状态 ==="
cd /home/ubuntu/fwmap-run
python3 -m fwmap nvd status 2>&1 | head -6
echo
echo "=== 查重：DIR-615 ==="
python3 -m fwmap nvd search "DIR-615" 2>&1 | head -12
echo
echo "=== 查重：DIR-615 + login.cgi ==="
python3 -m fwmap nvd search "DIR-615 login.cgi" 2>&1 | head -8
"""

_rc, out, err = vm.run(CMD, timeout=300)
sys.stdout.write(out)
if err.strip():
    print("stderr:", err[-300:])
