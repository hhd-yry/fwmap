"""教练用：开课前把现场收拾干净（VM 活着、没有残留 httpd、仓库是新的）。"""

import sys

import vm

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CMD = r"""
echo "1) 机器：$(uptime | sed 's/.*up/up/')"
echo "2) 仓库：$(cd /home/ubuntu/fwmap-run && grep -c want_probe fwmap/agent/loop.py) 处新代码标记"
echo "3) 残留 httpd：$(pgrep -x httpd | wc -l) 个"
echo "4) 端口 80：$( (echo > /dev/tcp/127.0.0.1/80) >/dev/null 2>&1 && echo 占用 || echo 空闲)"
echo "5) rootfs：$(ls -d /home/ubuntu/lab/d615/root 2>/dev/null || echo 缺失)"
"""

_rc, out, err = vm.run(CMD, timeout=60)
sys.stdout.write(out)

print("\n清理残留 httpd ...")
_rc, out, err = vm.run("pkill -9 -x httpd 2>/dev/null; sleep 1; echo 剩余=$(pgrep -x httpd | wc -l)",
                       timeout=60, sudo=True)
sys.stdout.write(out)
