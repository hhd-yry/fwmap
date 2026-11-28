"""看看旧的 m2 产物里有没有现成的 login.cgi → handler 映射。"""

import sys

import vm

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CMD = r"""
for d in /home/ubuntu/fwmap-m2 /home/ubuntu/fwmap-run/fwmap-m2; do
  echo "== $d =="
  ls -la $d 2>/dev/null | head -8
done
echo
echo "== 找含 login 的文件 =="
grep -rl "login.cgi" /home/ubuntu/fwmap-m2 /home/ubuntu/fwmap-run/fwmap-m2 2>/dev/null | head -5
echo
echo "== d615_probe_flow.json 的结构 =="
head -c 600 /home/ubuntu/d615_probe_flow.json 2>/dev/null
echo
"""

_rc, out, err = vm.run(CMD, timeout=120)
sys.stdout.write(out)
