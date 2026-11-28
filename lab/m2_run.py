"""跑 m2（Ghidra headless）：端点 → handler 函数映射。"""

import sys

import vm

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

JAVA = "/home/ubuntu/fwmap-run/tools/jdk-25.0.5+8"

CMD = f"""
cd /home/ubuntu/fwmap-run
export JAVA_HOME={JAVA}
export PATH=$JAVA_HOME/bin:$PATH
export LANG=C.UTF-8 PYTHONIOENCODING=utf-8
python3 --version
JAVA_HOME={JAVA} python3 -m fwmap m2 \
    /home/ubuntu/lab/d615/root/sbin/httpd -o /tmp/d615-m2.json 2>&1 | tail -25
echo "=== 产物 ==="
ls -l /tmp/d615-m2.json 2>/dev/null
"""

_rc, out, err = vm.run(CMD, timeout=1800, sudo=True)
sys.stdout.write(out)
if err.strip():
    sys.stderr.write("\n--- stderr ---\n" + err[-600:])
