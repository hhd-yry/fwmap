"""确认这份 rootfs 到底是哪个版本、www 里有什么。"""

import sys

import vm

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CMD = r"""
R=/home/ubuntu/lab/d615/root
ls -l $R/sbin/httpd
echo "--- 版本文件 ---"
cat $R/etc/version 2>/dev/null | head -3
cat $R/etc/versions 2>/dev/null | head -5
echo "--- www ---"
ls $R/www | head -12
echo "…共 $(ls $R/www 2>/dev/null | wc -l) 个文件"
ls -l $R/www/index.asp 2>/dev/null
ls -l $R/www/login.asp 2>/dev/null
echo "--- 首页里有没有版本字样 ---"
grep -o 'DIR-615[^<]*' $R/www/index.asp 2>/dev/null | head -3
grep -o 'V[0-9]\+\.[0-9]\+\.[0-9]\+' $R/www/index.asp 2>/dev/null | head -3
"""

_rc, out, err = vm.run(CMD, timeout=180, sudo=True)
sys.stdout.write(out)
if err.strip():
    print("stderr:", err[-300:])
