#!/bin/bash
# 第 2 步（修正版）：看 /login.cgi 是凭什么被当作候选的
#
# 两个坑：
#   1. `fwmap routes` 默认只打印前 20 条，login 不在其中 —— grep 不到不代表不存在；
#   2. `echo passwd | sudo -S cmd <<'PY'` 里 heredoc 会抢走 sudo 的密码输入，直接失败。
#      所以先把 python 写到 /tmp，再 sudo 执行。
cd "${FWMAP_VM_ROOT:-/home/ubuntu/fwmap-run}" || exit 1
ROOT=/home/ubuntu/lab/d615/root
export LANG=C.UTF-8 PYTHONIOENCODING=utf-8

cat > /tmp/inspect_routes.py <<'PY'
import sys
sys.path.insert(0, "/home/ubuntu/fwmap-run")
from fwmap import pages

root = sys.argv[1]
forms = pages.scan(root)
uris = sorted({f["uri"] for f in forms})
print(f"表单 {len(forms)} 个 → 去重后 {len(uris)} 条 URI")
print()
print("含 login 的端点：")
for f in forms:
    if "login" in f["uri"]:
        print(f"  {f['uri']}")
        print(f"     参数: {', '.join(f.get('params') or [])}")
print()
seen = sorted({p for f in forms for p in (f.get("params") or []) if "graph" in p})
print("全固件里带 graph 字样的参数：")
print("  " + (", ".join(seen) if seen else "（没有）"))
PY

echo ubuntu | sudo -S env LANG=C.UTF-8 PYTHONIOENCODING=utf-8 \
    python3 /tmp/inspect_routes.py "$ROOT"
