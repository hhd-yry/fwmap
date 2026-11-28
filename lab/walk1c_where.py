"""查清楚：/login.cgi 到底是从哪一步、以什么形态被抽出来的。

`fwmap routes`（discover.apply_plan）和 `pages.scan` 不是同一个视角，
汇报时如果说混了就会被问倒。
"""

import sys

import vm

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PY = r'''
import sys
sys.path.insert(0, "/home/ubuntu/fwmap-run")
from fwmap import pages
forms = pages.scan("/home/ubuntu/lab/d615/root")
print("pages.scan 表单数：", len(forms))
uris = sorted({f["uri"] for f in forms})
print("去重后 URI 数：", len(uris))
hits = [f for f in forms if "login" in f["uri"]]
print("含 login 的表单：", len(hits))
for f in hits[:5]:
    print("   ", f["uri"], "参数:", f.get("params"))
print("含 graph 的参数：",
      [p for f in forms for p in (f.get("params") or []) if "graph" in p][:6])
'''

CMD = f"cd /home/ubuntu/fwmap-run && python3 - <<'PY'\n{PY}\nPY"

_rc, out, err = vm.run(CMD, timeout=300, sudo=True)
sys.stdout.write(out)
if err.strip():
    print("stderr:", err[-400:])
