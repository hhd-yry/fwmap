import json
import sys

import paramiko

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HOST, USER, PWD = "192.168.8.137", "ubuntu", "ubuntu"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PWD, timeout=15)
s = c.open_sftp()

for tag, path in (("LLM", "/tmp/plan-d615.json"), ("NOLLM", "/tmp/plan-d615-nollm.json")):
    try:
        with s.open(path) as fh:
            d = json.loads(fh.read().decode("utf-8"))
    except Exception as e:                                  # noqa: BLE001
        print(tag, "读不到：", e)
        continue
    cands = d.get("candidates") or []
    print(f"\n=== {tag} ===  候选 {len(cands)} 条")
    if "/login.cgi" in cands:
        print("  /login.cgi 在候选里的位置：第", cands.index("/login.cgi") + 1, "条")
    for t in d.get("trace") or []:
        print(f"  {t.get('step')}. {t.get('action'):6s} {str(t.get('args'))[:46]:46s}"
              f" src={t.get('source'):9s} {str(t.get('why'))[:34]}")
s.close()
c.close()
