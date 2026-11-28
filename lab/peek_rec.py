import json
import sys

import paramiko

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("192.168.8.137", username="ubuntu", password="ubuntu", timeout=20)

for path in ("/tmp/rec/temp00/temp00-1.json", "/tmp/rec/temp07/temp07-2.json"):
    try:
        s = c.open_sftp()
        with s.open(path) as fh:
            d = json.loads(fh.read().decode("utf-8"))
        s.close()
    except Exception as e:                                   # noqa: BLE001
        print(path, "读不到", e)
        continue
    print(f"\n=== {path} ===")
    print("status:", d.get("status"), "| stop:", d.get("stop_reason"))
    print("candidates:", len(d.get("candidates") or []),
          "| probed:", len(d.get("probed") or {}),
          "| findings:", len(d.get("findings") or []))
    for t in d.get("trace") or []:
        print(f"  {t.get('step')}. {t.get('action'):7s} {str(t.get('args'))[:44]:44s}"
              f" src={t.get('source'):9s} ok={t.get('ok')} {str(t.get('detail'))[:40]}")
c.close()
