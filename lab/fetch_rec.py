"""把 VM 上的运行记录取回 `lab/recordings/`，供离线重算。

    py -3 lab/fetch_rec.py [远程根目录]      # 默认 /tmp/rec
"""

import os
import sys

import paramiko

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEST = os.path.join(ROOT, "lab", "recordings")
GROUPS = ("temp00", "temp07", "anon")

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> int:
    remote_root = sys.argv[1] if len(sys.argv) > 1 else "/tmp/rec"
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect("192.168.8.137", username="ubuntu", password="ubuntu", timeout=20)
    sftp = c.open_sftp()
    total = 0
    for g in GROUPS:
        local_dir = os.path.join(DEST, g)
        os.makedirs(local_dir, exist_ok=True)
        try:
            names = sftp.listdir(f"{remote_root}/{g}")
        except OSError as exc:
            print(f"[!] {g}: {exc}")
            continue
        for name in sorted(names):
            if not name.endswith(".json"):
                continue
            with sftp.open(f"{remote_root}/{g}/{name}") as fh:
                data = fh.read()
            with open(os.path.join(local_dir, name), "wb") as out:
                out.write(data)
            total += 1
            print(f"  {g}/{name}  {len(data)} 字节")
    sftp.close()
    c.close()
    print(f"\n共取回 {total} 份 → {DEST}")
    return 0 if total else 1


if __name__ == "__main__":
    sys.exit(main())
