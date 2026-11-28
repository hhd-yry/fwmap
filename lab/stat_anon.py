import glob
import json
import os

for p in sorted(glob.glob("lab/recordings/anon/*.json")):
    d = json.load(open(p, encoding="utf-8"))
    t = d.get("trace") or []
    m = [x for x in t if x.get("source") == "model"]
    print(f"{os.path.basename(p):12s} 步{len(t)} 模型决定{len(m)} "
          f"探测{len(d.get('probed') or {})} status={d.get('status')}")
