#!/bin/bash
# 同一固件连跑 5 次：看 75% / 100% 是不是稳定值，还是单次运气。
cd /home/ubuntu/fwmap-run || exit 1
ROOT=/home/ubuntu/lab/d615/root
BIN=$ROOT/sbin/httpd
export FWMAP_LLM_ENDPOINT=http://127.0.0.1:11434/v1
export LANG=C.UTF-8 PYTHONIOENCODING=utf-8

for i in 1 2 3 4 5; do
  echo "===== RUN $i ====="
  echo ubuntu | sudo -S env FWMAP_LLM_ENDPOINT="$FWMAP_LLM_ENDPOINT" \
      LANG=C.UTF-8 PYTHONIOENCODING=utf-8 \
      python3 -m fwmap plan "$BIN" --rootfs "$ROOT" --arch mips \
      --max-steps 8 --probe --json "/tmp/run-$i.json" 2>&1 \
      | grep -E "^自评|^      |^  \[|^动作序列|^跑了"
done

cat > /tmp/summarize_runs.py <<'PY'
import glob, json
rows = []
for path in sorted(glob.glob("/tmp/run-*.json")):
    try:
        d = json.load(open(path, encoding="utf-8"))
    except Exception:
        continue
    s = d.get("stats") or {}
    fs = d.get("findings") or []
    rows.append({
        "run": path.split("-")[-1].split(".")[0],
        "steps": s.get("steps"), "model": s.get("model_steps"),
        "share": s.get("model_share"), "rej": s.get("rejects"),
        "probed": s.get("probed"), "handlers": s.get("handlers"),
        "anom": len(s.get("anomalies") or []),
        "vt": s.get("verdict_tried"), "va": s.get("verdict_accepted"),
        "find": f"{fs[0]['kind']} {fs[0]['uri']}" if fs else "-",
    })
hdr = f"{'run':>3} {'步':>3} {'模型':>4} {'参与':>5} {'被拒':>4} {'探测':>4} {'handler':>7} {'异常':>4} {'结论':>8}  发现"
print(hdr); print("-" * len(hdr))
for r in rows:
    print(f"{r['run']:>3} {r['steps']:>3} {r['model']:>4} "
          f"{(r['share'] or 0) * 100:>4.0f}% {r['rej']:>4} {r['probed']:>4} "
          f"{r['handlers']:>7} {r['anom']:>4} "
          f"{r['va']:>3}/{r['vt']:<3} {r['find']}")
if rows:
    n = len(rows)
    hit = sum(1 for r in rows if "crash /login.cgi" in (r["find"] or ""))
    print()
    print(f"判出 /login.cgi 崩溃：{hit}/{n}")
    print(f"平均参与率：{sum((r['share'] or 0) for r in rows) / n * 100:.0f}%")
PY
python3 /tmp/summarize_runs.py
