#!/bin/bash
# 温度组：temp=0.7 跑 5 次，和前面 temp=0 的 5 次并排比。
cd /home/ubuntu/fwmap-run || exit 1
ROOT=/home/ubuntu/lab/d615/root
BIN=$ROOT/sbin/httpd
export FWMAP_LLM_ENDPOINT=http://127.0.0.1:11434/v1
export LANG=C.UTF-8 PYTHONIOENCODING=utf-8

for i in 1 2 3 4 5; do
  echo "===== T0.7 RUN $i ====="
  echo ubuntu | sudo -S env FWMAP_LLM_ENDPOINT="$FWMAP_LLM_ENDPOINT" \
      LANG=C.UTF-8 PYTHONIOENCODING=utf-8 \
      python3 -m fwmap plan "$BIN" --rootfs "$ROOT" --arch mips \
      --max-steps 8 --probe --temperature 0.7 --json "/tmp/rt-$i.json" 2>&1 \
      | grep -E "^自评|^      |^  \[|^动作序列"
done

cat > /tmp/cmp.py <<'PY'
import glob, json, os

def load(pat):
    rows = []
    for p in sorted(glob.glob(pat)):
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception:
            continue
        s = d.get("stats") or {}
        fs = d.get("findings") or []
        rows.append((os.path.basename(p).split(".")[0], s, fs))
    return rows

for label, pat in (("temp=0.0", "/tmp/run-*.json"), ("temp=0.7", "/tmp/rt-*.json")):
    rows = load(pat)
    if not rows:
        continue
    print(f"\n===== {label} =====")
    print(f"{'run':>9} {'步':>3} {'模型':>4} {'参与':>5} {'被拒':>4} {'探测':>4} "
          f"{'handler':>7} {'异常':>4} {'结论':>6}  发现")
    hit = 0
    for name, s, fs in rows:
        f = f"{fs[0]['kind']} {fs[0]['uri']}" if fs else "-"
        if "crash /login.cgi" in f:
            hit += 1
        print(f"{name:>9} {s.get('steps'):>3} {s.get('model_steps'):>4} "
              f"{s.get('model_share', 0) * 100:>4.0f}% {s.get('rejects'):>4} "
              f"{s.get('probed'):>4} {s.get('handlers'):>7} "
              f"{len(s.get('anomalies') or []):>4} "
              f"{s.get('verdict_accepted')}/{s.get('verdict_tried')} "
              f" {f}")
    n = len(rows)
    avg = sum(s.get("model_share", 0) for _, s, _ in rows) / n * 100
    print(f"判出 /login.cgi 崩溃：{hit}/{n}　平均参与率：{avg:.0f}%")
PY
python3 /tmp/cmp.py
