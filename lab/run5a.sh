#!/bin/bash
# 匿名组：候选名和参数全藏起来，只给编号。测「模型挑的是名字还是行为」。
cd /home/ubuntu/fwmap-run || exit 1
ROOT=/home/ubuntu/lab/d615/root
BIN=$ROOT/sbin/httpd
export FWMAP_LLM_ENDPOINT=http://127.0.0.1:11434/v1
export LANG=C.UTF-8 PYTHONIOENCODING=utf-8

for i in 1 2 3 4 5; do
  echo "===== ANON RUN $i ====="
  echo ubuntu | sudo -S env FWMAP_LLM_ENDPOINT="$FWMAP_LLM_ENDPOINT" \
      LANG=C.UTF-8 PYTHONIOENCODING=utf-8 \
      python3 -m fwmap plan "$BIN" --rootfs "$ROOT" --arch mips \
      --max-steps 8 --probe --temperature 0.7 --anonymize \
      --json "/tmp/ra-$i.json" 2>&1 \
      | grep -E "^自评|^      |^  \[|^端点探测|^  [✓·] /"
done

cat > /tmp/cmp3.py <<'PY'
import glob, json, os

def load(pat):
    out = []
    for p in sorted(glob.glob(pat)):
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception:
            continue
        out.append((os.path.basename(p).split(".")[0], d.get("stats") or {},
                    d.get("findings") or [], list((d.get("probed") or {}).keys())))
    return out

for label, pat in (("temp=0.0 具名", "/tmp/run-*.json"),
                   ("temp=0.7 具名", "/tmp/rt-*.json"),
                   ("temp=0.7 匿名", "/tmp/ra-*.json")):
    rows = load(pat)
    if not rows:
        continue
    print(f"\n===== {label} =====")
    hit = 0
    for name, s, fs, probed in rows:
        f = f"{fs[0]['kind']} {fs[0]['uri']}" if fs else "-"
        if "login.cgi" in f:
            hit += 1
        print(f"{name:>9} 参与{s.get('model_share', 0) * 100:>3.0f}% "
              f"探测{s.get('probed'):>2} handler{s.get('handlers'):>2} "
              f"异常{len(s.get('anomalies') or []):>2} 结论{s.get('verdict_accepted')}"
              f"  发现 {f}")
    n = len(rows)
    print(f"→ 判出 /login.cgi 崩溃：{hit}/{n}")
    print(f"→ 探到过的端点：{sorted({u for _, _, _, ps in rows for u in ps})[:8]}")
PY
python3 /tmp/cmp3.py
