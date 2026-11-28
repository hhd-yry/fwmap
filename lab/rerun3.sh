#!/bin/bash
# 三组实验重跑，产出可核对的原始记录（2026-11-28，旧记录已随 VM 重启丢失）
#
# 与 11-26 那次的口径一致：同固件、8 步预算、同一套模型，只有条件不同。
# 输出写到 /tmp/rec/<组>/<轮>.json，供 lab/recount.py 离线重算。
cd /home/ubuntu/fwmap-run || exit 1
ROOT=/home/ubuntu/lab/d615/root
BIN=$ROOT/sbin/httpd
export FWMAP_LLM_ENDPOINT=http://127.0.0.1:11434/v1
export LANG=C.UTF-8 PYTHONIOENCODING=utf-8

mkdir -p /tmp/rec/temp00 /tmp/rec/temp07 /tmp/rec/anon

run_one() {     # $1=组名 $2=轮次 $3=温度 $4=额外参数
  local out="/tmp/rec/$1/$1-$2.json"
  rm -f "$out"
  echo ubuntu | sudo -S env FWMAP_LLM_ENDPOINT="$FWMAP_LLM_ENDPOINT" \
      LANG=C.UTF-8 PYTHONIOENCODING=utf-8 \
      python3 -m fwmap plan "$BIN" --rootfs "$ROOT" --arch mips \
      --max-steps 8 --probe --temperature "$3" $4 \
      --json "$out" --out-dir "/tmp/rec/$1" 2>&1 \
      | grep -E "^完成状态|^自评|^      |^  \[|^端点探测|^交接文件" || true
}

for i in 1 2 3 4 5; do
  echo "===== temp00 第 $i 轮 ====="
  run_one temp00 "$i" 0.0 ""
done

for i in 1 2 3 4 5; do
  echo "===== temp07 第 $i 轮 ====="
  run_one temp07 "$i" 0.7 ""
done

for i in 1 2 3 4 5; do
  echo "===== anon 第 $i 轮 ====="
  run_one anon "$i" 0.7 "--anonymize"
done

echo "===== 汇总 ====="
for g in temp00 temp07 anon; do
  echo "--- $g ---"
  python3 /home/ubuntu/fwmap-run/lab/recount.py "/tmp/rec/$g" \
      --target /login.cgi --kind crash --planned 5
done
