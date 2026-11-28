#!/bin/bash
# 只重跑匿名组 5 轮（2026-11-28：修好"匿名只作用于一道题"的漏洞之后）
#
# 之前的 5 轮里，第 2 步走的是通用提示，state_brief 把 36 条真实 uri 全列了出来 ——
# 匿名条件被污染，0/5 不能算数。现在 state_brief / 结论提示都换成了 /slot-NN，
# 提示里不再出现真名和参数。
cd "${FWMAP_VM_ROOT:-/home/ubuntu/fwmap-run}" || exit 1
ROOT=/home/ubuntu/lab/d615/root
BIN=$ROOT/sbin/httpd
export FWMAP_LLM_ENDPOINT=http://127.0.0.1:11434/v1
export LANG=C.UTF-8 PYTHONIOENCODING=utf-8

mkdir -p /tmp/rec/anon

for i in 1 2 3 4 5; do
  echo "===== anon 第 $i 轮 ====="
  rm -f "/tmp/rec/anon/anon-$i.json"
  echo ubuntu | sudo -S env FWMAP_LLM_ENDPOINT="$FWMAP_LLM_ENDPOINT" \
      LANG=C.UTF-8 PYTHONIOENCODING=utf-8 \
      python3 -m fwmap plan "$BIN" --rootfs "$ROOT" --arch mips \
      --max-steps 8 --probe --temperature 0.7 --anonymize \
      --json "/tmp/rec/anon/anon-$i.json" --out-dir /tmp/rec/anon 2>&1 \
      | grep -E "^完成状态|^自评|^      |^  \[|^端点探测" || true
done

echo "===== 汇总 ====="
python3 "${FWMAP_VM_ROOT:-/home/ubuntu/fwmap-run}/lab/recount.py" /tmp/rec/anon \
    --target /login.cgi --kind crash --planned 5
