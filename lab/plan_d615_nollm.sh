#!/bin/bash
# 对照组：不接模型，固定顺序（pages → routes → 按发现顺序逐条探）。
cd /home/ubuntu/fwmap-run || exit 1
ROOT=/home/ubuntu/lab/d615/root
BIN=$ROOT/sbin/httpd
export LANG=C.UTF-8 PYTHONIOENCODING=utf-8
echo ubuntu | sudo -S env LANG=C.UTF-8 PYTHONIOENCODING=utf-8 \
    python3 -m fwmap plan "$BIN" --rootfs "$ROOT" --arch mips \
    --max-steps 6 --no-llm --probe --json /tmp/plan-d615-nollm.json 2>&1 \
    | tee /tmp/plan-d615-nollm.log
echo "=== rc=${PIPESTATUS[0]} ==="
