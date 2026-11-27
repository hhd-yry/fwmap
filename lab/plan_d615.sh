#!/bin/bash
# 在 VM 里跑 agent 循环：模型在宿主机显卡上（走 SSH 反向隧道），qemu 在 VM 里。
cd /home/ubuntu/fwmap-run || exit 1
ROOT=/home/ubuntu/lab/d615/root
BIN=$ROOT/sbin/httpd
export FWMAP_LLM_ENDPOINT=http://127.0.0.1:11434/v1
export LANG=C.UTF-8 PYTHONIOENCODING=utf-8
echo ubuntu | sudo -S env FWMAP_LLM_ENDPOINT="$FWMAP_LLM_ENDPOINT" \
    LANG=C.UTF-8 PYTHONIOENCODING=utf-8 \
    python3 -m fwmap plan "$BIN" --rootfs "$ROOT" --arch mips \
    --max-steps 8 --probe --json /tmp/plan-d615.json 2>&1 | tee /tmp/plan-d615.log
echo "=== rc=${PIPESTATUS[0]} ==="
