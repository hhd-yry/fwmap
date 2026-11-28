#!/bin/bash
# 阶段 1：从固件里抽路由（不问模型）
cd "${FWMAP_VM_ROOT:-/home/ubuntu/fwmap-run}" || exit 1
ROOT=/home/ubuntu/lab/d615/root
export LANG=C.UTF-8 PYTHONIOENCODING=utf-8
echo ubuntu | sudo -S env LANG=C.UTF-8 PYTHONIOENCODING=utf-8 \
    python3 -m fwmap routes "$ROOT/sbin/httpd" --rootfs "$ROOT" --no-llm 2>&1 \
    | tail -40
