"""实验虚拟机的连接参数 —— 全部从环境变量取，**仓库里不留口令**。

    export FWMAP_LAB_HOST=192.0.2.10       # 换成你的实验机地址
    export FWMAP_LAB_USER=<用户名>
    export FWMAP_LAB_PWD=<口令>
    export FWMAP_LAB_ROOT=/home/<user>/fwmap-run      # 可选

**没有默认口令**：不设 `FWMAP_LAB_PWD` 就直接报错退出，
免得把一个实验室口令连同仓库一起交出去。
"""

import os

__all__ = ["HOST", "USER", "PWD", "VM_ROOT", "PORT", "require"]

HOST = os.environ.get("FWMAP_LAB_HOST", "")
USER = os.environ.get("FWMAP_LAB_USER", "")
PWD = os.environ.get("FWMAP_LAB_PWD", "")
PORT = int(os.environ.get("FWMAP_LAB_PORT", "22"))
VM_ROOT = os.environ.get("FWMAP_LAB_ROOT", "/home/ubuntu/fwmap-run")


def require() -> None:
    """连机器之前调用：缺哪个变量就说哪个。"""
    missing = [k for k in ("FWMAP_LAB_HOST", "FWMAP_LAB_USER", "FWMAP_LAB_PWD")
               if not os.environ.get(k)]
    if missing:
        raise SystemExit(
            "缺少实验虚拟机连接参数：" + "、".join(missing) + "\n"
            "先设置环境变量再跑，例如：\n"
            "  $env:FWMAP_LAB_HOST='<ip>'; $env:FWMAP_LAB_USER='<user>';"
            " $env:FWMAP_LAB_PWD='<password>'")
