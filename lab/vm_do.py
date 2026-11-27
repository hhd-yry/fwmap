"""在 VM 里跑一条命令并打印结果。

    python vm_do.py [--sudo] <bash 命令>
"""
import sys

import vm

args = sys.argv[1:]
sudo = False
if args and args[0] == "--sudo":
    sudo = True
    args = args[1:]

cmd = " ".join(args)
rc, out, err = vm.run(cmd, timeout=1800, sudo=sudo)
sys.stdout.write(out)
if err.strip():
    sys.stderr.write("\n--- stderr ---\n" + err)
sys.exit(rc)
