"""在实验虚拟机里跑命令（SSH + 口令）。

连接参数见 `vmcfg.py`：全部从环境变量取，代码里不写死凭据。
"""
import sys

import paramiko

try:                                   # 直接跑脚本时
    from vmcfg import HOST, PWD, USER, require  # noqa: F401
except ImportError:                    # 作为包导入时
    from .vmcfg import HOST, PWD, USER, require  # type: ignore  # noqa: F401


def run(cmd: str, timeout: int = 900, sudo: bool = False):
    require()
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PWD, timeout=20)
    if sudo:
        cmd = f"echo {PWD} | sudo -S bash -lc {shell_quote(cmd)}"
    _in, out, err = c.exec_command(cmd, timeout=timeout)
    o = out.read().decode("utf-8", "replace")
    e = err.read().decode("utf-8", "replace")
    rc = out.channel.recv_exit_status()
    c.close()
    return rc, o, e


def shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def put(local: str, remote: str):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PWD, timeout=20)
    sftp = c.open_sftp()
    sftp.put(local, remote)
    sftp.close()
    c.close()


if __name__ == "__main__":
    sudo = "--sudo" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--sudo"]
    rc, o, e = run(" ".join(args), sudo=sudo)
    sys.stdout.write(o)
    if e.strip():
        sys.stderr.write(e)
    sys.exit(rc)
