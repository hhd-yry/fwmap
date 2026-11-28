"""反向隧道：让 VM 的 127.0.0.1:11434 通到 Windows 的 127.0.0.1:11434。

为什么是反向：Windows 上开着防火墙，入站 11434 不一定放行；但 SSH 出站是通的。
所以让 VM 的 sshd 去监听 11434，把连接沿这条已建立的 SSH 连接送回来。
"""
import socket
import threading

import paramiko

try:
    from vmcfg import HOST, PWD, USER, require
except ImportError:
    from .vmcfg import HOST, PWD, USER, require  # type: ignore
PORT = 11434


def pipe(src, dst):
    try:
        while True:
            data = src.recv(8192)
            if not data:
                break
            dst.sendall(data)
    except Exception:                                  # noqa: BLE001
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:                          # noqa: BLE001
                pass


def main():
    require()
    c = paramiko.SSHClient()
    require()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PWD, timeout=15)
    t = c.get_transport()
    t.request_port_forward("127.0.0.1", PORT)
    print(f"[tunnel] VM 127.0.0.1:{PORT} → Windows 127.0.0.1:{PORT}", flush=True)
    while True:
        ch = t.accept(1.0)
        if ch is None:
            continue
        try:
            # 不能设 timeout：模型一次要说 20 秒以上，超时会把 socket 关掉，
            # 服务端回包时就是 WinError 10053（实测踩过）。
            s = socket.create_connection(("127.0.0.1", PORT))
        except OSError as e:
            print(f"[tunnel] Windows 端没起：{e}", flush=True)
            ch.close()
            continue
        print("[tunnel] 一条连接建立", flush=True)
        threading.Thread(target=pipe, args=(ch, s), daemon=True).start()
        threading.Thread(target=pipe, args=(s, ch), daemon=True).start()


if __name__ == "__main__":
    main()