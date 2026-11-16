# 换目标：D-Link（国外品牌）实测记录

> 目的：换一台「没被翻烂」的国外固件，看能不能挖到新东西。
> 记录的是**踩到的坑**和**结论**，不是猜测。

## 一、下载源

| 厂商 | 站点 | 直连 | 代理 | 备注 |
|---|---|---|---|---|
| TOTOLINK（韩） | www.totolink.net | ✅ | ✅ | 下载页是动态的，要抓接口 |
| Linksys（美） | downloads.linksys.com | ✅ | ✅ | 有目录式直链 |
| TRENDnet（美） | www.trendnet.com | ✅ | ✅ | 固件链接在 JS 里，要另外抓 |
| Zyxel（台） | www.zyxel.com | ❌ 超时 | ✅ | ftp.zyxel.com 连不上 |
| Buffalo（日） | www.buffalo.jp | ✅ | ✅ | ftp 镜像连不上 |
| Netgear（美） | downloads.netgear.com | ❌ DNS | ❌ SSL 断 | 不可用 |
| D-Link（台/美） | support.dlink.com | ❌ 断连 | ❌ SSL 断 | **反而 `ftp.dlink.ru` 可用** |

**结论**：`https://ftp.dlink.ru/pub/` 有完整目录列表，是最好用的直链源（58 个顶层目录、223 个路由器型号）。

## 二、D-Link 固件的两种形态（关键发现）

### 1. `cr6b` 加密镜像（2015 年以后基本都是）

```
文件头: cr6b 80 50 00 00 ...
熵: 7.99 bits/byte（= 加密）
```

- DIR-816L（2015）、DIR-615（2020）、DIR-815（2022）、DIR-825（2025）**全是 cr6b**
- 里面那个 `hsqs`（偏移 0x100000）是**假阳性**：按 squashfs 解会报
  `version 17962.6141`、`-3851803321129669649 bytes` 这种明显不对的超级块
- **没有密钥就解不开**，这条路直接堵死（不是我们的问题，是格式加密）

### 2. uImage + squashfs 3.1（2013 年的老固件）

DIR-320 NRU 1.4.3（2013-02-13）：

```
0x000000  uImage 头（MIPS，LZMA 内核，load 0x80000000，name DIR_320NRU）
0x05667B  gzip 数据
0x100000  Squashfs 3.1（小端，非标准魔数）
```

**坑**：`unsquashfs` 直接拒绝 —— `squashfs-tools 4.x` 不支持 3.x 超级块。
**解法**：`7z x root.sqfs` 能读，解出 **927 个文件 / 16.8 MB**（v3 的读支持在 p7zip 里还在）。

```bash
dd if=fw.bin of=root.sqfs bs=1 skip=1048576 status=none
7z x root.sqfs -o./root
```

## 三、DIR-320 NRU 的 Web 架构（和我们现有能力不匹配）

```
/etc/httpd.conf          → busybox httpd
webs/www/index.cgi       → 单入口二进制 CGI（MIPS ELF）
webs/www/*.html + JS     → 前端用 index.cgi?v2_action=xxx 调后端
```

- **不是** Boa/GoAhead，**没有** `/goform/`，**没有** `websGetVar`
- 我们现有的「网页表单 → /goform + POST 参数」这条路**对不上**
- 要打它，需要新机制：`cgi_dispatch` —— 从 JS 里抽 `v2_action=` 的名字，
  把 `index.cgi` 当成唯一入口，按 action 名 + 表单字段去 fuzz

## 四、下一台该选谁

| 候选 | 优点 | 障碍 |
|---|---|---|
| **TOTOLINK**（韩） | Boa + `/boafrm/` + `.asp`，和我们现有机制**完全匹配**；韩国品牌，国内研究少 | 下载页要抓接口 |
| **TRENDnet TEW-827DRU**（美） | AC2600，Boa 系 | 固件链接在 JS 里 |
| **D-Link DIR-320 NRU**（2013） | 老、冷门、CGI 结构简单 | 需要先写 `cgi_dispatch` 机制（约半天） |
| **Linksys EA 系列** | 目录式直链好下 | 新固件是 lighttpd + `prog.cgi`，同样要新机制 |

## 五、结论

1. **加密镜像（cr6b）是硬墙** —— D-Link 2015 年后的型号基本无解，别再花时间
2. **老固件（2013）能解**，但 Web 架构是 CGI 单入口，需要新机制
3. **最省时间的下一步**：TOTOLINK（Boa + asp），现有 pages/routes/dyn 直接可用
4. **最有"新洞"希望的下一步**：DIR-320 NRU 这类冷门 CGI 机型，但先要补 `cgi_dispatch`

---

## 六、接着打：DIR-320 NRU 实跑记录（2026-11-16）

### 6.1 起来了

```bash
# 7z 解包丢执行位 → 给 200 个 ELF 补 +x（必须，否则 chroot 报 Permission denied）
R=/home/ubuntu/d320/root
mknod $R/dev/null c 1 3
chroot $R /bin/busybox httpd -f -p 80 -h /webs/www -c /etc/httpd.conf
```

- `GET /index.html` → **200**（服务器真的起来了）
- `GET /index.cgi` → 200，但任何大小（64/512/2048/4096 字节）的 **Cookie 都不崩**

### 6.2 直接用 env 喂 CGI（比走 httpd 干净）

```bash
env -i PATH=/bin:/sbin REQUEST_METHOD=GET QUERY_STRING="v2_action=xxx" \
    HTTP_COOKIE="$(8KB 的 A)" chroot $R /webs/www/index.cgi
```

- 基线、8 KB Cookie、8 KB Content-Type boundary、8 KB QUERY_STRING → **全部 rc=0**
- 页面/JS 里只找到 6 个 action 名：`exportlog / givemeconfig / null / options / somovdParams / this`
- 逐个 action + 8 KB Cookie 或 8 KB POST body → **全部正常返回，没有一个崩**

### 6.3 为什么没打穿（诚实结论）

1. M3 给的三条链是 **2 跳、medium 置信**：

   ```
   FUN_00401a58              json_string_value()  → sprintf[bof]
   read_multipart_form_data  getenv(CONTENT_TYPE) → strcpy[bof]
   get_cookies               getenv(HTTP_COOKIE)  → strcpy[bof]  ×2跳
   ```

   多半是有界拷贝，或者落地在需要**登录态/特定字段**的分支上
2. `index.cgi` 是单入口分发器，真正的 action 名可能藏在 **POST body** 或
   登录后的 JS 里；我们只从静态页面抽到 6 个，覆盖不到
3. M3.2 只反编译了 11 个函数（31 KB 的二进制 + 2 轮取池），
   **覆盖率不够**，漏掉的路径比命中的多

**这一轮没有打出新东西。** 不是工具坏了，是这台机器要打得穿需要先解决"登录态 + action 枚举"。

### 6.4 留个后手

`cgi_direct` 这个跑法本身很有用（不用起 httpd、不用管 fork，退出码就是崩溃信号）。
如果以后要专门打 CGI 型固件，把它做成 dyn 的一种运行时即可，约 60 行。
---

## 七、重要更正（2026-11-16 晚）：cr6b **不是**解不开

前面第 2 节我写过「cr6b 是加密，没密钥解不开」——**这个结论是错的**，当天就被自己的工具推翻了。

新写的 `fwmap unpack` 在同一个 DIR-816L 镜像上：

```
[unpack] d816.bin 7435 KB · 头 'cr6b...' · 熵 7.99 · 头是 cr6b（D-Link 私有加密容器）
[unpack] 试 binwalk —— 没成（link points outside of the extraction directory）
[unpack] 试 7z —— 成功 → 1384 个文件 / 26 MB / 71 个真 ELF
[+] rootfs: /tmp/unp-enc/7z
```

解出来的东西是真的：

```
顶层: bin dev etc home lib lib32 lib64 mnt opt proc root sbin share sys tmp usr var VERSION webs
VERSION: NAME: DIR_816LA1A   VERSION: 2.5.3   BUILDTIME: 2015-07-22
webs/www/index.cgi  + 9 个 .htm   ← 和 DIR-320 NRU 一样是 CGI 单入口
```

**教训**：`unsquashfs` 报 "version 17962.6141" 只能证明**这个偏移上不是标准 squashfs**，
不能证明整个镜像加密。我当时从「熵 7.99 + 私有头 + unsquashfs 失败」直接跳到「加密」，
少试了一步 `7z` —— 而 `7z` 恰恰认识 v3 超级块。

这条经验已经变成代码：`fwmap unpack` 会**依次试**，失败不跳结论；
而且验收看的是「像不像 rootfs」（bin/etc/lib + 真 ELF 计数），不是看工具的退出码。

### 两个可用的国外目标（都解开了）

| 型号 | 年份 | 文件数 | Web 架构 |
|---|---|---|---|
| DIR-320 NRU 1.4.3 | 2013 | 927 | busybox httpd + index.cgi |
| DIR-816L A1A 2.5.3 | 2015 | 1384 | busybox httpd + index.cgi |

两台都是 **CGI 单入口**（不是 Boa /goform）—— 缺的正是 `cgi_dispatch` 这个机制。
---

## 八、DIR-816L 挖到哪儿了（2026-11-16 晚）

### 8.1 三个必须先解决的问题，已解决两个半

| 问题 | 现象 | 解法 | 状态 |
|---|---|---|---|
| 符号链接被 7z 写成文本 | `/lib/ld-uClibc.so.0` 是 21 字节的文本，动态程序全部起不来 | `repair_symlinks()` 还原 148 个 | ✅ 进代码了 |
| 执行位丢失 | chroot 报 Permission denied | `fix_exec_bits()` 补 422 个 | ✅ 进代码了 |
| **CGI 找不到模板** | 只回 20 字节；stderr 说 `Can not read templates file!` | **必须 `cd /webs/www` 再执行** `./index.cgi` | ✅ 已定位 |
| 鉴权 | 未登录只给登录页 | 会话存在 `/tmp/check_session.json`（明文 JSON），伪造 privilege 不够 | ⚠️ 未绕过 |

第 3 条是通用经验：**CGI 一定用相对路径找模板/配置**，所以运行时必须
`chdir` 到脚本所在目录，否则它永远只回几十字节 —— 看起来像"没这个 action"，
其实是"根本没跑起来"。

```bash
env -i ... REQUEST_METHOD=GET SCRIPT_NAME=/index.cgi \
  chroot $ROOT /bin/sh -c 'cd /webs/www && exec ./index.cgi'
# → 5420 字节的登录页（之前只有 20 字节）
```

### 8.2 这个 Web 后台的结构（从 JS 和二进制里读出来的）

```
分发：POST 的 action 字段（JS 框架 data:{action:…}）；v2_action 只用于 exportlog/givemessage
响应：res_config_action0/1/…（是响应字段，不是请求参数）
模板：webs/www/templates；前端 jquery.json.js（JSON RPC）
会话：/tmp/check_session.json，字段 privilege(0=未登录)/ip_address/session_is_update
鉴权：client_login / create_auth_session / check_auth / check_ban / check_from_lan
```

伪造 `privilege=1/2/3` 的会话，页面仍是登录模板（5348 字节）—— 说明
`check_auth` 不只看这个文件，或者登录时还要置别的状态。

### 8.3 M3 给的 4 条强源链（还没验证）

```
FUN_004027a4                 json_string_value()  → sprintf[bof]
__read_multipart_form_data   getenv(CONTENT_TYPE) → strcpy[bof]
get_cookies                  getenv(HTTP_COOKIE)  → strcpy[bof]  ×2跳
FUN_004022bc                 json_string_value()  → strcpy[bof]  ×2跳
```

**JSON 解析 → sprintf/strcpy**，2015 年的代码。现在只差过鉴权这一步。
### 8.4 B 路线：打登录前入口 —— 找到一个崩溃，但判定为环境问题

`fwupdate.cgi` 在 httpd 下**任何请求都崩**：

```
GET  /index.html    → 200 OK        （对照组正常）
GET  /fwupdate.cgi  → 空响应，httpd 日志: qemu: uncaught target signal 11
POST /fwupdate.cgi  → 同样崩
```

一开始以为中了，做了三组排除：

| 变量 | 结果 |
|---|---|
| 完整 multipart（boundary + 假固件文件） | 崩 |
| 空 body / 无 Content-Type | 崩 |
| boundary 放大 512 / 2048 / 8192 | 崩（和基线一样）|
| filename 放大 512 / 2048 | 崩（一样）|
| 会话文件：伪造的 / 删除 / 让 index.cgi 正常建 | **三种都崩** |

**结论：和输入无关，是无条件崩溃。** 一条"无论发什么都崩"的路径，
在真机上不可能存在（否则固件升级页永远用不了）——
所以这是我们的环境缺东西（`strings` 显示它依赖 `start_session_file_use`、
`set_lock_file`、`json_loadf`，很可能在等某个 `/tmp` 锁文件或 `/dev/mtd*`）。

**不作为漏洞上报。** 这条正好印证了对照组纪律：
先证明"和输入有关"，再谈漏洞。
### 8.5 B2 路线：transmission / miniupnpd —— 在 user-mode 模拟下起不来

`usr/bin/transmission-daemon` 是 **Transmission 2.82**（2013 年的版本，CVE 库里有一堆）。

```
版本：Transmission/2.82
启动：chroot $R /usr/bin/transmission-daemon -f -T -p 9091 -g /tmp/trans -w /tmp/dl
      --no-dht --no-lpd --no-portmap
```

结果：**进程活着，但 9091 一直不监听，配置文件也不生成**。

strace 看它卡在 `nanosleep(100ms)` 的循环里，另有一个线程挂在 futex 上 —— 
典型的"守护进程初始化没完成"。已经排除的：

| 尝试 | 结果 |
|---|---|
| 挂 /proc /sys /dev 进 chroot | 还是不起 |
| 关掉 DHT / LPD / 端口映射 | 还是不起 |
| 等 10 秒（qemu 慢） | 还是不起 |
| 给它 /tmp 配置目录（chmod 全开） | 配置文件根本没写出来 |

`miniupnpd` 同理 —— 它要真实的网络接口和 iptables，user-mode 下更不可能。

**结论：user-mode（qemu-user + chroot）只能跑"单进程、无守护化、无复杂网络"的目标。**
`index.cgi` 这种 CGI 能跑；`transmission-daemon` / `miniupnpd` 这种要网络栈和线程的，
必须上 **qemu-system 全系统模拟**（或用真机）。

### 8.6 今晚的净结果

| 结论 | 性质 |
|---|---|
| DIR-816L 能解包、能跑 index.cgi | ✅ 能力已验证 |
| Web 后台结构摸清（action 分发 / 明文会话 / 鉴权链） | ✅ 情报 |
| 4 条强源链（JSON→sprintf/strcpy 等） | ⏳ 待过鉴权 |
| fwupdate.cgi 崩溃 | ❌ 环境假象，已排除 |
| transmission / miniupnpd RPC | ❌ user-mode 起不来 |
| 新漏洞 | **0 个** |

**下一步的岔路口**：要么上 qemu-system（半天到一天，之后所有守护进程都能跑），
要么换一台"没有守护进程、纯 CGI"的目标（现有工具直接可用）。
### 8.7 C 路线：逆鉴权 —— 已经看到模型，但还差最后一环

反编译 `index.cgi` 的鉴权函数（Ghidra，函数名来自字符串表）：

```c
// is_auth_session()：只要 auth_session[session_num] 这个键存在，就返回 1
iVar1 = get_param(params, "session_num");        // ← 从**请求参数**取，不只是 Cookie
...
auth = json_object_get(root, "auth_session");
entry = json_object_get(auth, iVar1);
if (entry != 0) return 1;                        // ★ 有键就算登录

// get_privilege_session()：权限等级也是从同一个文件读
uVar5 = json_object_get(entry, "privilege");
uVar5 = json_integer_value(uVar5);

// check_ban()：封禁状态存在 ip_session[ip] 里（is_ban / ban_time / fails）
```

**模型非常明确**：鉴权全在 `/tmp/check_session.json` 这个明文文件里，

- 有一个 `auth_session[<session_num>]` 条目 → 认为已登录
- 该条目的 `privilege` 字段就是权限等级
- `session_num` 是**请求参数**（`get_param`），Cookie 只是其中一种传法

按这个模型，我们把 `session_num` 塞进 query，配合伪造的会话文件，应该就够了。
**但实测仍然返回登录模板**（5348 / 5379 字节，都带 `login.css`）：

```
?session_num=SID              5379 字节（登录模板）
?session_num=SID + Cookie     5348 字节（登录模板）
只 Cookie                     5348 字节（登录模板）
什么都没有                    5420 字节（登录模板）
```

说明页面选择还看别的条件 —— 最可能是 `get_auth_state()` 或者模板选择处，
它可能还要求 `privilege` 达到某值、或 `session_is_update` 的标志。

**下一步（明确到函数）**：反编译渲染入口（`main` / `index_page` / `get_auth_state`），
看它到底按哪个条件选模板。这是纯静态活，不需要再折腾环境。