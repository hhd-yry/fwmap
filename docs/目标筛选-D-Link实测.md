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
