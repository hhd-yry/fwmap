# 评估：同学的 Mango-Agent

> 材料两份：代码 `jzy137137/Mango-Agent` @ `c6bb5f1`（2026-11-09），
> 运行产物 `jzy137137/runs` @ `ab002d9`（2026-11-15 上传，2026-11-06/07 跑出来的）。
> 方法：代码真跑（clone 下来跑测试和命令），产物逐条比对（反编译证据、模型决策、截断边界）。

---

## 0. 三句话结论

1. **她真的跑完了。** 四个 run：一个完整的 API 闭环（6 轮模型决策 / 15 次 IDA 请求 /
   真 DeepSeek / 真 IDA），一个模型断连，两个文件交接停在等人。
2. **她审的那条线索是真的。** `TendaTelnet` 从 NVRAM 取 `lan.ip` 拼进
   `doSystemCmd("telnetd -b %s &")`，上游 `fromAdvSetLanip` 把 HTTP 参数原样写进
   `lan.ip`，**没有任何 IP 格式校验**。我逐行复核了反编译证据，成立。
3. **她的结论 `insufficient_evidence` 是诚实的，但只差 4 行代码就能翻转**——
   那句"注册关系"就在她抓回来的证据里，被上下文预算截在了前面（§4）。
   而 CVE 库里 0.3 秒就有答案（§5）。**这两条恰好把"为什么要融合"证明完了。**

---

## 1. 她的工具是什么

```
Mango（候选生成）→ closures[]：汇点 + 指令地址 + rank + depth
                          │
                          ▼
              agent.py：模型自主决定下一步查什么（JSON 协议）
                          │
              IDA MCP 只读：decompile / callers / callees / xrefs / strings
                          │
              runs/<时间>-<id>/：state · evidence/E*.json · model-round-*.json · report.md
```

| | 数字 |
|---|---|
| 代码 | 585 行 + 124 行测试（纯标准库） |
| 依赖 | IDA Pro 8.3 + MCP 插件、Mango、OpenAI 兼容 API |
| 预算 | 6 轮模型决策 / 16 次 IDA 请求 / 上下文 18 K 字符 |
| 结论词 | `supported` / `contradicted` / `insufficient_evidence`（没有 "confirmed"） |
| 动态验证 | 无，报告里硬编码 `dynamic_validation: not_performed` |

---

## 2. 我实际跑了什么

### 代码层（不需要 IDA 就能验的）

```bash
$ py -3.13 -m unittest -v test_agent.py
Ran 9 tests in 4.8s   OK          # 记录文档写 7 项，实际 9 项

$ py -3.13 agent.py doctor
{"python":"3.13.0", ..., "ida_error":"无法连接接口：…"}   # 缺 IDA 时优雅降级

$ py -3.13 agent.py list --results <照着格式造的最小样例>
0: do_cmd @ 0x498890; rank=0.91; depth=3
```

### 数据层（她上传的四个 run）

| run | 模式 | 结果 | 轮次/请求 |
|---|---|---|---|
| `20261106-224013-1f096d` | handoff | `pending_model`（等人贴模型回答） | 0 轮 / 1 请求 |
| **`20261106-224212-97e4d1`** | **api** | **`completed`，`insufficient_evidence`** | **6 轮 / 15 请求（3 个失败）** |
| `20261107-115740-517fc4` | handoff | `pending_model` | 0 轮 / 1 请求 |
| `20261107-115751-6c46d5` | api | `model_error`（模型接口断连） | 2 轮 / 8 请求 |

还有一份 Mango 自己的运行目录 `mango-tool-a21bb…`（`gl_nas_sys`，143 秒，6 条 closures），
**没有对应的 review**——她只跑了分析，没审那 6 条。

> 一个可复现性问题：仓库里的 `agent.py` 比跑出这些 run 的版本旧。
> 证据：runs 里的 `invocation.json` 带 `sha256`、`status.json` 带 `started_at / finished_at`，
> 而仓库版 `analyze` 只写 `{"exit_code": code}`。想复现的人拿到的不是同一份代码。

---

## 3. 她这轮真跑出了什么

候选（Mango 排第 1，rank 0.7）：

```
TendaTelnet(0x498798)  →  doSystemCmd("telnetd -b %s &")  @ 0x498890
                          ↑ 实参来自 GetValue("lan.ip")
```

她自己抓到的反编译原文（E0001，我用她的 evidence 文件复核过，一字不差）：

```c
int __fastcall TendaTelnet(int a1)
{
  int v2[8];                       // 32 字节栈缓冲
  memset(v2, 0, sizeof(v2));
  GetValue("lan.ip", v2);          // ← 外部可控的 NVRAM 键
  console_control(1);
  SetValue("console_switch", "enable");
  CommitCfm();
  system("killall -9 telnetd");
  doSystemCmd("telnetd -b %s &", (const char *)v2);   // ← 拼进 shell
  websWrite(a1, "load telnetd success.");
  return websDone(a1, 200);
}
```

上游写入点（E0013，`fromAdvSetLanip` @ 0x48a0b8）：

```c
Var = (char *)websGetVar(a1, "lanIp", "192.168.0.1");   // ← HTTP 参数
if ( !strcmp(Var, "undefined") ) Var = "192.168.0.1";    // ← 只判了这一个字符串
SetValue("dhcps.gw", Var);
...
SetValue("lan.ip", Var);                                // ← 原样落库，没有 IP 校验
```

**「从 HTTP 参数到 shell」整条链，除了最后一步可达性，她都拿到了。** 这不是假阳性。

6 轮决策的走向（`model-round-*.json`）：先 `callers/xrefs` 找注册点 →
`decompile formDefineTendDa`（0x438824）找注册表 → 用 `strings "lan.ip"` 找写入点 →
`function_by_name fromAdvSetLanip` → `decompile` 确认无过滤。**问的问题是对的**，
比"让模型自由发挥"靠谱得多。

她的结论（原样）：

> `insufficient_evidence` —— 静态风险线索成立但网络可控性与可达性未证实。
> 缺：(1) `TendaTelnet` 是否被 `websFormDefine` 注册；(2) `GetValue` 实现反编译失败；
> (3) 从 `lan.ip` 写入到触发的时序。

---

## 4. 差 4 行：一个真实的上下文预算 bug

她说「E0005 的 `websFormDefine` 列表中未观察到 `TendaTelnet`」。**这句话是真的**——
因为那行被截掉了。她自己的 `next_request.json` 里存着模型当时看到的原文：

```
--- E0005  长度 7000  truncated=True
    末尾: '... websFormDefine(\"usb_get\", &form_usb_get);
           /* line: 95 */   websFormDefine(\"SysToo'
```

分界线停在 **line 95**。而完整证据里是这样：

```
/* line: 96 */ websFormDefine("SetRemoteWebCfg", &formSetSafeWanWebMan);
/* line: 97 */ websFormDefine("GetRemoteWebCfg", formGetSafeWanWebMan);
/* line: 98 */ websFormDefine("GetSySLogCfg", formGetSysLog);
/* line: 99 */ websFormDefine("telnet", TendaTelnet);      ← 就是它
```

数字对一下：这份反编译 JSON 序列化后 **8369 字符**，这行在 **7299** 处，
而 `bounded()` 只给前 **7000** —— 差 299 字。**答案是第 100 行，模型看到第 95 行。**

她自己的 prompt 也写了「截断」标记，模型甚至在总结里写了"截断输出中未出现"，
但没有任何机制让它回头翻后面那截。

**这里只做定位，不动她的代码**：她的仓库我一次都没提交过，也没有写权限。
我们自己这边验证过修法有效（在本地临时克隆里试，试完就删）：

```python
head = int(limit * 0.6); tail = limit - head
item["result"] = text[:head] + "\n...[中间省略 %d 字符]...\n" % (len(text) - limit) + text[-tail:]
item["original_chars"] = len(text)
```

外加 SYSTEM 里一句：

> *An observation marked "truncated" was cut: absence inside it is NOT evidence of absence.*

实测效果（拿她那份真 E0005 跑）：

| | 长度 | 含注册行 |
|---|---|---|
| 她现在的版本（前 7000 字） | 7000 | **False** |
| 首尾各留一部分之后 | 7022 | **True** |

**这就是"效果"和"正确性"的差别**：一个真实候选因为 299 个字符被判证据不足。
要不要采纳是她的事 —— 我们自己的结论不依赖这一条。

---

## 5. 她缺的那条，CVE 库里 0.3 秒就有答案

`fwmap merge --from mango <她的 run 目录>` 的输出（完整件见
`examples/示例-合并-她的AC20候选.md`）：

```
[+] 她的结论：insufficient_evidence
[+] 新颖性核对：已公开（1 个函数名在 CVE 描述里出现）
    TendaTelnet: 4 条命中，路由 /goform/telnet
```

| CVE | 发布 | 等级 | 路由 | 内容 |
|---|---|---|---|---|
| CVE-2025-1819 | 2025-03-02 | 5.3 | `/goform/telnet` | Tenda AC7：**`TendaTelnet`，参数 `lan_ip`，命令注入** |
| CVE-2026-6989 | 2026-04-25 | 2.1 | `/goform/telnet` | Tenda F453：`TendaTelnet`，命令注入 |
| CVE-2026-82693 | 2026-08-31 | 9.3 | `/goform/telnet` | Tenda AC1206：`TendaTelnet`，**鉴权缺失** |
| CVE-2023-51094 | 2023-12-26 | 9.8 | — | Tenda M3：经 `TendaTelnet` 的命令执行 |

**CVE-2025-1819 描述的就是她这条链**：同一个 handler、同一个参数名、同一种注入。

所以：

- 她那条「缺失证据第 1 条」（`TendaTelnet` 有没有注册成 HTTP 处理函数）——
  **答案是有，路由 `/goform/telnet`**，公开记录里写死了，不需要 IDA。
- 她的 `insufficient_evidence` 对她的证据而言正确，但**补上这一条之后，
  正确的结论是「已公开手法，需确认本型号/版本是否同样受影响」**，
  而不是"证据不足"。

这不是说她该被减分——**恰恰相反**：她拒绝在证据不足时下结论，
比"看起来像就报高危"强得多。她缺的是**最后一道工序**，而那正好是我们这边做的事。

> 附带一个副产品：她的 E0001 里 `int v2[8]` 只有 32 字节，
> 若 NVRAM 里的 `lan.ip` 能超过 31 字节，`GetValue("lan.ip", v2)` 还是个栈溢出候选。
> 她的证据里已经能看出来，但 `GetValue` 反编译失败（E0010），没法定论。

---

## 6. 另一份产物：`gl_nas_sys` 那轮没人审

`mango-tool-a21bb…` 是她拿 Mango 跑 `slate7pro-win/squashfs-root/usr/bin/gl_nas_sys`
（GL.iNet Slate 7 Pro 固件，GL 的 NAS 服务）的结果：143 秒，6 条 closures
（`system` ×4、`execve` ×1，地址 0x465100 / 0x465120 / 0x46db14 / 0x4282c8）。

**这 6 条一条都没进过她的 review**。而库里有一条对得上的：

> **CVE-2026-19983**（2026-08-17，6.9）：GL.iNet A1300/AX1800/AXT1800/MT2500/MT3000/
> MT6000/X3000/XE3000 4.8.x，`/usr/bin/gl_nas_sys` 的 NAS Command Service，
> **OS 命令注入**，远程可利用，4.9.0 修复，厂商确认"漏洞确实存在"。

也就是说：**她手上另有一个已知含洞的组件，只是流水线停在了 analyze。**
（型号列表里没有 BE3600，她那份是不是同版本要另说。）

---

## 7. 代码层问题清单（按严重度）

### ① 截断策略会切掉答案 —— 已复现，见 §4
不是理论问题：一个真实候选因为它被降级。

### ② 证据引用只校验编号存在，不校验「这条证据支不支持这句话」
`validate_finish`（`agent.py:187`）只检查 `evidence id ∈ 成功返回的编号`。
这次的实例更微妙：模型的 claim 是"E0005 里**没看到**注册行"——
对**它看到的那 7000 字**而言完全正确，但报告把它写成了对二进制的事实陈述，
读者无法区分「不存在」和「没看到」。
**修法**：claim 涉及"未出现/不存在"时，若那条证据 `truncated` 为真就拒收。

### ③ 一次坏输出烧掉一整轮
`run_loop`（`agent.py:296`）把协议错误记进 `protocol_feedback` 就进下一轮，
本轮什么都不做。`max_rounds=6` 时连续两次坏 JSON 就废一半预算。
（这次没触发——6 轮都是合法 JSON。但机制在那儿。）

### ④ 失败过的查询永久不可重试
`record()`（`agent.py:131`）在调用**前**就把签名写进 `seen`。
这轮有 3 个 `decompile` 失败（E0006 / E0010 / E0014），
其中 0x4ffbec（`GetValue`）的失败直接变成了「缺失证据第 2 条」，
而它已经不可能再被问一次——只能靠模型换个问法（`strings` / `function_by_name`）。

### ⑤ 只有 Windows 能完整跑
`credentials.py:17` 密钥走 DPAPI（Linux 直接 raise）；`analyze` 超时用 `taskkill`。

### ⑥ clone 下来跑不起来
`start.cmd` 写死 `C:\Users\hp\...\mango-pyenv\Scripts\python.exe`，
README 说代码在 `D:\chatgpt\mango-agent`。仓库里 10 个文件是工程切片。

### 撤回一条以前的判断
我早先说「`agent.py:398` 用汇点指令地址调 `decompile` 会挂」——
**实测没挂**：她的 IDA 插件能接受 0x498890（函数中间地址）并返回所属函数。
这条撤回，不是问题。

---

## 8. 值得直接抄的五件事

1. **SHA256 身份核对**：结果 JSON 记哈希，分析前和 IDA 里的比对。这轮真生效了
   （Mango 的 `6887f4…` 和 IDA metadata 一致才开跑）。我们的 `m2`/`m3` 输出只记路径不记哈希。
   → **已落地**（2026-11-15）：`fwmap/integrity.py`；`m2` / `flow.json` 记 `binary_sha256`+`binary_size`，
   `verify` / `dyn` 读前核对，**对不上直接拒绝**（`--allow-stale` 放行）。
2. **结论必须点名证据编号**，编号不存在直接拒收。
3. **上下文预算显式化**：塞不下的进 `omitted_evidence_ids` 告诉模型（`['E0004','E0003','E0002','E0001']`），
   而不是静默丢弃。这条思路对，只是截断那一半没做对。
4. **`set(args) != 声明参数` 的严格匹配**：一行挡掉模型乱加参数。
5. **`missing_evidence` 是一等输出**：她把「缺什么」直接写进报告，这是她这轮最值钱的地方。
   → **已落地**（2026-11-15）：每条链带 `missing_evidence`，报告里单列一栏 + 缺口汇总，
   `autopilot` 结论里也会列"还缺什么（按条数）"。

---

## 9. 我们自己的一个坑（已修）

对接时第一件事就踩了：她输出中文，我们按 UTF-8 解码；Windows 上 Python 子进程默认
按 **GBK** 写管道，一句「无法连接接口」变成一串 `\ufffd`。
根因是**我们的 manifest 根本没法给外部工具设环境变量**——约定 UTF-8 却不给人开关。
现在加了 `env` 字段，Python 解释器自动补 `PYTHONUTF8/PYTHONIOENCODING`，3 条回归测试。

---

## 10. 融合：两个方向今天都通了

### 方向 A：我们的链 → 她的审查循环（已测）

```bash
fwmap export --to mango examples/示例-flow-tenda19.json --top 5 -o t.json
python agent.py list --results t.json        # 她的代码一行不改
0: doSystemCmd @ 0x000a88a4; rank=1; depth=1
```

用 mock IDA + mock 模型把她的完整循环跑通（2 轮 / 3 次请求 / 生成 report），
证明的是**接线**，不是结论。

### 方向 B：她的结论 → 我们的新颖性核对（已测，用的就是她这份真数据）

```bash
fwmap merge --from mango <她的 run 目录>
→ examples/示例-合并-她的AC20候选.md
```

合并报告里她的 `insufficient_evidence`、她的 5 条证据、她列的 4 条缺失证据
**一字未改**，我们只在下面加了自己查到的东西。这是刻意的：
**合并不能改写对方的结论，否则两边都不敢用。**

---

## 11. 两边各占什么

| | 她 | 我们 |
|---|---|---|
| 分析手段 | IDA 反编译 + 交叉引用，看调用者/字符串/守卫 | Ghidra + 语句级污点，看源→汇路径 |
| 模型角色 | **裁决**（结论词由模型给） | **只取证**（结论由规则算） |
| 数据来源 | Mango 候选 | 自己从 rootfs 一路做到链 |
| 新颖性 | 无 | 离线 42 万条 CVE，断网可查，0.3 秒/函数 |
| 动态验证 | 无（明说没做） | qemu 真跑，命令注入能取证 |
| 门槛 | 要 IDA Pro（商业） | 只要 Ghidra（开源） |
| 独立性 | 需要一个已定位的候选 | 能从固件包开始 |

---

## 12. 如果要给她回一条消息

1. **结论被截断改写**：你这轮写的"截断输出中未出现 TendaTelnet"是真的（你只看到第 95 行），
   但注册行在第 99 行 —— 差 299 个字符。是预算问题，不是判断问题。
2. **`TendaTelnet` 已经是公开手法**：CVE-2025-1819 / 2026-6989 / 2026-82693 / 2023-51094，
   路由 `/goform/telnet`。你缺的第 1 条证据，库里就有。
3. **`gl_nas_sys` 那 6 条没人审**：GL.iNet 4.8.x 的 `/usr/bin/gl_nas_sys` 有
   CVE-2026-19983（4.9.0 修），值得再跑一轮 review。
4. **把 `start.cmd` 里的绝对路径改掉**，不然别人 clone 下来只能看不能跑。
5. 顺手：仓库里的 `agent.py` 比跑出这些 run 的版本旧，补一次提交。

> 以上只是评估结论，**不包含任何对她代码的改动**，也没有往她仓库提交过东西。
