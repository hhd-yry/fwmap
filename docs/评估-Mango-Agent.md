# 评估：同学的 Mango-Agent（jzy137137/Mango-Agent）

> 评估日期 2026-11-15，对方仓库 HEAD `c6bb5f1`（2026-11-09 23:43，单次提交 "Add files via upload"）。
> 方法：clone 下来真跑（不是读 README 猜），再接到我们这边跑一遍。

---

## 0. 三句话结论

1. **她做的是一件对的事，而且做得比我们更贴题**：写了一个 585 行的**编排层**，
   调现成的 Mango + IDA MCP，模型自己决定「我下一步要看哪个函数的调用者」。
   这正是老师说的「不要重造，要接着现有的工具做」。
2. **但她这版还没在真实数据上跑完过一次**：9 项测试全过（模拟 IDA + 模拟模型），
   真正需要 IDA 的路径一次都没走通过——她自己的记录里也这么写。
3. **能接**：我把我们的 87 条链导出成 Mango 格式，她的 `agent.py` **一行没改**就读了，
   完整 agent 循环（mock IDA + mock 模型）跑通并产出了 report。融合这件事今天有了实物。

---

## 1. 她的工具长什么样

```
Mango（她们的候选生成器）          我们的 M3 链
        │                              │
        └──────────┬───────────────────┘
                   ▼
         candidates：汇点函数 + 地址 + rank + depth
                   │
                   ▼
   agent.py  ←── 模型自主决策（JSON 协议，非 function calling）
      │  │
      │  └──→ IDA MCP (127.0.0.1:13337) 只读：decompile / callers / callees / xrefs / strings
      │
      └──→ runs/<时间戳>/  state.json · evidence/E*.json · model-round-*.json · report.md/json
```

| | 数字 |
|---|---|
| 代码 | `agent.py` 422 行 + 3 个小模块，共 585 行；测试 124 行 |
| 依赖 | 纯标准库；外部要 **IDA Pro 8.3 + MCP 插件**、**Mango**、一个 OpenAI 兼容 API |
| 约束 | 最多 6 轮模型决策、16 次 IDA 请求、上下文 18 K 字符 |
| 结论词 | `supported` / `contradicted` / `insufficient_evidence`（没有 "confirmed"） |
| 动态验证 | 无，报告里硬编码 `dynamic_validation: not_performed` |

设计上有三处明显比我们讲究：**工具白名单 + 参数集完全匹配**（`set(args) != TOOLS[tool][1]`
一行挡住多余参数）、**SHA256 身份核对**（Mango 结果和 IDA 里打开的必须是同一个二进制）、
**证据编号必须真实存在**（模型说 supported 却引用了没跑过的 E0009，直接拒收）。

---

## 2. 我实际跑了什么

```bash
# ① 她的单元测试
$ py -3.13 -m unittest -v test_agent.py
Ran 9 tests in 4.844s
OK

# ② 不需要 IDA 的两条命令
$ py -3.13 agent.py list --results synthetic_results.json
0: do_cmd @ 0x498890; rank=0.91; depth=3
1: do_sys @ 0x498a10; rank=0.72; depth=4

$ py -3.13 agent.py doctor
{"python": "3.13.0", ..., "ida_error": "无法连接接口：请检查地址、网络、代理或 IDA 服务是否启动"}

# ③ 真路径（需要 IDA）——卡在这一步，符合预期
$ py -3.13 agent.py review --results ... --candidate 0 --mode handoff
ERROR: 无法连接接口：请检查地址、网络、代理或 IDA 服务是否启动
```

> 注：第 ② 条的 Mango 结果是**我照格式造的**（我这边没有 Mango 的真实输出），
> 所以它只证明 `list` 的解析逻辑对，不证明她的 AC20 结果能被读。

### 声称 vs 实测

| README / 记录里的声称 | 实测 |
|---|---|
| Python 3.11+，纯标准库 | ✅ 3.13 直接跑通，零安装 |
| 「标准库 unittest 共 7 项通过」 | ⚠️ **实际 9 项**，全过（文档没跟上） |
| 强制核对 SHA256 | ✅ 代码在，`review`/`resume` 都调；但 `analyze` 不核对 |
| 不执行模型返回的代码或命令 | ✅ 白名单 + 参数集校验，确实做到了 |
| 「列出四条 AC20 CMDi 候选」 | ⚠️ 无法复核：她没把 AC20 结果文件传上来 |
| 「模拟测试不代表 AC20 已完成实际模型审查」 | ✅ 记录里写了；但 README 顶部没写，第一眼容易误读 |
| 结论不叫「已确认漏洞」 | ✅ 三个状态词一致，报告末尾还有免责句 |

**净结论**：逻辑层可信（测试真绿、边界处理真的做了），**数据层未验证**（没有一次真实
IDA + 真实模型的闭环）。这不是她偷懒——IDA 要钱要装，验收环境未必有。

---

## 3. 发现的问题（按严重度）

### ① 初始取代码用的是汇点指令地址，不是函数入口
`agent.py:398`：

```python
initial = record(state, "decompile", {"address": state["candidate"]["sink"]["ins_addr"]},
                 "初始获取危险调用所在函数", ida, config)
```

而它自己的 prompt（`agent.py:37`）写着 *"Use function_at to resolve a call-site address to
its containing function before callers/callees"*。Mango 的 `ins_addr` 是**汇点调用指令**的
地址，`decompile_function(中间地址)` 在 IDA 里能不能解析要看插件实现——很可能开局就
`ida_error`，而这条路径恰好是她唯一没跑过的。
**修法**：先 `function_at(ins_addr)` 拿函数起点，再 decompile。

### ② 「有证据」和「证据支持这个结论」是两件事
`validate_finish`（`agent.py:187-200`）只校验 `证据编号 ∈ 已成功返回的编号`。
模型完全可以引用一条 `decompile` 的证据去支撑「调用者里没有鉴权」这种需要 `callers`
才能回答的断言，报告看起来有据可查，实际张冠李戴。
她 README 也承认「语义是否成立仍需人工审查」——**这跟我这边「模型只取证、规则裁决」
的分歧就在这儿**：她把裁决权给了模型，我们把裁决权留在规则里。
**修法**（低成本）：claim 里出现「调用者/caller」就必须真有 callers 证据，出现
「字符串」就必须有 strings 证据。一行映射表能挡掉大半。

### ③ 一次坏输出烧掉一整轮
`run_loop`（`agent.py:296`）捕获协议错误后只写进 `protocol_feedback`，本轮什么都不做，
下一轮再试。`max_rounds=6` 意味着模型连续两次吐坏 JSON，预算就废了一半。
我们这边的做法是**带原因重试一次**再降级到规则。

### ④ 失败过的查询永久不可重试
`record()` 用 `state["seen"]` 去重（`agent.py:131`），但签名在**调用前**就写进去了：
IDA 抽风一次（超时），这个查询这辈子都不能再问。

### ⑤ 只有 Windows 能完整跑
`credentials.py:17` 存密钥走 DPAPI（Linux 直接 raise）；`analyze` 超时用 `taskkill`
（`agent.py:356`，Linux 上是 `FileNotFoundError`）。验收机若是 Linux，`--mode api`
必须先手设环境变量，超时分支还会抛异常。

### ⑥ clone 下来跑不起来
`README.md:3` 说「代码、配置、日志与结果位于 `D:\chatgpt\mango-agent`」，`start.cmd` 里
写死了 `C:\Users\hp\...\mango-pyenv\Scripts\python.exe`。仓库里只有 10 个文件，
是**工程的一个切片**，不是能交付的包。这条和老师「工具」的要求直接相关。

> 另外两处小的：`setup_model.py:17` 默认模型名 `deepseek-flash`（官方 id 是
> `deepseek-chat` / `deepseek-reasoner`，填错会 404，而她的 404 文案是「接口路径或模型名
> 不存在」，容易把人带偏）；`开发与验证记录.md` 写 7 项测试、实际 9 项。

---

## 4. 值得直接抄的四件事

1. **SHA256 身份核对**：结果 JSON 记着输入二进制的哈希，分析前和磁盘上/IDA 里的比对。
   我们的 `m2`/`m3` 输出有 `binary` 路径但**没有哈希**——换了个版本的固件重跑，
   旧结果照样能用，这是个静默错误源。→ 已列入待办。
2. **结论必须点名证据编号**，编号不存在直接拒收。
3. **上下文预算显式化**：塞不下的证据进 `omitted_evidence_ids` 告诉模型「这些我没给你看」，
   而不是静默丢。
4. **`set(args) != 声明参数` 的严格匹配**：一行代码，挡掉模型乱加参数。

---

## 5. 顺手发现我们自己的一个坑（已修）

对接时第一件事就踩了：她的 `agent.py` 输出中文，我们的插件按 UTF-8 解码——
Windows 上 Python 子进程默认按 **GBK** 写管道，一句「无法连接接口」变成一串 `\ufffd`。

```python
# 修前：受继承环境影响
inherited                fffd=True   escaped=\ufffd\u07b7\ufffd\ufffd...
# 修后：给 Python 子进程补 PYTHONUTF8 / PYTHONIOENCODING
PYTHONUTF8=1             fffd=False  escaped=\u65e0\u6cd5\u8fde\u63a5\u63a5\u53e3...
```

我们的 `manifest` 之前**没有任何办法给外部工具设环境变量**，等于「约定输出 UTF-8，
却不给人设编码的开关」。现在加了 `env` 字段，并对 Python 解释器自动补 UTF-8
（manifest 里显式写了就听它的）。`tests/test_plugins.py` 加了 3 条回归。

---

## 6. 融合：今天接通了什么

### 方向 A：我们的链 → 她的审查循环（**已通，她不用改代码**）

她的 `agent.py` 只认一种输入：`closures[]` + `rank/depth` + `sha256`。我们 `m3 --flow`
的链里什么都有，换个壳就行：

```bash
$ py -3.13 -m fwmap export --to mango examples/示例-flow-tenda19.json --top 5 -o tenda19.mango.json
[+] 导出 5 条链 → tenda19.mango.json
    sha256 e9d1b92527c57f24…

# 她那边，一行没改：
$ py -3.13 agent.py list --results tenda19.mango.json
0: doSystemCmd @ 0x000a88a4; rank=1; depth=1
1: doSystemCmd @ 0x000a88a4; rank=2; depth=1
2: FUN_000b00fc @ 0x000b04d4; rank=3; depth=1
...
```

（这份导出已经放进仓库：`examples/示例-导出mango-5条.json`，可以直接拿去喂她的 `list`。）

再往下跑完整循环（我用 mock IDA + mock 模型，因为真 IDA 不在这台机器上）：
```
[mock] 退出码 0
Run directory: ...\runs\20261115-143656-5c3b07
Status: completed
[mock] 模型轮次： [(0, 15), (1, 14)]  IDA 请求数： 3
```

它产出的 `report.md` 里，汇点、SHA256、证据编号、`dynamic_validation: not_performed`
都齐全。**接口这条路是通的，缺的只是 IDA 和真模型。**

一个可以立刻改的小毛病：她的 `report.md` 只印汇点，**把我们附带的
`handler` / `source_param` / `guard` 丢了**——模型看得到，人看不到。她的报告模板里
加一行 `candidate.get("fwmap", {})` 就补上。

### 方向 B：她的结论 → 我们的 verify / dyn（**没做，说清为什么**）

她的 `report.json` 只有「汇点 + 一段中文 + 三个状态词」，没有链级数据，
没法直接变成我们 `verify`/`dyn` 的输入。要做只需她多吐三行：

```json
{"candidate_addr": "0x000a88a4", "sink": "doSystemCmd", "status": "supported"}
```

我这边拿到就能按地址 join 回链上，让「她审过的」直接进我们的新颖性核对和动态验证。
现在这步没做，因为**没有真实数据喂它 = 写了个没人用的解析器**，不如等她那边真跑一次。

### 两边各占什么

| | 她 | 我们 |
|---|---|---|
| 分析深度 | IDA 反编译 + 交叉引用，看调用者、字符串引用 | Ghidra + 语句级污点，看源→汇路径和守卫 |
| 模型角色 | **裁决**（结论词由模型给） | **只取证**（结论由规则算） |
| 数据来源 | Mango 候选 | 自己从 rootfs 一路做到链 |
| 新颖性 | 无 | 离线 42 万条 CVE，断网可查 |
| 动态验证 | 无（明说没做） | qemu 真跑，命令注入能取证 |
| 门槛 | 要 IDA Pro（商业） | 只要 Ghidra（开源） |
| 能不能独立跑 | 不能（这是切片） | 能（`plugin`/`setup`/`doctor` 齐） |

**一句话**：她做的是「怎么让模型有纪律地查证据」，我们做的是「怎么从固件到可验证的链」。
两件事不重复，接起来才完整——这也是老师说的融合。

---

## 7. 如果要给她回一条消息

1. `agent.py:398` 那个 `ins_addr` 先过一遍 `function_at`，不然真 IDA 上大概率开局就挂；
2. 证据的**工具类型**和 claim 对一下（要 callers 的证据别拿 decompile 顶）；
3. 把 `start.cmd` 里的 Python 路径和 README 的 `D:\chatgpt\...` 改成相对路径，
   不然别人 clone 下来只能看不能跑；
4. 报告模板里把我们给的 `handler` / `source_param` / `guard` 印出来；
5. 能跑通一次真 IDA + 真模型的话，把 `runs/` 里那一份报告发我，我这边直接接上
   `verify` + `dyn`。
