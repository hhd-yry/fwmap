# 智能体：让工具自己决定下一步

> 老师的原话：「智能体既要结合自己的知识去挖这些路，也能调用一些现有的工具」。
> 我们原来是**流水线**（顺序由人定），这一步把它变成**能自己选动作的智能体**。

## 1. 一个跑通的例子

```bash
python -m fwmap autopilot C:\deepseek\fw\p5\root --limit 12 --context "Edimax,BR-6478AC"
```

```
[1] 先确认解包完整——解包不全，后面所有结论都不可信
     → 调用 check
     ← 解包自检：有问题 （阻断 1 项 / 警告 0 项）
[2] 还没选目标，先按攻击面排序
     → 调用 scan
     ← 扫描 1030 个文件 / 78 个 ELF，最高分 87（bin/webs）
[3] 要把函数对上 URL，才能按路由名做双路检索
     → 调用 m2
     ← 端点 45 个，定位到 handler 0 个（策略 strcmp-chain）
[4] 端点知道了，现在找「外部输入 → 危险函数」的链
     → 调用 m3
     ← 数据流：候选 51 条，保留 13 条（bof×8, fmt×5）
[5] 链出来了，先查有没有人报过——没报过的才值得花时间验证
     → 调用 verify
     ← 新颖性：已公开 5 / 未命中 2；值得深挖：getiNICIndex, getiNICInfo
[6] 这 2 个函数没被报过，试着真打一发
     → 调用 dyn
     ← 动态验证跳过：这台机器没有能跑 mipsel 的运行时

  用时 729.7s，共 6 步
  目标二进制：...\bin\webs
  端点 45 个 · 链 13 条
  新颖性：已公开 5 · 未命中 2 · 需人工 0
  值得人工深挖：getiNICIndex, getiNICInfo
```

**每一步都有「为什么」**，这是给老师看的关键：不是黑箱跑一遍，而是能解释的决策链。

## 2. 工具注册表

```bash
python -m fwmap tools
```

```
可调用工具 7 个：
  check   校验 rootfs 解包是否完整
  scan    按攻击面对 ELF 排序
  m2      端点 → 处理函数映射
  m3      源→汇数据流分析
  verify  核对链是否已被公开报告
  dyn     把链翻成 PoC 在模拟器里真打
  bof     二分测栈溢出的最小崩溃长度
```

每个工具都声明「名字 / 用途 / 参数」，planner 才能看着状态挑下一个。

## 3. 三条设计约束（都是踩出来的）

| 约束 | 原因 |
|---|---|
| **只返回摘要** | `webs_m3.json` 有 16 MB，整包塞进模型上下文会当场爆掉。工具只回「一句话 + 几个数字 + 产物路径」 |
| **失败也结构化** | 工具挂了返回 `{ok: False, summary: "为什么没成"}`，不抛异常穿透整个流程，planner 才有机会换路子 |
| **结论区分「没跑」和「没有」** | 0 条链时**不能**写「这个固件很干净」。第一版就犯了这个错，被回归测试钉住了 |

## 4. 为什么先上规则，不直接让模型选

- 7B 模型做工具选择不稳定，选错一次要等 Ghidra 跑十分钟才发现；
- 规则的决策链路**可解释**，日志里能写清「为什么这一步要跑 verify」；
- 等链路稳定后，把 `planner.decide()` 换成模型输出即可，接口不用动。

## 5. 融合：把别人的工具接进来（插件）

老师说的「两套工具融合」，技术难点不是功能，是**边界**：两套工具各自迭代，
谁也不想为了合体去改自己的工程。所以这里只约定一件事——**一份 JSON**：

```json
{
  "name": "otherscan",
  "desc": "某某做的端点扫描器",
  "cmd": ["python", "C:/tools/otherscan.py", "--target", "{target}"],
  "args": {"target": "解包后的 rootfs 目录"},
  "output": "json",
  "timeout": 600
}
```

用法：

```bash
fwmap autopilot <rootfs> --plugin otherscan.json          # 单个
fwmap autopilot <rootfs> --plugin ./plugins/              # 整个目录
```

跑起来是这样：

```
[plugin] 已加载 fake_external：演示用外部工具
[3] 调外部工具 plugin.fake_external（融合的关键：能调别人做的东西）
     → 调用 plugin.fake_external
     ← [外部] fake_external：返回对象（n=3、msg=中文输出、files=1030）
```

对方仍然是**一个普通命令行程序**，可以独立运行、独立发版；
我们只负责替换参数、起进程、收输出、压成摘要塞回注册表。

### 三个约束（和内置工具一致）

| 约束 | 原因 |
|---|---|
| 只回摘要 | 外部工具可能吐几十 MB，`data` 里只留标量字段，实测 < 500 字节 |
| 失败结构化 | 超时 / 非零退出 / 坏 JSON 都变成 `{ok: False, summary: "退出码 3：boom"}` |
| 不猜语义 | 摘要只写「跑出来了 / 多少条 / 前几项」，不做价值判断 |

### 一个踩到的坑

Windows 上 `subprocess.run(text=True)` 默认按 **GBK** 解码子进程输出，
外部工具一输出中文就 `UnicodeDecodeError`，而且报在读取线程里，极难定位。
现在显式指定 `encoding="utf-8", errors="replace"`。

## 6. 模型参与决策（`--llm`）

```bash
fwmap autopilot <rootfs> --llm                 # 默认 7B（8 GB 卡够用）
fwmap autopilot <rootfs> --llm --llm-model E:/models/Qwen2.5-Coder-32B-Instruct
```

分工很明确：**模型负责「选哪个工具」，程序负责「能不能这么选」**。

```
[1] (模型) 还没有选择目标，需要按攻击面对 rootfs 里的 ELF 排序，确定优先级。
     → 调用 scan   ← 78 个 ELF，最高分 87（bin/webs）
[2] (模型) 确保 rootfs 解包完整性
     → 调用 check  ← 解包自检：有问题（阻断 1 项）
     ...
     模型这一步被拦下（目标已经选出来了），带原因重试一次
     重试仍被拦下（解包自检已经做过了），退回规则
```

括号里的「(模型)/(规则)」标明这一步是谁定的 —— **可解释性比自动化程度更重要**。

### 四条硬校验（不靠模型自觉）

| 校验 | 例子 |
|---|---|
| 工具必须存在 | 模型编个 `rm_rf` → 直接拒绝 |
| 依赖必须满足 | 还没选目标就要跑 `m2` → 拒绝 |
| 不许重复 | `check` 已经做过还提议 → 拒绝 |
| 模式必须匹配 | `--skip-ghidra` 下提 `m3` → 拒绝 |

被拒之后还会**带原因重试一次**（「你上次选的 X 不能用：Y，请换一个」）。
小模型经常只是没意识到自己刚做过什么，给它一次反馈比直接退规则更有效。

### 7B 的真实表现（4060 / 8 GB 实测）

- 选**做什么**基本正确：先 `scan` 还是先 `check` 都对，两种顺序都合理；
- 选**什么时候停**不行：`--skip-ghidra` 下已经没活可干，它还在反复提议 check/scan。

所以收敛由规则兜底 —— 这正是「规则兜底」存在的意义，不是补丁。
5090 上换 32B 之后，预期主要改善的就是「知道什么时候该收工」。


## 7. 两机分工：静态在 Windows，动态在 Linux

Ghidra 在 Windows 上、qemu 在 Linux 上，不必两边都装全套。用 `--flow` 把静态产物
带过去，`autopilot` 就会跳过 M2/M3，直接做核对和动态验证：

```bash
# Windows（有 Ghidra）：跑静态，产出 flow.json
fwmap autopilot <rootfs> --context "Edimax,BR-6478AC" -o log.json

# Linux（有 qemu）：拿现成的链，直接核对 + 真打
sudo fwmap autopilot <rootfs> --flow flow.json --binary <rootfs>/bin/webs
```

实测（Ubuntu 22.04 + qemu-user-static）：

```
[1] (规则) 先确认解包完整 → check   ← 通过（1045 文件 / 79 ELF）
[2] (规则) 还没选目标     → scan    ← 87 分 bin/webs
[3] (规则) 先查有没有人报过 → verify ← 已公开 8 / 未命中 7
[4] (规则) 这 7 个没被报过 → dyn    ← chroot+qemu-mipsel，试了 6 发：崩溃 0 / 未崩 6
用时 54.8s
```

两边的耗时差得很明显：带 Ghidra 的完整静态跑 810 秒，
用现成 flow 的核对+动态只要 55 秒。

## 8. 还没做的


- **插件结果的合并**：外部工具的结果现在只进日志，还没和我们的链做交叉验证
  （比如对方报的端点 vs 我们报的端点，取并集/差集）。
- **多轮记忆**：现在每步把状态重新压成几行喂回去，没有跨步对话历史。

