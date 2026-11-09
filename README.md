# fwmap · 固件攻击面分诊工具

> 给它一个解包后的固件 rootfs，它告诉你：**先看哪个二进制**、**它处理哪些 URL**、
> **有哪些源→汇的可疑链**，并用本地 LLM 逐条取证（每条结论引用真实代码行）。

---

## 30 秒跑起来

```powershell
cd <你解压出来的目录>\fwmap-tool      # 例如 D:\tools\fwmap-tool

# 第 1 步：只挑文件（几十秒，不需要 Ghidra）
py -3.13 -m fwmap scan <rootfs目录> --top 10

# 第 2 步：一条命令跑完四层，出 HTML 报告
$env:PYTHONPATH="C:\deepseek\libs-bnb"      # 只有开 --agent 才需要
py -3.13 -m fwmap triage <rootfs目录> -o out\myfw --agent
```

报告：`out\myfw\report.html`（浏览器直接打开）。

> 也可以用 `fwmap.cmd triage <rootfs> -o out\myfw --agent`。
> 它会自己切到包所在目录、设好编码和 PYTHONPATH，**可以放在任何路径、从任何目录调用**。

---

## 四层各干什么

| 层 | 命令 | 做什么 | 慢不慢 |
|---|---|---|---|
| M1 | `scan` | 上千个文件 → 按攻击面排序 | 几十秒 |
| M2 | `m2` | 端点 → handler 映射 | 1~2 分钟 |
| M3 | `m3 --induce --flow` | 源→汇数据流，出链 | 几分钟到半小时 |
| 复核 | `agent` | 本地 LLM 逐条取证 + 规则裁决 | 每条 10~40 秒 |

`triage` 就是把上面四步串起来。

---

## 环境要求

| 东西 | 要求 | 说明 |
|---|---|---|
| Python | **3.10+**，本机用 `py -3.13` | 裸 `python` 若是 Anaconda 2.7 会直接崩 |
| Ghidra | 12.x + JDK 21/25 | 默认找 `C:\deepseek\tools\ghidra_12.2_PUBLIC`；换机器用环境变量 `FWMAP_GHIDRA` 指定 |
| 本地模型 | 可选，只在 `--agent` 时用 | 默认 Qwen2.5-Coder-7B-Instruct，4-bit 跑，5.6 GB 显存；换路径用 `FWMAP_LLM_MODEL` |
| Python 依赖 | 仅 agent 需要 | 默认 `C:\deepseek\libs-bnb`（torch/transformers/bitsandbytes/accelerate）|

> **搬机器/换目录**：工具本身可以放在任何路径（`fwmap.cmd` 会自己定位）。
> 只有三样是「外部资源」，路径写死时要改：Ghidra、模型、agent 依赖。
> 前两个用环境变量覆盖，第三个是 `PYTHONPATH`。

**验证环境没坏**：

```powershell
cd <你解压出来的目录>\fwmap-tool
py -3.13 tests\test_endpoints.py      # 期望 11/11 passed
```

---

## 目录结构

```
fwmap-tool\
  fwmap\                Python 包（约 2900 行）
    cli.py              命令行入口
    triage.py           一条命令跑完四层 + HTML
    scan.py             M1 挑文件
    m2.py / m3.py       M2 端点、M3.1 源汇提取
    m3flow.py           M3.2 数据流 + 规则（最核心）
    agent\              LLM 取证 + 规则裁决
    tests\              回归测试
  ghidra_scripts\       Ghidra 脚本（M2/M3 必需）
  examples\             示例报告
  案例-负结果-Tenda19.html  实战案例：在饱和目标上做零日猎取
  README.md             本文件
  使用手册.md            详细用法、字段含义、常见坑
```

---

## 实战案例：一次完整的零日猎取（负结果）

`案例-负结果-Tenda19.html`（浏览器打开）记录了对 **Tenda AC15 V15.03.05.19**
—— 一个工具从未见过的构建 —— 的完整猎取过程：

- 187 个 ELF → `httpd` 排第 1；184 个端点 → 142 个定位到 handler；
  87 条候选链 → **保留 42 条，覆盖 25 个函数**。
- 逐条人工复核 + NVD 双路检索（函数名 / 路由名）后：**24 个可达函数全部对应已公开 CVE**，
  剩下 1 个用交叉引用证明是死代码。
- 结论：**该攻击面已被 fuzz 饱和，此目标上不存在零日**。报告同时给出
  4 个工具边界（等值约束、调试日志误判、可达性缺失、GoAhead 归纳失灵）。

> 怎么判断"新不新"这个方法本身比结果重要：**函数名和路由名必须双路检索**。
> 只按函数名查时 `formDLNAserver` 看起来无人报过；按路由名 `SetDlnaCfg` 一查，
> 立刻命中 CVE-2024-10661，且版本号正是 `15.03.05.19`。

---

## 它不能做什么（先看这段，省得到处踩）

1. **不保证找到漏洞。** 它给的是"可疑链"，判断真假还得人看。
2. **报告里的 `CONFIRMED` 不等于漏洞。** 它只表示"模型没看到保护、规则也放了行"。
   实测里 `CONFIRMED` 有相当比例是假阳性（有界拷贝、白名单校验、变量重赋值）。
3. **只处理 ELF。** PHP/lua 驱动的固件直接失明。
4. **挑文件这一层最可靠。** 在 5 个没见过的固件上，目标二进制都排进了前二（4 次第一）。


---

## 换一台机器 / 换个目录

### 1) 先装依赖（Ghidra + JDK）

```powershell
py -3.13 -m fwmap setup --dry-run   # 先看它打算下什么、从哪下
py -3.13 -m fwmap setup             # 真装（约 700 MB，装到 包目录\tools\）
```

- **下载源自动回退**：Ghidra 走 官方 GitHub → ghproxy.net → gh-proxy.com；JDK 走 清华 TUNA → Adoptium。
- **装完自动改配置**：官方 zip 的 `support/launch.properties` 里写死了作者机器的绝对路径（JDK、settings、cache），
  `setup` 会把这几行注释掉，运行时改用随包 JDK，换机器才能跑。
- **网络不通时**：用浏览器/下载工具手动下好 zip，再 `py -3.13 -m fwmap setup --from D:\下载\ghidra_12.2_PUBLIC_xxxx.zip`
  （这条完全不联网，秒级完成）。
- 也可以只装一个：`--ghidra` 或 `--jdk`。

### 2) 再自检

**跑这一条**，它会告诉你缺什么：

```powershell
py -3.13 -m fwmap doctor --agent
```

输出形如：

```
Python      3.13.0  (...\python.exe)
[OK]   包目录      D:\tools\fwmap-tool
[OK]   汇词表      ...\fwmap\data\taint.txt
[OK]   Ghidra      C:\tools\ghidra_12.2_PUBLIC
[OK]   本地模型     C:\tools\models\Qwen2.5-Coder-7B-Instruct
[OK]   accelerate  1.15.0
```

`Ghidra` 和 `本地模型` 这两行是 `[MISS]` 也不影响 `scan`（M1 只读 ELF 头，不需要它们）。

**三样外部资源都是「环境变量 → 常见位置 → 包旁边」三级回退**，所以多数情况下不用配：

| 资源 | 找的顺序 |
|---|---|
| Ghidra | `FWMAP_GHIDRA` / `GHIDRA_HOME` → 常见安装位置 → 包旁边 `tools\ghidra*` → 盘符下 `ghidra*` |
| 本地模型 | `FWMAP_LLM_MODEL` → 内置默认 → 包旁边 `tools\models\*Qwen*` → HuggingFace 缓存 |
| agent 依赖 | `FWMAP_AGENT_LIBS` → `C:\deepseek\libs-bnb`（存在才用） |

找不到时手动指定：

```powershell
$env:FWMAP_GHIDRA     = "D:\tools\ghidra_12.2_PUBLIC"
$env:FWMAP_LLM_MODEL  = "D:\models\Qwen2.5-Coder-7B-Instruct"
$env:FWMAP_AGENT_LIBS = "D:\pylibs\fwmap-deps"
```

## 其它环境变量（调优 / 排错用）

| 变量 | 默认 | 用途 |
|---|---|---|
| `FWMAP_GHIDRA_TIMEOUT` | 1800 | 单次 Ghidra 调用超时（秒）。大二进制跑超时就调大 |
| `FWMAP_M2_DIR` | 当前目录下的 `fwmap-m2\` | Ghidra 工程放哪。放到 SSD 上可明显提速 |

```powershell
$env:FWMAP_GHIDRA_TIMEOUT = "3600"
$env:FWMAP_M2_DIR         = "D:\fwmap-m2"
py -3.13 -m fwmap triage <rootfs> -o out\myfw --agent
```

超时报错里会附上 **Ghidra 自己最后几行输出**，据此判断是卡在导入、分析，还是工程锁。
每个二进制用独立工程目录，上一次残留的锁不会卡住下一次；Ghidra 还用自己的私有临时目录，不依赖系统 `%TEMP%`。