# fwmap

> 从一个**已解包的固件 rootfs** 出发，自动收敛到「先看哪个二进制、哪些外部输入能流到危险函数」，
> 再回答两个收尾问题：**这是不是别人已经报过**（离线 42 万条 CVE）、**它现在真的打得动吗**（qemu 里真跑）。

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![LLM](https://img.shields.io/badge/LLM-local%20only-8A2BE2)](#设计取舍)
[![Ghidra](https://img.shields.io/badge/backend-Ghidra%2012.x-orange)](https://ghidra-sre.org/)
[![Offline](https://img.shields.io/badge/offline-42%E4%B8%87%E6%9D%A1CVE%E6%9C%AC%E5%9C%B0%E5%BA%93-success)](#新颖性核对verify)

---

## 一句话看懂

```
固件 rootfs（上千个文件）
   │  M1 排序      →  挑出 1 个目标二进制
   │  M2 端点      →  45 个 URL，映射到处理函数
   │  M3 数据流    →  13 条「外部输入 → 危险函数」的链
   │  verify       →  9 条已公开 / 6 条没查到
   │  dyn          →  真跑固件打一发：命令执行了？崩了？还是没跑起来？
   ▼
十几条可复核的线索 + 证据（或者明确告诉你「这里没有」）
```

全程离线，不依赖任何在线 API。

---

## 30 秒演示（真实输出）

```bash
python -m fwmap autopilot <rootfs> --llm
```

```
[llm] Qwen2.5-Coder-7B-Instruct loaded in 18s, VRAM 5.56 GB
[1] (模型) 还没有确认解包完整性           → check   ← 有问题（阻断 1 项）
[2] (模型) 需要确定攻击面，选优先级最高的   → scan    ← 78 个 ELF，最高分 87（bin/webs）
[3] (规则) 要把函数对上 URL               → m2      ← 端点 45 个
[4] (规则) 端点知道了，现在找链            → m3      ← 候选 51 条，保留 13 条
[5] (规则) 先查有没有人报过               → verify  ← 已公开 5 / 未命中 2
[6] (规则) 这 2 个没被报过，真打一发       → dyn     ← 跳过（本机没有 qemu）

用时 810.1s · 端点 45 · 链 13 · 已公开 5 / 未命中 2
值得人工深挖：getiNICIndex, getiNICInfo
```

每一步都标了 **谁做的决定**（模型 / 规则），以及 **为什么这么做** —— 不是黑箱跑一遍。

---

## 能做什么 / 不能做什么

| ✅ 能 | ❌ 不能 |
|---|---|
| 把上千个文件收敛到十几条线索 | 自动判定「这是漏洞」 |
| 判断线索**是否已被公开**（断网可用） | 发现跨服务、跨进程的逻辑漏洞 |
| 在 qemu 里真跑固件，并用**对照组**排除环境干扰 | 自动写 exploit（只到「命令执行」和「溢出阈值」） |
| 命令注入**直接执行任意命令**并取证 | 覆盖 PHP / Lua / JS 驱动的固件 |
| 让本地 LLM 提议下一步，规则兜底 | 让 LLM 自己提出攻击假设 |

---

## 真实性说明：我们测过什么

| 固件 | 做了什么 | 结果 |
|---|---|---|
| **Edimax BR-6478AC** | 全链 + 动态 | **命令注入复现成功**（`/etc/passwd` 真的被拷出来）；溢出阈值 ≈800 字节（两次测量 799 / 801） |
| Tenda AC15 | 全链 + 新颖性 | 24/25 可达函数对应公开 CVE，剩余 1 个经交叉引用确认为死代码 |
| TRENDnet TEW-818DRU | 全链 | 82 端点 / 40 链，符号全被 strip；动态被 nvram 设备挡住 |
| ASUS RT-AC68U（2026-05） | 全链 + 版本差分 | 65 条链，2 个注入候选追到底都不成立；差分发现 2 条**已修**的问题 |

> **四个固件、五轮打法，没挖到过 0day。**
> 这个工具是**漏斗和验证器**，不是挖掘机 —— 它能把「人工翻上千个文件」变成
> 「看十几条带证据的线索」，也能明确告诉你「这里没有」，但它不替你做最终判断。
>
> 完整过程见 [`docs/全过程命令实录.md`](docs/全过程命令实录.md)。

---

## 四条设计原则

1. **模型只取证、不做裁决。**
   LLM 只回答「危险调用前有没有检查」，且必须以**语句下标**作答，证据文本由程序回填；
   裁决由规则计算，避免模型幻觉直接影响结论。
2. **证据可回溯。**
   每条链都带源、汇、中间语句与守卫代码，报告能定位到反编译行。
3. **结论必须分得清「没跑」和「没有」。**
   解包失败、查询超时、服务没起来，都不允许写成「没发现漏洞」——
   这是这类工具最容易犯、也最致命的错。
4. **断网可用。**
   CVE 库、模型、Ghidra 全在本地；`verify` 有网走 API、没网查离线库，两边结论一致。

---

## 工作流程

```
                固件 rootfs（已解包）
                        │
   ┌────────────────────┼────────────────────┐
   │                    │                    │
  M1 scan             M2 m2               M3 m3 --flow
 二进制排序        端点 → handler       源/汇提取 + 数据流
 （无 Ghidra）      （Ghidra）           （Ghidra + 反编译）
   │                    │                    │
   └────────────────────┴────────────────────┘
                        │
                   Agent 复核
              （本地 LLM 取证 + 规则裁决）
                        │
         ┌──────────────┴──────────────┐
         │                             │
    verify 新颖性核对              dyn 动态验证
  （离线 42 万条 CVE）           （qemu 真跑固件）
   已公开/未命中/需人工           对照组 → 载荷 → 崩溃 / 命令执行
         │                             │
         └──────────────┬──────────────┘
                        │
                   report.html
```

| 层 | 命令 | 输入 → 输出 | 依赖 | 典型耗时 |
|---|---|---|---|---|
| M1 | `scan` | rootfs → 二进制排名 | — | 数十秒 |
| M2 | `m2` | 单个 ELF → 端点/处理函数表 | Ghidra | 1–2 分钟 |
| M3 | `m3 --induce --flow` | 函数 → 源到汇的链 | Ghidra | 数分钟至数十分钟 |
| 复核 | `agent` | 链 → 裁决 + 证据 | 本地模型 | 每条 20–75 秒 |
| 核对 | `verify` | 链 → 已公开 / 未命中 | 离线库或 NVD API | 0.3 秒 / 函数（离线） |
| 验证 | `dyn` / `bof` | 链 → 崩溃 / 命令执行 / 溢出阈值 | qemu（+ root） | 每条数十秒 |
| 汇总 | `triage` | rootfs → 完整 HTML 报告 | 以上全部 | 约 10–30 分钟 |

---

## 快速开始

```bash
# 1) 仅排序：不需要 Ghidra，几十秒出结果
python -m fwmap scan <rootfs> --top 10

# 2) 完整流程：四层 + 本地模型复核
python -m fwmap triage <rootfs> -o out/myfw --agent

# 报告
out/myfw/report.html
```

首次使用建议先执行环境检查：

```bash
python -m fwmap setup --dry-run    # 查看将安装的组件与下载源
python -m fwmap setup              # 安装 Ghidra + JDK（约 700 MB）
python -m fwmap doctor --agent     # 环境自检
```

断网机器还要准备离线 NVD 库（否则 `verify` 只能联网用）：

```bash
python -m fwmap nvd fetch          # 下载官方年包（约 240 MB）
python -m fwmap nvd build          # 建索引（约 90 秒）
```

> **Windows 提示**：若 `python` 指向旧版本（例如 Anaconda 2.x），请改用 `py -3.13 -m fwmap`；
> 也可直接使用 `fwmap.cmd`，它会自动切换工作目录并设置编码，可从任意路径调用。

---

## 输出示例

报告包含四个部分：

1. **二进制排序**：分数、角色、架构、体积、端点数量；
2. **端点映射**：每个 URL 对应的处理函数与置信度；
3. **LLM 复核**：每条链的裁决（`CONFIRMED` / `REFUTED` / `REVIEW` / `UNPROVEN`）、理由与引用代码；
4. **边界说明**：工具自身的能力限制。

示例报告见 [`examples/示例报告-DIR842.html`](examples/示例报告-DIR842.html)。

---

## 新颖性核对（verify）

判断一条线索「是不是已经被人报过」，是整条流程里最容易出错的一步。

`verify` 采用**双路检索**：

1. 用**函数名**查 NVD —— 多数公告会写函数名；
2. 再用它对应的**路由名**查一次 —— 很多公告只写 URL，不写函数名。

```bash
# 输入可以是 triage 的 report.json（自带端点映射）
python -m fwmap verify out/myfw/report.json

# 也可以拆开：数据流 + 端点映射
python -m fwmap verify out/3_m3.flow.json --m2 out/2_m2.json

# 先看看它会查哪些关键词，不发请求
python -m fwmap verify out/3_m3.flow.json --m2 out/2_m2.json --dry-run
```

结论分三类：

| 结论 | 含义 |
|---|---|
| `known` | 命中已公开 CVE（并确认关键词出现在描述里） |
| `unknown` | 按函数名/路由名都没查到 |
| `manual` | 函数名为 `FUN_xxxx` / `sub_xxxx`，无法检索，需人工 |

**实测**：`formDLNAserver` 按函数名查不到任何记录；按路由名 `SetDlnaCfg` 一查即命中
**CVE-2024-10661**，描述中的版本号 `15.03.05.19` 与目标完全一致。

### 数据源：有网走 API，没网用本地库

`--source auto`（默认）会先探一下网络：**通就用 NVD 在线 API，不通就退回本地的
离线 NVD 库**，两边判定逻辑完全一样。有网时加 `--update-index`，跑完顺手把本地库
刷到最新 —— 这样下次断网还有新数据可用。

```bash
python -m fwmap nvd fetch && python -m fwmap nvd build   # 建离线库（一次性，约 240 MB / 90 秒）
python -m fwmap nvd update                               # 有网时增量更新：只下变了的年包
python -m fwmap verify ... --update-index                # 核对完顺手更新
python -m fwmap verify ... --source local                # 强制离线
```

| | 在线 API | 离线库 |
|---|---|---|
| 网络 | 必须 | 不需要 |
| 用时（15 个函数） | ~97 s（限流 5 次 / 30 秒） | **2.6 s** |
| 可复现 | 否 | 是（报告写明快照日期） |
| 结论 | 9 已公开 / 6 未命中 | 完全一致 |

详见 [`docs/离线NVD.md`](docs/离线NVD.md)。

> **`unknown` 不等于新漏洞。** 它只说明按这个名字在 NVD 里查不到；大量固件漏洞从未申请 CVE，
> 或公告只写型号和 URL。结论必须人工复核。
>
> 在线模式下 NVD 无 API key 时限流约 5 次 / 30 秒，本命令默认间隔 6.5 秒并把结果缓存 7 天
> （`~/.fwmap/nvd-cache.json`），重复核对不会重复请求。

`triage` 已经默认接上这一步（`--no-verify` 可关），所以**一条命令出的报告自带「已公开 / 未命中」列**，
不用跑完再去补一条命令。

---

## 动态验证（dyn）

静态分析说「链在这」，`verify` 说「别人报过类似的」，都还没回答最后一个问题：**它现在真的会崩吗**。

`dyn` 做的是最小闭环：把链翻译成 PoC → 用 qemu 把二进制跑起来 → 把请求打进去 → 看进程是
正常退出、被信号打死、还是根本没起来。

```bash
# 先看要打什么（不发请求）
python -m fwmap dyn out/3_m3.flow.json --m2 out/2_m2.json \
    --binary out/root/bin/webs --rootfs out/root --dry-run -o poc.md

# 真跑（需要 qemu-user；Linux 上 apt install qemu-user-static）
python -m fwmap dyn out/3_m3.flow.json --m2 out/2_m2.json \
    --binary out/root/bin/webs --rootfs out/root --port 8080

# 命令注入：直接执行任意命令，并拿副作用当证据
python -m fwmap dyn out/3_m3.flow.json --m2 out/2_m2.json \
    --binary out/root/bin/webs --rootfs out/root --port 80 \
    --cmd "cp /etc/passwd /tmp/pwned" --check /tmp/pwned
```

`--cmd` 只对命令注入类生效：工具会把命令包成能突破常见包装的形态
（固件常把值塞进 `echo '%s'` 且按 `;` 截断，所以要「单引号闭合 + 换行」），
`--check` 则在执行后去固件里读那个文件——**命令副作用才是证据，不是崩溃**。

PoC 按汇的类别选载荷：

| 汇类别 | 载荷 | 判据 |
|---|---|---|
| `bof` | 64 / 200 / 512 / 1024 / 2048 字节，由短到长 | 进程被信号打死 |
| `ci` | `;id;`、`` `id` ``、`$(id)` | 响应里出现命令输出 |
| `fmt` | `%08x.` 连发 | 响应里漏出栈内容 |

三种结论**必须分开**，这是这一步最容易出错的地方：

| 状态 | 含义 |
|---|---|
| `crash` | 进程被信号打死 / 模拟器报 uncaught target signal —— 有崩溃证据 |
| `no-crash` | 请求打完了，进程还活着 —— **没有**崩溃证据，不等于安全 |
| `no-listener` | 服务根本没起来（缺配置、要 root 绑 80）—— **未验证**，不是「没漏洞」 |

开跑之前会先打一发**对照组**（无害 `GET /`）。固件在模拟器里经常因为缺 NVRAM、
缺 `/dev`、缺配置而「一请求就崩」；对照组的目的是把这种**环境崩溃**和真正的
载荷触发分开——对照组也崩的话，整份结果直接标成 `环境崩溃·未验证`，不当成漏洞。

当前机器没有 qemu-user 时，命令只会生成 PoC 并打印该在哪儿跑，**不会假装跑过了**。

执行链路本身用一个合成靶子（`examples/合成靶子.c`，故意 `strcpy` 溢出 64 字节栈缓冲区）
验证过：64 字节不崩、200 字节被访问违例打死（`0xC0000005`）。结果见
[`examples/合成靶子-dyn验证.md`](examples/合成靶子-dyn验证.md)。

在真固件（Edimax BR-6478AC）上把 webs 跑起来的完整踩坑记录、以及
NVRAM（`/dev/mtdblock0` ← `etc/config.bin`）怎么补，见
[`docs/动态验证-固件起机.md`](docs/动态验证-固件起机.md)。



---

## 评测结果

**二进制排序（M1）**：在 5 个未参与调参的固件上，人工认定的目标二进制全部进入前二，其中 4 次排名第一。

**链级判定**：46 条人工标注链（跨 3 个厂商），3 次采样下：

| 指标 | 数值 |
|---|---|
| 准确率 | 97% |
| 精确率 | 97% |
| 召回率 | 100% |
| 弃权 | 4 条 |

> 上述指标基于标注集，不代表真实环境中的绝对精度。`CONFIRMED` 仍需人工核对。

**动态验证**：在 Ubuntu + qemu-user-static 上把 Edimax 的 `webs` 真跑起来 ——
命令注入已复现（`/etc/passwd` 真的被拷出来）、溢出阈值 ≈800 字节，
并用**对照组**证明了不是环境碰巧。细节见
[`docs/动态验证-固件起机.md`](docs/动态验证-固件起机.md) 与
[`docs/全过程命令实录.md`](docs/全过程命令实录.md)。

> 精确 `ra` 偏移与 PC 可控**尚未**拿下（Boa 每连接 fork，qemu 的 gdbstub 跟不到子进程），
> 状态见 [`docs/L2-返回地址可控.md`](docs/L2-返回地址可控.md)。

**动态验证（合成靶子）**：`examples/合成靶子.c` 故意 `strcpy` 溢出 64 字节栈缓冲区，
64 字节不崩、200 字节被访问违例打死（`0xC0000005`），用来证明执行链路本身可用。


---

## 设计取舍

- **模型不作为裁决者。** LLM 的输出仅包含语句下标与分类标签，真值判定由 `agent/judge.py` 的规则完成。
- **数据流基于反编译 C 代码，而非 P-code。** 精度略低，但证据可直接呈现给人工复核，符合工具定位。
- **未知即未知。** 无法确定 handler 的端点标为 `low` 置信度，不做猜测；无法确认外部可控的源标为 `weak`。

---

## 环境要求

| 组件 | 要求 | 说明 |
|---|---|---|
| Python | 3.10+ | |
| Ghidra | 12.x | 需 Java 25；`fwmap setup` 可自动安装 |
| 本地模型 | 可选 | 默认 Qwen2.5-Coder-7B-Instruct（4-bit，约 5.6 GB 显存） |

`Ghidra` 与本地模型仅在运行 M2/M3 与 `--agent` 时需要；`scan` 无任何外部依赖。

---

## 路径与环境变量

三类外部资源均按 **环境变量 → 常见安装位置 → 包内 `tools/`** 的顺序查找：

| 资源 | 环境变量 |
|---|---|
| Ghidra | `FWMAP_GHIDRA` / `GHIDRA_HOME` / `GHIDRA_INSTALL_DIR` |
| 本地模型 | `FWMAP_LLM_MODEL` |
| Agent 依赖 | `FWMAP_AGENT_LIBS` |

调优与排错：

| 变量 | 默认 | 用途 |
|---|---|---|
| `FWMAP_GHIDRA_TIMEOUT` | 1800 | 单次 Ghidra 调用超时（秒） |
| `FWMAP_M2_DIR` | `./fwmap-m2` | Ghidra 工程目录 |
| `FWMAP_IDLE_TIMEOUT` | 60 | 下载空闲超时（秒） |
| `FWMAP_GHIDRA_URL` / `FWMAP_JDK_URL` | — | 覆盖下载地址（内网/镜像环境） |

网络受限时，可手动下载 Ghidra 后本地安装，不联网：

```bash
python -m fwmap setup --from /path/to/ghidra_12.2_PUBLIC_xxxx.zip
```

---

## 目录结构

```
fwmap-tool/
├── fwmap/                  Python 包
│   ├── cli.py              命令行入口
│   ├── scan.py             M1 二进制排序
│   ├── m2.py               M2 端点映射
│   ├── m3.py               M3.1 源/汇提取与框架归纳
│   ├── m3flow.py           M3.2 数据流分析（核心）
│   ├── auth.py             M2.5 端点鉴权检查
│   ├── verify.py           M4 新颖性核对
│   ├── nvd.py              离线 NVD 索引（fetch / build / update）
│   ├── poc.py              PoC 生成（按汇类别选载荷）
│   ├── dyn.py              动态验证（qemu 执行 + 对照组）
│   ├── exploit.py          溢出阈值 / 返回地址可控性探测
│   ├── triage.py           四层串联与报告生成
│   ├── check.py            rootfs 解包自检
│   ├── setup.py            依赖安装
│   ├── elf.py              ELF 解析（支持 sstrip）
│   └── agent/              LLM 取证与规则裁决
├── ghidra_scripts/         13 个 Ghidra 脚本
├── tests/                  8 套回归测试
├── examples/               示例报告、合成靶子
├── docs/                   专题文档（离线 NVD / 固件起机 / L2 / A 轮）
├── 使用手册.md              详细用法
└── README.md
```

---

## 命令参考

| 命令 | 作用 |
|---|---|
| `scan` | 二进制排序，生成攻击面地图 |
| `m2` | 端点 → 处理函数映射 |
| `auth` | 端点鉴权检查：handler 及调用者里有没有认证 |
| `m3` | 源/汇提取与数据流分析 |
| `agent` | 对已有链运行 LLM 复核 |
| `triage` | 串联四层，生成 HTML 报告 |
| `autopilot` | **智能体**：自己决定调哪个工具，一路跑到结论并输出调查日志 |
| `tools` | 列出智能体能调用的工具（名字 / 用途 / 参数） |
| `plugin` | 插件对接：`init` 生成模板、`test` 自测外部工具能不能接进来 |
| `verify` | 新颖性核对：函数名 + 路由名双路检索（有网走 API，没网用离线库） |
| `nvd` | 离线 NVD 索引：`fetch` / `build` / `update` / `check` / `status` / `search` |
| `dyn` | 动态验证：把 PoC 打进模拟器里的二进制，看它崩不崩 |
| `bof` | 栈溢出：`--threshold` 二分出「多长就崩」，串起 qemu+gdb 读寄存器 |
| `check` | 校验 rootfs 解包完整性 |
| `doctor` | 环境自检 |
| `setup` | 安装 / 校验 Ghidra 与 JDK |

---

## 已知限制

1. **不保证发现漏洞。** 输出为待验证线索，最终判定需人工完成。
2. **`CONFIRMED` 不等于漏洞。** 该结论仅表示模型未发现有效检查且规则放行；有界拷贝、白名单校验、变量重赋值等仍可能构成假阳性。
3. **仅处理 ELF。** 由 PHP/Lua 驱动的固件无法分析。
4. **端点可达性未闭环。** 未注册路由且无交叉引用的死代码仍可能出现在候选中。
5. **框架归纳存在边界。** 当前归纳规则针对 Tenda/D-Link 一类写法；在 GoAhead 等框架上识别率显著下降。
6. **鉴权判定只看证据存在性。** `unprotected` 是未鉴权候选，父级函数或前置代理鉴权无法完全排除；`protected` 不保证鉴权实现正确（弱比较、可预测 token 查不出来）。
7. **动态验证需要 Linux + root。** chroot 起机、绑 80 端口都要 root；真正跑起来还常需要补 NVRAM（见 `docs/动态验证-固件起机.md`）。
8. **`bof` 只到阈值，未到 PC 可控。** fork 型目标（Boa）崩溃在子进程，qemu gdbstub 跟不到，精确 `ra` 偏移仍未拿下。
9. **`fmt` 类尚未验证。** 只标可疑，没做 `%x` 泄漏验证。
10. **解包务必在 Linux 上做。** Windows 解 squashfs 会把符号链接变成 0 字节文件，`/bin/sh` 变空，固件里所有 `system()` 都会 `ENOEXEC`；`fwmap check` 会拦这种情况。

---

## 案例研究

[`案例-负结果-Tenda19.html`](案例-负结果-Tenda19.html) 记录了对 Tenda AC15 V15.03.05.19 的完整分析过程：

- 187 个 ELF → `httpd` 排名第一；184 个端点 → 142 个定位到处理函数；
- 87 条候选链 → 保留 42 条，覆盖 25 个函数；
- 逐条人工复核并做 NVD 双路检索（函数名 + 路由名）后，24 个可达函数均对应已公开的 CVE，剩余 1 个经交叉引用确认为死代码。

结论：该攻击面已被充分研究，未发现新漏洞。报告同时总结了四类工具边界与判定方法。

---

## 文档

- [使用手册.md](使用手册.md)：完整用法、字段含义、常见问题
- [docs/离线NVD.md](docs/离线NVD.md)：把 NIST 官方 42 万条 CVE 做成断网可用的本地库
- [docs/智能体-autopilot.md](docs/智能体-autopilot.md)：让工具自己决定下一步（工具注册表 + 决策循环）
- [docs/融合对接指南.md](docs/融合对接指南.md)：把别人的工具接进来（manifest + 自测，对方不用改代码）
- [docs/动态验证-固件起机.md](docs/动态验证-固件起机.md)：把固件在 qemu 里真正跑起来的六个坑，以及 NVRAM 怎么补
- [docs/L2-返回地址可控.md](docs/L2-返回地址可控.md)：溢出阈值与「PC 可控」还差什么
- [docs/A轮-筛查未报过的handler.md](docs/A轮-筛查未报过的handler.md)：7 个从未进过 CVE 的 handler 的筛查结论
- [案例-负结果-Tenda19.html](案例-负结果-Tenda19.html)：Tenda AC15 的完整分析记录

---

## License

[MIT](LICENSE)
