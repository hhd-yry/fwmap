# fwmap

> 固件攻击面分诊工具：从一个**已解包的固件 rootfs** 出发，自动收敛到「先看哪个二进制、它处理哪些端点、哪些外部输入能流到危险函数」，并由本地大模型对每条线索逐条取证。
>
> 目标是降低人工阅读量，而不是自动判定漏洞。

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![LLM](https://img.shields.io/badge/LLM-local%20only-8A2BE2)](#设计取舍)
[![Ghidra](https://img.shields.io/badge/backend-Ghidra%2012.x-orange)](https://ghidra-sre.org/)

---

## 概述

嵌入式固件通常包含数百个可执行文件，人工逐个审计不现实。`fwmap` 采用四层收敛流程：

1. **按攻击面排序**，把上千个文件压缩到一两个目标；
2. **建立端点与处理函数的映射**；
3. **在反编译出的 C 代码上做语句级污点分析**，输出「源 → 汇」候选链；
4. **调用本地 LLM 逐条取证**，由规则给出最终裁决。

全流程离线运行，不依赖任何在线 API。

---

## 核心特性

- **分层收敛**：每一层都可以单独运行，越靠前的层越稳定，越靠后的层越依赖人工复核。
- **证据可回溯**：每条链都带源、汇、中间语句与守卫代码，报告可直接定位到反编译行。
- **模型只取证、不做裁决**：LLM 仅回答「危险调用前是否存在有效检查」，且必须以**语句下标**作答，证据文本由程序回填。裁决由规则计算，避免模型幻觉直接影响结论。
- **多采样自洽**：同一线索采样 3 次，不一致即弃权（`UNPROVEN`）。
- **零配置迁移**：Ghidra、模型、依赖均支持「环境变量 → 常见路径 → 包内相对路径」三级回退；`fwmap setup` 可自动安装 Ghidra 与 JDK。
- **一键自检**：`fwmap doctor` 输出环境检查表。
- **新颖性核对**：`fwmap verify` 按「函数名 + 路由名」双路检索 NVD，自动判断线索是否已被公开报告。
- **断网可用**：`fwmap nvd` 把 NIST 官方 CVE 全量数据（2002 至今，42 万条）建成离线库；`verify` 有网走 API、没网查本地，结论一致。

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
                   report.html
```

| 层 | 命令 | 输入 → 输出 | 依赖 | 典型耗时 |
|---|---|---|---|---|
| M1 | `scan` | rootfs → 二进制排名 | — | 数十秒 |
| M2 | `m2` | 单个 ELF → 端点/处理函数表 | Ghidra | 1–2 分钟 |
| M3 | `m3 --induce --flow` | 函数 → 源到汇的链 | Ghidra | 数分钟至数十分钟 |
| 复核 | `agent` | 链 → 裁决 + 证据 | 本地模型 | 每条 20–75 秒 |
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

**动态验证**：在 QEMU 中运行真实固件，复现 D-Link DIR-842 的栈溢出，返回地址完全受控（`pc = ra = 0x41414141`），对应 CVE-2020-8962。

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
│   ├── triage.py           四层串联与报告生成
│   ├── setup.py            依赖安装
│   ├── elf.py              ELF 解析（支持 sstrip）
│   └── agent/              LLM 取证与规则裁决
├── ghidra_scripts/         13 个 Ghidra 脚本
├── tests/                  回归测试
├── examples/               示例流程与报告
├── 使用手册.md              详细用法
├── 案例-负结果-Tenda19.html  实战案例
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
| `verify` | 新颖性核对：函数名 + 路由名双路检索（有网走 API，没网用离线库） |
| `nvd` | 离线 NVD 索引：`fetch` / `build` / `update` / `check` / `status` / `search` |
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
- [案例-负结果-Tenda19.html](案例-负结果-Tenda19.html)：实战分析记录

---

## License

[MIT](LICENSE)
