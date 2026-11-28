# fwbench P0：盘点与契约

> **日期**：2026-11-28　**基线提交**：`3fa15af`（计划参照点，与当前 HEAD 一致）
> **依据**：`fwmap-端到端交互能力评测工具实施计划.md`（2026-11-28）
> **本文件交付**：生产入口调用图、覆盖矩阵、字段映射、32 例目录草案、需注入的最小接口

---

## 一、生产入口调用图（已按当前代码核对）

| 入口 | 实际签名 | 位置 |
|---|---|---|
| ELF 解析 | `read_elf(data: bytes) -> ELFInfo` | `fwmap/elf.py:223` |
| 解包自检 | `check(root: str, max_files: int = 200_000) -> dict` | `fwmap/check.py:25` |
| 证据缺口 | `missing_evidence(chain: dict) -> list[str]` | `fwmap/m3flow.py:677` |
| 工具总线 | `run(tool, src, outdir, *, timeout=None) -> dict` | `fwmap/toolbus.py:130` |
| 工具目录 | `catalog(capability: str \| None = None) -> list[dict]` | `fwmap/toolbus.py` |
| 生产决策循环 | `run(binary, rootfs=None, *, chat=None, max_steps=8, probe=None, ...)` | `fwmap/agent/loop.py:719` |

**调用关系（当前实际）**：

```
fwmap plan ──► agent/loop.run ──► _decide ──► agent/llm.chat（可选）
                        │            └──► _heuristic（规则兜底）
                        └──► _execute ──► pages.scan / discover.apply_plan
                                       └──► toolbus.run
                                       └──► firmware_probe（动态探针，可选）
```

`loop.run` 已经具备评测需要的三样东西：
**逐步 `source`（model / heuristic）**、**`findings` 带证据引用**、**`handoff` 汇总**。
这意味着 C 层接入不需要改生产逻辑，只需要一个 `run_subject` 适配器。

---

## 二、覆盖矩阵（首版 32 例）

| 层 | 能力 | 生产函数 | 用例数 | 运行方式 |
|---|---|---|---|---|
| A | ELF 头解析 | `elf.read_elf` | 3 | **实调** |
| A | 解包完整性检查 | `check.check` | 3 | **实调** |
| A | 证据缺口生成 | `m3flow.missing_evidence` | 3 | **实调** |
| A | 工具总线成功判据 | `toolbus.run` | 3 | **实调**（受控小样本） |
| B | 上游产物 → 报告 | `missing_evidence` + 报告渲染 | 3 | **归档回放** |
| B | 空产物 / 错对象 / 冲突记录 | 同上 | 3 | **合成** |
| B | 中途缺依赖 | `loop.run` + 缺失依赖 | 2 | **合成** |
| C | 六家族 × 每族 2 例 | `agent/loop.run` 或策略替身 | 12 | **合成**（首版 2 例实测） |

**合计 32 例**。`smoke` 为其中 6 例的快速子集，当前已实现 2 例（`c017` / `c018`）。

> 标注规则：**实调**＝真的调用生产函数并读它的返回值；
> **归档回放**＝读 `lab/recordings/` 的已落盘 JSON；
> **合成**＝评测器自造记录。三者不得混着算同一个指标。

---

## 三、字段映射（生产结果 → 提交格式）

| 生产字段 | 提交字段 | 说明 |
|---|---|---|
| `findings[].uri` | `claim` 的对象部分 | 端点即"对象" |
| `findings[].kind` | `claim` | `crash` / `suspicious` / `normal` |
| `findings[].evidence[]` | `citations` | 逐条引文映射为记录 id |
| `findings[].support` | 证据强度 | `observed-only` / `process-exit` |
| `stats.model_steps` | `proposed_by` 统计 | 参与率，不代替正确率 |
| `stats.fallback_steps` | `fallback_reason` | 兜底次数与原因 |
| `status` / `stop_reason` | 进程结束原因 | **与任务成败分开记** |

`invalid_submission` 时保留生产原文，不猜。

---

## 四、C 层六家族目录草案

| 家族 | 任务 | 双例之间改什么 | 已实现 |
|---|---|---|---|
| **运行状态** | 判断服务在指定时刻的状态 | e2 的 `state`：exited / running | ✅ `c017`/`c018` |
| 制品完整性 | 判断解包产物能否交付 | 关键产物完整 / 截断 | ⬜ |
| 版本识别 | 同名组件里确定对应版本 | 清单摘要与制品的关系 | ⬜ |
| 时序归属 | 一条日志是否属于本次运行 | 消息归属本次 / 前次 | ⬜ |
| 报告一致性 | 核对摘要与逐轮记录 | 摘要相同，有效轮数不同 | ⬜ |
| 证据可得性 | 据材料完成一次验收 | 证据齐全 / 证据源缺失 | ⬜ |

---

## 五、需要注入的最小接口

首版已在 `fwbench/adapters.py` 定义四个接口。要接真实生产入口，
**只需要实现 `run_subject`**，其余三个不变：

| 接口 | 现状 | 接生产要做什么 |
|---|---|---|
| `open_case` | ✅ 已实现 | 无（只给元信息） |
| `dispatch` | ✅ 回放后端 | 换成调用 `toolbus.run` 的只读白名单 |
| `run_subject` | ✅ 已实现 `fwmap-agent`：直接调 `loop._decide`，动作映射到只读后端 | 见 `docs/fwbench-P2-生产入口与归档回归.md` |
| `score` | ✅ 已实现 | 无 |

**替身必须标 `harness-only`**：当前 `rule` / `scripted` 两个策略都不是
fwmap 的生产决策入口，所以现在的分数只证明评测器可用，**不能给 fwmap 的交互能力记分**。

---

## 六、尚未覆盖（写清楚，别越界解读）

| 项 | 状态 |
|---|---|
| 真实模型 `M` 组 | ⬜ 未接入 |
| 基线 `H`（领域知识） | ⬜ 未实现 |
| 信息消融（遮掉记录类型） | ⬜ 未实现 |
| IDA / Mango 补证 | ⬜ 不在首版范围 |
| 动态验证（qemu） | ⬜ 沿用 `lab/recordings/` 已有记录，不新跑 |
| 其余五个家族 | ⬜ 未实现 |

---

## 七、下一步（P1 收尾 → P2）

1. ~~实现 `run_subject`~~ —— 已实现（`fwmap-agent`，调 `loop._decide`，事件带 `proposed_by`），见 P2 文档；
2. 合并计划第 7 节的五条回归（离线复算 / 百分比 / 证据强度 / 分母 / 独立金标）——
   其中前三项目前只覆盖了"证据强度"和"分母"两类的评测器侧，
   历史归档复算要等 `lab/recordings/` 接入；
3. P2 再补 A/B 层 20 例。
