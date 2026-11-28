# fwbench P2：生产决策入口 + 归档回归

> **日期**：2026-11-28　**基线**：`337cb36` 之后
> **依据**：实施计划第 7 节（用已知记录验收评测器本身）、P2 门槛

---

## 一、接上生产决策入口（`run_subject`）

新增被测工具 `fwmap-agent`（`fwbench/subjects/fwmap_agent.py`）：

| 项 | 内容 |
|---|---|
| 决策来源 | **直接调** `fwmap.agent.loop._decide(state, chat)` —— 生产函数，不重写 |
| 执行 | `probe` 动作落到评测器的只读后端 `read_record` |
| 输出映射 | 谁读过、哪条记录主体与任务一致 → 按它作答（`claim` + `citations`） |
| 标注 | manifest 里 `capability=record-triage`；分数性质为 **adapted**（决策是生产的、执行是评测器的） |

实测（`--suite smoke --subject fwmap-agent`）：

```
c017 ✅  c018 ✅    通过 2/2，双例 1/1
```

事件里能看出决策来源：

```json
{"seq":1,"type":"decision","action":"read:e1","proposed_by":"heuristic"}
{"seq":3,"type":"decision","action":"read:e2","proposed_by":"heuristic"}
{"seq":5,"type":"decision","action":"read:e3","proposed_by":"heuristic"}
{"seq":7,"type":"decision","action":"done",  "proposed_by":"heuristic"}
```

**一个可写进报告的观察**：生产规则循环**不提前收工**——它把三条候选全部读完才 `done`，
而评测器自带的 `rule` 策略读 1 条就作答。同一任务，**工具调用 3 次 vs 1 次**。
这是"决策成本"这一栏的真实数据，不是估算。

---

## 二、第 7 节 #1–#4：归档回归

新增 `fwbench/archive.py` + `python -m fwbench archive`：

```bash
python -m fwbench archive lab/recordings --expect 5,5,0
```

实测输出：

```
| 组 | 命中/有效 | 命中/计划 | 模型参与 | 证据强度 |
| temp00 | 5/5 | 5/5 | 75%（30/40 步） | 进程退出已确认 |
| temp07 | 5/5 | 5/5 | 78%（31/40 步） | 进程退出已确认 |
| anon   | 0/5 | 0/5 | 24%（9/38 步）  | 没有形成结论 |
[+] 与期望一致：5,5,0
```

逐条对应计划：

| 计划要求 | 实现 | 结果 |
|---|---|---|
| #1 离线复算三组 | `summarize_groups` 读 15 份原始 JSON | **5/5、5/5、0/5** ✅ |
| #2 百分比 | `model_share`：内部 0.75，渲染 75%；合成 2/8 → 0.25 | ✅ 不写死 |
| #3 证据强度 | `support_counts` + `_strength_text` 由计数生成文字 | ✅ 三档都能区分 |
| #4 分母 | `recount`：遍历全部 findings、两个分母、损坏/缺失分开计 | ✅ 2/3 与 2/5 |

**#4 的合成用例**特意把命中放在**第二条**结论里，验证"不只看第一条"。

## 三、第 7 节 #6：断点续跑

`run --resume` 以「用例 + 已落盘 submission」定位轮次：

- 删掉 `c018` 后重跑，只补 `c018` 一行，`c017` 不重复执行也不被覆盖；✅
- 配置变化写入已有目录仍直接报错（`输出目录已有内容`），需显式 `--resume`。✅

## 四、第 7 节 #5、#7 的现状

| 项 | 状态 |
|---|---|
| #5 独立金标 | 机制齐全（金标只在评分加载、替换金标重判已验证）；**人工复核**仍未做，所有金标 `provisional=true` |
| #7 核验边界 | 已测：运行目录不含金标、引用未读记录判失败、引用不支持判失败；**未测**：越界路径、编造记录号 |

---

## 五、这一轮新增/修改的文件

| 文件 | 说明 |
|---|---|
| `fwbench/subjects/fwmap_agent.py` | 生产决策入口适配器 |
| `fwbench/archive.py` | 归档复算 + 文字渲染 |
| `fwbench/runner.py` | 支持 `supports_interactive` 的被测工具 |
| `fwbench/__main__.py` | `archive` 子命令 |
| `tests/test_fwbench.py` | 21 → **35 项**检查 |
| `bench/README.md` | 补 archive / fwmap-agent / resume |

---

## 六、仍然没有覆盖的

| 项 | 影响 |
|---|---|
| 真实模型 `M` 组 | `fwmap-agent` 目前只用规则分支（`chat=None`）；接模型后才有 M 组 |
| 其余五个家族 | 只做了「运行状态」 |
| A 层 12 例 / B 层 8 例 | 现在 A 层 3 例（elfmeta），B 层 0 例 |
| `pyelftools` 真跑 | 仍未安装 |
| 人工复核金标 | 全部 `provisional` |

**结论边界**：现在的分数只说明「评测器可用且能接生产决策」，**不能**当作 fwmap
交互能力的结论——样本只有 2 例 + 3 例。
