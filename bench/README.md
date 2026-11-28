# fwbench —— fwmap 的端到端交互能力评测器

回答问题：**fwmap 的模块能否产出正确结果？模块组合后证据能否传到报告？
允许模型参与决策，哪些任务更好、哪些更差、代价多少？**

首版只做 **C 层「运行状态」家族的配对双例**（垂直切片）：

| 用例 | 记录 e2（进程监控） | 期望 |
|---|---|---|
| `c017` | svc-17 @10:00:10 `exited` | `exited`，必须引用 `e2` |
| `c018` | svc-17 @10:00:10 `running` | `running`，必须引用 `e2` |

其余记录两例完全相同：`e1` 是业务日志（只能支持"该次无响应"），
`e3` 是另一台机器 svc-71 的进程记录（引用它算无证据命中）。

---

## 快速开始

```bash
# 1) 校验用例与金标（会指出文件、字段和原因）
python -m fwbench validate --suite bench/suites/smoke.json

# 2) 跑两个策略
python -m fwbench run --suite bench/suites/smoke.json \
    --profile bench/profiles/rule.json --out runs/smoke-rule
python -m fwbench run --suite bench/suites/smoke.json \
    --profile bench/profiles/scripted.json --out runs/smoke-scripted

# 3) 看报告（--recompute 表示从已落盘事件重算，不重跑工具）
python -m fwbench report runs/smoke-rule --recompute

# 4) 对照两个同条件运行
python -m fwbench compare runs/smoke-rule runs/smoke-scripted --out runs/cmp
```

**最短示例就是上面 1→2→3 三行**，不需要固件、GPU 或模型服务。

## 默认值与退出码

| 项 | 默认值 |
|---|---|
| 套件 | `bench/suites/smoke.json` |
| 夹具目录 | `bench/fixtures` |
| 金标 | `bench/oracle/smoke.json` |
| 预算 | 每例 `decisions=6`、`tool_calls=4`（用例可覆盖，profile 可再覆盖） |
| 随机种子 | `0`（用于打乱未读记录的推荐顺序，不编码答案） |

| 退出码 | 含义 |
|---|---|
| 0 | 正常 |
| 2 | 参数/校验问题，或 `compare` 发现条件不一致（拒绝给合并结论） |
| 3 | `report --check-gates` 时有指标未达标 |

> `run` 落盘成功只表示**评测器**完成了工作，允许其中存在失败任务。

## 一次运行产出什么

```
runs/smoke-rule/
  manifest.json      套件摘要、profile、种子、用例数
  cases/<case_id>/
    events.jsonl     逐步事件：decision / tool_result / submission
    submission.json  被测系统的原始提交
  results.jsonl      每个用例一行（含 served 证据集合）
  report.md          人读
  summary.json       机器读（报告由同一份汇总对象渲染）
```

**金标不在运行目录里**：`report` 时才加载，运行器全程看不到。

## 评分口径

一条提交要同时满足四条才算通过：

1. `outcome=answered`（或金标允许弃权）；
2. `claim` 与 `expected` 完全一致；
3. 引用的每条记录**本轮都读过**（否则 `citation_not_read`）；
4. 引用的记录**支持这个主张**（主体、采样时间对得上，且有 `state` 时与本主张一致），
   并且命中金标给出的某一组"充分证据"（否则 `insufficient_evidence`）。

失败原因只记第一处能解释失败的地方。指标见 `report.md`：
通过率、双例通过率、无依据的确定结论率。

## 增加用例

1. 在 `bench/fixtures/<ref>/` 放记录 JSON，形如
   `{"id":"e2","type":"process_sample","subject":"svc-17","sample_time":"10:00:10","state":"exited"}`；
2. 在 `bench/suites/*.json` 加一条 case：`case_id` **不能含答案暗示**
   （`exit` / `running` 之类会被 `validate` 直接拒），`catalog` 只写 `id` 和 `type`；
3. 在 `bench/oracle/*.json` 写金标：`expected` + `acceptable_evidence_sets`；
4. 配对用例必须同家族、同 `pair_id`，且**只改一条记录**。

## 当前覆盖边界（别当成结论）

- 实测的是 `rule` 与 `scripted` 两个策略 —— **都不是 fwmap 的生产决策入口**。
  要接 `fwmap/agent/loop.py` 需按计划实现 `run_subject` 适配器，
  未接通前结果应标 `harness-only`。
- 未接入真实模型（`M` 组）、未做基线 `H`、未做信息消融。
- 只覆盖「运行状态」一个家族，其余五个家族（制品完整性、版本识别、
  时序归属、报告一致性、证据可得性）尚未实现。

细节见 `docs/fwbench-P0-盘点与契约.md`。
