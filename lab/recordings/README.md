# 运行记录归档（逐次清单）

这里放 `fwmap plan --json` 的**原始运行记录**，供 `lab/recount.py` 离线重算。

> 当前状态：**15 份已归档**（`temp00/`、`temp07/`、`anon/` 各 5 份）。
>
> ⚠️ 来源说明：11-26 的首批原件随 VM 重启丢失（`/tmp` 已清空，全盘搜无果）。
> 现在这 15 份是 **2026-11-28 用当日代码重跑**产出的。
> 条件与结论和历史汇总一致，但**不是同一批文件** ——
> 历史汇总值仍标「历史转述」，本文档的数字来自可核对的新原件。
> 详见 `docs/验收-2026-11-28-C.md`。

## 一、15 轮清单

| 组 | 条件 | 文件名 | 计划 | 有效 | 命中 |
|---|---|---|---|---|---|
| T0 | `--temperature 0`（贪心） | `temp00/temp00-1..5.json` | 5 | 5 | **5/5** |
| T07 | `--temperature 0.7`（采样） | `temp07/temp07-1..5.json` | 5 | 5 | **5/5** |
| ANON | `--temperature 0.7 --anonymize` | `anon/anon-1..5.json` | 5 | 5 | **0/5** |

⚠️ 匿名组是**第二版**：第一版（同日更早）虽然也是 0/5，但当时匿名只作用于"挑端点"
这一道题，第 2 步的通用提示把 36 条真实 uri 全列了出来 —— 条件被污染，已作废。
现在的 5 份是在提示全链路换名之后重跑的，详见 `docs/验收-2026-11-28-D.md`。

其他固定条件：DIR-615 C2 `sbin/httpd`、8 步预算、`--probe`、
模型 Qwen2.5-Coder-1.5B（宿主机 GPU，经反向隧道给 VM 用）。

每组每轮的实际 `status`（`no_progress` 表示无进展提前停，`budget_exhausted` 表示用满预算）
都写在对应 JSON 里，写论文时要分开报，不能都算成"跑完了"。

## 二、怎么重算

```bash
python lab/recount.py lab/recordings/temp00 --target /login.cgi --kind crash --planned 5
python lab/recount.py lab/recordings/temp07 --target /login.cgi --kind crash --planned 5
python lab/recount.py lab/recordings/anon   --target /login.cgi --kind crash --planned 5
```

需要重新产生一批记录时（VM 上跑，约 50 分钟）：

```bash
bash lab/rerun3.sh          # 三组各 5 轮，写到 /tmp/rec/<组>/
python lab/fetch_rec.py     # 取回 lab/recordings/
```

## 三、口径（写死，不允许临时改）

1. 每轮遍历**全部**结论，按 `uri` 精确匹配 + `kind` 精确匹配，每轮最多计一次；
2. 两个分母都给：`命中/有效`（成功读入）与 `命中/计划`；
3. 损坏、缺失分别计数，不静默跳过，也不拿"成功读入数"冒充计划轮次；
4. 原件、汇总、人工标签分开保存；`lab/recount.py` 只读不写原件；
5. 拿不到原件的单元格保留「历史汇总，未逐轮核对」，不用新跑的结果顶替。

## 四、旧记录字段说明

2026-11-28 之前的 JSON 没有 `status` / `support` 字段。
`recount.py` 遇到时显示「（旧记录，无状态字段）」，**不会**替它推断完成状态，
也不会把缺字段的结论升级成强结论。
