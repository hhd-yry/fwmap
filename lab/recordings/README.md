# 运行记录归档（逐次清单）

这里放 `fwmap plan --json` 的**原始运行记录**，供 `lab/recount.py` 离线重算。

> 当前状态：**15 份原始 JSON 全部缺失**。
> 它们写在实验 VM 的 `/tmp` 下，VM 目前连不上（22 端口可建连但不返回 banner）。
> 因此下面三组历史数字，在原件取回之前一律标注为
> **「历史汇总，未逐轮核对」**，不得当作可重算的证据。

## 一、计划中的 15 轮

| 组 | 条件 | 文件名 | 计划轮次 | 状态 |
|---|---|---|---|---|
| T0 | `--temperature 0`（贪心） | `temp00/run-1..5.json` | 5 | **缺失** |
| T07 | `--temperature 0.7`（采样） | `temp07/rt-1..5.json` | 5 | **缺失** |
| ANON | `--temperature 0.7 --anonymize` | `anon/ra-1..5.json` | 5 | **缺失** |

历史汇总值（出处：`docs/日志-2026-11-26.md`）：

| 组 | 历史记录 |
|---|---|
| T0 | 5/5 判出 `/login.cgi` = crash |
| T07 | 5/5 判出 |
| ANON | 0/5 判出 |

**这三行现在只能当"历史转述"引用，不能参与"命中/计划"的统计。**

## 二、取回原件后怎么重算

```bash
# 1) 从 VM 拷回来（VM 恢复后）
scp ubuntu@192.168.8.137:/tmp/run-*.json lab/recordings/temp00/
scp ubuntu@192.168.8.137:/tmp/rt-*.json  lab/recordings/temp07/
scp ubuntu@192.168.8.137:/tmp/ra-*.json  lab/recordings/anon/

# 2) 逐组重算（每轮遍历全部结论，两个分母都出）
python lab/recount.py lab/recordings/temp00 --target /login.cgi --kind crash --planned 5
python lab/recount.py lab/recordings/temp07 --target /login.cgi --kind crash --planned 5
python lab/recount.py lab/recordings/anon   --target /login.cgi --kind crash --planned 5
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
