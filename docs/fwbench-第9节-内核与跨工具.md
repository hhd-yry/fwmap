# fwbench 第 9 节：内核 / 适配器分离与跨工具接入

> **日期**：2026-11-28　**依据**：实施计划新增的第 9 节与结尾要求
> 「通用内核和 fwmap 适配器要能分别导入；同一任务包换被测工具能跑。」

---

## 一、分层：内核不认识 fwmap

```
fwbench/                     ← 通用内核（零 fwmap 依赖）
  cases.py  events.py  runner.py  scoring.py  report.py  __main__.py
  subjects/                  ← 被测工具适配器（唯一与具体工具打交道的地方）
    __init__.py              REGISTRY / get / available_subjects
    fwmap_elf.py             调 fwmap.elf.read_elf
    stdlib_elf.py            纯标准库参考实现
    elftools_elf.py          可选依赖 pyelftools
bench/                       ← 任务包（用例 / 夹具 / 金标 / profile）
```

**怎么证明内核真的不依赖 fwmap**：测试里起一个子进程，把 `sys.modules['fwmap']` 置空，
再导入内核模块并跑 `stdlib` 适配器：

```python
sys.modules['fwmap'] = None
import fwbench.cases, fwbench.scoring, fwbench.report, fwbench.runner
from fwbench.subjects import get
print(get('stdlib').inspect_elf(open('…/elf-a/input.bin','rb').read()))
```

测试项：`内核在无 fwmap 环境可独立运行` ✅

---

## 二、适配器契约

每个适配器声明五样，`manifest.json` 里原样落盘：

| 字段 | 含义 |
|---|---|
| `subject_id` | 工具 ID（`fwmap` / `stdlib` / `elftools`） |
| `version` | 工具版本（运行时取，取不到记 `unknown`） |
| `capability` | 支持的任务能力，目前都是 `elf-meta` |
| `available` | 当前环境能否跑；不可用时带 `unavailable_reason` |
| `requires` | 依赖说明 |

**归一在适配器里做，不污染任务包**：`fwmap` 的 `endian` 是 `>` / `<`，
适配器转成 `big` / `little`；`etype`、`machine_id` 从整型转成名字。
任务包只认一套字段。

**不推测**：工具没给出的字段不补；未安装的可选依赖记 `not_run`，
不拿别的实现冒充（计划第 9 节：工具没提供的内容记不可观察）。

---

## 三、跨工具演示（A 层 3 例）

任务包 `bench/suites/elfmeta.json`，同一份金标 `bench/oracle/elfmeta.json`：

| 用例 | 输入 | 期望 |
|---|---|---|
| `c201` | 32 位**大端** MIPS、`exec` | 四个字段全对 |
| `c202` | 32 位**小端** ARM、`dyn` | 四个字段全对 |
| `c203` | 取 c201 前 **30 字节** | 报 `truncated` |

**结果**（同一批用例、同一份金标）：

| 被测工具 | 可用 | 通过/适用 | 未运行 |
|---|---|---|---|
| `fwmap` 0.1.0 | ✅ | **3/3** | 0 |
| `stdlib` 1 | ✅ | **3/3** | 0 |
| `elftools` | ❌ 未安装 pyelftools | — | 3（不计入分母） |

```bash
python -m fwbench run --suite bench/suites/elfmeta.json --subject stdlib \
    --profile bench/profiles/rule.json --out runs/elf-stdlib
python -m fwbench report runs/elf-stdlib --oracle bench/oracle/elfmeta.json
python -m fwbench compare runs/elf-fwmap runs/elf-stdlib \
    --oracle bench/oracle/elfmeta.json --out runs/elf-cmp
```

`compare` 的输出：三个用例两边都是 ✅，指标并列，**差异列留空**；
若两边不一致，会标 `**不一致**`。

---

## 四、顺带发现的 fwmap 缺陷（已修）

`c203` 一跑就暴露了：

```
fwmap  ：not_elf        ← 错
stdlib ：truncated      ← 对
```

原因：`fwmap/elf.py` 把「文件太短」和「不是 ELF」合并成一个判断：

```python
if len(data) < 52 or data[:4] != b"\x7fELF":
    raise ELFError("not an ELF file")
```

已改成先判魔数、再判长度，错误信息分别是 `not an ELF file` 和
`truncated header: 只有 N 字节…`。

**这条正好说明评测器的价值**：不是"再跑一遍已知能跑的东西"，
而是用独立金标去撞被测实现的边界。修复后两边都 3/3。

---

## 五、长期回归的固定项

`manifest.json` 现在固定记录：

| 字段 | 用途 |
|---|---|
| `bench_version` | 评测器版本 |
| `suite` + `suite_digest` | 任务包与其摘要 |
| `subject`（id/version/available） | 被测工具与其版本 |
| `profile`（含 limits/repeats） | 冻结的运行条件 |
| `seed` | 置换种子 |

`compare` 在 `suite_digest`、`seed`、`profile.limits`、`profile.repeats`
不一致时**列出差异并拒绝合并**；一致的才出对照表。

**基于基线的回归**：`compare` 支持把首个运行当基线，输出
「通过→失败 / 失败→通过」清单（`flips`）。日常提交跑 smoke；
换模型、改决策逻辑、发版前跑完整对照。

---

## 六、未覆盖（别当作已完成）

| 项 | 说明 |
|---|---|
| `pyelftools` 真跑 | 本机未安装；已实现适配器并验证 `not_run` 路径，装上即可参与比较 |
| 无 fwmap 的独立环境 | 测试用「阻断导入」模拟，未在真实干净机器上跑过 |
| 共同任务计分 | 已有"同一金标两边打分"，但"能力范围外填不适用"只做了 `not_run` 一档 |
| 真实模型 `M` 组 | 仍未接入 |
| 新旧版本回归 | 机制（manifest + flips）已就位，尚未做一次真实的新旧对照 |

---

## 七、与 P0 文档的关系

`docs/fwbench-P0-盘点与契约.md` 的第五节「需要注入的最小接口」仍是准的，
但要补一句：**适配器现在有了三个真实实现**，`run_subject`（驱动 fwmap 的
`agent/loop.run`）仍未实现 —— 所以 C 层分数仍标 `harness-only`。
