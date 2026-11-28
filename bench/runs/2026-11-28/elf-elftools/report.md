# fwbench 运行报告

- 运行目录：`C:\deepseek\tmp\elf-elftools`
- 被测工具：`elftools` 版本 0　可用=False（未安装 pyelftools）
- 用例数：3　适用：0　未运行：3
- 通过：0（—）
- 双例通过：0/0（—）
- 无依据的确定结论：0/0（—）

| 用例 | 家族 | 配对 | 结论 | 期望 | 引用 | 结果 |
|---|---|---|---|---|---|---|
| c201 | elfmeta | — | — | bits=32, endian=big, etype=exec, machine_id=mips | — | —（不适用：被测工具未运行） |
| c202 | elfmeta | — | — | bits=32, endian=little, etype=dyn, machine_id=arm | — | —（不适用：被测工具未运行） |
| c203 | elfmeta | — | — | truncated | — | —（不适用：被测工具未运行） |

> 未通过原因只记第一处能解释失败的地方；引用必须本轮读过且支持主张。
> 「不适用」＝ 被测工具声明不支持或依赖缺失，**不计入通过率分母**。
