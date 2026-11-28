# fwbench 运行报告

- 运行目录：`C:\deepseek\tmp\elf-stdlib`
- 用例数：3　通过：3（100%）
- 双例通过：0/0（—）
- 无依据的确定结论：0/2（0%）

| 用例 | 家族 | 配对 | 结论 | 期望 | 引用 | 结果 |
|---|---|---|---|---|---|---|
| c201 | elfmeta |  | {'bits': 32, 'endian': 'big', 'etype': 'exec', 'machine_id': 'mips'} | {'bits': 32, 'endian': 'big', 'etype': 'exec', 'machine_id': 'mips'} |  | ✅ |
| c202 | elfmeta |  | {'bits': 32, 'endian': 'little', 'etype': 'dyn', 'machine_id': 'arm'} | {'bits': 32, 'endian': 'little', 'etype': 'dyn', 'machine_id': 'arm'} |  | ✅ |
| c203 | elfmeta |  | {} | truncated |  | ✅ |

> 未通过原因只记第一处能解释失败的地方；引用必须本轮读过且支持主张。
