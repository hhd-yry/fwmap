# fwbench 运行报告

- 运行目录：`C:\deepseek\tmp\dev2-h`
- 用例数：8　适用：8　未运行：0
- 通过：7（88%）
- 双例通过：3/4（75%）
- 无依据的确定结论：1/8（12%）

| 用例 | 家族 | 配对 | 结论 | 期望 | 引用 | 结果 |
|---|---|---|---|---|---|---|
| c017 | lifecycle | p03 | exited | exited | e2 | ✅ |
| c018 | lifecycle | p03 | running | running | e2 | ✅ |
| c031 | integrity | p31 | complete | complete | e2 | ✅ |
| c032 | integrity | p31 | truncated | truncated | e2 | ✅ |
| c041 | timing | p32 | current | current | e2 | ✅ |
| c042 | timing | p32 | stale | stale | e2 | ✅ |
| c071 | timeshift | p35 | exited | exited | e2 | ✅ |
| c072 | timeshift | p35 | exited | running | e2 | ❌（claim_mismatch） |

> 未通过原因只记第一处能解释失败的地方；引用必须本轮读过且支持主张。
> 「不适用」＝ 被测工具声明不支持或依赖缺失，**不计入通过率分母**。
