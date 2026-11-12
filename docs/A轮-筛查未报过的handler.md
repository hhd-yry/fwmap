# A 轮：筛查 7 个「从未出现在任何 CVE 里」的 handler

目标：Edimax BR-6478AC v1.23 的 `bin/webs`，挑出 `fwmap verify --all-handlers`
判为「未命中」的 7 个 `form*` handler，看能不能捞到新东西。

## 方法

1. 从 `webs_m3.json` 里取这 7 个函数的源/汇统计；
2. 只把这 7 个函数当候选池，跑 M3.2 数据流（`run_flow`，`limit=11`）；
3. 有链的再做新颖性核对。

## 源/汇统计

| 函数 | 源 | 汇 | 汇类别 |
|---|---:|---:|---|
| `formVirtualSv` | 168 | 30 | strcpy / strncpy（bof） |
| `formWizSetup` | 49 | 11 | **system（ci）** |
| `formWlEnableSwitch` | 37 | 30 | sprintf（bof） |
| `formSaveText` | 304 | 77 | printf（fmt），源全是 `apmib_get`（配置非外部） |
| `formSaveConfigSec` | **0** | 21 | sscanf（bof） |
| `formResetDefault` | **0** | 13 | system（ci） |
| `formBandwidth_Calc` | **0** | 8 | system（ci） |

一眼就能看出问题的：`formSaveConfigSec` / `formResetDefault` / `formBandwidth_Calc`
**一个源都没有**——它们的 `system()` 参数来自常量或配置，不是用户输入。
这类「有危险函数但没有入口」正是最容易骗人的假线索。

## 数据流结果：2 条链，都被规则降级

```
formVirtualSv  websGetVar → strncpy(auStack_410, param_1, uVar1)
               verdict=demoted  reason=length-checked
formVirtualSv  websGetVar → strcpy(param_1, auStack_410)
               verdict=demoted  reason=taint-in-destination
```

第二条特别值得说：`strcpy(param_1, auStack_410)` 里污点在**目的地**
（把栈上数据拷到参数指向的缓冲区），方向反了，不是攻击面。
如果工具不做方向判断，这条会被报成「栈溢出」。

其余 6 个函数：**0 条链**。源和汇在语句级连不起来。

## 结论

**这 7 个 handler 里没有可利用的新漏洞。**

但这不是「白跑」：

1. 反证了工具**不会见危险函数就报**——有 `system` 的三个函数因为没源，一条链都没有；
2. `formVirtualSv` 的两条被规则按「长度校验」「污点方向」准确降级；
3. 顺手抓到一个**严重回归**（见下），不跑这一轮根本发现不了。

## 意外收获：一个会让数据流静默归零的 bug

`_parse_decompile_output` 里判断反编译块头时，Ghidra 实际打出来的行是：

```
INFO  DecompileFuncs.java> ===== formStaDrvSetup @ 004914e8 ===== (GhidraScript)
```

前后都挂着东西。之前用 `line.find("===== ")` 是能过的；我在修「函数名含 END」
那个 bug 时改成了 `startswith/endswith("=====")`，前缀一来就匹配不上，
**整个数据流会静默返回 0 条链**——看起来像「固件很干净」。

现在改成「取两个 `=====` 之间的内容」，前后缀都不影响，并加了回归测试。
