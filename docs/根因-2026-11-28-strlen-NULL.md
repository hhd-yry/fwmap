# 根因：`/login.cgi` 崩溃点 = `strlen(NULL)`

> **日期**：2026-11-28
> **方法**：qemu + gdbstub + gdb-multiarch 抓现场（静态工具在这颗 MIPS 上定不到位，见第 4 节）
> **结论等级**：崩溃点已确认；"为什么传了 NULL"仍需反汇编调用者

---

## 一、现场

```
Program received signal SIGSEGV, Segmentation fault.

pc: 0x3fd407d0      ra: 0x3fd39070
sp: 0x407ff1c0
a0: 0x0             ← 空指针
a1: 0x3fd4e158

=> 0x3fd407d0:  lb   v0, 0(a0)
   0x3fd407d4:  move v1, a0
   0x3fd407d8:  beqz v0, 0x3fd407ec
   0x3fd407dc:  nop
   0x3fd407e0:  addiu v1, v1, 1
```

## 二、这段代码是什么

四条指令构成 **`strlen()`** 的主循环：

| 指令 | 含义 |
|---|---|
| `lb v0, 0(a0)` | 读 `*s` |
| `move v1, a0` | 保存起始指针 |
| `beqz v0, +` | `*s == 0` → 结束 |
| `addiu v1, v1, 1` | `s++` |

**`a0 = 0x0`**，所以 `lb v0, 0(a0)` 从地址 0 读 —— 立即 SIGSEGV。

**结论：`strlen(NULL)`。** 一个空指针被当作 C 字符串传给长度计算。

## 三、和触发矩阵对上了

| 请求 | 查询串 | 服务端拿到什么 | 结果 |
|---|---|---|---|
| `GET /login.cgi` | **根本不存在** | `NULL` | `strlen(NULL)` → 崩 |
| `GET /login.cgi?` | 空串 `""` | `""`（不是 NULL） | 正常 |
| `GET /login.cgi?x=1` | `"x=1"` | 非空串 | 正常 |
| `POST /login.cgi` | — | 走另一条取值路径，同样拿到 NULL | 崩 |

这就解释了为什么"缺 `graph_id`"是错的：**问题不在缺哪个参数，而在查询串整个不存在时返回了 NULL**。

## 四、为什么静态没定位到

| 尝试 | 结果 |
|---|---|
| `fwmap m2`（strcmp 链） | 56 个端点全部"未定位" |
| Ghidra `FindStringRef.java "graph_id"` | `strings-hit=1 functions=0` —— 字符串在，没有任何函数引用它 |

原因：这颗 MIPS 大端二进制用 **`$gp` 相对寻址**访问字符串（Ghidra 输出里那句
`_mips_gp0_value=0x1000b340` 就是线索），Ghidra 没解析出 `addiu $a0, $gp, imm`
到数据地址的映射，所以交叉引用为空。

**这条要写进论文**：静态工具在 GP 相对寻址的 MIPS 目标上会漏引用，
必须用动态（gdb）兜底 —— 而动态只花了几分钟就拿到了静态几次都没拿到的答案。

## 五、还没确认的

1. **`0x3fd407d0` 属于哪个库**：二进制本身在 `0x004xxxxx`，这个地址在共享库映射区，
   大概率是 `libc.so.0` 的 `strlen`；
2. **调用者 `ra = 0x3fd39070`** 是谁、为什么传 NULL；
3. 是 `getenv("QUERY_STRING")` 返回 NULL，还是 `websGetVar` 的容器没初始化 ——
   需要看调用者附近的代码。

**下一步**：在 gdb 里对 `ra` 下断点、打印栈回溯，或把 `0x3fdxxxxx` 映射回具体库后
反汇编调用者。这一步做完，报告才能从"崩在 strlen"升级成"handler 第 N 行传了 NULL"。

## 六、复现命令

```powershell
py -3 lab\crash_gdb.py
```

脚本会：把 `qemu-mips-static` 放进 rootfs → 用 `-g 1234` 起 httpd →
gdb 连上去 `continue` → 发一条 `GET /login.cgi` → 打印 PC/寄存器/出错指令。
