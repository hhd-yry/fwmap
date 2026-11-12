# 合成靶子上的 dyn 验证

> **这不是固件。** examples/合成靶子.c 是一个几十行的小程序，故意写成
> 「strcpy 进 64 字节栈缓冲区」——它唯一的作用是证明 wmap dyn 的
> **执行链路和崩溃判定是真的**，而不是只打印一句「未执行」。
>
> 真固件（MIPS）需要 qemu-user，见 examples/示例-dyn报告.md（那里是真实链路，
> 但这台机器没有 qemu，所以状态是「未执行」）。

编译与运行：

\gcc -O0 -o fixture.exe 合成靶子.c -lws2_32
python -m fwmap dyn flow.json --m2 m2.json --binary fixture.exe --arch x86_64 --port 8080
\
结果：**64 字节不崩，200 字节被访问违例打死（0xC0000005）** —— 崩溃判定走的是
真实进程的真实退出码，不是模拟出来的。

---

# fwmap dyn · 动态验证

- 目标：`C:\deepseek\tmp\fixture.exe`
- 架构 / 运行时：x86_64 / native
- 端口：8080

> `no-listener` 表示服务没起来，**不是**「没有漏洞」；
> `no-crash` 表示打完了没崩，也不等于安全。

## `formTest` → strcpy[bof]

| 载荷 | 结果 | 细节 |
|---|---|---|
| `X` = `AAAAAAAAAAAAAA…（64B）` | 未崩溃 | 退出码 0x00000000 |
| `X` = `AAAAAAAAAAAAAA…（200B）` | **崩溃** | 退出码 0xC0000005 |

```
curl -sS -X POST "http://127.0.0.1:8080/goform/formTest" -H "Host: 127.0.0.1:8080" -H "Content-Type: application/x-www-form-urlencoded" -H "Connection: close" --data "X=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
```

