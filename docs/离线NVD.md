# 离线 NVD：让 `verify` 在没有网络的机器上也能用

> 一句话：把 NIST 官方的 CVE 数据整包搬下来建成一个本地库，
> 有网时走 API，断网时查本地，两边判定逻辑完全一样。

---

## 1. 为什么要有这个东西

`fwmap verify` 回答的是「这条线索是不是已经被人报过」。它原本的实现是拿
函数名/路由名去查 NVD 的在线 API。三个问题在验收环节会同时炸：

| 问题 | 后果 |
|---|---|
| 验收机**完全断网**（连内网都没有） | 整个新颖性核对环节直接不可用 |
| 无 API key 时限流 **5 次 / 30 秒** | 30 个函数要跑三分钟以上 |
| 数据天天在变 | 今天的「未命中」明天可能就变「已公开」，报告不可复现 |

离线 NVD 就是把这一步从「发请求」变成「查本地库」。

## 2. 数据从哪来

**NIST 官方 CVE JSON feed**，不是自己拼的库、也不是二手镜像：

```
https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-<年>.json.gz
```

- 覆盖 2002 年至今，按年打包，共 **25 个包 / 236 MB**（压缩后）
- 每个包附带 `.meta`：`sha256`、`gzSize`、`lastModifiedDate` —— 下载后逐包校验
- 解压后总量约 **2.5 GB**

抽取的字段只有五个：`CVE 号 / 发布日期 / 严重级 / CVSS 分 / 英文描述`。
其余（引用链接、CPE、CWE）对「这个名字有没有被报过」这个问题没用，直接丢掉。

## 3. 结构

```
                   NVD 官方年包（2002-2026, 236 MB gz）
                              │
                    ① fetch   │  逐包 sha256 校验，可断点重来
                              ▼
                 data/nvd/raw/*.json.gz
                              │
                    ② build   │  流式解析（不整包进内存）
                              ▼
                 data/nvd/nvd.sqlite   ≈ 259 MB / 424k 条
                   ├─ cve 表（号 / 日期 / 严重级 / 描述）
                   └─ FTS5 全文索引（外部内容表，不重复存描述）
                              │
                    ③ verify  │  --source local / auto
                              ▼
                      判定：known / unknown / manual
```

解析必须流式：2026 年那个包解压后 542 MB，`json.load` 峰值要几个 GB。
现在的做法是按块读 + 用正则跨过字符串内容，**内存恒定在几十 MB**，
整库建完约 **90 秒**。

## 4. 命令

```bash
# ① 下载（约 240 MB，可重复执行，已下好的会跳过）
python -m fwmap nvd fetch
python -m fwmap nvd fetch --from-year 2015 --proxy http://127.0.0.1:7897

# ② 建索引（→ data/nvd/nvd.sqlite）
python -m fwmap nvd build

# ③ 看状态：多少条、覆盖哪些年、快照哪天、多大
python -m fwmap nvd status

# ④ 手工查（调试/演示都方便）
python -m fwmap nvd search formStaDrvSetup
python -m fwmap nvd search "Tenda AC15" --limit 5

# ⑤ 增量更新：只比 .meta，只下变了的年包；没变化不重建
python -m fwmap nvd update
python -m fwmap nvd check          # 只看有没有新数据，不下载
```

## 5. `verify` 怎么选数据源

```
--source auto（默认）
    │
    ├─ 探一下 NVD 通不通（取一个几百字节的 .meta，不消耗 API 配额）
    │
    ├─ 通   → 在线 API   ← 权威、当天最新
    └─ 不通 → 本地库     ← 零网络、亚秒级、快照冻结
```

| 参数 | 行为 |
|---|---|
| `--source auto` | 默认。有网走 API，没网用本地库 |
| `--source api` | 强制联网 |
| `--source local` | 强制本地（`FWMAP_OFFLINE=1` 等价） |
| `--update-index` | 走完 API 后顺手更新本地库（只下变了的年包） |
| `--db <路径>` | 指定离线库 |
| `--no-scan` | 本地模式只做整词匹配，跳过子串兜底（快，但可能漏） |

报告抬头会写明这次用的是哪个源、快照是哪天的：

```
- 检索源：离线 NVD 库 `nvd.sqlite`（423984 条 CVE，2002-2026 年，快照 2026-11-12 10:02:09）
> 本报告基于 **2026-11-12 10:02:09** 的 NVD 快照；之后再公开的 CVE 不会出现在这里。
```

## 6. 检索是两层的

| 层 | 做法 | 典型耗时 | 覆盖 |
|---|---|---|---|
| 整词 | FTS5（unicode61 分词）精确匹配 | ~0 ms | 描述里原样出现 `formStaDrvSetup` |
| 兜底 | `LIKE '%kw%'` 全表扫描 | ~0.3 s | 出现在更长标识符里，如 `formStaDrvSetup_extra` |

只做第一层会漏：公告里常把函数名拼进 URL 或加后缀。第二层宁可慢一点也不能漏。

FTS5 的 unicode61 分词把下划线当分隔符，所以 `formStaDrvSetup_extra` 会切成
`formstadvsetup` + `extra`，这时**整词层就会命中**（`formStaDrvSetup` 是它的前缀词）；
真正需要兜底的是 `StaDrvSetup_ext` 这种跨词边界的部分匹配。

## 7. 效果对比（真实数据）

同一份输入（Edimax BR-6478AC 收到的 15 个 handler）：

| | 在线 API | 离线库 |
|---|---|---|
| 用时 | ~97 s（15 × 6.5 s 限流） | **2.6 s** |
| 网络 | 必须 | 不需要 |
| 可复现 | 否（数据每天变） | 是（快照固定） |
| 结论 | 9 已公开 / 6 未命中 | **完全一致** |

离线那次还多找出 4 条在线漏掉的同类 CVE（`CVE-2026-13581` / `19960` / `8777` / `9297`），
因为本地年包比在线缓存新。

## 8. 断网验收怎么用

数据不进 git（见 `.gitignore`），**跟着文件夹一起拷**：

```
fwmap-tool/
├── fwmap/                 ← 代码
├── data/nvd/
│   ├── nvd.sqlite         ← 259 MB，拷过去就能用
│   └── raw/               ← 236 MB，可选；有它才能 nvd update / build
└── ...
```

只拷 `nvd.sqlite` 就能离线核对；带上 `raw/` 才能在没有网的机器上重建索引。

落地后先跑自检：

```bash
python -m fwmap doctor
# [OK]  离线NVD     423984 条 CVE，快照 2026-11-12 10:02:09，259 MB  .../data/nvd/nvd.sqlite
```

## 9. 维护

- **有网时**：`python -m fwmap nvd update`，或 `verify --update-index` 顺手更新。
  NVD 只改当年和前一年的包，其余年份基本冻结；`update` 只比 `.meta`，
  没变化的年份不会重新下载，**没有变化也不会重建索引**。
- **多久一次**：一周一次足够；赶在验收前跑一次即可。
- **环境变量**：
  - `FWMAP_NVD_DB` —— 索引路径
  - `FWMAP_NVD_DIR` —— 数据目录
  - `FWMAP_PROXY` —— 代理（`fetch/probe` 会用）
  - `FWMAP_OFFLINE=1` —— 强制离线，`auto` 不再探测

## 10. 已知限制

- **只索引英文描述**。NVD 的 `descriptions` 多语言字段里偶尔只有非英文条目，这类会被丢掉（数量极少）。
- **只能证明「报过」，不能证明「没报过」**。`unknown` 依旧不等于新漏洞：
  大量固件漏洞从未申请 CVE，或者公告只写型号和 URL 不写函数名。
- **快照有时效**。报告里写明了快照日期；比它更新的 CVE 不会出现。
- **只覆盖 CVE**。CNVD / CNNVD 以及各厂商自己的安全公告不在 NVD 里，需要人工补。

---

相关：[`fwmap/nvd.py`](../fwmap/nvd.py) · [`fwmap/verify.py`](../fwmap/verify.py) · [`tests/test_nvd.py`](../tests/test_nvd.py)
