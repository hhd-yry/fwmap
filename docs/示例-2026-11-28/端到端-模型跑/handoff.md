# 交接：httpd　2026-11-28 15:06:22

- **完成状态**：`budget_exhausted` —— 预算用尽（8 步）
- **请求范围**：模型 on · 探针 开 · 预算 8 步
- **尚欠阶段**：无

## 已经确认的
- `/login.cgi` crash（进程退出已确认）：服务直接没了
  - 证据：`/apply.cgi 1818B handler 首行:<html>`
  - 证据：`/login.cgi 0B unknown`

## 记录到的观测
- `/apply.cgi` → 1818B · handler · 首行 `<html>`
- `/login.cgi` → 0B · unknown
- `/save_log.cgi` → 1818B · handler · 首行 `<html>`
- `/online_firmware_check.cgi` → 1818B · handler · 首行 `<html>`
- `/log_first_page.cgi` → 1818B · handler · 首行 `<html>`

## 归因
- 模型决定 6 步 / 主动规则 0 步 / 兜底 2 步
- 模型被拒 2 次：多余参数 1、重复动作 1
- 结论 1/1

## 卡在哪 / 建议下一步
- 未完成（预算用尽（8 步））：可加预算重跑，或先处理上面「尚欠阶段」
