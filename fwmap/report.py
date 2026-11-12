"""生成单文件 HTML 报告 —— 零外部依赖，双击就能看，发给谁都能打开。"""

from __future__ import annotations

import json
import re

from .scan import ScanResult

ROLE_LABEL = {
    "http_server": "HTTP 服务",
    "network_service": "网络服务",
    "cgi_binary": "CGI 程序",
    "library": "库",
    "tool": "命令行工具",
    "busybox": "busybox",
    "other": "其他",
}

ROLE_COLOR = {
    "http_server": "#A32D2D",
    "network_service": "#854F0B",
    "cgi_binary": "#185FA5",
    "library": "#5F5E5A",
    "tool": "#888780",
    "busybox": "#888780",
    "other": "#B4B2A9",
}

HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>fwmap · 固件攻击面地图</title>
<style>
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
         color: #2C2C2A; background: #FBFAF7; font-size: 13px; line-height: 1.6; }
  header { padding: 20px 24px 14px; border-bottom: 1px solid rgba(0,0,0,.1); background: #fff; }
  h1 { margin: 0 0 4px; font-size: 17px; font-weight: 600; }
  .sub { color: #5F5E5A; font-size: 12px; }
  .stats { display: flex; gap: 22px; margin-top: 12px; }
  .stat b { display: block; font-size: 20px; font-weight: 600; line-height: 1.2; }
  .stat span { color: #5F5E5A; font-size: 11px; }
  .bar { display: flex; gap: 8px; align-items: center; padding: 10px 24px;
         border-bottom: 1px solid rgba(0,0,0,.08); background: #fff; flex-wrap: wrap; }
  .chip { padding: 4px 10px; border-radius: 999px; border: 1px solid rgba(0,0,0,.15);
          background: #fff; cursor: pointer; font-size: 12px; color: #444441; }
  .chip.on { background: #2C2C2A; color: #fff; border-color: #2C2C2A; }
  input[type=search] { padding: 5px 10px; border: 1px solid rgba(0,0,0,.15);
          border-radius: 6px; font-size: 12px; width: 220px; outline: none; }
  main { display: flex; height: calc(100vh - 150px); }
  .left { flex: 1; overflow: auto; }
  .right { width: 400px; border-left: 1px solid rgba(0,0,0,.1); overflow: auto;
           background: #fff; padding: 16px 18px; }
  table { width: 100%; border-collapse: collapse; }
  th { position: sticky; top: 0; background: #F4F2EC; text-align: left; padding: 8px 12px;
       font-weight: 500; font-size: 11px; color: #5F5E5A; border-bottom: 1px solid rgba(0,0,0,.1);
       cursor: pointer; user-select: none; white-space: nowrap; }
  td { padding: 8px 12px; border-bottom: 1px solid rgba(0,0,0,.05); vertical-align: top; }
  tr.row { cursor: pointer; }
  tr.row:hover { background: #F7F5F0; }
  tr.row.sel { background: #EEEDFE; }
  .score { font-weight: 600; font-variant-numeric: tabular-nums; }
  .path { font-family: ui-monospace, Consolas, monospace; font-size: 12px; word-break: break-all; }
  .tag { display: inline-block; padding: 1px 7px; border-radius: 4px; font-size: 11px;
         color: #fff; white-space: nowrap; }
  .sig { display: inline-block; padding: 1px 6px; margin: 1px 3px 1px 0; border-radius: 4px;
         background: #F1EFE8; color: #444441; font-size: 11px; }
  .sig.hint { background: transparent; border: 1px dashed rgba(0,0,0,.28); color: #5F5E5A; }
  .sig.neg { background: #FCEBEB; color: #A32D2D; }
  .banner { padding: 9px 24px; background: #FAEEDA; color: #412402; font-size: 12px;
            border-bottom: 1px solid rgba(0,0,0,.08); }
  .muted { color: #888780; font-size: 11px; }
  .empty { padding: 40px; text-align: center; color: #888780; }
  h2 { font-size: 14px; font-weight: 600; margin: 0 0 10px; }
  h3 { font-size: 12px; font-weight: 500; color: #5F5E5A; margin: 16px 0 6px;
       text-transform: none; letter-spacing: 0; }
  code { font-family: ui-monospace, Consolas, monospace; font-size: 11px;
         background: #F4F2EC; padding: 1px 5px; border-radius: 3px; word-break: break-all; }
  ul { margin: 0; padding-left: 16px; }
  li { margin: 2px 0; font-size: 12px; word-break: break-all; }
  .k { color: #888780; font-size: 11px; }
</style>
</head>
<body>
<header>
  <h1>固件攻击面地图</h1>
  <div class="sub" id="root"></div>
  <div class="stats" id="stats"></div>
</header>
<div class="banner">
  这是一份<b>优先级排序</b>，不是漏洞列表。实线标签是客观事实（文件里确实存在该字符串或导入），
  虚线标签是启发式提示，<b>只影响排序，不构成结论</b>——"引用了 system"不等于"有漏洞"。
</div>
<div class="bar" id="bar">
  <input type="search" id="q" placeholder="搜索路径 / 端点 / 符号…">
  <span id="chips"></span>
</div>
<main>
  <div class="left"><table><thead><tr>
    <th data-k="score">分</th><th data-k="path">路径</th><th data-k="role">角色</th>
    <th data-k="arch">架构</th><th data-k="size">大小</th><th>信号</th>
  </tr></thead><tbody id="tbody"></tbody></table></div>
  <div class="right" id="detail"><div class="empty">点左边任一行看详情</div></div>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
const DATA = JSON.parse(document.getElementById('data').textContent);
const ROLE_LABEL = __ROLE_LABEL__;
const ROLE_COLOR = __ROLE_COLOR__;
let filterRole = null, query = '', sortKey = 'score', sortDir = -1, selected = null;

document.getElementById('root').textContent = 'rootfs: ' + DATA.root + ' · 扫描于 ' + DATA.started_at;

const counts = {};
DATA.targets.forEach(t => { counts[t.role] = (counts[t.role]||0)+1; });
const hot = DATA.targets.filter(t => t.score >= 40).length;
document.getElementById('stats').innerHTML = [
  ['文件', DATA.files_seen], ['ELF', DATA.elf_count],
  ['高危候选', hot], ['端点合计', DATA.targets.reduce((a,t)=>a+t.endpoints.length,0)]
].map(([k,v]) => `<div class="stat"><b>${v}</b><span>${k}</span></div>`).join('');

const roles = Object.keys(counts).sort((a,b)=>counts[b]-counts[a]);
document.getElementById('chips').innerHTML = roles.map(r =>
  `<span class="chip" data-r="${r}">${ROLE_LABEL[r]||r} ${counts[r]}</span>`).join(' ');
document.getElementById('chips').addEventListener('click', e => {
  const c = e.target.closest('.chip'); if (!c) return;
  const r = c.dataset.r;
  filterRole = (filterRole === r) ? null : r;
  document.querySelectorAll('.chip').forEach(x =>
    x.classList.toggle('on', x.dataset.r === filterRole));
  render();
});
document.getElementById('q').addEventListener('input', e => { query = e.target.value.toLowerCase(); render(); });
document.querySelectorAll('th[data-k]').forEach(th => th.addEventListener('click', () => {
  const k = th.dataset.k;
  if (sortKey === k) sortDir = -sortDir; else { sortKey = k; sortDir = -1; }
  render();
}));

function fmt(n){ return n >= 1048576 ? (n/1048576).toFixed(1)+'M' : n >= 1024 ? (n/1024).toFixed(0)+'K' : n+'B'; }

function rows(){
  let rs = DATA.targets.slice();
  if (filterRole) rs = rs.filter(t => t.role === filterRole);
  if (query) rs = rs.filter(t =>
    t.path.toLowerCase().includes(query) ||
    t.endpoints.join(' ').toLowerCase().includes(query) ||
    t.imports.join(' ').toLowerCase().includes(query));
  rs.sort((a,b) => {
    let x = a[sortKey], y = b[sortKey];
    if (sortKey === 'size') { x = a.size; y = b.size; }
    if (typeof x === 'string') return sortDir * x.localeCompare(y);
    return sortDir * (x - y);
  });
  return rs;
}

function render(){
  const rs = rows();
  const tb = document.getElementById('tbody');
  if (!rs.length) { tb.innerHTML = '<tr><td colspan="6" class="empty">没有匹配项</td></tr>'; return; }
  tb.innerHTML = rs.map((t,i) => `
    <tr class="row ${selected===t.path?'sel':''}" data-p="${i}">
      <td class="score" style="color:${t.score>=60?'#A32D2D':t.score>=30?'#854F0B':'#5F5E5A'}">${t.score}</td>
      <td class="path">${t.path}${t.stripped?' <span class="muted">·stripped</span>':''}</td>
      <td><span class="tag" style="background:${ROLE_COLOR[t.role]||'#B4B2A9'}">${ROLE_LABEL[t.role]||t.role}</span></td>
      <td class="muted">${t.arch}${t.kind?' · '+t.kind:''}</td>
      <td class="muted">${fmt(t.size)}</td>
      <td>${t.signals.map(s => `<span class="sig ${s.kind==='hint'?'hint':''} ${s.weight<0?'neg':''}">${s.label}</span>`).join('')}</td>
    </tr>`).join('');
  tb.querySelectorAll('tr.row').forEach(tr => tr.addEventListener('click', () => {
    selected = rs[+tr.dataset.p].path;
    render(); showDetail(rs[+tr.dataset.p]);
  }));
  if (selected) {
    const cur = rs.find(t => t.path === selected);
    if (cur) showDetail(cur);
  }
}

function showDetail(t){
  // 固件里的字符串会原样进 innerHTML。不转义的话，一个含标签的字符串就能在
  // 打开报告时执行 JS —— 而报告本来就是发给别人看的文件，等于把分析机交给固件作者。
  const esc = s => String(s).replace(/[&<>"']/g, c => (
    {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const L = s => `<li><code>${esc(s)}</code></li>`;
  const surf = t.signals.filter(s => s.kind !== 'hint');
  const hint = t.signals.filter(s => s.kind === 'hint');
  const li = s => `<li>${esc(s.label)} <span class="k">${s.weight>0?'+':''}${s.weight}</span></li>`;
  // M2 结果（可选）：端点清单来自反编译，比 M1 的字符串扫描全得多
  const m2block = t => {
    if (!t.m2 || !t.m2.endpoints || !t.m2.endpoints.length) return '';
    const withH = t.m2.endpoints.filter(e => e.handler).length;
    const rows = t.m2.endpoints.map(e => {
      const h = e.handler ? ` <span class="k">→ ${esc(e.handler_name || e.handler)}</span> <span class="muted">[${esc(e.confidence)}]</span>` : '';
      return `<li>${esc(e.uri)}${h}</li>`;
    }).join('');
    return `<h3>M2 端点清单 (${t.m2.endpoints.length}${withH ? ` · ${withH} 个定位到 handler` : ''})</h3>
      <div class="muted" style="margin-bottom:4px">策略：${t.m2.strategy}　清单由反编译得出，比字符串扫描更全；handler 为空表示未能确定，不是不存在</div>
      <ul>${rows}</ul>`;
  };
  document.getElementById('detail').innerHTML = `
    <h2>${t.path.split('/').pop()}</h2>
    <div class="muted" style="word-break:break-all">${t.path}</div>
    <h3>客观证据 · 合计 ${t.score}</h3>
    <ul>${surf.map(li).join('') || '<li class="muted">无</li>'}</ul>
    <h3>排序提示（不构成结论）</h3>
    <ul>${hint.map(li).join('') || '<li class="muted">无</li>'}</ul>
    ${t.endpoints.length ? `<h3>暴露端点 (${t.endpoints.length})</h3><ul>${t.endpoints.map(L).join('')}</ul>` : ''}
    ${m2block(t)}
    ${t.dangerous.length ? `<h3>引用的危险函数 (${t.dangerous.length})</h3>
      <div class="muted" style="margin-bottom:4px">引用 ≠ 漏洞，需看调用点是否可控</div>
      <ul>${t.dangerous.map(L).join('')}</ul>` : ''}
    ${t.needed.length ? `<h3>依赖库</h3><ul>${t.needed.map(L).join('')}</ul>` : ''}
    ${t.imports.length ? `<h3>导入符号 (${t.imports.length})</h3><ul>${t.imports.slice(0,50).map(L).join('')}</ul>` : ''}
    ${t.strings.length ? `<h3>可疑字符串</h3><ul>${t.strings.slice(0,30).map(L).join('')}</ul>` : ''}
    <h3>下一步</h3>
    <div class="muted">${
      t.role === 'http_server' || t.role === 'cgi_binary'
        ? '把这些端点映射到具体 handler 函数，再看哪个参数可控 —— 需要 Ghidra 反编译（M2，未实现）'
        : '优先级较低，除非已知该服务在此固件中启用'
    }</div>
  `;
}

render();
</script>
</body>
</html>
"""


def render_html(res: ScanResult, out_path: str) -> str:
    # 先替换角色表，最后注入数据：反过来的话，固件里只要出现 __ROLE_LABEL__
    # 这类字面量，数据就会被二次替换，整块 JSON 坏掉、页面白屏。
    payload = json.dumps(res.to_dict(), ensure_ascii=False)
    # `</script>` 会提前闭合脚本块；HTML 的结束标签大小写不敏感，
    # 所以 `</SCRIPT>`、`</Script>` 也要一起转义。
    payload = re.sub(r"</", r"<\\/", payload)
    html = (HTML
            .replace("__ROLE_LABEL__", json.dumps(ROLE_LABEL, ensure_ascii=False))
            .replace("__ROLE_COLOR__", json.dumps(ROLE_COLOR, ensure_ascii=False))
            .replace("__DATA__", payload))
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return out_path
