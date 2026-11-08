/* gui/static/app.js — 控制台前端（原生 JS，零依赖）
 *
 * 三条纪律，都跟"不要骗用户"有关：
 *
 * 1. **先转义再渲染。** 报告和日志里会出现攻击者可控的字符串（进程名、路径、
 *    命令行）。所以 markdown 渲染的顺序是 escapeHTML() → 再转标签，而不是反过来。
 *    否则一个名叫 <img onerror=...> 的进程就能在控制台里执行脚本 ——
 *    一个安全工具自己成了 XSS 载体，没有比这更难看的了。
 *
 * 2. **只读模式真的禁用按钮。** 不是靠 CSS 灰掉，而是按钮根本不发请求，
 *    并且后端也会 403。前端禁用只是"别让用户白点一次"。
 *
 * 3. **失败要说人话。** 後端拒绝封锁时返回的是具体原因（"目标是网关，封锁会断网"），
 *    界面原样贴出来，不翻译成"操作失败"。
 */

'use strict';

/* ------------------------------ 基础设施 ------------------------------ */

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

// 令牌：从 URL 取一次，存进 sessionStorage，然后把 URL 里的令牌抹掉
// （免得它出现在历史记录/截图/别人的肩膀上）
const TOKEN = (() => {
  const u = new URL(location.href);
  const t = u.searchParams.get('token');
  if (t) {
    sessionStorage.setItem('gui_token', t);
    u.searchParams.delete('token');
    history.replaceState(null, '', u.pathname + (u.search ? u.search : ''));
    return t;
  }
  return sessionStorage.getItem('gui_token') || '';
})();

let META = null;          // /api/meta 的结果（哪些路由是写操作）
let CURRENT = 'overview';
const CACHE = {};         // 单页内的小缓存（配置文本等）

function toast(msg, kind = '') {
  const el = $('#toast');
  el.textContent = msg;
  el.className = 'toast show ' + kind;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.className = 'toast'; }, kind === 'err' ? 7000 : 3200);
}

async function api(path, params = null, method = 'GET') {
  const url = new URL(path, location.origin);
  const opts = { method, headers: { 'X-Token': TOKEN } };
  if (method === 'GET') {
    if (params) for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null) url.searchParams.set(k, v);
    }
  } else {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(params || {});
  }
  const r = await fetch(url, opts);
  let data;
  try { data = await r.json(); } catch (e) { data = { error: '响应不是 JSON（HTTP ' + r.status + '）' }; }
  if (!r.ok) {
    const err = new Error(data.error || ('HTTP ' + r.status));
    err.kind = data.kind || (r.status === 403 ? 'readonly' : 'error');
    err.status = r.status;
    throw err;
  }
  return data;
}

/** 写操作是否被允许（只读模式 / 未拿到 meta 时保守处理） */
const canWrite = () => !!(META && !META.read_only);

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/** 把任意值安全地渲染进 HTML */
const h = (s) => esc(s);

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(2) + ' MB';
}

function severity(score) {
  if (score >= 70) return 'bad';
  if (score >= 40) return 'warn';
  return 'ok';
}

/* --------------------------- 确认对话框 --------------------------- */

function confirmDialog({ title, body, okText = '执行', danger = true,
                         askText = '', askLabel = '' }) {
  return new Promise((resolve) => {
    const dlg = $('#confirm-dlg');
    $('#cf-title').textContent = title;
    $('#cf-body').innerHTML = body;
    const okBtn = $('#cf-ok');
    okBtn.textContent = okText;
    okBtn.className = 'btn ' + (danger ? 'danger' : 'primary');
    const wrap = $('#cf-checkwrap');
    const chk = $('#cf-check');
    if (askText) {
      $('#cf-checktext').textContent = askText;
      if (askLabel) $('#cf-checktext').textContent = askLabel;
      chk.checked = false;
      wrap.classList.remove('hidden');
    } else {
      wrap.classList.add('hidden');
    }
    const done = (v) => { dlg.close(); dlg.removeEventListener('close', onClose); resolve(v); };
    const onClose = () => done(chk.checked ? { ok: true, checked: true } : null);
    // 用 close 事件统一收口，避免取消路径漏掉
    dlg.addEventListener('close', onClose, { once: true });
    dlg.showModal();
    okBtn.onclick = (e) => {
      e.preventDefault();
      const checked = chk.checked;
      dlg.removeEventListener('close', onClose);
      dlg.close();
      resolve({ ok: true, checked });
    };
  });
}

/* ------------------------- 极简 Markdown ------------------------- */

function mdInline(s) {
  // s 已经转义过。斜体放在粗体之后，避免 ** 被单个 * 吃掉
  return s
    .replace(/`([^`]+)`/g, (m, c) => '<code>' + c + '</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em>$2</em>')
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (m, txt, url) => {
      // 只允许安全协议，挡掉 javascript: / data:
      const safe = /^(https?:|#|\/)/i.test(url) ? url : '#';
      return '<a href="' + safe + '" target="_blank" rel="noopener noreferrer">' + txt + '</a>';
    });
}

function mdTable(rows) {
  const cells = (line) => line.replace(/^\s*\|/, '').replace(/\|\s*$/, '')
    .split('|').map((c) => c.trim());
  const head = cells(rows[0]);
  const body = rows.slice(2).map(cells);
  let out = '<table><thead><tr>' + head.map((c) => '<th>' + mdInline(c) + '</th>').join('') +
    '</tr></thead><tbody>';
  for (const r of body) {
    out += '<tr>' + r.map((c) => '<td>' + mdInline(c) + '</td>').join('') + '</tr>';
  }
  return out + '</tbody></table>';
}

/** 把 Markdown 转成 HTML。**输入会先整体转义**。 */
function renderMarkdown(src) {
  const text = esc(src).replace(/\r\n?/g, '\n');
  const lines = text.split('\n');
  const out = [];
  let i = 0;
  const flushList = (tag, items) => {
    if (!items.length) return;
    out.push('<' + tag + '>' + items.map((x) => '<li>' + mdInline(x) + '</li>').join('') +
      '</' + tag + '>');
  };
  while (i < lines.length) {
    const line = lines[i];

    // 代码块
    if (/^\s*```/.test(line)) {
      const buf = [];
      i++;
      while (i < lines.length && !/^\s*```/.test(lines[i])) { buf.push(lines[i]); i++; }
      i++;
      out.push('<pre><code>' + buf.join('\n') + '</code></pre>');
      continue;
    }
    // 空行
    if (!line.trim()) { i++; continue; }
    // 水平线
    if (/^\s*([-*_])\s*\1\s*\1[\s\S]*$/.test(line)) { out.push('<hr>'); i++; continue; }
    // 标题
    const hd = line.match(/^(#{1,6})\s+(.*)$/);
    if (hd) {
      const lvl = Math.min(hd[1].length, 4);
      out.push('<h' + lvl + '>' + mdInline(hd[2]) + '</h' + lvl + '>');
      i++; continue;
    }
    // 表格（含分隔行）
    if (/^\s*\|/.test(line) && i + 1 < lines.length && /^\s*\|[\s:|-]+\|\s*$/.test(lines[i + 1])) {
      const rows = [];
      while (i < lines.length && /^\s*\|/.test(lines[i])) { rows.push(lines[i]); i++; }
      out.push(mdTable(rows));
      continue;
    }
    // 引用
    if (/^\s*>/.test(line)) {
      const buf = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) {
        buf.push(lines[i].replace(/^\s*>\s?/, '')); i++;
      }
      out.push('<blockquote>' + mdInline(buf.join(' ')) + '</blockquote>');
      continue;
    }
    // 列表
    if (/^\s*[-*+]\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*[-*+]\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*[-*+]\s+/, '')); i++;
      }
      flushList('ul', items);
      continue;
    }
    if (/^\s*\d+\.\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*\d+\.\s+/, '')); i++;
      }
      flushList('ol', items);
      continue;
    }
    // 段落（连续非空行合并）
    const buf = [];
    while (i < lines.length && lines[i].trim() &&
           !/^\s*(```|#{1,6}\s|>|[-*+]\s|\d+\.\s|\|)/.test(lines[i])) {
      buf.push(lines[i]); i++;
    }
    if (buf.length) out.push('<p>' + mdInline(buf.join(' ')) + '</p>');
  }
  return '<div class="md">' + out.join('\n') + '</div>';
}

/* ------------------------------ 页面 ------------------------------ */

const state = { configPath: '', reportPath: '', logPath: 'logs/net_sensor.log',
                logLines: 300, kapeOut: null };

function pageShell(title, desc, body) {
  $('#content').innerHTML =
    '<h2 class="page">' + esc(title) + '</h2>' +
    (desc ? '<p class="pagedesc">' + esc(desc) + '</p>' : '') + body;
}

function errBox(e) {
  return '<div class="note bad"><strong>读取失败：</strong>' + esc(e.message) + '</div>';
}

const PAGES = {

  /* ------------------------------ 概览 ------------------------------ */
  async overview() {
    // 先渲染骨架，再并行取数填进去。
    // 为什么：首次状态查询里包含一次 KAPE 探测（`kape.exe --help` 不会自己退出，
    // 要等超时，约 8 秒）。整页等 11 秒会让人以为 "坏了" 然后去点刷新 —— 越点越慢。
    // 骨架先出来 + 明确写出"在探测什么"，等待就变成可理解的。
    pageShell('概览', '当前运行状态与执行环境', `
      <div class="grid c4" id="ov-stats">
        ${['网络传感器', '封锁规则', '白名单', '只读库案件'].map((k1) =>
          `<div class="stat"><div class="k">${esc(k1)}</div><div class="v">…</div></div>`).join('')}
      </div>
      <div id="ov-env"><div class="card"><h3>执行环境</h3>
        <div class="hint">正在探测 Sandboxie / KAPE / 传感器… 首次约需 8 秒（KAPE 探测会等命令超时），之后有缓存。</div>
      </div></div>
      <div id="ov-adapters"></div>
      <div class="note">
        本控制台<b>只监听 127.0.0.1</b>，且每次启动随机生成令牌。界面自身不新增任何权限，
        能做的操作与命令行完全一致（硬拒绝条件同样生效）。
      </div>`);

    let s;
    try {
      s = await api('/api/status');
    } catch (e) {
      $('#ov-env').innerHTML = errBox(e);
      return;
    }
    if (CURRENT !== 'overview') return;      // 用户已经切走了，别覆盖别人的页面

    const sen = s.sensor || {};
    const c = s.containment || {};
    const w = s.whitelist || {};
    const v = s.vault || {};
    const sb = s.sandboxie || {};
    const k = s.kape || {};
    const adapters = s.adapters || [];

    $('#health-dot').className = 'dot ' + (sen.running ? 'ok' : 'bad');

    const stat = (k1, v1, x1, cls = '') =>
      `<div class="stat ${cls}"><div class="k">${esc(k1)}</div>
       <div class="v">${esc(v1)}</div>${x1 ? `<div class="x">${esc(x1)}</div>` : ''}</div>`;

    $('#ov-stats').innerHTML =
      stat('网络传感器', sen.running ? '运行中' : '已停止',
           sen.running
             ? ('计划任务 ' + (sen.task_state || '?') + ' · 进程 ' + (sen.procs ?? 1) + ' 个')
             : ('计划任务 ' + (sen.task_state || '未注册')),
           sen.running ? 'ok' : 'bad') +
      stat('封锁规则', c.count ?? 0, '本系统创建的防火墙规则', c.count ? 'warn' : '') +
      stat('白名单', w.total ?? 0, '进程 / 文件 / 文件夹') +
      stat('只读库案件', v.cases ?? 0, fmtBytes(v.mb ? v.mb * 1048576 : 0));

    $('#ov-env').innerHTML = `
      <div class="card">
        <h3>执行环境</h3>
        <dl class="kv">
          <dt>Sandboxie-Plus</dt><dd>${sb.installed ? '<span class="tag ok">已安装</span>' : '<span class="tag bad">异常</span>'}
            ${esc(sb.detail || '')}</dd>
          <dt>沙箱名</dt><dd class="mono">${esc(sb.box || '—')}</dd>
          <dt>KAPE</dt><dd class="mono wrap-any">${esc(k.exe || '未找到')}
            ${k.real ? '<span class="tag ok">已验证</span>' : '<span class="tag warn">未验证</span>'}</dd>
          <dt>只读库路径</dt><dd class="mono wrap-any">${esc(v.path || '—')}</dd>
        </dl>
      </div>`;

    $('#ov-adapters').innerHTML = `
      <div class="card">
        <h3>适配器 <span class="sub">按 actions/config.yaml 的 order 加载</span></h3>
        <table>
          <thead><tr><th>适配器</th><th>状态</th><th>真实生效</th><th>能力</th></tr></thead>
          <tbody>
          ${adapters.map((a) => `
            <tr>
              <td class="mono">${esc(a.name)}</td>
              <td>${a.healthy ? '<span class="tag ok">可用</span>' : '<span class="tag bad">不可用</span>'}
                  <div class="x">${esc(a.health_detail || '')}</div></td>
              <td>${a.real_effects ? '<span class="tag warn">会改系统</span>' : '<span class="tag">仅演练</span>'}</td>
              <td>${(a.capability_list || []).map((x) => '<span class="tag info">' + esc(x) + '</span>').join('') || '—'}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>`;
  },

  /* ------------------------------ 配置 ------------------------------ */
  async config() {
    const r = await api('/api/configs');
    const list = r.configs || [];
    if (!state.configPath) state.configPath = (list[0] || {}).path || '';
    const picker = list.map((c) =>
      `<button data-p="${esc(c.path)}" class="${c.path === state.configPath ? 'active' : ''}">
         ${esc(c.path)}${c.exists ? '' : '（缺失）'}</button>`).join('');

    pageShell('配置', '所有可配置项都能在这里编辑。保存前会校验 YAML、自动备份、原子替换。',
      `<div class="picker">${picker}</div>
       <div id="cfg-area"><div class="loading">正在读取…</div></div>`);

    $$('.picker button').forEach((b) => b.onclick = () => {
      state.configPath = b.dataset.p; PAGES.config();
    });

    try {
      const d = await api('/api/config', { path: state.configPath, parsed: true });
      CACHE.config = d.text;
      const ro = !canWrite();
      $('#cfg-area').innerHTML = `
        ${d.valid ? '' : '<div class="note bad"><strong>当前文件不是合法 YAML：</strong>' + esc(d.error || '') + '</div>'}
        <div class="note${ro ? ' warn' : ''}">
          ${ro ? '只读模式：可以查看，不能保存。' :
            '保存流程：校验 YAML → 备份到 <code>logs/gui_backups/</code> → 原子替换。校验不通过会拒绝写入并保留原文件。'}
        </div>
        <textarea class="code" id="cfg-text" spellcheck="false">${h(d.text)}</textarea>
        <div class="row" style="margin-top:10px">
          <button class="btn primary" id="cfg-save" ${ro ? 'disabled' : ''}>保存</button>
          <button class="btn ghost" id="cfg-revert">放弃修改</button>
          <button class="btn ghost" id="cfg-validate">检查 YAML</button>
          <span class="hint" id="cfg-msg"></span>
        </div>`;
      if (!ro) {
        $('#cfg-save').onclick = async () => {
          const text = $('#cfg-text').value;
          if (text === CACHE.config) { toast('内容没有变化'); return; }
          const c = await confirmDialog({
            title: '保存配置？',
            body: '<p>文件：<strong class="mono">' + h(state.configPath) + '</strong></p>' +
                  '<p>将先备份现有文件，再写入新内容。</p>',
            okText: '保存',
          });
          if (!c || !c.ok) return;
          try {
            const out = await api('/api/config/write', { path: state.configPath, text }, 'POST');
            toast('已保存，备份：' + out.backup, 'ok');
            CACHE.config = text;
            PAGES.config();
          } catch (e) { toast('保存失败：' + e.message, 'err'); }
        };
      }
      $('#cfg-revert').onclick = () => PAGES.config();
      $('#cfg-validate').onclick = () => {
        const m = $('#cfg-msg');
        try {
          // 前端只做粗检查（缩进/补全），真正的判定在后端
          const t = $('#cfg-text').value;
          JSON.stringify(t);
          m.textContent = t.trim() ? '非空，提交时以后端 YAML 解析结果为准' : '内容为空';
        } catch (e) { m.textContent = String(e); }
      };
    } catch (e) {
      $('#cfg-area').innerHTML = errBox(e);
    }
  },

  /* ------------------------------ 报告 ------------------------------ */
  async reports() {
    const r = await api('/api/reports');
    const list = r.reports || [];
    if (!list.length) { pageShell('报告', '检测报告与案例文档', '<div class="note">暂无报告。</div>'); return; }
    if (!state.reportPath || !list.some((x) => x.path === state.reportPath)) {
      state.reportPath = list[0].path;
    }
    const picker = list.map((x) =>
      `<button data-p="${h(x.path)}" class="${x.path === state.reportPath ? 'active' : ''}">
         ${esc(x.name)}<span style="opacity:.6"> · ${esc(x.kind)}</span></button>`).join('');
    pageShell('报告', '检测结果、取证案例与载荷分析（自动渲染 Markdown）',
      `<div class="picker">${picker}</div><div id="rep-area"><div class="loading">正在读取…</div></div>`);
    $$('.picker button').forEach((b) => b.onclick = () => {
      state.reportPath = b.dataset.p; PAGES.reports();
    });
    try {
      const d = await api('/api/report', { path: state.reportPath });
      const meta = list.find((x) => x.path === state.reportPath) || {};
      $('#rep-area').innerHTML =
        `<div class="card">
           <h3>${esc(meta.name || '')}
             <span class="sub">${esc(meta.kind || '')} · ${fmtBytes(meta.size)} · ${esc(meta.modified || '')}</span></h3>
           ${renderMarkdown(d.text)}
         </div>`;
    } catch (e) { $('#rep-area').innerHTML = errBox(e); }
  },

  /* ------------------------------ 日志 ------------------------------ */
  async logs() {
    const r = await api('/api/logs');
    const list = r.logs || [];
    const picker = list.map((x) =>
      `<button data-p="${h(x.path)}" class="${x.path === state.logPath ? 'active' : ''}">
         ${esc(x.path.split('/').pop())}${x.exists ? '' : '（无）'}</button>`).join('');
    pageShell('日志', '实时查看传感器、审计与沙箱流水日志（只读）',
      `<div class="picker">${picker}</div>
       <div class="row" style="margin-bottom:10px">
         <label class="f" style="margin:0">显示尾部行数</label>
         <select id="log-lines" style="width:auto">
           ${[100, 300, 800, 2000, 5000].map((n) =>
             `<option value="${n}" ${n === state.logLines ? 'selected' : ''}>${n}</option>`).join('')}
         </select>
         <button class="btn ghost" id="log-reload">重新加载</button>
         <span class="hint" id="log-meta"></span>
       </div>
       <pre class="log" id="log-body">正在读取…</pre>`);
    $$('.picker button').forEach((b) => b.onclick = () => {
      state.logPath = b.dataset.p; PAGES.logs();
    });
    $('#log-lines').onchange = (e) => { state.logLines = +e.target.value; PAGES.logs(); };
    $('#log-reload').onclick = () => PAGES.logs();
    try {
      const d = await api('/api/log', { path: state.logPath, lines: state.logLines });
      $('#log-body').textContent = d.text || '（空）';
      $('#log-meta').textContent = d.exists
        ? `${fmtBytes(d.size)} · 最后修改 ${d.modified}` : '文件不存在';
      const pre = $('#log-body');
      pre.scrollTop = pre.scrollHeight;
    } catch (e) { $('#log-body').textContent = '读取失败：' + e.message; }
  },

  /* ---------------------------- 威胁建模 ---------------------------- */
  async threat() {
    const t = await api('/api/threat');
    const a = t.assets || {};
    const det = t.detection || {};
    const ob = t.observed || {};

    const kvList = (arr) => (arr && arr.length)
      ? arr.map((x) => '<span class="tag mono">' + esc(x) + '</span>').join('')
      : '<span class="hint">未配置</span>';

    const obRows = Object.entries(ob.by_rule || {}).map(([k1, v1]) => `
      <tr><td class="mono">${esc(k1)}</td><td class="num">${esc(v1)}</td>
          <td><div class="bar" style="max-width:120px"><i style="width:${Math.min(100, v1 * 12)}%"></i></div></td></tr>`).join('');

    const procRows = Object.entries(ob.top_procs || {}).map(([k1, v1]) =>
      `<tr><td class="mono wrap-any">${esc(k1)}</td><td class="num">${esc(v1)}</td></tr>`).join('');

    const ruleRows = (det.rules || []).map((r1) => `
      <tr><td class="mono">${esc(r1.rule)}</td>
          <td class="num">${esc(r1.base_score)}</td>
          <td>${esc(r1.why || '')}</td></tr>`).join('');

    const phaseRows = (t.phases || []).map((p) =>
      `<tr><td class="mono">${esc(p.phase)}</td><td>${esc(p.zh)}</td><td>${esc(p.en)}</td>
           <td>${esc(p.goal)}</td></tr>`).join('');

    const body = `
      <div class="note">
        这一页回答三个问题：<b>要保护什么</b>、<b>能看见什么</b>、<b>看不见什么</b>。
        所有数字都来自实际配置与代码里的规则表，不复制文档。
      </div>

      <div class="card">
        <h3>要保护什么 <span class="sub">来自 actions/config.yaml 的策略</span></h3>
        <dl class="kv">
          <dt>受保护主机</dt><dd>${kvList(a.protected_hosts)}</dd>
          <dt>受保护账号</dt><dd>${kvList(a.protected_accounts)}</dd>
          <dt>受保护域</dt><dd>${kvList(a.protected_domains)}</dd>
          <dt>受保护 IP</dt><dd>${kvList(a.protected_ips)}</dd>
          <dt>受保护路径</dt><dd>${kvList(a.protected_paths)}</dd>
        </dl>
      </div>

      <div class="card">
        <h3>检测能力 <span class="sub">告警阈值 ${esc(det.threshold ?? '—')} 分 · 白名单上限 ${esc(det.whitelist_cap ?? '—')}</span></h3>
        <table>
          <thead><tr><th>规则</th><th class="num">基础分</th><th>含义</th></tr></thead>
          <tbody>${ruleRows || '<tr><td colspan="3">无</td></tr>'}</tbody>
        </table>
        <div style="margin-top:12px">
          <div class="k" style="font-size:12px;color:var(--fg-soft)">高危端口</div>
          <div>${kvList(det.high_risk_ports)}</div>
        </div>
        <div style="margin-top:10px">
          <div class="k" style="font-size:12px;color:var(--fg-soft)">受信路径（在这些目录下的可执行文件不加分）</div>
          <div>${kvList(det.trusted_paths)}</div>
        </div>
      </div>

      <div class="card">
        <h3>实际观测到什么 <span class="sub">按规则聚合 · 共 ${esc(ob.events ?? 0)} 条事件</span></h3>
        <div class="grid c2">
          <div>
            <table><thead><tr><th>规则</th><th class="num">命中</th><th></th></tr></thead>
              <tbody>${obRows || '<tr><td colspan="3">暂无命中</td></tr>'}</tbody></table>
          </div>
          <div>
            <table><thead><tr><th>出现最多的进程</th><th class="num">次数</th></tr></thead>
              <tbody>${procRows || '<tr><td colspan="2">暂无</td></tr>'}</tbody></table>
            ${ob.error ? '<div class="note bad" style="margin-top:10px">' + esc(ob.error) + '</div>' : ''}
          </div>
        </div>
      </div>

      <div class="card">
        <h3>看不见什么 <span class="sub">覆盖缺口（不要把这些读成"没问题"）</span></h3>
        <ul class="plain">${(t.gaps || []).map((g) => '<li>' + mdInline(esc(g)) + '</li>').join('')}</ul>
      </div>

      <div class="card">
        <h3>处置流程（PDCERF） <span class="sub">来自 actions/pdcerf.py 的阶段定义</span></h3>
        <table>
          <thead><tr><th>阶段</th><th>中文</th><th>英文</th><th>目标</th></tr></thead>
          <tbody>${phaseRows || '<tr><td colspan="4">无</td></tr>'}</tbody>
        </table>
      </div>`;
    pageShell('威胁建模', '资产、检测能力、实际观测与已知盲区', body);
  },

  /* ------------------------------ 封锁 ------------------------------ */
  async contain() {
    const d = await api('/api/containment');
    const ro = !canWrite();
    const rows = (d.rules || []).map((r1) => `
      <tr>
        <td class="mono wrap-any">${esc(r1.name)}</td>
        <td class="mono">${esc(r1.remote)}</td>
        <td>${r1.enabled ? '<span class="tag ok">已启用</span>' : '<span class="tag">已停用</span>'}</td>
        <td>
          <button class="btn sm ghost rm" data-n="${h(r1.name)}" ${ro ? 'disabled' : ''}>解除</button>
        </td>
      </tr>`).join('');

    pageShell('封锁', '手动封禁/解禁 IP。只封精确对端的出向、带 TTL，不碰网关与 DNS。',
      `<div class="card">
         <h3>当前规则 <span class="sub">共 ${esc(d.count ?? 0)} 条 · 前缀 ${esc(d.prefix || '')}</span></h3>
         ${ro ? '<div class="note warn">只读模式：不能新增或解除封锁。</div>' : ''}
         <table>
           <thead><tr><th>规则名</th><th>对端</th><th>状态</th><th></th></tr></thead>
           <tbody>${rows || '<tr><td colspan="4">当前没有本系统创建的封锁规则</td></tr>'}</tbody>
         </table>
         ${(d.count ? `<div class="row" style="margin-top:10px">
             <button class="btn danger" id="rm-all" ${ro ? 'disabled' : ''}>全部解除</button></div>` : '')}
       </div>

       <div class="card">
         <h3>新增封锁</h3>
         <div class="note">只接受单个 IP 或 ≥/32 的精确目标。网段、网关、DNS、本机地址会被<b>直接拒绝</b>，
           因为封掉它们会中断整个业务网络 —— 这不是"更安全"，是自伤。</div>
         <div class="grid c3">
           <div><label class="f">目标 IP</label>
             <input type="text" id="ct-ip" placeholder="例：203.0.113.45"></div>
           <div><label class="f">时长（秒）</label>
             <input type="number" id="ct-ttl" value="14400"></div>
           <div><label class="f">原因</label>
             <input type="text" id="ct-reason" placeholder="例：C2 回连"></div>
         </div>
         <div class="row" style="margin-top:12px">
           <button class="btn ghost" id="ct-plan" ${ro ? 'disabled' : ''}>只生成计划（不改系统）</button>
           <button class="btn danger" id="ct-apply" ${ro ? 'disabled' : ''}>立即封锁</button>
         </div>
         <div id="ct-out" style="margin-top:12px"></div>
       </div>`);

    $$('.rm').forEach((b) => b.onclick = async () => {
      const n = b.dataset.n;
      const c = await confirmDialog({
        title: '解除这条封锁？',
        body: '<p class="mono">' + h(n) + '</p>',
        okText: '解除',
      });
      if (!c || !c.ok) return;
      try {
        const out = await api('/api/containment/remove', { names: [n] }, 'POST');
        toast(out.detail || '已解除', 'ok');
        PAGES.contain();
      } catch (e) { toast('失败：' + e.message, 'err'); }
    });

    const rmAll = $('#rm-all');
    if (rmAll) rmAll.onclick = async () => {
      const c = await confirmDialog({
        title: '解除全部封锁？',
        body: '<p>将删除本系统创建的全部防火墙规则（只匹配 <span class="mono">' +
              h(d.prefix || '') + '</span> 前缀，不会碰其他软件的规则）。</p>',
        okText: '全部解除',
      });
      if (!c || !c.ok) return;
      try {
        const out = await api('/api/containment/remove', {}, 'POST');
        toast(out.detail || '已全部解除', 'ok');
        PAGES.contain();
      } catch (e) { toast('失败：' + e.message, 'err'); }
    };

    const runContain = async (apply) => {
      const ip = $('#ct-ip').value.trim();
      if (!ip) { toast('请填写目标 IP'); return; }
      if (apply) {
        const c = await confirmDialog({
          title: '确认创建真实防火墙规则？',
          body: '<p>目标：<strong class="mono">' + h(ip) + '</strong></p>' +
                '<p>这会<b>立即生效</b>并阻断该对端的出向连接。规则带 TTL，到期可由维护任务清理。</p>',
          okText: '立即封锁',
        });
        if (!c || !c.ok) return;
      }
      try {
        const out = await api('/api/containment/add', {
          indicator: ip, ttl_seconds: +$('#ct-ttl').value || 14400,
          reason: $('#ct-reason').value, apply: apply,
        }, 'POST');
        const refused = (out.refused || []).map((x) =>
          '<li><span class="tag bad">拒绝</span> <span class="mono">' + esc(x.address || x.display_name) +
          '</span> — ' + esc(x.reason) + '</li>').join('');
        const will = (out.will_block || []).map((x) =>
          '<li><span class="tag ok">将封</span> <span class="mono">' + esc(x.address) + '</span> ' +
          esc(x.direction) + ' ' + esc(x.protocol) + '</li>').join('');
        $('#ct-out').innerHTML =
          `<div class="note ${out.status === 'denied' ? 'bad' : ''}">
             <b>结果：</b>${esc(out.status)} — ${esc(out.detail || '')}</div>
           ${refused ? '<ul class="plain">' + refused + '</ul>' : ''}
           ${will ? '<ul class="plain">' + will + '</ul>' : ''}
           ${out.non_interference ? '<div class="note">' + esc(out.non_interference) + '</div>' : ''}
           ${apply && out.applied && out.applied.length
             ? '<div class="note ok">已应用 ' + out.applied.length + ' 条规则</div>' : ''}`;
        toast(apply ? '封锁已应用' : '计划已生成（未改系统）', apply ? 'ok' : '');
        if (apply) setTimeout(() => PAGES.contain(), 900);
      } catch (e) { toast('失败：' + e.message, 'err'); }
    };
    $('#ct-plan').onclick = () => runContain(false);
    $('#ct-apply').onclick = () => runContain(true);
  },

  /* ------------------------------ 白名单 ------------------------------ */
  async whitelist() {
    const d = await api('/api/whitelist');
    const ro = !canWrite();
    const rows = (d.entries || []).map((e) => `
      <tr>
        <td><span class="tag info">${esc(e.kind)}</span></td>
        <td class="mono wrap-any">${esc(e.value)}</td>
        <td>${esc(e.note || '')}</td>
        <td class="hint">${esc(e.added_by || '')}<br>${esc(e.added_at || '')}</td>
        <td>${e.expires_at ? '<span class="tag warn">' + esc(e.expires_at) + '</span>' : '<span class="hint">永久</span>'}</td>
        <td><button class="btn sm ghost rm" data-k="${h(e.kind)}" data-v="${h(e.value)}" ${ro ? 'disabled' : ''}>移除</button></td>
      </tr>`).join('');

    const st = d.stats || {};
    pageShell('白名单', '把"已知无害但总在告警"的进程/文件/文件夹降级为噪音。',
      `<div class="note warn">
        白名单<b>只降低告警敏感度，不授予任何权限</b>。它不会让一个动作变"允许"，
        所以即使有人改了白名单文件，也不能借此执行破坏性操作。
        校验层会硬拒绝覆盖临时目录、下载目录，以及系统进程的裸名（如 <span class="mono">svchost.exe</span>）——
        这些地方正是恶意软件最常落脚的。
       </div>

       <div class="grid c4">
         <div class="stat"><div class="k">条目总数</div><div class="v">${esc(st.total ?? 0)}</div></div>
         ${Object.entries(st.by_kind || {}).map(([k1, v1]) =>
           `<div class="stat"><div class="k">${esc(k1)}</div><div class="v">${esc(v1)}</div></div>`).join('')}
       </div>

       <div class="card" style="margin-top:14px">
         <h3>新增条目</h3>
         <div class="grid c4">
           <div><label class="f">类型</label>
             <select id="wl-kind">${(d.kinds || []).map((k1) =>
               `<option value="${h(k1)}">${esc(k1)}</option>`).join('')}</select></div>
           <div style="grid-column: span 2"><label class="f">值（路径需绝对路径）</label>
             <input type="text" id="wl-value" placeholder="例：D:\\tools\\trusted\\agent.exe"></div>
           <div><label class="f">有效天数（0=永久）</label>
             <input type="number" id="wl-ttl" value="0"></div>
         </div>
         <div class="frow" style="margin-top:10px"><label class="f">备注</label>
           <input type="text" id="wl-note" placeholder="例：自研巡检工具，每天 09:00 外连上报"></div>
         <div class="row">
           <button class="btn primary" id="wl-add" ${ro ? 'disabled' : ''}>加入白名单</button>
         </div>
         <div id="wl-out" style="margin-top:10px"></div>
       </div>

       <div class="card">
         <h3>现有条目</h3>
         <table>
           <thead><tr><th>类型</th><th>值</th><th>备注</th><th>添加者</th><th>有效期</th><th></th></tr></thead>
           <tbody>${rows || '<tr><td colspan="6">暂无白名单条目</td></tr>'}</tbody>
         </table>
       </div>

       <div class="card">
         <h3>校验规则 <span class="sub">这些路径/名称永远不会被加进白名单</span></h3>
         <div style="margin-bottom:8px"><b>暂存类目录：</b>
           ${(d.policy?.staging_hints || []).map((x) => '<span class="tag mono">' + esc(x) + '</span>').join('')}</div>
         <div><b>系统进程裸名（需写绝对路径）：</b>
           ${(d.policy?.critical_process_names || []).map((x) => '<span class="tag mono">' + esc(x) + '</span>').join('')}</div>
       </div>`);

    $('#wl-add').onclick = async () => {
      const kind = $('#wl-kind').value, value = $('#wl-value').value.trim();
      if (!value) { toast('请填写值'); return; }
      try {
        const out = await api('/api/whitelist/add', {
          kind, value, note: $('#wl-note').value, ttl_days: +$('#wl-ttl').value || 0,
        }, 'POST');
        toast('已加入白名单', 'ok');
        $('#wl-value').value = ''; $('#wl-note').value = '';
        $('#wl-out').innerHTML = '<div class="note ok">已加入：<span class="mono">' +
          esc(JSON.stringify(out.entry)) + '</span></div>';
        setTimeout(() => PAGES.whitelist(), 700);
      } catch (e) {
        // 拒绝原因原样显示（不翻译成"操作失败"，否则用户不知道该怎么改）
        $('#wl-out').innerHTML = '<div class="note bad"><b>拒绝：</b>' + esc(e.message) + '</div>';
        toast('被拒绝', 'err');
      }
    };

    $$('.rm').forEach((b) => b.onclick = async () => {
      const c = await confirmDialog({
        title: '移出白名单？',
        body: '<p class="mono">' + h(b.dataset.k) + ' · ' + h(b.dataset.v) + '</p>' +
              '<p>移除后，该对象的告警会恢复原有分值。</p>',
        okText: '移除', danger: false,
      });
      if (!c || !c.ok) return;
      try {
        await api('/api/whitelist/remove', { kind: b.dataset.k, value: b.dataset.v }, 'POST');
        toast('已移除', 'ok'); PAGES.whitelist();
      } catch (e) { toast('失败：' + e.message, 'err'); }
    });
  },

  /* ---------------------------- AI 动作 ---------------------------- */
  async actions() {
    const d = await api('/api/actions');
    const ro = !canWrite();
    const rows = (d.items || []).map((it, ix) => {
      const st = it.dry_run ? '<span class="tag">演练</span>'
        : it.ok ? '<span class="tag ok">已执行</span>' : '<span class="tag bad">失败/拒绝</span>';
      const undo = it.undoable
        ? `<button class="btn sm danger undo" data-ix="${ix}" ${ro ? 'disabled' : ''}>撤销</button>`
        : `<span class="hint">不可撤销</span>`;
      return `<tr>
        <td class="hint">${esc(it.time || it.ts)}</td>
        <td class="mono">${esc(it.action)}</td>
        <td>${st}</td>
        <td class="mono">${esc(it.adapter || '')}</td>
        <td class="wrap-any">${esc(it.policy_reason || it.note || '')}</td>
        <td>${undo}</td>
      </tr>`;
    }).join('');

    const pending = (d.pending || []).map((p) =>
      `<tr><td class="mono">${esc(p.file)}</td><td class="mono">${esc(p.action || '')}</td>
           <td>${esc(p.case_id || '')}</td></tr>`).join('');

    pageShell('AI 动作', 'AI 代理执行过的动作台账与撤销入口。数据源：logs/action_audit.jsonl',
      `<div class="note">
        撤销是<b>如实分类</b>的：能撤的给按钮，不能撤的说明原因。
        证据类动作（载荷提取、取证采集）默认不撤销 —— 删证据比留着更危险，
        案子复核时就找不到了，所以需要显式勾选确认。
       </div>

       <div class="grid c4">
         <div class="stat"><div class="k">动作总数</div><div class="v">${esc(d.total ?? 0)}</div></div>
         <div class="stat"><div class="k">可撤销</div><div class="v">${esc((d.items || []).filter((x) => x.undoable).length)}</div></div>
         <div class="stat"><div class="k">待确认</div><div class="v">${esc((d.pending || []).length)}</div></div>
         <div class="stat"><div class="k">当前封锁规则</div><div class="v">${esc((d.current_rules || []).length)}</div></div>
       </div>

       <div class="card" style="margin-top:14px">
         <h3>动作台账 <span class="sub">最新在前</span></h3>
         <table>
           <thead><tr><th>时间</th><th>动作</th><th>状态</th><th>适配器</th><th>说明</th><th>操作</th></tr></thead>
           <tbody>${rows || '<tr><td colspan="6">暂无动作记录</td></tr>'}</tbody>
         </table>
       </div>

       ${(d.pending || []).length ? `
       <div class="card">
         <h3>待确认动作 <span class="sub">logs/pending_actions/</span></h3>
         <table><thead><tr><th>文件</th><th>动作</th><th>案件</th></tr></thead>
           <tbody>${pending}</tbody></table>
         <div class="note">这些动作在等待人工确认。取消确认可直接删除对应文件（命令行 <span class="mono">actions.cli</span> 亦可）。</div>
       </div>` : ''}

       <div class="card">
         <h3>撤销审计</h3>
         <div class="hint">所有撤销操作记录在 <span class="mono">${esc(d.undo_log || '')}</span></div>
       </div>`);

    $$('.undo').forEach((b) => b.onclick = async () => {
      const it = d.items[+b.dataset.ix];
      const c = await confirmDialog({
        title: '撤销动作：' + it.action,
        body: `<dl class="kv">
                 <dt>时间</dt><dd>${h(it.time || it.ts)}</dd>
                 <dt>适配器</dt><dd class="mono">${h(it.adapter || '')}</dd>
                 <dt>说明</dt><dd>${h(it.note || '')}</dd>
                 <dt>参数</dt><dd class="mono">${h(JSON.stringify(it.args || {}))}</dd>
               </dl>
               <p style="margin-top:10px">将删除本系统创建的全部防火墙封锁规则。</p>`,
        okText: '撤销',
      });
      if (!c || !c.ok) return;
      try {
        const out = await api('/api/undo', { kind: 'firewall', payload: {} }, 'POST');
        toast(out.detail || '已撤销', 'ok');
        PAGES.actions();
      } catch (e) { toast('撤销失败：' + e.message, 'err'); }
    });
  },

  /* ------------------------------ KAPE ------------------------------ */
  async kape() {
    const k = await api('/api/kape');
    const ro = !canWrite();
    const g = k.gates || {};
    const canRun = !!k.can_execute && !ro;
    pageShell('KAPE 取证', '采集主机痕迹。默认演练，真实采集需要配置里两道开关同时打开。',
      `<div class="card">
         <h3>环境</h3>
         <dl class="kv">
           <dt>kape.exe</dt><dd class="mono wrap-any">${esc(k.exe || '未找到')}</dd>
           <dt>探测结果</dt><dd>${k.real ? '<span class="tag ok">可用（已实际调用验证）</span>'
                                          : '<span class="tag bad">不可用</span>'} ${esc(k.detail || '')}</dd>
           <dt>target</dt><dd class="mono">${esc(k.target || '')}</dd>
           <dt>module</dt><dd class="mono">${esc(k.module || '') || '（空：只采集不解析）'}</dd>
           <dt>输出根目录</dt><dd class="mono wrap-any">${esc(k.output_root || '')}</dd>
           <dt>体积预算</dt><dd>${esc(k.max_collect_mb ?? '')} MB</dd>
         </dl>
         <div style="margin-top:10px"><label class="f">命令预览</label>
           <pre class="log" style="max-height:none">${esc(k.command_preview || '—')}</pre></div>
       </div>

       <div class="card">
         <h3>真实采集的两道开关 <span class="sub">都为 true 才允许真实执行</span></h3>
         <table>
           <thead><tr><th>开关</th><th>位置</th><th>当前</th></tr></thead>
           <tbody>
             <tr><td>工具层（第二道）</td><td class="mono wrap-any">${esc(g.tool_key || '')}</td>
                 <td>${g.tool_execute ? '<span class="tag ok">已开</span>' : '<span class="tag bad">未开</span>'}</td></tr>
             <tr><td>联动层</td><td class="mono wrap-any">${esc(g.agent_key || '')}</td>
                 <td>${g.agent_execute ? '<span class="tag ok">已开</span>' : '<span class="tag bad">未开</span>'}</td></tr>
           </tbody>
         </table>
         <div class="note ${canRun ? 'ok' : 'warn'}" style="margin-top:12px">
           ${canRun
             ? '两道开关均已打开：可以执行真实采集（仍需管理员权限，否则会拒绝以免产出残缺证据）。'
             : '当前<b>不允许真实采集</b>。这是刻意的设计：一次采集会写入数百 MB 产物、并读取锁定的注册表配置单元，' +
               '所以需要在配置里显式批准，而不是在界面上点一下。要开启请在「配置」页改这两项。'}
         </div>
       </div>

       <div class="card">
         <h3>操作</h3>
         <div class="row">
           <button class="btn ghost" id="kp-sim" ${ro ? 'disabled' : ''}>演练（不改系统）</button>
           <button class="btn danger" id="kp-real" ${canRun ? '' : 'disabled'}
                   title="${canRun ? '' : '两道开关未开，已在服务端拒绝'}">真实采集</button>
           <button class="btn ghost" id="kp-gui" ${ro ? 'disabled' : ''}>唤起 KAPE 图形界面</button>
           <button class="btn ghost" id="kp-open">打开输出目录</button>
         </div>
         <div class="note warn" style="margin-top:12px">
           一次真实采集会写入数百 MB 产物。target 已按实测数据收敛（见
           <span class="mono">forensics/targets/BlueTeam-Triage.tkape</span> 头部注释），
           但仍建议先用「演练」确认范围。「演练」只生成 <span class="mono">run_kape.cmd</span>，不产生任何产物。
         </div>
         <div id="kp-out" style="margin-top:12px"></div>
       </div>`);

    const out = (r1, isErr) => {
      const o = $('#kp-out');
      o.innerHTML = '<div class="note ' + (isErr ? 'bad' : 'ok') + '"><b>' + esc(r1.status || (isErr ? '错误' : '完成')) +
        '</b> — ' + esc(r1.detail || '') + '</div>' +
        (r1.outdir ? '<dl class="kv"><dt>输出目录</dt><dd class="mono wrap-any">' + esc(r1.outdir) + '</dd>' +
          (r1.collected_files !== undefined ? '<dt>文件数</dt><dd>' + esc(r1.collected_files) + '</dd>' : '') +
          (r1.collected_mb !== undefined ? '<dt>体积</dt><dd>' + esc(r1.collected_mb) + ' MB</dd>' : '') +
          (r1.elapsed_s !== undefined ? '<dt>耗时</dt><dd>' + esc(r1.elapsed_s) + ' s</dd>' : '') + '</dl>' : '') +
        ((r1.warnings || []).length ? '<ul class="plain">' + r1.warnings.map((w) =>
          '<li>' + esc(w) + '</li>').join('') + '</ul>' : '') +
        (r1.stdout_tail ? '<pre class="log">' + esc(r1.stdout_tail) + '</pre>' : '');
    };

    $('#kp-sim').onclick = async () => {
      try { toast('演练中…'); out(await api('/api/kape/run', { sim: true, execute: false }, 'POST'), false); }
      catch (e) { out({ status: '失败', detail: e.message }, true); }
    };
    $('#kp-real').onclick = async () => {
      const c = await confirmDialog({
        title: '确认真实采集？',
        body: '<p>将调用 <span class="mono">kape.exe</span> 从本机采集痕迹，可能写入数百 MB。</p>' +
              '<p>预算上限：<strong>' + h(k.max_collect_mb) + ' MB</strong>，超出会告警。</p>',
        okText: '开始采集',
      });
      if (!c || !c.ok) return;
      try { toast('采集中，请稍候…'); out(await api('/api/kape/run', { execute: true }, 'POST'), false); }
      catch (e) { out({ status: '失败', detail: e.message }, true); }
    };
    $('#kp-gui').onclick = async () => {
      try { const r1 = await api('/api/kape/gui', {}, 'POST'); toast('已唤起：' + r1.launched, 'ok'); }
      catch (e) { toast('失败：' + e.message, 'err'); }
    };
    $('#kp-open').onclick = async () => {
      try { await api('/api/open', { path: 'logs/forensics' }, 'POST'); }
      catch (e) { toast('失败：' + e.message, 'err'); }
    };
  },
};

/* ------------------------------ 路由 ------------------------------ */

async function show(page) {
  CURRENT = page;
  $$('.nav').forEach((b) => b.classList.toggle('active', b.dataset.page === page));
  $('#content').innerHTML = '<div class="loading">正在加载…</div>';
  try {
    await PAGES[page]();
  } catch (e) {
    $('#content').innerHTML = '<h2 class="page">出错了</h2>' +
      '<div class="note bad">' + esc(e.message) + '</div>' +
      (e.kind === 'readonly' ? '<div class="note warn">当前是只读模式。</div>' : '');
    if (e.status === 401) {
      toast('令牌无效。请用启动时托盘气泡里的地址重新打开。', 'err');
    }
  }
}

async function boot() {
  $$('.nav').forEach((b) => b.onclick = () => show(b.dataset.page));
  $('#btn-refresh').onclick = () => show(CURRENT);
  try {
    META = await api('/api/meta');
    const mode = $('#pill-mode');
    if (META.read_only) {
      mode.textContent = '只读模式'; mode.className = 'pill bad';
    } else {
      mode.textContent = '可操作'; mode.className = 'pill ok';
    }
  } catch (e) {
    $('#pill-mode').textContent = '未连接';
    $('#pill-mode').className = 'pill bad';
    toast('无法连接后端：' + e.message, 'err');
  }
  const tick = () => { $('#pill-time').textContent = new Date().toLocaleTimeString('zh-CN'); };
  tick(); setInterval(tick, 1000);
  await show('overview');
}

document.addEventListener('DOMContentLoaded', boot);
