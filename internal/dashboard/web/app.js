'use strict';
/* netinspect dashboard — vanilla JS, no dependencies.
 * 只展示连接级元数据：这里没有任何 body/headers/path 的概念。 */

const $ = (id) => document.getElementById(id);

/* ---------- pure helpers ---------- */
function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function fmtBytes(n) {
  n = +n || 0;
  if (n < 1024) return n + ' B';
  const u = ['KB', 'MB', 'GB', 'TB'];
  let i = -1, v = n;
  do { v /= 1024; i++; } while (v >= 1024 && i < u.length - 1);
  const r = v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2);
  return r + ' ' + u[i];
}
function fmtMs(v) {
  v = +v || 0;
  return (v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)) + ' ms';
}
function fmtDT(ms) {           // 本地日期时间
  ms = +ms || 0;
  return ms > 0 ? new Date(ms).toLocaleString() : '—';
}
function fmtT(ms) {            // 本地时间（表内用）
  ms = +ms || 0;
  return ms > 0 ? new Date(ms).toLocaleTimeString() : '—';
}
function isFailed(r) { return !!r && r !== 'ok' && r !== 'open'; }
function matchesQ(c, q) {      // 与后端 ListConnections 的过滤语义一致
  if (!q) return true;
  q = q.toLowerCase();
  return (c.orig_host + ' ' + c.sni + ' ' + c.orig_ip + ' ' + c.comm)
    .toLowerCase().includes(q);
}
function resultBadge(r) {
  if (r === 'ok')   return '<span class="rbadge ok">ok</span>';
  if (r === 'open') return '<span class="rbadge open">open</span>';
  if (isFailed(r))  return '<span class="rbadge fail">' + esc(r) + '</span>';
  return '<span class="rbadge pending">…</span>';
}

/* ---------- state ---------- */
const state = {
  conns: new Map(),   // id -> conn
  dns: [],            // newest first
  q: '',
  tab: 'conns',
  stats: { conns: 0, failed: 0, bytes_up: 0, bytes_down: 0, dns: 0 },
  detailId: null,
  ws: null,
  wsTimer: null,
};
const MAX_KEEP = 2000;   // 本地最多保留的条目数
const ROW_LIMIT = 500;   // 表格最多渲染行数

/* ---------- topbar / stats ---------- */
function renderSession(s) {
  if (!s) return;
  $('session-id').textContent = String(s.id || '').slice(0, 8) || '—';
  $('session-id').title = 'session id: ' + (s.id || '');
  $('mode-badge').textContent = s.mode || '—';
  $('command').textContent = s.command || '—';
  $('command').title = s.command || '';
  const ended = (+s.ended_at || 0) > 0;
  $('stop-server').disabled = !ended;
  const st = $('status');
  st.textContent = ended ? '已结束' : '运行中';
  st.className = 'status ' + (ended ? 'ended' : 'running');
}
function renderStats() {
  const s = state.stats;
  $('st-conns').textContent = s.conns;
  $('st-failed').textContent = s.failed;
  $('st-up').textContent = fmtBytes(s.bytes_up);
  $('st-down').textContent = fmtBytes(s.bytes_down);
  $('st-dns').textContent = s.dns;
}
async function loadSession() {
  if (serverStopped) return;
  try {
    const r = await fetch('/api/session');
    if (!r.ok) throw new Error(r.status);
    const d = await r.json();
    renderSession(d.session);
    if (d.stats) { state.stats = { ...state.stats, ...d.stats }; renderStats(); }
  } catch (e) { /* 后台轮询失败时静默，ws 指示灯会反映状态 */ }
}

/* ---------- connections ---------- */
function connRow(c) {
  const target = esc(c.orig_host || c.orig_ip || '') + ':' + esc(c.orig_port ?? '');
  const sniLine = (c.sni && c.sni !== c.orig_host)
    ? '<div class="sni">SNI: ' + esc(c.sni) + '</div>' : '';
  let latency = '<span class="num">' + esc(fmtMs(c.connect_ms)) + '</span>';
  if (c.proto === 'tls' && (+c.tls_ms || 0) > 0)
    latency += '<span class="tlsms">tls ' + esc(fmtMs(c.tls_ms)) + '</span>';
  const traffic = '<span class="num">↓' + esc(fmtBytes(c.bytes_down)) +
                  ' ↑' + esc(fmtBytes(c.bytes_up)) + '</span>';
  return '<tr class="row" data-id="' + esc(c.id) + '">' +
    '<td class="mono">' + target + sniLine + '</td>' +
    '<td class="mono">' + esc(c.comm) + '<span class="dim">(' + esc(c.pid) + ')</span></td>' +
    '<td><span class="dim small">' + esc(c.mode) + '</span></td>' +
    '<td class="proto mono">' + (c.proto ? esc(c.proto) : '<span class="dim">—</span>') + '</td>' +
    '<td>' + latency + '</td>' +
    '<td>' + traffic + '</td>' +
    '<td>' + resultBadge(c.result) + '</td></tr>';
}
function sortedConns() {
  return [...state.conns.values()]
    .filter((c) => matchesQ(c, state.q))
    .sort((a, b) => (b.started_at || 0) - (a.started_at || 0) || (b.id || 0) - (a.id || 0));
}
function renderConns() {
  const list = sortedConns().slice(0, ROW_LIMIT);
  $('conns-body').innerHTML = list.length
    ? list.map(connRow).join('')
    : '<tr><td colspan="7" class="empty">暂无连接' + (state.q ? '（过滤条件无匹配）' : '') + '</td></tr>';
  $('count-note').textContent = state.q
    ? '显示 ' + list.length + ' / 已知 ' + state.conns.size
    : '共 ' + state.conns.size + ' 条连接';
  markSelectedRow();
}
function trimConns() {
  if (state.conns.size <= MAX_KEEP) return;
  const ids = [...state.conns.values()]
    .sort((a, b) => (a.started_at || 0) - (b.started_at || 0))
    .slice(0, state.conns.size - MAX_KEEP).map((c) => c.id);
  ids.forEach((id) => state.conns.delete(id));
}
function applyConn(cur) {
  const old = state.conns.get(cur.id);
  state.conns.set(cur.id, cur);
  trimConns();
  // 增量维护统计（/api/session 轮询会定期校准）
  const s = state.stats;
  const up = +cur.bytes_up || 0, down = +cur.bytes_down || 0;
  if (!old) {
    s.conns++;
    s.bytes_up += up; s.bytes_down += down;
    if (isFailed(cur.result)) s.failed++;
  } else {
    s.bytes_up += up - (+old.bytes_up || 0);
    s.bytes_down += down - (+old.bytes_down || 0);
    if (!isFailed(old.result) && isFailed(cur.result)) s.failed++;
  }
  renderStats();
  renderConns();
  if (state.detailId === cur.id) renderDetail(cur);
}
async function loadConns() {
  try {
    const r = await fetch('/api/connections?q=' + encodeURIComponent(state.q) + '&limit=1000');
    if (!r.ok) throw new Error(r.status);
    const arr = await r.json();
    state.conns.clear();
    (Array.isArray(arr) ? arr : []).forEach((c) => state.conns.set(c.id, c));
    renderConns();
  } catch (e) {
    $('conns-body').innerHTML = '<tr><td colspan="7" class="empty">加载失败，请检查后端</td></tr>';
  }
}

/* ---------- DNS ---------- */
function dnsRow(d) {
  return '<tr><td class="num">' + esc(fmtT(d.at)) + '</td>' +
    '<td class="mono">' + esc(d.comm) + '<span class="dim">(' + esc(d.pid) + ')</span></td>' +
    '<td class="mono">' + esc(d.qname) + '</td>' +
    '<td class="mono dim">' + esc(d.qtype) + '</td>' +
    '<td class="mono small">' + (d.answer ? esc(d.answer) : '<span class="dim">—</span>') + '</td>' +
    '<td class="num">' + esc(fmtMs(d.ms)) + '</td></tr>';
}
function renderDNS() {
  const list = state.dns.slice(0, ROW_LIMIT);
  $('dns-body').innerHTML = list.length
    ? list.map(dnsRow).join('')
    : '<tr><td colspan="6" class="empty">暂无 DNS 查询</td></tr>';
}
function applyDNS(d) {
  state.dns.unshift(d);
  if (state.dns.length > MAX_KEEP) state.dns.length = MAX_KEEP;
  state.stats.dns++;
  renderStats();
  if (state.tab === 'dns') renderDNS();
}
async function loadDNS() {
  try {
    const r = await fetch('/api/dns?limit=1000');
    if (!r.ok) throw new Error(r.status);
    const arr = await r.json();
    state.dns = Array.isArray(arr) ? arr : [];
    renderDNS();
  } catch (e) {
    $('dns-body').innerHTML = '<tr><td colspan="6" class="empty">加载失败，请检查后端</td></tr>';
  }
}

/* ---------- detail drawer ---------- */
function drow(k, v, mono) {
  return '<div class="drow"><div class="dk">' + esc(k) + '</div><div class="dv' +
    (mono ? ' mono' : '') + '">' + v + '</div></div>';
}
function renderDetail(c) {
  const b = $('detail-body');
  b.innerHTML =
    drow('ID', '<span class="num">' + esc(c.id) + '</span>', true) +
    drow('进程', esc(c.comm) + ' <span class="dim">(' + esc(c.pid) + ')</span>') +
    drow('模式', esc(c.mode || '—')) +
    drow('目标', esc((c.orig_host || c.orig_ip || '') + ':' + (c.orig_port ?? '')), true) +
    drow('原始 IP', esc(c.orig_ip || '—'), true) +
    drow('路由', esc(c.route || '—'), true) +
    drow('协议', esc(c.proto || '—'), true) +
    drow('SNI', esc(c.sni || '—'), true) +
    drow('ALPN', esc(c.alpn || '—'), true) +
    drow('开始', esc(fmtDT(c.started_at))) +
    drow('结束', (+c.ended_at || 0) > 0 ? esc(fmtDT(c.ended_at)) : '<span class="dim">进行中</span>') +
    drow('建连耗时', '<span class="num">' + esc(fmtMs(c.connect_ms)) + '</span>') +
    drow('TLS 握手', '<span class="num">' + esc(fmtMs(c.tls_ms)) + '</span>') +
    drow('上行', '<span class="num">' + esc(fmtBytes(c.bytes_up)) + ' (' + esc(c.bytes_up ?? 0) + ' B)</span>') +
    drow('下行', '<span class="num">' + esc(fmtBytes(c.bytes_down)) + ' (' + esc(c.bytes_down ?? 0) + ' B)</span>') +
    drow('结果', resultBadge(c.result)) +
    drow('错误', '<pre>' + esc(c.error || '—') + '</pre>');
  markSelectedRow();
}
function openDetail(id) {
  state.detailId = id;
  const c = state.conns.get(id);
  if (c) renderDetail(c);
  const p = $('detail');
  p.classList.add('open');
  p.setAttribute('aria-hidden', 'false');
}
function closeDetail() {
  state.detailId = null;
  $('detail').classList.remove('open');
  $('detail').setAttribute('aria-hidden', 'true');
  markSelectedRow();
}
function markSelectedRow() {
  document.querySelectorAll('#conns-body tr.row.selected')
    .forEach((tr) => tr.classList.remove('selected'));
  if (state.detailId != null) {
    const tr = document.querySelector('#conns-body tr.row[data-id="' + CSS.escape(String(state.detailId)) + '"]');
    if (tr) tr.classList.add('selected');
  }
}

/* ---------- tabs / filter ---------- */
function switchTab(tab) {
  state.tab = tab;
  document.querySelectorAll('.tabs button').forEach((b) =>
    b.classList.toggle('active', b.dataset.tab === tab));
  $('conns-table').hidden = tab !== 'conns';
  $('dns-table').hidden = tab !== 'dns';
  $('toolbar-conns').style.display = tab === 'conns' ? '' : 'none';
  if (tab === 'dns') renderDNS();
}
let filterTimer = null;
function onFilterInput(e) {
  clearTimeout(filterTimer);
  filterTimer = setTimeout(() => {
    state.q = e.target.value.trim();
    loadConns();               // 防抖后调 q 参数请求后端
  }, 300);
}

/* ---------- websocket ---------- */
function setWS(on) {
  $('ws-dot').classList.toggle('on', on);
  $('ws-text').textContent = on ? 'ws 已连接' : 'ws 断开，重连中…';
}
function connectWS() {
  if (state.ws) { try { state.ws.close(); } catch (e) {} state.ws = null; }
  clearTimeout(state.wsTimer);
  let ws;
  try {
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
    ws = new WebSocket(scheme + '://' + location.host + '/api/ws');
  } catch (e) { scheduleReconnect(); return; }
  state.ws = ws;
  ws.onopen = () => setWS(true);
  ws.onmessage = (ev) => {
    let m;
    try { m = JSON.parse(ev.data); } catch (e) { return; }
    if (!m || !m.type) return;
    if ((m.type === 'conn_new' || m.type === 'conn_update' || m.type === 'conn_closed') && m.conn) {
      applyConn(m.conn);
    } else if (m.type === 'dns' && m.dns) {
      applyDNS(m.dns);
    }
    // 未知 type 直接忽略
  };
  const down = () => { if (!serverStopped) { setWS(false); scheduleReconnect(); } };
  ws.onclose = down;
  ws.onerror = down;
}
function scheduleReconnect() {
  if (serverStopped) return;
  clearTimeout(state.wsTimer);
  state.wsTimer = setTimeout(connectWS, 3000);
}

/* ---------- init ---------- */
let serverStopped = false;
async function stopServer() {
  const button = $('stop-server');
  button.disabled = true;
  try {
    const control = await fetch('/api/control', { headers: { 'X-Netinspect-Control': '1' } });
    if (!control.ok) throw new Error('无法获取面板控制权限');
    const { token } = await control.json();
    const response = await fetch('/api/shutdown', { method: 'POST', headers: { Authorization: 'Bearer ' + token } });
    if (!response.ok) throw new Error('关闭失败：目标程序可能仍在运行');
    serverStopped = true;
    clearTimeout(state.wsTimer);
    if (state.ws) state.ws.close();
    $('ws-text').textContent = 'Server 已关闭';
    $('ws-dot').classList.remove('on');
    button.textContent = 'Server 已关闭';
  } catch (e) {
    button.disabled = false;
    button.textContent = '重试关闭';
    button.title = e.message;
  }
}
function init() {
  $('stop-server').addEventListener('click', stopServer);
  document.querySelectorAll('.tabs button').forEach((b) =>
    b.addEventListener('click', () => switchTab(b.dataset.tab)));
  $('filter').addEventListener('input', onFilterInput);
  $('conns-body').addEventListener('click', (e) => {
    const tr = e.target.closest('tr.row');
    if (tr) openDetail(+tr.dataset.id);
  });
  $('detail-close').addEventListener('click', closeDetail);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDetail(); });
  Promise.all([loadSession(), loadConns(), loadDNS()]);
  connectWS();
  setInterval(loadSession, 5000);   // 统计校准 + 会话结束状态
}
document.addEventListener('DOMContentLoaded', init);
