/* ── Dark Web Monitoring — Frontend SPA ─────────────────────────────────────── */
'use strict';

(function () {

// ── State ─────────────────────────────────────────────────────────────────────
let _dwTab        = 'dashboard';
let _findings     = [];
let _findPage     = 1;
let _findFilters  = {};
const PAGE_SIZE   = 25;

// ── API helper ────────────────────────────────────────────────────────────────
async function dwApi(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(path, opts);
  return r.json();
}

// ── Escape helper ─────────────────────────────────────────────────────────────
function e(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function fmtDate(s) {
  if (!s) return '—';
  try { return new Date(s).toLocaleString(); } catch { return s; }
}

function fmtDateShort(s) {
  if (!s) return '—';
  try { return new Date(s).toLocaleDateString(); } catch { return String(s).slice(0,10); }
}

function truncate(s, n) {
  if (!s) return '';
  return s.length > n ? s.slice(0, n) + '…' : s;
}

// ── Severity badge ────────────────────────────────────────────────────────────
function severityBadge(sev) {
  const cls = { CRITICAL: 'dw-sev-critical', HIGH: 'dw-sev-high', MEDIUM: 'dw-sev-medium', LOW: 'dw-sev-low' };
  return `<span class="dw-severity-badge ${cls[sev] || 'dw-sev-low'}">${e(sev || 'LOW')}</span>`;
}

function categoryBadge(cat) {
  const labels = {
    ransomware:'Ransomware', credentials:'Credentials', initial_access:'Initial Access',
    stealer_logs:'Stealer Logs', phishing:'Phishing', malware:'Malware',
    financial_fraud:'Financial Fraud', carding:'Carding', other:'Other',
  };
  return `<span class="dw-cat-badge dw-cat-${(cat||'other').replace(/_/g,'-')}">${e(labels[cat] || cat || 'other')}</span>`;
}

function scoreBar(score) {
  const pct = Math.min(100, (score / 20) * 100);
  const col = score >= 13 ? 'var(--danger)' : score >= 8 ? 'var(--orange)' : score >= 4 ? 'var(--warning)' : 'var(--text-dim)';
  return `<div class="dw-score-bar"><div style="width:${pct}%;background:${col}"></div></div><span style="font-family:var(--font-mono);font-size:11px;color:${col}">${score}</span>`;
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function toast(msg, type = 'info') {
  const c = document.getElementById('toast-container');
  if (!c) return;
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.innerHTML = `<span>${msg}</span>`;
  c.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

// ── Shell ─────────────────────────────────────────────────────────────────────
function renderShell() {
  const el = document.getElementById('view-darkweb');
  if (!el) return;
  el.innerHTML = `
    <div class="dw-header">
      <div>
        <h1 class="page-title">Dark Web Monitoring</h1>
        <p class="page-subtitle" id="dw-last-updated">Initializing collection…</p>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <span class="dw-status-dot" id="dw-status-dot"></span>
        <span id="dw-status-text" style="font-size:12px;color:var(--text-dim)">Idle</span>
        <button class="btn btn-primary btn-sm" id="dw-scan-now">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
          Scan Now
        </button>
      </div>
    </div>

    <div class="dw-tab-nav">
      ${['dashboard','findings','sources','alerts','ioc-search','settings'].map(tab => `
        <button class="dw-tab${_dwTab === tab ? ' active' : ''}" data-tab="${tab}">
          ${tabLabel(tab)}
        </button>
      `).join('')}
    </div>

    <div id="dw-tab-body" class="dw-tab-body"></div>
  `;

  // Tab switching
  el.querySelectorAll('.dw-tab').forEach(btn => {
    btn.addEventListener('click', () => {
      el.querySelectorAll('.dw-tab').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      _dwTab = btn.dataset.tab;
      renderTab(_dwTab);
    });
  });

  // Scan Now
  document.getElementById('dw-scan-now')?.addEventListener('click', runScanNow);
}

function tabLabel(tab) {
  return {
    dashboard:    '📊 Dashboard',
    findings:     '🔍 Findings',
    sources:      '📡 Sources',
    alerts:       '🔔 Alerts',
    'ioc-search': '🔎 IOC Search',
    settings:     '⚙️ Settings',
  }[tab] || tab;
}

// ── Tab router ────────────────────────────────────────────────────────────────
function renderTab(tab) {
  switch (tab) {
    case 'dashboard':   loadDashboard();   break;
    case 'findings':    loadFindings();    break;
    case 'sources':     loadSources();     break;
    case 'alerts':      loadAlerts();      break;
    case 'ioc-search':  renderIOCSearch(); break;
    case 'settings':    renderDwSettings(); break;
  }
}

// ── Scan Now ──────────────────────────────────────────────────────────────────
async function runScanNow() {
  const btn = document.getElementById('dw-scan-now');
  const dot = document.getElementById('dw-status-dot');
  const txt = document.getElementById('dw-status-text');
  if (btn) { btn.disabled = true; btn.textContent = 'Scanning…'; }
  if (dot) dot.classList.add('active');
  if (txt) txt.textContent = 'Scanning…';

  try {
    const res = await dwApi('POST', '/api/darkweb/collect');
    toast(`Scan complete — ${res.data?.newCount ?? 0} new findings`, 'success');
    renderTab(_dwTab);
  } catch {
    toast('Scan failed', 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg> Scan Now`; }
    if (dot) dot.classList.remove('active');
    if (txt) txt.textContent = `Last scan: ${new Date().toLocaleTimeString()}`;
    document.getElementById('dw-last-updated').textContent = `Last scan: ${new Date().toLocaleString()}`;
  }
}

// ── DASHBOARD TAB ─────────────────────────────────────────────────────────────
async function loadDashboard() {
  const body = document.getElementById('dw-tab-body');
  body.innerHTML = '<div class="dw-loading">Loading…</div>';

  const res = await dwApi('GET', '/api/darkweb/stats');
  if (!res.success) { body.innerHTML = '<div class="dw-loading">Failed to load</div>'; return; }
  const s = res.data;

  document.getElementById('dw-last-updated').textContent =
    `Last updated: ${new Date().toLocaleString()} · ${s.total.toLocaleString()} total findings`;

  body.innerHTML = `
    <!-- Stat cards -->
    <div class="dw-stat-grid">
      ${statCard('New (24h)',          s.last24h,     '#58a6ff', '🆕')}
      ${statCard('High / Critical',   s.highRisk,    '#f85149', '🚨')}
      ${statCard('Ransomware',        s.ransomware,  '#ff7b72', '💀')}
      ${statCard('Credentials',       s.credentials, '#d29922', '🔑')}
      ${statCard('Initial Access',    s.initAccess,  '#8957e5', '🚪')}
      ${statCard('Total IOCs',        s.totalIOCs,   '#3fb950', '🎯')}
    </div>

    <div class="dw-dash-row">
      <!-- By Category -->
      <div class="dw-panel">
        <div class="dw-panel-title">Findings by Category</div>
        ${s.byCategory.length ? `
          <div class="dw-bar-list">
            ${renderBarList(s.byCategory, 'category', 'count', cat => categoryBadge(cat))}
          </div>` : '<div class="dw-empty">No findings yet</div>'}
      </div>

      <!-- By Severity -->
      <div class="dw-panel">
        <div class="dw-panel-title">Findings by Severity</div>
        ${s.bySeverity.length ? `
          <div class="dw-bar-list">
            ${renderBarList(s.bySeverity, 'severity', 'count', sev => severityBadge(sev))}
          </div>` : '<div class="dw-empty">No findings yet</div>'}
      </div>

      <!-- Top Keywords -->
      <div class="dw-panel">
        <div class="dw-panel-title">Top Financial Keywords (7d)</div>
        ${s.topKeywords.length ? `
          <div style="display:flex;flex-wrap:wrap;gap:6px;padding-top:4px">
            ${s.topKeywords.map(k =>
              `<span class="dw-kw-chip">${e(k.keyword)} <strong>${k.count}</strong></span>`
            ).join('')}
          </div>` : '<div class="dw-empty">No keyword data yet</div>'}
      </div>
    </div>

    <!-- Recent findings -->
    <div class="dw-panel" style="margin-top:0">
      <div class="dw-panel-title">Recent Findings</div>
      ${s.recent.length ? renderFindingsTable(s.recent, true) : '<div class="dw-empty">No findings yet — click Scan Now to start collection</div>'}
    </div>
  `;
}

function statCard(label, value, color, icon) {
  return `
    <div class="dw-stat-card">
      <div class="dw-stat-icon" style="color:${color}">${icon}</div>
      <div class="dw-stat-value" style="color:${color}">${(value ?? 0).toLocaleString()}</div>
      <div class="dw-stat-label">${label}</div>
    </div>
  `;
}

function renderBarList(items, labelKey, countKey, labelFn) {
  const max = Math.max(...items.map(i => i[countKey]), 1);
  return items.map(item => `
    <div class="dw-bar-row">
      <div class="dw-bar-label">${labelFn ? labelFn(item[labelKey]) : e(item[labelKey])}</div>
      <div class="dw-bar-track">
        <div class="dw-bar-fill" style="width:${Math.max(4, (item[countKey]/max)*100)}%"></div>
      </div>
      <div class="dw-bar-count">${item[countKey]}</div>
    </div>
  `).join('');
}

// ── FINDINGS TAB ──────────────────────────────────────────────────────────────
async function loadFindings(page = 1) {
  _findPage = page;
  const body = document.getElementById('dw-tab-body');
  body.innerHTML = '<div class="dw-loading">Loading…</div>';

  const params = new URLSearchParams({
    limit:  PAGE_SIZE,
    offset: (page - 1) * PAGE_SIZE,
    ..._findFilters,
  });
  const res = await dwApi('GET', `/api/darkweb/findings?${params}`);
  _findings = res.data || [];

  // Count for pagination
  const countRes = await dwApi('GET', `/api/darkweb/findings?${new URLSearchParams(_findFilters)}&limit=2000&offset=0`);
  const total = countRes.data?.length ?? 0;

  body.innerHTML = `
    <!-- Filter bar -->
    <div class="dw-filter-bar">
      <div class="search-wrap" style="flex:1;min-width:200px">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
        <input type="text" id="find-search" placeholder="Search title, snippet, source…" value="${e(_findFilters.search || '')}">
      </div>
      <select id="find-cat" class="form-control" style="width:auto">
        <option value="">All Categories</option>
        ${['ransomware','credentials','initial_access','stealer_logs','phishing','malware','financial_fraud','carding','other'].map(c =>
          `<option value="${c}"${_findFilters.category===c?' selected':''}>${c.replace(/_/g,' ')}</option>`
        ).join('')}
      </select>
      <select id="find-sev" class="form-control" style="width:auto">
        <option value="">All Severity</option>
        ${['CRITICAL','HIGH','MEDIUM','LOW'].map(s =>
          `<option value="${s}"${_findFilters.severity===s?' selected':''}>${s}</option>`
        ).join('')}
      </select>
      <select id="find-src" class="form-control" style="width:auto">
        <option value="">All Sources</option>
        ${['ransomware.live','URLhaus','MalwareBazaar','Ahmia'].map(s =>
          `<option value="${s}"${_findFilters.source===s?' selected':''}>${s}</option>`
        ).join('')}
      </select>
      <button class="btn btn-secondary btn-sm" id="find-clear">Clear</button>
    </div>

    <div class="table-wrap">
      <div class="table-header">
        <span class="table-count">${total.toLocaleString()} finding${total !== 1 ? 's' : ''}</span>
        <div style="display:flex;gap:6px">
          ${page > 1 ? `<button class="btn btn-secondary btn-sm" id="find-prev">← Prev</button>` : ''}
          <span style="font-size:12px;color:var(--text-dim);align-self:center">Page ${page}</span>
          ${total > page * PAGE_SIZE ? `<button class="btn btn-secondary btn-sm" id="find-next">Next →</button>` : ''}
        </div>
      </div>
      <div class="table-scroll">
        <table>
          <thead><tr>
            <th style="width:130px">Time</th>
            <th style="width:120px">Category</th>
            <th style="width:110px">Severity</th>
            <th style="width:120px">Source</th>
            <th>Title</th>
            <th>Snippet</th>
          </tr></thead>
          <tbody>
            ${_findings.length ? _findings.map(f => `
              <tr onclick="window._dwOpenFinding(${f.id})" style="cursor:pointer">
                <td style="font-family:var(--font-mono);font-size:11px;white-space:nowrap">${fmtDateShort(f.created_at)}</td>
                <td>${categoryBadge(f.category)}</td>
                <td>${severityBadge(f.severity)}</td>
                <td><span class="badge badge-default" style="font-size:11px">${e(f.source_name)}</span></td>
                <td style="max-width:220px;font-size:12px;font-weight:500">${e(truncate(f.title, 80))}</td>
                <td style="max-width:280px;font-size:11px;color:var(--text-muted)">${e(truncate(f.snippet, 120))}</td>
              </tr>
            `).join('') : `<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--text-dim)">No findings match your filters</td></tr>`}
          </tbody>
        </table>
      </div>
    </div>
  `;

  // Filter events
  const apply = () => {
    _findFilters.search   = document.getElementById('find-search')?.value.trim() || undefined;
    _findFilters.category = document.getElementById('find-cat')?.value || undefined;
    _findFilters.severity = document.getElementById('find-sev')?.value || undefined;
    _findFilters.source   = document.getElementById('find-src')?.value || undefined;
    loadFindings(1);
  };
  document.getElementById('find-search')?.addEventListener('input', debounce(apply, 350));
  document.getElementById('find-cat')?.addEventListener('change', apply);
  document.getElementById('find-sev')?.addEventListener('change', apply);
  document.getElementById('find-src')?.addEventListener('change', apply);
  document.getElementById('find-clear')?.addEventListener('click', () => {
    _findFilters = {};
    loadFindings(1);
  });
  document.getElementById('find-prev')?.addEventListener('click', () => loadFindings(page - 1));
  document.getElementById('find-next')?.addEventListener('click', () => loadFindings(page + 1));
}

// ── Finding detail modal ──────────────────────────────────────────────────────
window._dwOpenFinding = async function(id) {
  const res = await dwApi('GET', `/api/darkweb/findings/${id}`);
  const f = res.data;
  if (!f) return;

  let modal = document.getElementById('dw-finding-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'dw-finding-modal';
    modal.className = 'modal-backdrop';
    document.body.appendChild(modal);
    modal.addEventListener('click', ev => { if (ev.target === modal) modal.classList.add('hidden'); });
  }

  let kws = [];
  try { kws = JSON.parse(f.keyword_hits || '[]'); } catch {}

  modal.innerHTML = `
    <div class="modal" style="max-width:760px">
      <div class="modal-header">
        <h2 class="modal-title" style="font-size:15px">${e(truncate(f.title, 100))}</h2>
        <button class="modal-close" onclick="document.getElementById('dw-finding-modal').classList.add('hidden')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg>
        </button>
      </div>
      <div class="modal-body">
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px">
          ${severityBadge(f.severity)}
          ${categoryBadge(f.category)}
          <span class="badge badge-default">${e(f.source_name)}</span>
          <span class="badge badge-default" style="margin-left:auto">Score: ${f.risk_score}</span>
        </div>
        <div class="detail-grid" style="grid-template-columns:1fr 1fr;margin-bottom:16px">
          <div class="detail-field"><div class="detail-label">Discovered</div><div class="detail-value" style="font-family:var(--font-mono);font-size:12px">${fmtDate(f.discovered_date)}</div></div>
          <div class="detail-field"><div class="detail-label">Indexed</div><div class="detail-value" style="font-family:var(--font-mono);font-size:12px">${fmtDate(f.created_at)}</div></div>
          ${f.url ? `<div class="detail-field full"><div class="detail-label">Source URL</div><div class="detail-value"><a href="${e(f.url)}" target="_blank" rel="noopener noreferrer">${e(truncate(f.url, 80))}</a></div></div>` : ''}
        </div>
        <div class="detail-field" style="margin-bottom:16px">
          <div class="detail-label">Snippet</div>
          <div style="background:var(--bg-surface);border:1px solid var(--border);border-radius:var(--radius);padding:12px;font-size:13px;color:var(--text-muted);line-height:1.6;white-space:pre-wrap">${e(f.snippet || '—')}</div>
        </div>
        ${kws.length ? `
          <div class="detail-field" style="margin-bottom:16px">
            <div class="detail-label">Keyword Hits</div>
            <div style="display:flex;flex-wrap:wrap;gap:6px;padding-top:4px">
              ${kws.map(k => `<span class="dw-kw-chip">${e(k)}</span>`).join('')}
            </div>
          </div>` : ''}
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="document.getElementById('dw-finding-modal').classList.add('hidden')">Close</button>
      </div>
    </div>
  `;
  modal.classList.remove('hidden');
};

function renderFindingsTable(items, compact = false) {
  return `
    <div class="table-scroll">
      <table>
        <thead><tr>
          <th style="width:110px">Time</th>
          ${compact ? '' : '<th>Category</th>'}
          <th style="width:100px">Severity</th>
          <th style="width:120px">Source</th>
          <th>Title</th>
          ${compact ? '' : '<th>Snippet</th>'}
        </tr></thead>
        <tbody>
          ${items.map(f => `
            <tr onclick="window._dwOpenFinding(${f.id})" style="cursor:pointer">
              <td style="font-family:var(--font-mono);font-size:11px;white-space:nowrap">${fmtDateShort(f.created_at || f.discovered_date)}</td>
              ${compact ? '' : `<td>${categoryBadge(f.category)}</td>`}
              <td>${severityBadge(f.severity)}</td>
              <td><span class="badge badge-default" style="font-size:11px">${e(f.source_name)}</span></td>
              <td style="font-size:12px;font-weight:500">${e(truncate(f.title, compact ? 80 : 120))}</td>
              ${compact ? '' : `<td style="font-size:11px;color:var(--text-muted)">${e(truncate(f.snippet, 100))}</td>`}
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

// ── SOURCES TAB ───────────────────────────────────────────────────────────────
async function loadSources() {
  const body = document.getElementById('dw-tab-body');
  body.innerHTML = '<div class="dw-loading">Loading…</div>';
  const res = await dwApi('GET', '/api/darkweb/sources');
  const sources = res.data || [];

  const categories = [...new Set(sources.map(s => s.category))];

  body.innerHTML = categories.map(cat => `
    <div class="dw-panel" style="margin-bottom:16px">
      <div class="dw-panel-title">${e(cat.charAt(0).toUpperCase() + cat.slice(1))}</div>
      <div class="dw-source-grid">
        ${sources.filter(s => s.category === cat).map(s => `
          <div class="dw-source-card${s.enabled ? '' : ' disabled'}">
            <div class="dw-source-card-header">
              <div>
                <div class="dw-source-name">${e(s.name)}</div>
                <div class="dw-source-url">${e(truncate(s.url, 50))}</div>
              </div>
              <div style="display:flex;gap:6px;align-items:center;margin-left:auto">
                ${s.tor_required ? '<span class="dw-tor-badge">TOR</span>' : ''}
                <label class="dw-toggle" title="${s.enabled ? 'Disable' : 'Enable'}">
                  <input type="checkbox" ${s.enabled ? 'checked' : ''} onchange="dwToggleSource(${s.id}, this.checked)">
                  <span></span>
                </label>
              </div>
            </div>
            ${s.notes ? `<div class="dw-source-notes">${e(s.notes)}</div>` : ''}
            <div class="dw-source-meta">
              <span>${s.last_checked ? 'Last: ' + fmtDateShort(s.last_checked) : 'Never checked'}</span>
              ${!s.tor_required && s.enabled ? `<button class="btn btn-secondary btn-sm" style="font-size:11px;padding:2px 8px" onclick="dwFetchSource('${e(s.name)}', this)">Fetch</button>` : ''}
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `).join('');
}

window.dwToggleSource = async function(id, enabled) {
  await dwApi('POST', `/api/darkweb/sources/${id}/toggle`, { enabled });
  toast(`Source ${enabled ? 'enabled' : 'disabled'}`, 'success');
};

window.dwFetchSource = async function(name, btn) {
  btn.disabled = true;
  btn.textContent = '…';
  try {
    const res = await dwApi('POST', `/api/darkweb/sources/${encodeURIComponent(name)}/fetch`);
    toast(`${name}: ${res.data?.newCount ?? 0} new findings`, 'success');
    loadSources();
  } catch {
    toast(`Fetch failed`, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Fetch';
  }
};

// ── ALERTS TAB ────────────────────────────────────────────────────────────────
async function loadAlerts() {
  const body = document.getElementById('dw-tab-body');
  body.innerHTML = '<div class="dw-loading">Loading…</div>';
  const res = await dwApi('GET', '/api/darkweb/alerts');
  const alerts = res.data || [];

  body.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
      <div class="dw-panel">
        <div class="dw-panel-title">Monitored Keywords</div>
        <p style="font-size:12px;color:var(--text-dim);margin-bottom:14px">Alert triggers when a finding matches and risk score ≥ threshold.</p>
        <div id="alerts-list">
          ${alerts.length ? alerts.map(a => `
            <div class="dw-alert-row" id="alert-${a.id}">
              <span class="dw-kw-chip${a.enabled ? '' : ' disabled'}">${e(a.keyword)}</span>
              <span style="font-size:11px;color:var(--text-dim)">≥${a.risk_threshold}</span>
              <label class="dw-toggle" style="margin-left:auto">
                <input type="checkbox" ${a.enabled ? 'checked' : ''} onchange="dwToggleAlert(${a.id}, this.checked)">
                <span></span>
              </label>
              <button class="settings-item-delete" onclick="dwDeleteAlert(${a.id})">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="width:13px;height:13px"><path d="M18 6 6 18M6 6l12 12"/></svg>
              </button>
            </div>
          `).join('') : '<div class="dw-empty">No alert keywords configured</div>'}
        </div>
        <div class="settings-add-row" style="margin-top:14px">
          <input class="form-control" id="alert-new-kw" placeholder="New keyword…" onkeydown="if(event.key==='Enter')dwAddAlert()">
          <input class="form-control" id="alert-new-thresh" type="number" min="0" max="20" value="8" style="width:70px">
          <button class="btn btn-primary btn-sm" onclick="dwAddAlert()">Add</button>
        </div>
      </div>

      <div class="dw-panel">
        <div class="dw-panel-title">Recent High-Risk Findings</div>
        <p style="font-size:12px;color:var(--text-dim);margin-bottom:14px">Findings with score ≥ 8 from the last 48 hours.</p>
        <div id="alerts-triggered"></div>
      </div>
    </div>
  `;

  // Load triggered alerts (high-risk recent findings)
  const since48h = new Date(Date.now() - 48 * 3600_000).toISOString();
  const trig = await dwApi('GET', `/api/darkweb/findings?min_score=8&since=${since48h}&limit=20`);
  const triggered = trig.data || [];
  document.getElementById('alerts-triggered').innerHTML = triggered.length
    ? triggered.map(f => `
        <div class="dw-alert-trigger" onclick="window._dwOpenFinding(${f.id})" style="cursor:pointer">
          ${severityBadge(f.severity)}
          <div style="flex:1;min-width:0">
            <div style="font-size:12px;font-weight:500">${e(truncate(f.title, 70))}</div>
            <div style="font-size:11px;color:var(--text-dim)">${e(f.source_name)} · ${fmtDateShort(f.created_at)}</div>
          </div>
        </div>
      `).join('')
    : '<div class="dw-empty">No high-risk findings in the last 48 hours</div>';
}

window.dwToggleAlert = async function(id, enabled) {
  await dwApi('PUT', `/api/darkweb/alerts/${id}`, { enabled });
  toast(`Alert ${enabled ? 'enabled' : 'disabled'}`, 'success');
};

window.dwDeleteAlert = async function(id) {
  if (!confirm('Remove this alert keyword?')) return;
  await dwApi('DELETE', `/api/darkweb/alerts/${id}`);
  toast('Alert removed', 'success');
  loadAlerts();
};

window.dwAddAlert = async function() {
  const kw = document.getElementById('alert-new-kw')?.value.trim();
  const thresh = parseInt(document.getElementById('alert-new-thresh')?.value) || 8;
  if (!kw) return;
  await dwApi('POST', '/api/darkweb/alerts', { keyword: kw, risk_threshold: thresh });
  toast(`Alert added: "${kw}"`, 'success');
  loadAlerts();
};

// ── IOC SEARCH TAB ────────────────────────────────────────────────────────────
function renderIOCSearch() {
  const body = document.getElementById('dw-tab-body');
  body.innerHTML = `
    <div class="dw-panel">
      <div class="dw-panel-title">IOC Search</div>
      <p style="font-size:12px;color:var(--text-dim);margin-bottom:16px">Search for domains, IPs, emails, hashes, CVEs, and Bitcoin/Ethereum addresses extracted from findings.</p>
      <div style="display:flex;gap:10px;margin-bottom:20px">
        <div class="search-wrap" style="flex:1">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
          <input type="text" id="ioc-query" placeholder="Search IOC value — domain, IP, email, hash, CVE, wallet address…">
        </div>
        <select id="ioc-type" class="form-control" style="width:auto">
          <option value="">All Types</option>
          <option value="domain">Domain</option>
          <option value="ipv4">IPv4</option>
          <option value="email">Email</option>
          <option value="url">URL</option>
          <option value="hash_md5">MD5</option>
          <option value="hash_sha1">SHA1</option>
          <option value="hash_sha256">SHA256</option>
          <option value="cve">CVE</option>
          <option value="btc_address">Bitcoin</option>
          <option value="eth_address">Ethereum</option>
        </select>
        <button class="btn btn-primary btn-sm" id="ioc-search-btn">Search</button>
      </div>
      <div id="ioc-results"><div class="dw-empty">Enter a query above to search IOCs</div></div>
    </div>
  `;

  const runSearch = debounce(async () => {
    const q    = document.getElementById('ioc-query')?.value.trim();
    const type = document.getElementById('ioc-type')?.value;
    if (!q) {
      document.getElementById('ioc-results').innerHTML = '<div class="dw-empty">Enter a query above</div>';
      return;
    }
    const res = await dwApi('GET', `/api/darkweb/iocs?query=${encodeURIComponent(q)}${type ? '&ioc_type='+type : ''}`);
    const iocs = res.data || [];
    renderIOCResults(iocs);
  }, 400);

  document.getElementById('ioc-query')?.addEventListener('input', runSearch);
  document.getElementById('ioc-type')?.addEventListener('change', runSearch);
  document.getElementById('ioc-search-btn')?.addEventListener('click', runSearch);
}

function renderIOCResults(iocs) {
  const el = document.getElementById('ioc-results');
  if (!el) return;
  if (!iocs.length) {
    el.innerHTML = '<div class="dw-empty">No IOCs found matching that query</div>';
    return;
  }
  el.innerHTML = `
    <div style="font-size:12px;color:var(--text-dim);margin-bottom:10px">${iocs.length} result${iocs.length !== 1 ? 's' : ''}</div>
    <div class="table-scroll">
      <table>
        <thead><tr>
          <th style="width:110px">Type</th>
          <th>Value</th>
          <th style="width:120px">Source</th>
          <th style="width:100px">First Seen</th>
          <th style="width:100px">Last Seen</th>
          <th style="width:200px">Context</th>
        </tr></thead>
        <tbody>
          ${iocs.map(i => `
            <tr>
              <td><span class="dw-ioc-type-badge dw-ioc-${i.ioc_type}">${e(i.ioc_type.replace(/_/g,' '))}</span></td>
              <td style="font-family:var(--font-mono);font-size:12px;word-break:break-all">${e(i.ioc_value)}</td>
              <td><span class="badge badge-default" style="font-size:11px">${e(i.source_name || '—')}</span></td>
              <td style="font-family:var(--font-mono);font-size:11px">${fmtDateShort(i.first_seen)}</td>
              <td style="font-family:var(--font-mono);font-size:11px">${fmtDateShort(i.last_seen)}</td>
              <td style="font-size:11px;color:var(--text-muted)">
                ${i.title ? `<span onclick="window._dwOpenFinding(${i.finding_id})" style="cursor:pointer;color:var(--accent-hover)">${e(truncate(i.title, 60))}</span>` : '—'}
                ${i.severity ? ' ' + severityBadge(i.severity) : ''}
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

// ── SETTINGS TAB ──────────────────────────────────────────────────────────────
function renderDwSettings() {
  const torProxy = localStorage.getItem('dw_tor_proxy') || '';
  const body = document.getElementById('dw-tab-body');
  body.innerHTML = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
      <div class="dw-panel">
        <div class="dw-panel-title">Collection</div>
        <p style="font-size:12px;color:var(--text-dim);margin-bottom:16px">
          Dark web collection runs automatically every 30 minutes. Use the <strong>Scan Now</strong> button for an immediate pass.
        </p>
        <div class="detail-field">
          <div class="detail-label">Active Clearnet Collectors</div>
          <div class="detail-value">ransomware.live · URLhaus · MalwareBazaar · Ahmia</div>
        </div>
        <div class="detail-field" style="margin-top:12px">
          <div class="detail-label">Collection Schedule</div>
          <div class="detail-value">Every 30 minutes (server cron)</div>
        </div>
        <div class="detail-field" style="margin-top:12px">
          <div class="detail-label">Risk Score Alert Threshold</div>
          <div class="detail-value">≥ 8 (HIGH or CRITICAL)</div>
        </div>
      </div>

      <div class="dw-panel">
        <div class="dw-panel-title">Tor Proxy (Optional)</div>
        <p style="font-size:12px;color:var(--text-dim);margin-bottom:16px">
          Set the <code>TOR_PROXY</code> environment variable on the server to enable .onion source collection.<br>
          Example: <code>socks5h://127.0.0.1:9050</code>
        </p>
        <div class="detail-field">
          <div class="detail-label">Status</div>
          <div class="detail-value">${process?.env?.TOR_PROXY ? '✅ Configured' : '⚠️ Not configured — .onion sources disabled'}</div>
        </div>
        <div class="alert alert-info" style="margin-top:14px">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4m0-4h.01"/></svg>
          <span>Install Tor Browser or Tor daemon on your server, then set <code>TOR_PROXY=socks5h://127.0.0.1:9050</code> in your environment.</span>
        </div>
      </div>

      <div class="dw-panel">
        <div class="dw-panel-title">API Key Sources</div>
        <p style="font-size:12px;color:var(--text-dim);margin-bottom:14px">These sources require free API keys set as environment variables.</p>
        ${[
          ['AlienVault OTX',  'OTX_API_KEY',       'https://otx.alienvault.com'],
          ['AbuseIPDB',       'ABUSEIPDB_API_KEY',  'https://www.abuseipdb.com'],
        ].map(([name, envKey, url]) => `
          <div class="dw-source-card" style="margin-bottom:8px">
            <div class="dw-source-card-header">
              <div>
                <div class="dw-source-name">${e(name)}</div>
                <div class="dw-source-url"><code>${e(envKey)}</code></div>
              </div>
              <a href="${e(url)}" target="_blank" rel="noopener" class="btn btn-secondary btn-sm" style="font-size:11px;margin-left:auto">Get Key</a>
            </div>
          </div>
        `).join('')}
      </div>

      <div class="dw-panel">
        <div class="dw-panel-title">Future Enhancements</div>
        <div style="display:flex;flex-direction:column;gap:8px;margin-top:4px">
          ${['Telegram Channel Monitoring','LLM Summarization (Claude API)','Vector Search / RAG Knowledge Base','Threat Actor Profiling','STIX/TAXII Export','MISP Integration','Elastic/OpenSearch Backend'].map(f =>
            `<div style="display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text-muted)">
              <span style="color:var(--text-dim)">○</span> ${e(f)}
            </div>`
          ).join('')}
        </div>
      </div>
    </div>
  `;
}

// ── Utility ───────────────────────────────────────────────────────────────────
function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

// ── Entry point ───────────────────────────────────────────────────────────────
window.darkwebDashboard = {
  load() {
    renderShell();
    renderTab(_dwTab);
  },
};

})();
