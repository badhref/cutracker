/* ── State ──────────────────────────────────────────────────────────────────── */
let allBreaches = [];
let filteredBreaches = [];
let sortKey = 'breach_date';
let sortDir = 'desc';
let charts = {};
let editingId = null;

/* ── Init ───────────────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  setupNav();
  setupButtons();
  loadDashboard();
  loadBreaches();
});

/* ── Navigation ─────────────────────────────────────────────────────────────── */
function setupNav() {
  document.querySelectorAll('.nav-item[data-view]').forEach(btn => {
    btn.addEventListener('click', () => {
      const view = btn.dataset.view;
      document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
      document.getElementById(`view-${view}`).classList.add('active');
      if (view === 'analytics') loadAnalytics();
      if (view === 'sources') loadSources();
      if (view === 'fetch-log') loadFetchLog();
    });
  });
}

function setupButtons() {
  document.getElementById('btn-fetch-all').addEventListener('click', fetchAll);
  document.getElementById('btn-add').addEventListener('click', () => openAddModal());
  document.getElementById('btn-save-breach').addEventListener('click', saveBreach);
  const fetchSrc = document.getElementById('btn-fetch-sources');
  if (fetchSrc) fetchSrc.addEventListener('click', fetchAll);
  setupDashboardControls();
}

/* ── API ────────────────────────────────────────────────────────────────────── */
async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(path, opts);
  return r.json();
}

/* ── Dashboard ──────────────────────────────────────────────────────────────── */
let allBreachesForTimeline = [];
let timelineMonths = 3;
let recentSortKey = 'notification_date';

async function loadDashboard() {
  try {
    const [{ data: stats }, { data: breaches }] = await Promise.all([
      api('GET', '/api/stats'),
      api('GET', '/api/breaches'),
    ]);
    allBreachesForTimeline = breaches || [];
    updateStatCards(stats);
    renderCharts(stats);
    renderSourceBars(stats.bySource);
    renderTimelineChart(timelineMonths);
    renderRecentTable(allBreachesForTimeline, recentSortKey);
    document.getElementById('last-updated').textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (e) {
    showToast('Failed to load dashboard', 'error');
  }
}

function setupDashboardControls() {
  // Timeline month filter buttons
  document.querySelectorAll('.timeline-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.timeline-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      timelineMonths = parseInt(btn.dataset.months);
      renderTimelineChart(timelineMonths);
    });
  });

  // Recent incidents sort buttons
  document.querySelectorAll('.recent-sort-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.recent-sort-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      recentSortKey = btn.dataset.sort;
      renderRecentTable(allBreachesForTimeline, recentSortKey);
    });
  });
}

function updateStatCards(stats) {
  document.getElementById('stat-total').textContent = stats.total?.toLocaleString() ?? '0';
  document.getElementById('stat-records').textContent = formatLargeNum(stats.totalRecords ?? 0);
  document.getElementById('stat-active').textContent =
    stats.bySource?.reduce((n, s) => n + s.count, 0)?.toLocaleString() ?? '0';
  document.getElementById('nav-count').textContent = stats.total ?? 0;
}

function renderCharts(stats) {
  // Breach type doughnut
  buildChart('chart-type', 'doughnut', stats.byType, 'breach_type', 'count', {
    colors: ['#f85149','#d29922','#8957e5','#f0883e','#85e89d','#79c0ff','#8b949e','#bc8cff'],
  });

  // By year bar
  const years = [...(stats.byYear || [])].reverse();
  buildChart('chart-year', 'bar', years, 'year', 'count', {
    colors: ['#1f6feb'],
    fillColors: ['rgba(31,111,235,.7)'],
  });

  // By state horizontal bar (top 8)
  buildChart('chart-state', 'bar', (stats.byState || []).slice(0, 8), 'state', 'count', {
    indexAxis: 'y',
    colors: ['#3fb950'],
  });
}

function buildChart(canvasId, type, data, labelKey, valueKey, opts = {}) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;

  if (charts[canvasId]) { charts[canvasId].destroy(); }

  const labels = (data || []).map(d => d[labelKey] || 'Unknown');
  const values = (data || []).map(d => d[valueKey] || 0);

  const palette = [
    '#1f6feb','#3fb950','#f85149','#d29922','#8957e5',
    '#f0883e','#79c0ff','#85e89d','#bc8cff','#ff7b72',
  ];

  const bgColors = type === 'doughnut'
    ? (opts.colors || palette)
    : (opts.fillColors || [`${opts.colors?.[0] || palette[0]}cc`]);

  charts[canvasId] = new Chart(canvas, {
    type,
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: bgColors,
        borderColor: type === 'doughnut' ? '#1c2128' : (opts.colors || palette),
        borderWidth: type === 'doughnut' ? 2 : 1,
        borderRadius: type === 'bar' ? 4 : 0,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: opts.indexAxis || 'x',
      plugins: {
        legend: {
          display: type === 'doughnut',
          position: 'bottom',
          labels: {
            color: '#8b949e',
            font: { size: 11 },
            padding: 12,
            boxWidth: 10,
          }
        },
        tooltip: {
          backgroundColor: '#1c2128',
          borderColor: '#30363d',
          borderWidth: 1,
          titleColor: '#e6edf3',
          bodyColor: '#8b949e',
        }
      },
      scales: type !== 'doughnut' ? {
        x: { ticks: { color: '#6e7681', font: { size: 11 } }, grid: { color: '#21262d' } },
        y: { ticks: { color: '#6e7681', font: { size: 11 } }, grid: { color: '#21262d' } },
      } : undefined,
    }
  });
}

function renderSourceBars(sources) {
  const el = document.getElementById('source-bars');
  if (!el || !sources) return;
  const max = Math.max(...sources.map(s => s.count), 1);
  el.innerHTML = sources.map(s => `
    <div class="bar-chart-row">
      <div class="bar-label" title="${s.source}">${s.source}</div>
      <div class="bar-track">
        <div class="bar-fill" style="width:${Math.max(2, (s.count / max) * 100)}%">${s.count > 3 ? s.count : ''}</div>
      </div>
      <div class="bar-value">${s.count}</div>
    </div>
  `).join('');
}

function renderTimelineChart(months) {
  if (!allBreachesForTimeline.length) return;

  // Build array of month labels going back N months from today
  const now = new Date();
  const labels = [];
  for (let i = months - 1; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    labels.push(`${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`);
  }

  const occurrenceCounts = Object.fromEntries(labels.map(l => [l, 0]));
  const notificationCounts = Object.fromEntries(labels.map(l => [l, 0]));

  allBreachesForTimeline.forEach(b => {
    const bd = (b.breach_date || '').slice(0, 7);
    const nd = (b.notification_date || '').slice(0, 7);
    if (occurrenceCounts[bd] !== undefined) occurrenceCounts[bd]++;
    if (notificationCounts[nd] !== undefined) notificationCounts[nd]++;
  });

  const canvas = document.getElementById('chart-timeline');
  if (!canvas) return;
  if (charts['chart-timeline']) charts['chart-timeline'].destroy();

  charts['chart-timeline'] = new Chart(canvas, {
    type: 'line',
    data: {
      labels: labels.map(l => {
        const [y, m] = l.split('-');
        return new Date(y, m - 1).toLocaleString('default', { month: 'short', year: '2-digit' });
      }),
      datasets: [
        {
          label: 'Breach Occurred',
          data: labels.map(l => occurrenceCounts[l]),
          borderColor: '#f85149',
          backgroundColor: 'rgba(248,81,73,.12)',
          fill: true,
          tension: .3,
          pointRadius: 4,
          pointHoverRadius: 6,
        },
        {
          label: 'Notification Published',
          data: labels.map(l => notificationCounts[l]),
          borderColor: '#58a6ff',
          backgroundColor: 'rgba(88,166,255,.12)',
          fill: true,
          tension: .3,
          pointRadius: 4,
          pointHoverRadius: 6,
        },
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: {
          position: 'top',
          labels: { color: '#8b949e', font: { size: 11 }, boxWidth: 12, padding: 16 }
        },
        tooltip: {
          backgroundColor: '#1c2128',
          borderColor: '#30363d',
          borderWidth: 1,
          titleColor: '#e6edf3',
          bodyColor: '#8b949e',
        }
      },
      scales: {
        x: {
          ticks: { color: '#6e7681', font: { size: 11 } },
          grid: { color: '#21262d' }
        },
        y: {
          beginAtZero: true,
          ticks: { color: '#6e7681', font: { size: 11 }, stepSize: 1 },
          grid: { color: '#21262d' }
        }
      }
    }
  });
}

function renderRecentTable(items, sortKey = 'notification_date') {
  const tbody = document.getElementById('recent-tbody');
  if (!tbody) return;

  // Sort and take top 10
  const sorted = [...items]
    .filter(b => b[sortKey])
    .sort((a, b) => (b[sortKey] || '').localeCompare(a[sortKey] || ''))
    .slice(0, 10);

  if (!sorted.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-dim);padding:32px">No recent incidents</td></tr>`;
    return;
  }
  tbody.innerHTML = sorted.map(b => `
    <tr onclick="openDetail(${b.id})">
      <td class="td-org">${esc(b.organization)}</td>
      <td>
        <div style="font-family:var(--font-mono);font-size:12px;color:${sortKey === 'notification_date' ? 'var(--text)' : 'var(--text-muted)'}">${b.notification_date || '—'}</div>
        <div style="font-size:11px;color:var(--text-dim)">notified</div>
      </td>
      <td>
        <div style="font-family:var(--font-mono);font-size:12px;color:${sortKey === 'breach_date' ? 'var(--text)' : 'var(--text-muted)'}">${b.breach_date || '—'}</div>
        <div style="font-size:11px;color:var(--text-dim)">occurred</div>
      </td>
      <td>${breachTypeBadge(b.breach_type)}</td>
      <td class="td-num">${b.records_affected ? b.records_affected.toLocaleString() : '—'}</td>
      <td>${sourceBadge(b.source)}</td>
    </tr>
  `).join('');
}

/* ── Breach List ────────────────────────────────────────────────────────────── */
async function loadBreaches() {
  try {
    const { data } = await api('GET', '/api/breaches');
    allBreaches = data || [];
    filteredBreaches = [...allBreaches];
    renderBreachTable();
  } catch (e) {
    showToast('Failed to load breaches', 'error');
  }
}

function applyFilters() {
  const search = document.getElementById('filter-search').value.toLowerCase();
  const source = document.getElementById('filter-source').value;
  const type   = document.getElementById('filter-type').value;
  const state  = document.getElementById('filter-state').value;
  const year   = document.getElementById('filter-year').value;

  filteredBreaches = allBreaches.filter(b => {
    if (search && !`${b.organization} ${b.description} ${b.data_types}`.toLowerCase().includes(search)) return false;
    if (source && b.source !== source) return false;
    if (type && b.breach_type !== type) return false;
    if (state && b.state !== state) return false;
    if (year && !((b.breach_date || b.notification_date || '').startsWith(year))) return false;
    return true;
  });

  renderBreachTable();
}

function clearFilters() {
  ['filter-search','filter-source','filter-type','filter-state','filter-year'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  filteredBreaches = [...allBreaches];
  renderBreachTable();
}

function sortTable(key) {
  if (sortKey === key) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
  else { sortKey = key; sortDir = 'desc'; }
  renderBreachTable();
}

function renderBreachTable() {
  const tbody = document.getElementById('breach-tbody');
  const count = document.getElementById('breach-count');
  if (!tbody) return;

  count.textContent = `${filteredBreaches.length} breach${filteredBreaches.length !== 1 ? 'es' : ''}`;

  const sorted = [...filteredBreaches].sort((a, b) => {
    let va = a[sortKey] ?? '', vb = b[sortKey] ?? '';
    if (sortKey === 'records_affected') { va = Number(va); vb = Number(vb); }
    if (va < vb) return sortDir === 'asc' ? -1 : 1;
    if (va > vb) return sortDir === 'asc' ? 1 : -1;
    return 0;
  });

  if (!sorted.length) {
    tbody.innerHTML = `<tr><td colspan="9"><div class="empty-state">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
      <h3>No breaches found</h3>
      <p>Try adjusting your filters or add a manual entry.</p>
    </div></td></tr>`;
    return;
  }

  tbody.innerHTML = sorted.map(b => `
    <tr onclick="openDetail(${b.id})">
      <td>
        <div class="td-org">${esc(b.organization)}</div>
        ${b.attack_vector ? `<div class="td-org-sub">${esc(b.attack_vector)}</div>` : ''}
      </td>
      <td>${b.state || '—'}</td>
      <td style="font-family:var(--font-mono);font-size:12px">${b.breach_date || b.notification_date || '—'}</td>
      <td>${breachTypeBadge(b.breach_type)}</td>
      <td class="td-num">${b.records_affected ? b.records_affected.toLocaleString() : '—'}</td>
      <td style="max-width:180px;font-size:11px;color:var(--text-muted)">${b.data_types ? truncate(b.data_types, 50) : '—'}</td>
      <td>${sourceBadge(b.source)}</td>
      <td><span class="status-${(b.status||'').toLowerCase().replace(/\s+/g,'-')}">${b.status || '—'}</span></td>
      <td onclick="event.stopPropagation()">
        <button class="btn btn-secondary btn-sm" onclick="openDetail(${b.id})">View</button>
      </td>
    </tr>
  `).join('');
}

/* ── Detail Modal ───────────────────────────────────────────────────────────── */
async function openDetail(id) {
  const { data: b } = await api('GET', `/api/breaches/${id}`);
  if (!b) return;

  document.getElementById('detail-title').textContent = b.organization;

  const sev = getSeverity(b);
  document.getElementById('detail-body').innerHTML = `
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:20px">
      ${breachTypeBadge(b.breach_type)}
      ${sourceBadge(b.source)}
      <span class="badge badge-default" style="margin-left:auto">${sev.label}</span>
      <span class="severity-dot severity-${sev.level}"></span>
    </div>
    <div class="detail-grid">
      <div class="detail-field">
        <div class="detail-label">Organization</div>
        <div class="detail-value">${esc(b.organization)}</div>
      </div>
      <div class="detail-field">
        <div class="detail-label">State</div>
        <div class="detail-value">${b.state || '—'}</div>
      </div>
      <div class="detail-field">
        <div class="detail-label">Breach Date</div>
        <div class="detail-value">${b.breach_date || '—'}</div>
      </div>
      <div class="detail-field">
        <div class="detail-label">Discovery Date</div>
        <div class="detail-value">${b.discovery_date || '—'}</div>
      </div>
      <div class="detail-field">
        <div class="detail-label">Notification Date</div>
        <div class="detail-value">${b.notification_date || '—'}</div>
      </div>
      <div class="detail-field">
        <div class="detail-label">Status</div>
        <div class="detail-value"><span class="status-${(b.status||'').toLowerCase()}">${b.status || '—'}</span></div>
      </div>
      <div class="detail-field">
        <div class="detail-label">Breach Type</div>
        <div class="detail-value">${b.breach_type || '—'}</div>
      </div>
      <div class="detail-field">
        <div class="detail-label">Attack Vector</div>
        <div class="detail-value">${b.attack_vector || '—'}</div>
      </div>
      <div class="detail-field">
        <div class="detail-label">Records Affected</div>
        <div class="detail-value" style="font-size:20px;font-weight:700;color:var(--danger)">${b.records_affected ? b.records_affected.toLocaleString() : 'Unknown'}</div>
      </div>
      <div class="detail-field">
        <div class="detail-label">Source</div>
        <div class="detail-value">${esc(b.source)}</div>
      </div>
      <div class="detail-field full">
        <div class="detail-label">Data Types Compromised</div>
        <div class="detail-value">${b.data_types ? renderDataTypePills(b.data_types) : '—'}</div>
      </div>
      <div class="detail-field full">
        <div class="detail-label">Description</div>
        <div class="detail-value" style="color:var(--text-muted);line-height:1.6">${b.description ? esc(b.description) : '—'}</div>
      </div>
    </div>
  `;

  document.getElementById('detail-delete').onclick = async () => {
    if (!confirm(`Delete breach record for "${b.organization}"?`)) return;
    await api('DELETE', `/api/breaches/${id}`);
    closeModal('detail-modal');
    loadBreaches();
    loadDashboard();
    showToast('Breach deleted', 'success');
  };

  openModal('detail-modal');
}

function renderDataTypePills(dataTypes) {
  return dataTypes.split(',').map(t => t.trim()).filter(Boolean).map(t =>
    `<span class="badge badge-default" style="margin:2px">${esc(t)}</span>`
  ).join('');
}

/* ── Add/Edit Modal ─────────────────────────────────────────────────────────── */
function openAddModal(breach) {
  editingId = breach?.id || null;
  document.getElementById('add-modal-title').textContent = breach ? 'Edit Breach Record' : 'Add Breach Record';
  const form = document.getElementById('breach-form');
  form.reset();
  if (breach) {
    Object.entries(breach).forEach(([k, v]) => {
      const el = form.elements[k];
      if (el && v != null) el.value = v;
    });
  }
  openModal('add-modal');
}

async function saveBreach() {
  const form = document.getElementById('breach-form');
  if (!form.checkValidity()) { form.reportValidity(); return; }

  const data = Object.fromEntries(new FormData(form));
  if (data.records_affected) data.records_affected = parseInt(data.records_affected);

  try {
    if (editingId) {
      await api('PUT', `/api/breaches/${editingId}`, data);
      showToast('Breach updated', 'success');
    } else {
      await api('POST', '/api/breaches', data);
      showToast('Breach added', 'success');
    }
    closeModal('add-modal');
    loadBreaches();
    loadDashboard();
  } catch (e) {
    showToast('Save failed: ' + e.message, 'error');
  }
}

/* ── Analytics ──────────────────────────────────────────────────────────────── */
async function loadAnalytics() {
  const { data: stats } = await api('GET', '/api/stats');
  const { data: breaches } = await api('GET', '/api/breaches');

  // Attack Vector doughnut
  const vectorCounts = {};
  (breaches || []).forEach(b => {
    const v = b.attack_vector || 'Unknown';
    vectorCounts[v] = (vectorCounts[v] || 0) + 1;
  });
  buildChart('chart-vector', 'doughnut',
    Object.entries(vectorCounts).map(([k,v]) => ({ vector: k, count: v })).sort((a,b) => b.count - a.count),
    'vector', 'count', { colors: ['#79c0ff','#f85149','#3fb950','#d29922','#8957e5','#f0883e','#8b949e'] }
  );

  // Records by year bar
  const recordsByYear = {};
  (breaches || []).forEach(b => {
    const y = (b.breach_date || b.notification_date || '').slice(0,4);
    if (y && y.length === 4) recordsByYear[y] = (recordsByYear[y] || 0) + (b.records_affected || 0);
  });
  const years = Object.keys(recordsByYear).sort();
  buildChart('chart-records-year', 'bar',
    years.map(y => ({ year: y, count: recordsByYear[y] })),
    'year', 'count', { colors: ['#f85149'], fillColors: ['rgba(248,81,73,.7)'] }
  );

  // Breach type over time
  const typeByYear = {};
  (breaches || []).forEach(b => {
    const y = (b.breach_date || b.notification_date || '').slice(0,4);
    const t = b.breach_type || 'Unknown';
    if (!y || y.length !== 4) return;
    if (!typeByYear[y]) typeByYear[y] = {};
    typeByYear[y][t] = (typeByYear[y][t] || 0) + 1;
  });
  renderTypeTrend(typeByYear);

  // State bars
  renderHorizBars('state-bars', stats.byState?.slice(0,10), 'state', '#3fb950');

  // Type bars
  renderHorizBars('type-bars', stats.byType, 'breach_type', '#8957e5');

  // Data type heatmap
  renderDataTypeHeatmap(breaches || []);
}

function renderTypeTrend(typeByYear) {
  const canvas = document.getElementById('chart-type-trend');
  if (!canvas) return;
  if (charts['chart-type-trend']) charts['chart-type-trend'].destroy();

  const allYears = Object.keys(typeByYear).sort();
  const allTypes = [...new Set(Object.values(typeByYear).flatMap(y => Object.keys(y)))].slice(0, 6);
  const palette = ['#f85149','#d29922','#8957e5','#3fb950','#79c0ff','#f0883e'];

  charts['chart-type-trend'] = new Chart(canvas, {
    type: 'line',
    data: {
      labels: allYears,
      datasets: allTypes.map((t, i) => ({
        label: t,
        data: allYears.map(y => typeByYear[y]?.[t] || 0),
        borderColor: palette[i % palette.length],
        backgroundColor: 'transparent',
        tension: .3,
        pointRadius: 4,
      }))
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: '#8b949e', font: { size: 11 }, boxWidth: 10 } },
        tooltip: { backgroundColor: '#1c2128', borderColor: '#30363d', borderWidth: 1, titleColor: '#e6edf3', bodyColor: '#8b949e' }
      },
      scales: {
        x: { ticks: { color: '#6e7681', font: { size: 11 } }, grid: { color: '#21262d' } },
        y: { ticks: { color: '#6e7681', font: { size: 11 } }, grid: { color: '#21262d' } }
      }
    }
  });
}

function renderHorizBars(containerId, data, labelKey, color) {
  const el = document.getElementById(containerId);
  if (!el || !data) return;
  const max = Math.max(...data.map(d => d.count), 1);
  el.innerHTML = data.map(d => `
    <div class="bar-chart-row">
      <div class="bar-label" title="${d[labelKey]}">${d[labelKey] || 'Unknown'}</div>
      <div class="bar-track">
        <div class="bar-fill" style="width:${Math.max(2,(d.count/max)*100)}%;background:${color}">${d.count > 3 ? d.count : ''}</div>
      </div>
      <div class="bar-value">${d.count}</div>
    </div>
  `).join('');
}

function renderDataTypeHeatmap(breaches) {
  const el = document.getElementById('datatype-heatmap');
  if (!el) return;
  const counts = {};
  breaches.forEach(b => {
    if (!b.data_types) return;
    b.data_types.split(',').forEach(t => {
      const k = t.trim();
      if (k) counts[k] = (counts[k] || 0) + 1;
    });
  });
  const max = Math.max(...Object.values(counts), 1);
  const sorted = Object.entries(counts).sort((a,b) => b[1] - a[1]);
  const colors = ['#1f6feb','#388bfd','#58a6ff','#79c0ff','#b1d4ff'];
  el.innerHTML = sorted.map(([k, v]) => {
    const intensity = Math.floor((v / max) * 4);
    return `<span class="badge" style="background:${colors[intensity]}22;color:${colors[intensity]};border:1px solid ${colors[intensity]}44;font-size:12px;padding:4px 12px">
      ${esc(k)} <strong>${v}</strong>
    </span>`;
  }).join('');
}

/* ── Sources ─────────────────────────────────────────────────────────────────── */
const SOURCE_META = {
  'HHS OCR':          { desc: 'HIPAA breach portal. Financial institutions with health plan data. 500+ individual threshold.', color: '#8957e5', url: 'https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf' },
  'Maine AG':         { desc: 'Maine AG breach notification registry. Broad filing requirements covering many industries.', color: '#58a6ff', url: 'https://www.maine.gov/agviewer/content/ag/985235c7-cb9c-4b06-a025-7a4a77e9d52f/list.html' },
  'California AG':    { desc: 'California AG data breach list. CA requires notification for 500+ CA residents.', color: '#d29922', url: 'https://oag.ca.gov/privacy/databreach/list' },
  'DataBreaches.net': { desc: 'Crowdsourced breach news. Rich coverage of financial sector incidents.', color: '#ff7b72', url: 'https://www.databreaches.net' },
  'BankInfoSecurity': { desc: 'ISMG financial-sector news. Covers credit union and bank cyber incidents.', color: '#3fb950', url: 'https://www.bankinfosecurity.com' },
  'KrebsOnSecurity':  { desc: 'Brian Krebs investigative reporting. Deep-dive breach investigations.', color: '#f0883e', url: 'https://krebsonsecurity.com' },
  'Dark Reading':     { desc: 'Cybersecurity news outlet. Broad coverage of breach disclosures.', color: '#bc8cff', url: 'https://www.darkreading.com' },
  'NCUA':             { desc: 'National Credit Union Administration. Regulatory actions and supervisory letters.', color: '#79c0ff', url: 'https://www.ncua.gov' },
  'ITRC':             { desc: 'Identity Theft Resource Center. Comprehensive breach database.', color: '#e3b341', url: 'https://www.idtheftcenter.org' },
};

async function loadSources() {
  const { data: log } = await api('GET', '/api/fetch-log');
  const { data: stats } = await api('GET', '/api/stats');
  const grid = document.getElementById('source-grid');
  if (!grid) return;

  // Latest fetch per source
  const latestBySource = {};
  (log || []).forEach(l => { if (!latestBySource[l.source]) latestBySource[l.source] = l; });

  const countBySource = {};
  (stats.bySource || []).forEach(s => { countBySource[s.source] = s.count; });

  const allSources = Object.keys(SOURCE_META);
  grid.innerHTML = allSources.map(name => {
    const meta = SOURCE_META[name];
    const latest = latestBySource[name];
    const count = countBySource[name] || 0;
    const statusColor = latest?.status === 'success' ? 'var(--success)' : latest ? 'var(--danger)' : 'var(--text-dim)';
    const statusText  = latest?.status === 'success' ? 'OK' : latest ? 'Error' : 'Never fetched';
    const lastFetch   = latest ? new Date(latest.fetched_at).toLocaleString() : '—';

    return `
      <div class="source-card">
        <div class="source-card-header">
          <div class="source-card-icon" style="background:${meta.color}22">
            <svg viewBox="0 0 24 24" fill="none" stroke="${meta.color}" stroke-width="2">
              <circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20"/>
            </svg>
          </div>
          <div>
            <div class="source-card-name">${name}</div>
            <div style="font-size:11px;color:${statusColor}">${statusText}</div>
          </div>
          <button class="btn btn-secondary btn-sm" style="margin-left:auto"
            onclick="fetchSource('${name}', this)">Fetch</button>
        </div>
        <div class="source-card-desc">${meta.desc}</div>
        <div class="source-card-meta">
          <span>${count} breach${count !== 1 ? 'es' : ''} found</span>
          <span>Last: ${lastFetch}</span>
        </div>
      </div>
    `;
  }).join('');
}

async function fetchSource(name, btn) {
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div>';
  try {
    const result = await api('POST', '/api/fetch', { source: name });
    showToast(`${name}: ${result.results?.recordsNew || 0} new breaches`, 'success');
    loadBreaches();
    loadDashboard();
    loadSources();
  } catch (e) {
    showToast(`${name} fetch failed`, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Fetch';
  }
}

/* ── Fetch Log ───────────────────────────────────────────────────────────────── */
async function loadFetchLog() {
  const { data: log } = await api('GET', '/api/fetch-log');
  const el = document.getElementById('fetch-log-list');
  if (!el) return;

  if (!log?.length) {
    el.innerHTML = `<div class="empty-state"><p>No fetch events yet. Click "Refresh All" to start.</p></div>`;
    return;
  }

  el.innerHTML = log.map(l => `
    <div class="log-item">
      <div class="log-dot ${l.status}"></div>
      <div class="log-source">${esc(l.source)}</div>
      <div class="log-time">${new Date(l.fetched_at).toLocaleString()}</div>
      <div class="log-counts">${l.records_found} found · ${l.records_new} new</div>
      ${l.error ? `<div style="color:var(--danger);font-size:11px;margin-left:auto">${esc(l.error)}</div>` : ''}
    </div>
  `).join('');
}

/* ── Fetch All ──────────────────────────────────────────────────────────────── */
async function fetchAll() {
  const btn = document.getElementById('btn-fetch-all');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div> Fetching...';
  showToast('Fetching all sources…', 'info');
  try {
    await api('POST', '/api/fetch', {});
    showToast('All sources updated', 'success');
    loadBreaches();
    loadDashboard();
  } catch (e) {
    showToast('Fetch error: ' + e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg> Refresh All`;
  }
}

/* ── CSV Export ─────────────────────────────────────────────────────────────── */
function exportCSV() {
  const params = new URLSearchParams();
  const search = document.getElementById('filter-search')?.value;
  const source = document.getElementById('filter-source')?.value;
  const type   = document.getElementById('filter-type')?.value;
  const state  = document.getElementById('filter-state')?.value;
  const year   = document.getElementById('filter-year')?.value;
  if (search) params.set('search', search);
  if (source) params.set('source', source);
  if (type)   params.set('breach_type', type);
  if (state)  params.set('state', state);
  if (year)   params.set('year', year);
  window.location.href = `/api/export/csv?${params}`;
}

/* ── Helpers ─────────────────────────────────────────────────────────────────── */
function breachTypeBadge(type) {
  if (!type) return '<span class="badge badge-default">Unknown</span>';
  const cls = {
    'Ransomware': 'ransomware',
    'Phishing': 'phishing',
    'Unauthorized Access/Hacking': 'hacking',
    'Malware': 'malware',
    'Insider Threat': 'insider',
    'Third-Party/Vendor': 'vendor',
    'Accidental Exposure': 'accidental',
    'Data Breach': 'default',
  };
  const c = cls[type] || 'default';
  return `<span class="badge badge-${c}">${esc(type)}</span>`;
}

function sourceBadge(source) {
  if (!source) return '';
  const cls = {
    'DataBreaches.net': 'databreaches',
    'Maine AG': 'maine',
    'California AG': 'california',
    'HHS OCR': 'hhs',
    'NCUA': 'ncua',
    'ITRC': 'itrc',
    'Manual Entry': 'manual',
  };
  const key = cls[source] || 'manual';
  return `<span class="badge badge-source-${key}">${esc(source)}</span>`;
}

function getSeverity(b) {
  const r = b.records_affected || 0;
  const t = b.breach_type || '';
  if (r > 100000 || t === 'Ransomware') return { level: 'critical', label: 'Critical' };
  if (r > 10000  || t === 'Unauthorized Access/Hacking') return { level: 'high', label: 'High' };
  if (r > 1000   || t === 'Phishing') return { level: 'medium', label: 'Medium' };
  return { level: 'low', label: 'Low' };
}

function formatLargeNum(n) {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000)     return (n / 1_000).toFixed(0) + 'K';
  return n.toLocaleString();
}

function truncate(str, max) {
  return str && str.length > max ? str.slice(0, max) + '…' : (str || '');
}

function esc(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/* ── Modal Helpers ───────────────────────────────────────────────────────────── */
function openModal(id) {
  document.getElementById(id).classList.remove('hidden');
}

function closeModal(id) {
  document.getElementById(id).classList.add('hidden');
}

// Close on backdrop click
document.querySelectorAll('.modal-backdrop').forEach(el => {
  el.addEventListener('click', e => {
    if (e.target === el) el.classList.add('hidden');
  });
});

// Close on Escape
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') document.querySelectorAll('.modal-backdrop:not(.hidden)').forEach(m => m.classList.add('hidden'));
});

/* ── Toast ───────────────────────────────────────────────────────────────────── */
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}
