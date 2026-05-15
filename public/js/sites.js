/* ── Suspected Sites Module ──────────────────────────────────────────────────── */
(function () {
  'use strict';

  // ── Module state ─────────────────────────────────────────────────────────────
  let allSites = [];
  let filteredSites = [];
  let activeRiskFilter = '';
  let activeStatusFilter = '';
  let searchQuery = '';
  let currentSiteId = null;
  let activeTab = 'overview';

  // ── Analyst status options ───────────────────────────────────────────────────
  const STATUS_OPTIONS = [
    'new',
    'under_review',
    'needs_more_evidence',
    'likely_benign',
    'suspicious',
    'confirmed_fraud',
    'submitted_for_takedown',
    'submitted_to_law_enforcement',
    'resolved',
  ];

  const STATUS_LABELS = {
    'new':                          'New',
    'under_review':                 'Under Review',
    'needs_more_evidence':          'Needs More Evidence',
    'likely_benign':                'Likely Benign',
    'suspicious':                   'Suspicious',
    'confirmed_fraud':              'Confirmed Fraud',
    'submitted_for_takedown':       'Submitted for Takedown',
    'submitted_to_law_enforcement': 'Submitted to Law Enforcement',
    'resolved':                     'Resolved',
  };

  // ── Helpers ──────────────────────────────────────────────────────────────────
  function esc(str) {
    return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function fmt(val, fallback) {
    return val || fallback || '—';
  }

  function fmtDate(str) {
    if (!str) return '—';
    try { return new Date(str).toLocaleDateString(); } catch { return str; }
  }

  function riskBadge(level) {
    const cls = {
      critical:   'ss-risk-critical',
      high:       'ss-risk-high',
      suspicious: 'ss-risk-suspicious',
      watch:      'ss-risk-watch',
    };
    const label = level ? level.charAt(0).toUpperCase() + level.slice(1) : 'Unknown';
    return `<span class="ss-badge ${cls[level] || 'ss-risk-watch'}">${esc(label)}</span>`;
  }

  function statusBadge(status) {
    const cls = 'ss-status-' + (status || 'new').replace(/_/g, '-');
    const label = STATUS_LABELS[status] || status || 'New';
    return `<span class="ss-badge ${cls}">${esc(label)}</span>`;
  }

  async function ssApi(method, path, body) {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    if (body) opts.body = JSON.stringify(body);
    const r = await fetch(path, opts);
    return r.json();
  }

  function showToast(msg, type) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const t = document.createElement('div');
    t.className = `toast ${type || 'info'}`;
    t.innerHTML = `<span>${esc(msg)}</span>`;
    container.appendChild(t);
    setTimeout(() => t.remove(), 4000);
  }

  // ── Load entry point ─────────────────────────────────────────────────────────
  async function load() {
    renderShell();
    setupShellEvents();
    await refreshSites();
  }

  // ── Shell HTML ───────────────────────────────────────────────────────────────
  function renderShell() {
    const view = document.getElementById('view-sites');
    if (!view) return;
    view.innerHTML = `
      <div class="page-header">
        <div>
          <h1 class="page-title">Suspected Sites</h1>
          <p class="page-subtitle">Investigate and track suspected fraudulent credit union websites</p>
        </div>
      </div>

      <!-- Investigation form -->
      <div class="ss-investigate-form">
        <div class="ss-investigate-inner">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <input type="text" id="ss-url-input" class="ss-url-input" placeholder="https://example-suspected-site.com" autocomplete="off">
          <button class="btn btn-primary" id="ss-investigate-btn">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
            Investigate
          </button>
        </div>
        <p class="ss-investigate-note">Submitting a URL runs a full investigation pipeline: page crawl, risk scoring, and NCUA validation. All findings require analyst review.</p>
      </div>

      <!-- Stat cards -->
      <div class="ss-stat-grid" id="ss-stat-grid">
        <div class="ss-stat-card"><div class="ss-stat-label">Total Suspected</div><div class="ss-stat-value accent" id="ss-stat-total">—</div></div>
        <div class="ss-stat-card"><div class="ss-stat-label">Critical</div><div class="ss-stat-value" style="color:#ff4040" id="ss-stat-critical">—</div></div>
        <div class="ss-stat-card"><div class="ss-stat-label">High</div><div class="ss-stat-value danger" id="ss-stat-high">—</div></div>
        <div class="ss-stat-card"><div class="ss-stat-label">New Today</div><div class="ss-stat-value warning" id="ss-stat-new-today">—</div></div>
        <div class="ss-stat-card"><div class="ss-stat-label">Under Review</div><div class="ss-stat-value accent" id="ss-stat-under-review">—</div></div>
      </div>

      <!-- Filters -->
      <div class="ss-filter-bar">
        <div class="ss-risk-btns">
          <button class="btn btn-secondary btn-sm ss-risk-btn active" data-risk="">All Levels</button>
          <button class="btn btn-secondary btn-sm ss-risk-btn ss-risk-btn-critical" data-risk="critical">Critical</button>
          <button class="btn btn-secondary btn-sm ss-risk-btn ss-risk-btn-high" data-risk="high">High</button>
          <button class="btn btn-secondary btn-sm ss-risk-btn ss-risk-btn-suspicious" data-risk="suspicious">Suspicious</button>
          <button class="btn btn-secondary btn-sm ss-risk-btn ss-risk-btn-watch" data-risk="watch">Watch</button>
        </div>
        <select id="ss-status-filter" class="ss-filter-select">
          <option value="">All Statuses</option>
          ${STATUS_OPTIONS.map(s => `<option value="${s}">${STATUS_LABELS[s]}</option>`).join('')}
        </select>
        <div class="ss-search-wrap">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
          <input type="text" id="ss-search" class="ss-search-input" placeholder="Search domain or title...">
        </div>
      </div>

      <!-- Sites table -->
      <div class="table-wrap">
        <div class="table-header">
          <span class="table-count" id="ss-site-count">Loading...</span>
        </div>
        <div class="table-scroll">
          <table id="ss-sites-table">
            <thead><tr>
              <th>Domain</th>
              <th>Risk Level</th>
              <th>Score</th>
              <th>Status</th>
              <th>First Seen</th>
              <th>Source</th>
              <th></th>
            </tr></thead>
            <tbody id="ss-sites-tbody"></tbody>
          </table>
        </div>
      </div>

      <!-- Detail panel (slide-in right) -->
      <div class="ss-detail-panel" id="ss-detail-panel">
        <div class="ss-detail-header">
          <div class="ss-detail-header-info">
            <h2 class="ss-detail-domain" id="ss-detail-domain">—</h2>
            <div class="ss-detail-badges" id="ss-detail-badges"></div>
          </div>
          <button class="modal-close" id="ss-detail-close">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg>
          </button>
        </div>

        <div class="ss-detail-score-row" id="ss-detail-score-row"></div>

        <div class="ss-detail-actions" id="ss-detail-actions"></div>

        <div class="ss-tabs">
          <button class="ss-tab active" data-tab="overview">Overview</button>
          <button class="ss-tab" data-tab="evidence">Evidence</button>
          <button class="ss-tab" data-tab="ai">AI Analysis</button>
          <button class="ss-tab" data-tab="similar">Similar Sites</button>
          <button class="ss-tab" data-tab="audit">Audit Log</button>
        </div>

        <div class="ss-tab-content" id="ss-tab-overview"></div>
        <div class="ss-tab-content hidden" id="ss-tab-evidence"></div>
        <div class="ss-tab-content hidden" id="ss-tab-ai"></div>
        <div class="ss-tab-content hidden" id="ss-tab-similar"></div>
        <div class="ss-tab-content hidden" id="ss-tab-audit"></div>
      </div>

      <!-- Panel backdrop -->
      <div class="ss-panel-backdrop hidden" id="ss-panel-backdrop"></div>
    `;
  }

  // ── Shell event listeners ────────────────────────────────────────────────────
  function setupShellEvents() {
    // Investigate button
    const investigateBtn = document.getElementById('ss-investigate-btn');
    if (investigateBtn) {
      investigateBtn.addEventListener('click', handleInvestigate);
    }

    // URL input — Enter key
    const urlInput = document.getElementById('ss-url-input');
    if (urlInput) {
      urlInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') handleInvestigate();
      });
    }

    // Risk filter buttons
    document.querySelectorAll('.ss-risk-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.ss-risk-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeRiskFilter = btn.dataset.risk || '';
        applyFilters();
      });
    });

    // Status filter
    const statusFilter = document.getElementById('ss-status-filter');
    if (statusFilter) {
      statusFilter.addEventListener('change', () => {
        activeStatusFilter = statusFilter.value;
        applyFilters();
      });
    }

    // Search
    const searchInput = document.getElementById('ss-search');
    if (searchInput) {
      searchInput.addEventListener('input', () => {
        searchQuery = searchInput.value.toLowerCase();
        applyFilters();
      });
    }

    // Detail panel close
    const closeBtn = document.getElementById('ss-detail-close');
    if (closeBtn) closeBtn.addEventListener('click', closeDetailPanel);

    // Backdrop
    const backdrop = document.getElementById('ss-panel-backdrop');
    if (backdrop) backdrop.addEventListener('click', closeDetailPanel);

    // Tab switching
    document.querySelectorAll('.ss-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.ss-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        activeTab = tab.dataset.tab;
        document.querySelectorAll('.ss-tab-content').forEach(c => c.classList.add('hidden'));
        const content = document.getElementById(`ss-tab-${activeTab}`);
        if (content) content.classList.remove('hidden');
      });
    });
  }

  // ── Investigate handler ──────────────────────────────────────────────────────
  async function handleInvestigate() {
    const urlInput = document.getElementById('ss-url-input');
    const btn = document.getElementById('ss-investigate-btn');
    const url = (urlInput?.value || '').trim();
    if (!url) { showToast('Please enter a URL to investigate', 'error'); return; }

    btn.disabled = true;
    btn.innerHTML = '<div class="spinner"></div> Investigating...';
    showToast('Investigating site... this may take up to 30 seconds', 'info');

    try {
      const result = await ssApi('POST', '/api/sites/investigate', { url });
      if (!result.success) {
        showToast(`Investigation failed: ${result.error}`, 'error');
        return;
      }
      showToast(`Investigation complete. Risk: ${result.data?.scoring?.level?.toUpperCase() || 'unknown'}`, 'success');
      if (urlInput) urlInput.value = '';
      await refreshSites();
      if (result.data?.site?.id) {
        await openDetailPanel(result.data.site.id);
      }
    } catch (err) {
      showToast('Investigation error: ' + err.message, 'error');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg> Investigate';
    }
  }

  // ── Load and refresh data ────────────────────────────────────────────────────
  async function refreshSites() {
    try {
      const [sitesResult, statsResult] = await Promise.all([
        ssApi('GET', '/api/sites'),
        ssApi('GET', '/api/sites/stats'),
      ]);

      allSites = sitesResult.data || [];
      filteredSites = [...allSites];
      applyFilters();
      updateStatCards(statsResult.data || {});
    } catch (err) {
      showToast('Failed to load sites: ' + err.message, 'error');
    }
  }

  function updateStatCards(stats) {
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val ?? '0'; };
    set('ss-stat-total', stats.total);
    set('ss-stat-critical', stats.critical);
    set('ss-stat-high', stats.high);
    set('ss-stat-new-today', stats.newToday);

    const underReview = (stats.byStatus || []).find(s => s.analyst_status === 'under_review');
    set('ss-stat-under-review', underReview?.count ?? 0);

    // Update nav badge
    const navBadge = document.getElementById('nav-sites-count');
    if (navBadge) {
      const critical = stats.critical ?? 0;
      const high = stats.high ?? 0;
      navBadge.textContent = critical + high > 0 ? critical + high : stats.total ?? '—';
    }
  }

  // ── Filter and render table ──────────────────────────────────────────────────
  function applyFilters() {
    filteredSites = allSites.filter(site => {
      if (activeRiskFilter && site.risk_level !== activeRiskFilter) return false;
      if (activeStatusFilter && site.analyst_status !== activeStatusFilter) return false;
      if (searchQuery) {
        const haystack = `${site.domain} ${site.title || ''} ${site.url}`.toLowerCase();
        if (!haystack.includes(searchQuery)) return false;
      }
      return true;
    });
    renderSitesTable();
  }

  function renderSitesTable() {
    const tbody = document.getElementById('ss-sites-tbody');
    const count = document.getElementById('ss-site-count');
    if (!tbody) return;

    if (count) {
      count.textContent = `${filteredSites.length} site${filteredSites.length !== 1 ? 's' : ''}`;
    }

    if (!filteredSites.length) {
      tbody.innerHTML = `<tr><td colspan="7"><div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path stroke-linecap="round" stroke-linejoin="round" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <h3>No suspected sites found</h3>
        <p>Use the investigation form above to add a site, or adjust your filters.</p>
      </div></td></tr>`;
      return;
    }

    tbody.innerHTML = filteredSites.map(site => `
      <tr onclick="window.__ssOpenDetail(${site.id})">
        <td>
          <div class="td-org">${esc(site.domain)}</div>
          ${site.title ? `<div class="td-org-sub">${esc(site.title.slice(0, 60))}</div>` : ''}
        </td>
        <td>${riskBadge(site.risk_level)}</td>
        <td class="td-num">${site.risk_score ?? 0}</td>
        <td>${statusBadge(site.analyst_status)}</td>
        <td style="font-family:var(--font-mono);font-size:12px">${fmtDate(site.first_seen)}</td>
        <td style="font-size:12px;color:var(--text-muted)">${esc(site.source || '—')}</td>
        <td onclick="event.stopPropagation()">
          <button class="btn btn-secondary btn-sm" onclick="window.__ssOpenDetail(${site.id})">View</button>
        </td>
      </tr>
    `).join('');
  }

  // ── Detail panel ─────────────────────────────────────────────────────────────
  function openDetailPanel(siteId) {
    currentSiteId = siteId;
    const panel = document.getElementById('ss-detail-panel');
    const backdrop = document.getElementById('ss-panel-backdrop');
    if (panel) panel.classList.add('open');
    if (backdrop) backdrop.classList.remove('hidden');
    activeTab = 'overview';
    document.querySelectorAll('.ss-tab').forEach(t => t.classList.remove('active'));
    const overviewTab = document.querySelector('.ss-tab[data-tab="overview"]');
    if (overviewTab) overviewTab.classList.add('active');
    document.querySelectorAll('.ss-tab-content').forEach(c => c.classList.add('hidden'));
    const overviewContent = document.getElementById('ss-tab-overview');
    if (overviewContent) overviewContent.classList.remove('hidden');
    return loadDetailPanelData(siteId);
  }

  function closeDetailPanel() {
    const panel = document.getElementById('ss-detail-panel');
    const backdrop = document.getElementById('ss-panel-backdrop');
    if (panel) panel.classList.remove('open');
    if (backdrop) backdrop.classList.add('hidden');
    currentSiteId = null;
  }

  async function loadDetailPanelData(siteId) {
    try {
      const result = await ssApi('GET', `/api/sites/${siteId}`);
      if (!result.success) {
        showToast('Failed to load site details', 'error');
        return;
      }
      const { evidence, ai_analysis, related, audit_log, ...site } = result.data;
      renderDetailHeader(site);
      renderDetailActions(site);
      renderOverviewTab(site, evidence);
      renderEvidenceTab(evidence);
      renderAiTab(ai_analysis, siteId);
      renderSimilarTab(related);
      renderAuditTab(audit_log);
    } catch (err) {
      showToast('Error loading details: ' + err.message, 'error');
    }
  }

  function renderDetailHeader(site) {
    const domainEl = document.getElementById('ss-detail-domain');
    const badgesEl = document.getElementById('ss-detail-badges');
    const scoreRow = document.getElementById('ss-detail-score-row');

    if (domainEl) domainEl.textContent = site.domain || site.url;
    if (badgesEl) badgesEl.innerHTML = `${riskBadge(site.risk_level)} ${statusBadge(site.analyst_status)}`;
    if (scoreRow) {
      scoreRow.innerHTML = `
        <div class="ss-score-big">
          <span class="ss-score-num" style="color:${riskColor(site.risk_level)}">${site.risk_score ?? 0}</span>
          <span class="ss-score-label">Risk Score</span>
        </div>
        <div class="ss-score-meta">
          <div><span style="color:var(--text-dim)">First seen:</span> ${fmtDate(site.first_seen)}</div>
          <div><span style="color:var(--text-dim)">Last seen:</span> ${fmtDate(site.last_seen)}</div>
          <div><span style="color:var(--text-dim)">Source:</span> ${esc(site.source || '—')}</div>
        </div>
      `;
    }
  }

  function riskColor(level) {
    const colors = { critical: '#ff4040', high: '#f85149', suspicious: '#d29922', watch: '#58a6ff' };
    return colors[level] || 'var(--text)';
  }

  function renderDetailActions(site) {
    const el = document.getElementById('ss-detail-actions');
    if (!el) return;

    el.innerHTML = `
      <div class="ss-action-row">
        <button class="btn btn-secondary btn-sm" id="ss-btn-reinvestigate">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
          Re-Investigate
        </button>
        <button class="btn btn-secondary btn-sm" id="ss-btn-ai-analyze">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18"/></svg>
          AI Analysis
        </button>
        <button class="btn btn-secondary btn-sm" id="ss-btn-find-similar">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="m8.59 13.51 6.83 3.98M15.41 6.51l-6.82 3.98"/></svg>
          Find Similar
        </button>
        <button class="btn btn-secondary btn-sm" id="ss-btn-evidence-pkg">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
          Evidence Package
        </button>
        <button class="btn btn-danger btn-sm" id="ss-btn-delete">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a1 1 0 011-1h4a1 1 0 011 1v2"/></svg>
          Delete
        </button>
      </div>
      <div class="ss-status-update-row">
        <span style="font-size:12px;color:var(--text-muted)">Status:</span>
        <select id="ss-status-select" class="ss-filter-select" style="width:auto">
          ${STATUS_OPTIONS.map(s => `<option value="${s}" ${site.analyst_status === s ? 'selected' : ''}>${STATUS_LABELS[s]}</option>`).join('')}
        </select>
        <textarea id="ss-status-notes" class="form-control ss-notes-input" placeholder="Optional analyst notes..." rows="1">${esc(site.notes || '')}</textarea>
        <button class="btn btn-primary btn-sm" id="ss-btn-save-status">Save</button>
      </div>
    `;

    // Wire up action buttons
    document.getElementById('ss-btn-reinvestigate')?.addEventListener('click', () => handleReinvestigate(site));
    document.getElementById('ss-btn-ai-analyze')?.addEventListener('click', () => handleAiAnalysis(site.id));
    document.getElementById('ss-btn-find-similar')?.addEventListener('click', () => handleFindSimilar(site.id));
    document.getElementById('ss-btn-evidence-pkg')?.addEventListener('click', () => handleEvidencePackage(site.id, site.domain));
    document.getElementById('ss-btn-delete')?.addEventListener('click', () => handleDelete(site.id, site.domain));
    document.getElementById('ss-btn-save-status')?.addEventListener('click', () => handleSaveStatus(site.id));
  }

  function renderOverviewTab(site, evidence) {
    const el = document.getElementById('ss-tab-overview');
    if (!el) return;

    const emails = getEvidenceItems(evidence, 'email');
    const phones = getEvidenceItems(evidence, 'phone');
    const addresses = getEvidenceItems(evidence, 'address');
    const routing = getEvidenceItems(evidence, 'routing_number');
    const charter = getEvidenceItems(evidence, 'charter_number');
    const ncuaLang = getEvidenceItems(evidence, 'ncua_language');
    const scoringFactors = (evidence || [])
      .filter(e => e.evidence_type === 'scoring_factor')
      .map(e => { try { return JSON.parse(e.evidence_value); } catch { return null; } })
      .filter(Boolean);

    el.innerHTML = `
      <div class="ss-overview-grid">
        <div class="ss-overview-section">
          <div class="ss-overview-label">Page Title</div>
          <div class="ss-overview-value">${esc(site.title || '—')}</div>
        </div>
        <div class="ss-overview-section">
          <div class="ss-overview-label">Meta Description</div>
          <div class="ss-overview-value" style="color:var(--text-muted)">${esc(site.meta_description || '—')}</div>
        </div>
        <div class="ss-overview-section">
          <div class="ss-overview-label">URL</div>
          <div class="ss-overview-value">
            <a href="${esc(site.url)}" target="_blank" rel="noopener noreferrer">${esc(site.url)}</a>
          </div>
        </div>
      </div>

      <div class="ss-indicators-section">
        <div class="ss-indicators-title">Extracted Indicators</div>
        <div class="ss-indicators-grid">
          ${indicatorBlock('Email Addresses', emails)}
          ${indicatorBlock('Phone Numbers', phones)}
          ${indicatorBlock('Physical Addresses', addresses)}
          ${indicatorBlock('Routing Numbers', routing)}
          ${indicatorBlock('Charter Numbers', charter)}
          ${indicatorBlock('NCUA Language', ncuaLang)}
        </div>
      </div>

      <div class="ss-scoring-section">
        <div class="ss-indicators-title">Risk Scoring Breakdown</div>
        ${scoringFactors.length === 0
          ? '<p style="color:var(--text-dim);font-size:13px">No scoring factors recorded.</p>'
          : scoringFactors.map(f => `
            <div class="ss-factor-row">
              <span class="ss-factor-points">+${f.points}</span>
              <div>
                <div class="ss-factor-key">${esc(f.key)}</div>
                <div class="ss-factor-reason">${esc(f.reason)}</div>
              </div>
            </div>
          `).join('')
        }
      </div>
    `;
  }

  function getEvidenceItems(evidence, type) {
    return (evidence || [])
      .filter(e => e.evidence_type === type)
      .map(e => e.evidence_value);
  }

  function indicatorBlock(label, items) {
    return `
      <div class="ss-indicator-block">
        <div class="ss-indicator-label">${esc(label)}</div>
        ${items.length === 0
          ? '<div class="ss-indicator-empty">None detected</div>'
          : items.map(v => `<div class="ss-indicator-item">${esc(v)}</div>`).join('')
        }
      </div>
    `;
  }

  function renderEvidenceTab(evidence) {
    const el = document.getElementById('ss-tab-evidence');
    if (!el) return;

    if (!evidence || !evidence.length) {
      el.innerHTML = '<div class="empty-state"><p>No evidence items recorded.</p></div>';
      return;
    }

    el.innerHTML = `
      <div class="table-scroll">
        <table>
          <thead><tr>
            <th>Type</th>
            <th>Value</th>
            <th>Confidence</th>
            <th>Source Page</th>
            <th>Recorded</th>
          </tr></thead>
          <tbody>
            ${evidence.map(e => `
              <tr>
                <td><span class="badge badge-default">${esc(e.evidence_type)}</span></td>
                <td style="font-size:12px;max-width:280px;word-break:break-all">${esc(e.evidence_value)}</td>
                <td class="td-num">${e.confidence ?? '—'}%</td>
                <td style="font-size:12px;color:var(--text-muted)">${esc(e.source_page || '—')}</td>
                <td style="font-size:12px;color:var(--text-dim)">${fmtDate(e.created_at)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  function renderAiTab(aiAnalysis, siteId) {
    const el = document.getElementById('ss-tab-ai');
    if (!el) return;

    let parsedAnalysis = null;
    if (aiAnalysis?.analysis_json) {
      try { parsedAnalysis = JSON.parse(aiAnalysis.analysis_json); } catch { parsedAnalysis = null; }
    }

    const hasKey = !!(window.__ssOpenDetail); // placeholder — we check via /api/sites/:id/analyze response

    el.innerHTML = `
      <div class="ss-ai-header">
        <div>
          <div class="ss-indicators-title">AI-Generated Analysis</div>
          <p class="ss-ai-disclaimer">AI analysis is generated by an LLM and requires human analyst review. It does not constitute verified findings.</p>
        </div>
        <button class="btn btn-secondary btn-sm" id="ss-btn-run-ai">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
          Run AI Analysis
        </button>
      </div>
      ${!aiAnalysis
        ? '<div class="empty-state"><p>AI analysis has not been run for this site.<br>Click "Run AI Analysis" to generate observations.</p></div>'
        : renderAiResults(parsedAnalysis, aiAnalysis)
      }
    `;

    document.getElementById('ss-btn-run-ai')?.addEventListener('click', () => handleAiAnalysis(siteId));
  }

  function renderAiResults(parsed, aiAnalysis) {
    if (!parsed) {
      return `<div class="ss-ai-summary"><p style="color:var(--text-muted)">${esc(aiAnalysis.summary || 'No summary available.')}</p></div>`;
    }

    const classColors = {
      'likely_legitimate': 'var(--success)',
      'possibly_suspicious': 'var(--warning)',
      'likely_suspicious': 'var(--danger)',
      'requires_immediate_review': '#ff4040',
    };

    return `
      <div class="ss-ai-result">
        <div class="ss-ai-field">
          <span class="ss-ai-field-label">Classification:</span>
          <span style="color:${classColors[parsed.classification] || 'var(--text)'}; font-weight:700">${esc(parsed.classification || '—')}</span>
          <span style="margin-left:8px;color:var(--text-dim);font-size:12px">Confidence: ${esc(parsed.confidence || '—')}</span>
        </div>
        <div class="ss-ai-field">
          <span class="ss-ai-field-label">NCUA Claim Detected:</span>
          <span style="color:${parsed.ncua_claim_detected ? 'var(--danger)' : 'var(--text-muted)'}">${parsed.ncua_claim_detected ? 'YES' : 'NO'}</span>
        </div>
        <div class="ss-ai-field full">
          <span class="ss-ai-field-label">Summary:</span>
          <p style="margin-top:4px;color:var(--text-muted);line-height:1.6">${esc(parsed.summary || '—')}</p>
        </div>
        <div class="ss-ai-columns">
          <div>
            <div class="ss-ai-field-label" style="margin-bottom:8px">Red Flags</div>
            ${(parsed.red_flags || []).length === 0
              ? '<p style="color:var(--text-dim);font-size:13px">None listed</p>'
              : (parsed.red_flags || []).map(f => `<div class="ss-ai-list-item ss-ai-red">${esc(f)}</div>`).join('')
            }
          </div>
          <div>
            <div class="ss-ai-field-label" style="margin-bottom:8px">Possible Benign Explanations</div>
            ${(parsed.benign_explanations || []).length === 0
              ? '<p style="color:var(--text-dim);font-size:13px">None listed</p>'
              : (parsed.benign_explanations || []).map(f => `<div class="ss-ai-list-item ss-ai-benign">${esc(f)}</div>`).join('')
            }
          </div>
        </div>
        <div class="ss-ai-field full" style="margin-top:12px">
          <div class="ss-ai-field-label" style="margin-bottom:8px">Recommended Pivots</div>
          ${(parsed.recommended_pivots || []).map((f, i) => `<div class="ss-ai-list-item">${i + 1}. ${esc(f)}</div>`).join('') || '<p style="color:var(--text-dim);font-size:13px">None listed</p>'}
        </div>
        <div class="ss-ai-field full">
          <span class="ss-ai-field-label">Recommended Next Action:</span>
          <span style="color:var(--text);margin-left:6px">${esc(parsed.recommended_next_action || '—')}</span>
        </div>
        <div class="ss-ai-disclaimer" style="margin-top:12px">${esc(parsed.analyst_note || 'This analysis is AI-generated and requires human analyst review.')}</div>
      </div>
    `;
  }

  function renderSimilarTab(related) {
    const el = document.getElementById('ss-tab-similar');
    if (!el) return;

    el.innerHTML = `
      <div class="ss-indicators-title">Possible Infrastructure Overlap</div>
      <p class="ss-ai-disclaimer">Similarity scores indicate shared technical indicators only. They do NOT constitute confirmed attribution to the same actor.</p>
      ${!related || !related.length
        ? '<div class="empty-state"><p>No similar sites identified.<br>Click "Find Similar" to compare against known sites.</p></div>'
        : related.map(r => {
            let indicators = [];
            try { indicators = typeof r.shared_indicators_json === 'string' ? JSON.parse(r.shared_indicators_json) : (r.shared_indicators_json || []); } catch { indicators = []; }
            return `
              <div class="ss-similar-item" onclick="window.__ssOpenDetail(${r.related_site_id})">
                <div class="ss-similar-domain">${esc(r.domain || r.url)}</div>
                <div class="ss-similar-meta">
                  ${riskBadge(r.risk_level)}
                  <span class="ss-similar-score">Similarity: ${r.similarity_score}</span>
                </div>
                ${indicators.length ? `<div class="ss-similar-indicators">${indicators.map(i => `<span class="badge badge-default" style="font-size:11px;margin:2px">${esc(i)}</span>`).join('')}</div>` : ''}
              </div>
            `;
          }).join('')
      }
    `;
  }

  function renderAuditTab(auditLog) {
    const el = document.getElementById('ss-tab-audit');
    if (!el) return;

    if (!auditLog || !auditLog.length) {
      el.innerHTML = '<div class="empty-state"><p>No audit log entries.</p></div>';
      return;
    }

    el.innerHTML = `
      <div class="ss-audit-log">
        ${auditLog.map(entry => `
          <div class="ss-audit-entry">
            <div class="ss-audit-action">${esc(entry.action)}</div>
            <div class="ss-audit-details">${esc(entry.details || '—')}</div>
            <div class="ss-audit-time">${fmtDate(entry.created_at)}</div>
          </div>
        `).join('')}
      </div>
    `;
  }

  // ── Action handlers ──────────────────────────────────────────────────────────
  async function handleReinvestigate(site) {
    const btn = document.getElementById('ss-btn-reinvestigate');
    if (btn) { btn.disabled = true; btn.innerHTML = '<div class="spinner"></div>'; }
    showToast('Re-investigating site...', 'info');
    try {
      const result = await ssApi('POST', '/api/sites/investigate', { url: site.url });
      if (!result.success) { showToast('Re-investigation failed: ' + result.error, 'error'); return; }
      showToast('Re-investigation complete', 'success');
      await refreshSites();
      await loadDetailPanelData(site.id);
    } catch (err) {
      showToast('Error: ' + err.message, 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg> Re-Investigate'; }
    }
  }

  async function handleAiAnalysis(siteId) {
    const btn = document.getElementById('ss-btn-ai-analyze') || document.getElementById('ss-btn-run-ai');
    if (btn) { btn.disabled = true; btn.innerHTML = '<div class="spinner"></div> Analyzing...'; }
    showToast('Running AI analysis...', 'info');
    try {
      const result = await ssApi('POST', `/api/sites/${siteId}/analyze`);
      if (result.available === false) {
        showToast(result.reason || 'OpenAI API key not configured', 'error');
        return;
      }
      if (!result.success) { showToast('AI analysis failed: ' + result.error, 'error'); return; }
      showToast('AI analysis complete', 'success');
      await loadDetailPanelData(siteId);
      // Switch to AI tab
      document.querySelector('.ss-tab[data-tab="ai"]')?.click();
    } catch (err) {
      showToast('Error: ' + err.message, 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg> Run AI Analysis'; }
    }
  }

  async function handleFindSimilar(siteId) {
    const btn = document.getElementById('ss-btn-find-similar');
    if (btn) { btn.disabled = true; btn.innerHTML = '<div class="spinner"></div>'; }
    showToast('Searching for similar sites...', 'info');
    try {
      const result = await ssApi('POST', `/api/sites/${siteId}/find-similar`);
      if (!result.success) { showToast('Similarity search failed: ' + result.error, 'error'); return; }
      const count = (result.data || []).length;
      showToast(`Found ${count} site(s) with possible infrastructure overlap`, count > 0 ? 'success' : 'info');
      await loadDetailPanelData(siteId);
      document.querySelector('.ss-tab[data-tab="similar"]')?.click();
    } catch (err) {
      showToast('Error: ' + err.message, 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="m8.59 13.51 6.83 3.98M15.41 6.51l-6.82 3.98"/></svg> Find Similar'; }
    }
  }

  function handleEvidencePackage(siteId, domain) {
    window.location.href = `/api/sites/${siteId}/evidence-package`;
  }

  async function handleDelete(siteId, domain) {
    if (!confirm(`Delete all records for suspected site "${domain}"? This action cannot be undone.`)) return;
    try {
      const result = await ssApi('DELETE', `/api/sites/${siteId}`);
      if (!result.success) { showToast('Delete failed: ' + result.error, 'error'); return; }
      showToast('Site deleted', 'success');
      closeDetailPanel();
      await refreshSites();
    } catch (err) {
      showToast('Error: ' + err.message, 'error');
    }
  }

  async function handleSaveStatus(siteId) {
    const statusSelect = document.getElementById('ss-status-select');
    const notesInput = document.getElementById('ss-status-notes');
    const status = statusSelect?.value;
    const notes = notesInput?.value || undefined;

    if (!status) { showToast('Please select a status', 'error'); return; }

    const btn = document.getElementById('ss-btn-save-status');
    if (btn) { btn.disabled = true; btn.textContent = 'Saving...'; }

    try {
      const result = await ssApi('POST', `/api/sites/${siteId}/status`, { status, notes });
      if (!result.success) { showToast('Save failed: ' + result.error, 'error'); return; }
      showToast('Status updated', 'success');
      await refreshSites();
      await loadDetailPanelData(siteId);
    } catch (err) {
      showToast('Error: ' + err.message, 'error');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Save'; }
    }
  }

  // ── Expose globals ───────────────────────────────────────────────────────────
  window.__ssOpenDetail = openDetailPanel;

  window.sitesDashboard = { load };
})();
