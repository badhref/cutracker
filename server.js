const express = require('express');
const cors    = require('cors');
const cron    = require('node-cron');
const path    = require('path');
const fs      = require('fs');
const {
  getBreaches, getBreach, upsertBreach, deleteBreach, getStats, getFetchLog,
  getSetting, setSetting, getSettings,
  initDwSchema,
  getDwSources, updateDwSourceEnabled,
  getDwFindings, getDwFinding, getDwStats,
  searchDwIOCs,
  getDwAlerts, insertDwAlert, updateDwAlert, deleteDwAlert,
  initSitesSchema, upsertSite, getSites, getSite, deleteSite,
  updateSiteScore, updateSiteStatus, updateSiteAnalysis,
  addSiteEvidence, getSiteEvidence, addAiAnalysis, getAiAnalysis,
  addRelatedSite, getRelatedSites, auditLog, getSiteAuditLog,
  getClusters, getCluster, upsertCluster, addSiteToCluster, getSiteStats,
} = require('./db');
const { runAllFetchers, runFetcherByName, getFetcherNames, seedDemoData } = require('./fetchers/index');
const { runCollection, runSingleCollector, COLLECTORS } = require('./services/darkWebCollector');
const { investigateSite } = require('./services/siteInvestigator');
const { scoreSite } = require('./services/siteScoring');
const { validateWithNcua, getAllowlistStats, reloadAllowlists } = require('./services/ncuaValidation');
const { runAiAnalysis } = require('./services/aiAnalysis');
const { findSimilarSites } = require('./services/similarity');
const { generateEvidencePackage } = require('./services/evidencePackage');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Basic Auth ─────────────────────────────────────────────────────────────────
// Set APP_PASSWORD env var to enable. Skipped in local dev if not set.
const APP_PASSWORD = process.env.APP_PASSWORD;

if (APP_PASSWORD) {
  app.use((req, res, next) => {
    const auth = req.headers['authorization'];
    if (auth && auth.startsWith('Basic ')) {
      const decoded = Buffer.from(auth.slice(6), 'base64').toString();
      const [, pass] = decoded.split(':');
      if (pass === APP_PASSWORD) return next();
    }
    res.set('WWW-Authenticate', 'Basic realm="Credit Union Breach Tracker"');
    res.status(401).send('Unauthorized');
  });
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Breach Routes ──────────────────────────────────────────────────────────────

app.get('/api/breaches', (req, res) => {
  try {
    const breaches = getBreaches(req.query);
    res.json({ success: true, data: breaches, count: breaches.length });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/breaches/:id', (req, res) => {
  try {
    const breach = getBreach(parseInt(req.params.id));
    if (!breach) return res.status(404).json({ success: false, error: 'Not found' });
    res.json({ success: true, data: breach });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/breaches', (req, res) => {
  try {
    const breach = { ...req.body, is_manual: 1, source: req.body.source || 'Manual Entry' };
    const { id, isNew } = upsertBreach(breach);
    res.status(isNew ? 201 : 200).json({ success: true, id, isNew });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

app.put('/api/breaches/:id', (req, res) => {
  try {
    const existing = getBreach(parseInt(req.params.id));
    if (!existing) return res.status(404).json({ success: false, error: 'Not found' });
    const updated = { ...existing, ...req.body, id: undefined };
    upsertBreach({ ...updated, external_id: existing.external_id });
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

app.delete('/api/breaches/:id', (req, res) => {
  try {
    deleteBreach(parseInt(req.params.id));
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── App Settings ──────────────────────────────────────────────────────────────

const SETTING_DEFAULTS = {
  breach_types: [
    'Ransomware', 'Phishing', 'Unauthorized Access/Hacking', 'Malware',
    'Insider Threat', 'Third-Party/Vendor', 'Accidental Exposure',
    'Theft', 'Social Engineering', 'SQL Injection', 'Data Breach',
  ],
  attack_vectors: [
    'Email/Phishing', 'Web Application', 'Remote Access',
    'Third-Party', 'Physical', 'Insider', 'Social Engineering',
  ],
  data_types: [
    'SSN', "Driver's License", 'Full Name', 'Address', 'Date of Birth',
    'Email', 'Phone Number', 'Account Number', 'Payment Card',
    'Credentials', 'Health Information', 'Loan Information',
  ],
};

const ALLOWED_SETTING_KEYS = new Set(Object.keys(SETTING_DEFAULTS));

app.get('/api/settings', (req, res) => {
  try {
    const stored = getSettings();
    const data = { ...SETTING_DEFAULTS, ...stored };
    res.json({ success: true, data });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.put('/api/settings', (req, res) => {
  try {
    for (const [key, value] of Object.entries(req.body)) {
      if (!ALLOWED_SETTING_KEYS.has(key)) continue;
      if (!Array.isArray(value)) continue;
      setSetting(key, value.map(v => String(v).trim()).filter(Boolean));
    }
    const stored = getSettings();
    res.json({ success: true, data: { ...SETTING_DEFAULTS, ...stored } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── Stats ──────────────────────────────────────────────────────────────────────

app.get('/api/stats', (req, res) => {
  try {
    res.json({ success: true, data: getStats() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── Allowlist admin ────────────────────────────────────────────────────────────

app.get('/api/allowlist/stats', (req, res) => {
  try {
    res.json({ success: true, data: getAllowlistStats() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/allowlist/reload — call after uploading a new CSV without restarting
app.post('/api/allowlist/reload', (req, res) => {
  try {
    reloadAllowlists();
    res.json({ success: true, data: getAllowlistStats(), message: 'Allowlist caches cleared. Next lookup will re-read JSON and CSV files.' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── Fetch Controls ─────────────────────────────────────────────────────────────

app.post('/api/fetch', async (req, res) => {
  try {
    const { source } = req.body;
    let results;
    if (source) {
      results = await runFetcherByName(source);
    } else {
      results = await runAllFetchers();
    }
    res.json({ success: true, results });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/fetchers', (req, res) => {
  res.json({ success: true, data: getFetcherNames() });
});

app.get('/api/fetch-log', (req, res) => {
  try {
    res.json({ success: true, data: getFetchLog() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/seed', async (req, res) => {
  try {
    const count = await seedDemoData();
    res.json({ success: true, seeded: count });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── CSV Export ─────────────────────────────────────────────────────────────────

app.get('/api/export/csv', (req, res) => {
  try {
    const breaches = getBreaches(req.query);
    const headers = [
      'id', 'organization', 'state', 'breach_date', 'notification_date',
      'breach_type', 'attack_vector', 'records_affected', 'data_types',
      'source', 'source_url', 'status', 'description'
    ];
    const csvRows = [headers.join(',')];
    for (const b of breaches) {
      const row = headers.map(h => {
        const val = b[h] ?? '';
        const str = String(val).replace(/"/g, '""');
        return str.includes(',') || str.includes('"') || str.includes('\n') ? `"${str}"` : str;
      });
      csvRows.push(row.join(','));
    }
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="credit-union-breaches.csv"');
    res.send(csvRows.join('\n'));
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── Suspected Sites Routes ────────────────────────────────────────────────────

app.get('/api/sites', (req, res) => {
  try {
    const sites = getSites(req.query);
    res.json({ success: true, data: sites, count: sites.length });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/sites/stats', (req, res) => {
  try {
    res.json({ success: true, data: getSiteStats() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/sites/:id', (req, res) => {
  try {
    const site = getSite(parseInt(req.params.id));
    if (!site) return res.status(404).json({ success: false, error: 'Not found' });
    const evidence = getSiteEvidence(site.id);
    const ai_analysis = getAiAnalysis(site.id);
    const related = getRelatedSites(site.id);
    const audit_log = getSiteAuditLog(site.id);
    res.json({ success: true, data: { ...site, evidence, ai_analysis, related, audit_log } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.delete('/api/sites/:id', (req, res) => {
  try {
    deleteSite(parseInt(req.params.id));
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/sites/investigate', async (req, res) => {
  try {
    const { url } = req.body;
    if (!url || typeof url !== 'string') {
      return res.status(400).json({ success: false, error: 'url is required' });
    }

    // Run investigation — validate legitimacy FIRST so scoring can gate on it
    const result = await investigateSite(url);
    const ncua   = await validateWithNcua(result.domain, result.title);
    const scoring = scoreSite(result, ncua);

    // Derive initial analyst status from NCUA validation result
    // possible_match → needs_review so analyst can confirm the institution
    // known_legitimate → likely_benign (scoring already returned 0)
    const initialStatus = (() => {
      if (ncua.status === 'known_legitimate') return 'likely_benign';
      if (ncua.status === 'possible_match')   return 'needs_review';
      return 'new';
    })();

    // Upsert site
    const { id, isNew } = upsertSite({
      url: result.url,
      domain: result.domain,
      normalized_url: result.normalized_url,
      source: 'Manual Investigation',
      risk_score: scoring.score,
      risk_level: scoring.level,
      analyst_status: initialStatus,
      title: result.title ?? null,
      meta_description: result.meta_description ?? null,
      favicon_hash: result.favicon_hash ?? null,
      html_fingerprint: result.html_fingerprint ?? null,
    });

    // Store evidence items
    const evidenceItems = [];
    if (result.emails?.length)    evidenceItems.push({ evidence_type: 'email',          evidence_value: result.emails.join(', '),          confidence: 90 });
    if (result.phones?.length)    evidenceItems.push({ evidence_type: 'phone',          evidence_value: result.phones.join(', '),          confidence: 80 });
    if (result.addresses?.length) evidenceItems.push({ evidence_type: 'address',        evidence_value: result.addresses.join(' | '),      confidence: 70 });
    if (result.routing_numbers?.length) evidenceItems.push({ evidence_type: 'routing_number', evidence_value: result.routing_numbers.join(', '), confidence: 85 });
    if (result.charter_numbers?.length) evidenceItems.push({ evidence_type: 'charter_number', evidence_value: result.charter_numbers.join(', '), confidence: 75 });
    if (result.ncua_language?.length)   evidenceItems.push({ evidence_type: 'ncua_language',  evidence_value: result.ncua_language.join(' | '),   confidence: 95 });
    if (result.analytics_ids?.length)   evidenceItems.push({ evidence_type: 'analytics_id',   evidence_value: result.analytics_ids.join(', '),    confidence: 80 });
    if (result.has_login_form)          evidenceItems.push({ evidence_type: 'login_form',      evidence_value: 'Password input field detected',     confidence: 85 });

    // NCUA validation status — always store so analysts know what dataset quality was present
    evidenceItems.push({
      evidence_type:  'ncua_validation_status',
      evidence_value: JSON.stringify({
        status:         ncua.status,
        reason:         ncua.reason,
        matched_name:   ncua.matched_name ?? null,
        matched_domain: ncua.matched_domain ?? null,
        dataset_loaded: !['not_checked', 'error'].includes(ncua.status),
      }),
      source_page: 'ncua_validation',
      confidence:  100,
    });

    // When NCUA found an approximate institutional match, store it as trust evidence
    if (ncua.status === 'possible_match' && ncua.match) {
      evidenceItems.push({
        evidence_type:  'ncua_possible_match',
        evidence_value: JSON.stringify(ncua.match),
        source_page:    'ncua_validation',
        confidence:     50,
      });
    }

    // Store scoring factors as evidence
    for (const factor of scoring.factors) {
      evidenceItems.push({
        evidence_type: 'scoring_factor',
        evidence_value: JSON.stringify(factor),
        source_page: 'scoring_engine',
        confidence: 100,
      });
    }

    for (const e of evidenceItems) {
      addSiteEvidence({ site_id: id, ...e });
    }

    // Audit
    auditLog(id, isNew ? 'created' : 'reinvestigated', `Score: ${scoring.score} (${scoring.level}). NCUA status: ${ncua.status}. Pages crawled: ${result.pages_crawled?.length ?? 0}`);

    const site = getSite(id);
    const evidence = getSiteEvidence(id);

    res.status(isNew ? 201 : 200).json({
      success: true,
      data: { site, evidence, scoring, ncua, investigation: result },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/sites/:id/analyze', async (req, res) => {
  try {
    const site = getSite(parseInt(req.params.id));
    if (!site) return res.status(404).json({ success: false, error: 'Not found' });

    const evidence = getSiteEvidence(site.id);
    const scoringFactors = evidence
      .filter(e => e.evidence_type === 'scoring_factor')
      .map(e => { try { return JSON.parse(e.evidence_value); } catch { return null; } })
      .filter(Boolean);
    const scoring = { score: site.risk_score, level: site.risk_level, factors: scoringFactors };
    const ncua = await validateWithNcua(site.domain, site.title);

    const aiResult = await runAiAnalysis(site, evidence, scoring, ncua);
    if (aiResult.available === false) {
      return res.json({ success: true, available: false, reason: aiResult.reason });
    }
    if (aiResult.error) {
      return res.status(500).json({ success: false, error: aiResult.error });
    }

    addAiAnalysis({
      site_id: site.id,
      model: aiResult.model ?? 'gpt-4o-mini',
      analysis_json: JSON.stringify(aiResult.analysis),
      summary: aiResult.analysis?.summary ?? null,
    });
    auditLog(site.id, 'ai_analysis', `AI analysis completed. Classification: ${aiResult.analysis?.classification}`);

    res.json({ success: true, data: aiResult.analysis });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/sites/:id/find-similar', async (req, res) => {
  try {
    const site = getSite(parseInt(req.params.id));
    if (!site) return res.status(404).json({ success: false, error: 'Not found' });

    const allSites = getSites({ limit: 1000 });

    // Build evidenceMap so phone/email/analytics comparisons work correctly.
    // Without this, similarity comparisons only use favicon/html/title/footer
    // (fields on the site row) and miss all evidence-table indicators.
    const evidenceMap = {};
    for (const s of allSites) {
      evidenceMap[s.id] = getSiteEvidence(s.id);
    }
    // Ensure the target site is included even if it wasn't in getSites result
    if (!evidenceMap[site.id]) {
      evidenceMap[site.id] = getSiteEvidence(site.id);
    }

    const matches = findSimilarSites(site, allSites, evidenceMap);

    for (const match of matches) {
      addRelatedSite({
        site_id: site.id,
        related_site_id: match.site_id,
        similarity_score: match.similarity_score,
        shared_indicators_json: JSON.stringify(match.shared_indicators),
      });
    }
    auditLog(site.id, 'similarity_search', `Found ${matches.length} possible infrastructure overlap(s)`);

    res.json({
      success: true,
      data: {
        site_id:      site.id,
        related_sites: matches,
        message:      matches.length > 0
          ? `Found ${matches.length} site(s) with possible infrastructure overlap.`
          : 'No sites with sufficient infrastructure overlap detected.',
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/sites/:id/status', (req, res) => {
  try {
    const { status, notes } = req.body;
    if (!status) return res.status(400).json({ success: false, error: 'status is required' });
    const site = getSite(parseInt(req.params.id));
    if (!site) return res.status(404).json({ success: false, error: 'Not found' });

    updateSiteStatus(site.id, status);
    if (notes !== undefined) {
      updateSiteAnalysis(site.id, { notes });
    }
    auditLog(site.id, 'status_changed', `Status changed to: ${status}${notes ? '. Notes: ' + notes : ''}`);

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── Mark as Known Legitimate ───────────────────────────────────────────────────
// Analyst action: manually verify a domain as a real, legitimate credit union.
// Writes to official_credit_union_domains.json, reloads the allowlist cache,
// re-validates the domain (will now return known_legitimate), re-scores the site
// (score → 0), updates analyst_status → likely_benign, and records an audit entry.
app.post('/api/sites/:id/mark-legitimate', async (req, res) => {
  try {
    const site = getSite(parseInt(req.params.id));
    if (!site) return res.status(404).json({ success: false, error: 'Not found' });

    const { institution_name, notes } = req.body;
    const name       = (institution_name || '').trim() || site.title || site.domain;
    const rawDomain  = (site.domain || '').replace(/^www\./, '').toLowerCase();
    const wwwDomain  = 'www.' + rawDomain;
    const domainsToAdd = [rawDomain, wwwDomain];

    // ── 1. Update official_credit_union_domains.json ──────────────────────────
    const jsonPath = path.join(__dirname, 'data', 'official_credit_union_domains.json');
    let entries = [];
    try {
      entries = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
      if (!Array.isArray(entries)) entries = [];
    } catch {
      entries = [];
    }

    // Check whether domain is already present (normalised comparison)
    const existingNormalised = new Set();
    for (const entry of entries) {
      for (const d of (entry.domains || [])) {
        existingNormalised.add(d.toLowerCase().replace(/^www\./, ''));
      }
    }
    const alreadyInFile = existingNormalised.has(rawDomain);

    if (!alreadyInFile) {
      entries.push({
        name,
        domains: domainsToAdd,
        status:    'known_legitimate',
        added_by:  'analyst',
        added_at:  new Date().toISOString().slice(0, 10),
        notes:     notes ? notes.trim() : 'Manually verified by analyst',
      });
      fs.writeFileSync(jsonPath, JSON.stringify(entries, null, 2) + '\n', 'utf8');
    }

    // ── 2. Reload allowlist caches so the new entry takes effect immediately ──
    reloadAllowlists();

    // ── 3. Re-validate — should now return known_legitimate ──────────────────
    const ncua = await validateWithNcua(site.domain, site.title);

    // ── 4. Re-score — known_legitimate gate returns score 0 ──────────────────
    // Pass minimal investigation result; known_legitimate gate fires before
    // any content signals are evaluated.
    const scoring = scoreSite(
      { domain: site.domain, title: site.title, body_text: '', ncua_language: [], has_login_form: false,
        emails: [], routing_numbers: [], charter_numbers: [], domain_age_days: null },
      ncua
    );

    // ── 5. Persist updated score + status ────────────────────────────────────
    updateSiteScore(site.id, scoring.score, scoring.level);
    updateSiteStatus(site.id, 'likely_benign');

    // ── 6. Evidence record ────────────────────────────────────────────────────
    addSiteEvidence({
      site_id:        site.id,
      evidence_type:  'analyst_verification',
      evidence_value: JSON.stringify({
        action:             'mark_legitimate',
        institution_name:   name,
        added_to_allowlist: !alreadyInFile,
        domains_added:      alreadyInFile ? [] : domainsToAdd,
        analyst_notes:      notes ? notes.trim() : null,
      }),
      source_page: 'analyst_action',
      confidence:  100,
    });

    // ── 7. Audit log ──────────────────────────────────────────────────────────
    const location = alreadyInFile
      ? `domain "${site.domain}" was already present in the allowlist`
      : `added "${rawDomain}" and "${wwwDomain}" to official_credit_union_domains.json`;
    const notesClause = notes ? ` Analyst notes: ${notes.trim()}` : '';
    auditLog(
      site.id,
      'marked_legitimate',
      `Analyst marked as Known Legitimate. Institution: "${name}". ${location}. Risk reset to 0.${notesClause}`
    );

    const updatedSite = getSite(site.id);
    res.json({
      success: true,
      data: {
        site:               updatedSite,
        scoring,
        ncua,
        already_in_allowlist: alreadyInFile,
        message: alreadyInFile
          ? `Domain was already in the allowlist. Site score and status updated.`
          : `"${rawDomain}" added to official_credit_union_domains.json. Site score and status updated.`,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/sites/:id/evidence-package', async (req, res) => {
  try {
    const site = getSite(parseInt(req.params.id));
    if (!site) return res.status(404).json({ success: false, error: 'Not found' });

    const evidence = getSiteEvidence(site.id);
    const ai_analysis = getAiAnalysis(site.id);
    const related = getRelatedSites(site.id);
    const clusters = getClusters();

    const report = generateEvidencePackage(site, evidence, ai_analysis, related, clusters);

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="evidence-${site.domain}-${Date.now()}.txt"`);
    res.send(report);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── Cluster Routes ────────────────────────────────────────────────────────────

app.get('/api/clusters', (req, res) => {
  try {
    res.json({ success: true, data: getClusters() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/clusters/:id', (req, res) => {
  try {
    const cluster = getCluster(parseInt(req.params.id));
    if (!cluster) return res.status(404).json({ success: false, error: 'Not found' });
    res.json({ success: true, data: cluster });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/clusters', (req, res) => {
  try {
    const { id, isNew } = upsertCluster(req.body);
    res.status(isNew ? 201 : 200).json({ success: true, id, isNew });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

app.post('/api/clusters/:id/add-site', (req, res) => {
  try {
    const { site_id } = req.body;
    if (!site_id) return res.status(400).json({ success: false, error: 'site_id is required' });
    addSiteToCluster(parseInt(req.params.id), parseInt(site_id));
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
});

// ── Dark Web Monitoring Routes ────────────────────────────────────────────────

// GET /api/darkweb/stats
app.get('/api/darkweb/stats', (req, res) => {
  try { res.json({ success: true, data: getDwStats() }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/darkweb/findings
app.get('/api/darkweb/findings', (req, res) => {
  try {
    const findings = getDwFindings(req.query);
    res.json({ success: true, data: findings, count: findings.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/darkweb/findings/:id
app.get('/api/darkweb/findings/:id', (req, res) => {
  try {
    const f = getDwFinding(parseInt(req.params.id));
    if (!f) return res.status(404).json({ success: false, error: 'Not found' });
    res.json({ success: true, data: f });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/darkweb/sources
app.get('/api/darkweb/sources', (req, res) => {
  try { res.json({ success: true, data: getDwSources() }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// POST /api/darkweb/sources/:id/toggle — enable/disable a source
app.post('/api/darkweb/sources/:id/toggle', (req, res) => {
  try {
    const { enabled } = req.body;
    updateDwSourceEnabled(parseInt(req.params.id), enabled);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// POST /api/darkweb/sources/:name/fetch — trigger a single collector
app.post('/api/darkweb/sources/:name/fetch', async (req, res) => {
  try {
    const result = await runSingleCollector(decodeURIComponent(req.params.name));
    res.json({ success: true, data: result });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// POST /api/darkweb/collect — trigger full collection cycle
app.post('/api/darkweb/collect', async (req, res) => {
  try {
    const result = await runCollection();
    res.json({ success: true, data: result });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/darkweb/iocs
app.get('/api/darkweb/iocs', (req, res) => {
  try {
    const iocs = searchDwIOCs(req.query);
    res.json({ success: true, data: iocs, count: iocs.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/darkweb/search — unified IOC + finding search
app.get('/api/darkweb/search', (req, res) => {
  try {
    const { q, type } = req.query;
    if (!q) return res.json({ success: true, data: { iocs: [], findings: [] } });
    const iocs     = searchDwIOCs({ query: q, ioc_type: type });
    const findings = getDwFindings({ search: q, limit: 50 });
    res.json({ success: true, data: { iocs, findings } });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/darkweb/alerts
app.get('/api/darkweb/alerts', (req, res) => {
  try { res.json({ success: true, data: getDwAlerts() }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// POST /api/darkweb/alerts
app.post('/api/darkweb/alerts', (req, res) => {
  try {
    const { keyword, risk_threshold } = req.body;
    if (!keyword?.trim()) return res.status(400).json({ success: false, error: 'keyword required' });
    insertDwAlert(keyword.trim(), risk_threshold || 8);
    res.status(201).json({ success: true, data: getDwAlerts() });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// PUT /api/darkweb/alerts/:id — toggle enabled
app.put('/api/darkweb/alerts/:id', (req, res) => {
  try {
    const { enabled } = req.body;
    updateDwAlert(parseInt(req.params.id), enabled);
    res.json({ success: true, data: getDwAlerts() });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// DELETE /api/darkweb/alerts/:id
app.delete('/api/darkweb/alerts/:id', (req, res) => {
  try {
    deleteDwAlert(parseInt(req.params.id));
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── Scheduled Fetching (every 6 hours) ────────────────────────────────────────

cron.schedule('0 */6 * * *', () => {
  console.log('[Cron] Running scheduled fetch...');
  runAllFetchers().catch(err => console.error('[Cron] Error:', err.message));
});

// Dark web collection — every 30 minutes
cron.schedule('*/30 * * * *', () => {
  console.log('[DarkWeb Cron] Running collection...');
  runCollection().catch(err => console.error('[DarkWeb Cron] Error:', err.message));
});

// ── Start ──────────────────────────────────────────────────────────────────────

app.listen(PORT, async () => {
  console.log(`\n  Credit Union Breach Tracker`);
  console.log(`  ─────────────────────────────`);
  console.log(`  Server: http://localhost:${PORT}`);
  console.log(`  Seeding demo data...`);
  await seedDemoData();
  initSitesSchema();
  initDwSchema();
  console.log(`  Ready. Breach fetch every 6h. Dark web collection every 30m.\n`);
  // Kick off an initial dark web collection without blocking startup
  setImmediate(() => {
    runCollection().catch(err => console.error('[DarkWeb] Initial collection error:', err.message));
  });
});
