'use strict';

const path = require('path');
const fs   = require('fs');
const { getDb } = require('../db');

// ── Hardcoded allowlist (always trusted, regardless of file / DB state) ───────
// These are immutable — do NOT remove an entry without analyst review.
const HARDCODED_ALLOWLIST = [
  {
    name:    'Navy Federal Credit Union',
    domains: ['navyfederal.org', 'www.navyfederal.org'],
  },
  {
    name:    'Bellco Credit Union',
    domains: ['bellco.org', 'www.bellco.org'],
  },
  {
    name:    'National Credit Union Administration (NCUA)',
    domains: ['ncua.gov', 'www.ncua.gov', 'mapping.ncua.gov', 'mycreditunion.gov'],
  },
];

// ── JSON allowlist loader ─────────────────────────────────────────────────────
// Reads data/official_credit_union_domains.json — add entries there to expand
// the known-legitimate list without touching code.
let _jsonDomains = null;
function loadJsonAllowlist() {
  if (_jsonDomains !== null) return _jsonDomains;
  try {
    const filePath = path.join(__dirname, '..', 'data', 'official_credit_union_domains.json');
    const raw = fs.readFileSync(filePath, 'utf8');
    _jsonDomains = JSON.parse(raw);
  } catch {
    _jsonDomains = [];
  }
  return _jsonDomains;
}

// ── CSV allowlist loader ──────────────────────────────────────────────────────
// Reads data/official_credit_union_domains.csv — one row per domain.
// Expected columns (header row required): name, domain, charter_number, city, state, source
// Lines starting with # are treated as comments.
// This file is designed for bulk imports from the NCUA FOICU.txt export.
let _csvDomains = null;
function loadCsvAllowlist() {
  if (_csvDomains !== null) return _csvDomains;
  try {
    const filePath = path.join(__dirname, '..', 'data', 'official_credit_union_domains.csv');
    if (!fs.existsSync(filePath)) { _csvDomains = []; return _csvDomains; }

    const lines = fs.readFileSync(filePath, 'utf8')
      .split(/\r?\n/)
      .map(l => l.trim())
      .filter(l => l.length > 0 && !l.startsWith('#'));

    if (lines.length < 2) { _csvDomains = []; return _csvDomains; }

    const headers = parseCSVLine(lines[0]).map(h => h.toLowerCase());
    const nameIdx   = headers.indexOf('name');
    const domainIdx = headers.indexOf('domain');

    if (nameIdx === -1 || domainIdx === -1) { _csvDomains = []; return _csvDomains; }

    const results = [];
    for (let i = 1; i < lines.length; i++) {
      const cols = parseCSVLine(lines[i]);
      const domain = (cols[domainIdx] || '').trim();
      if (!domain) continue;
      results.push({
        name:    (cols[nameIdx] || 'Unknown Institution').trim(),
        domains: [domain],
      });
    }
    _csvDomains = results;
  } catch {
    _csvDomains = [];
  }
  return _csvDomains;
}

// ── Minimal RFC-4180 CSV line parser ─────────────────────────────────────────
function parseCSVLine(line) {
  const fields = [];
  let field    = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') { field += '"'; i++; } // escaped quote
      else { inQuotes = !inQuotes; }
    } else if (ch === ',' && !inQuotes) {
      fields.push(field.trim());
      field = '';
    } else {
      field += ch;
    }
  }
  fields.push(field.trim());
  return fields;
}

// ── Normalize domain for comparison ──────────────────────────────────────────
function normalizeDomain(domain) {
  return (domain || '').toLowerCase().replace(/^www\./, '').trim();
}

// ── Check all allowlist sources ───────────────────────────────────────────────
function checkAllowlist(domain) {
  const normalized = normalizeDomain(domain);
  const raw        = (domain || '').toLowerCase();

  const allSources = [
    ...HARDCODED_ALLOWLIST,
    ...loadJsonAllowlist(),
    ...loadCsvAllowlist(),
  ];

  for (const entry of allSources) {
    for (const d of (entry.domains || [])) {
      if (normalizeDomain(d) === normalized || d.toLowerCase() === raw) {
        return { matched: true, name: entry.name, domain: d };
      }
    }
  }
  return { matched: false };
}

// ── Expose for tests / admin routes ──────────────────────────────────────────
// Returns total count of distinct domains across all three allowlist sources.
function getAllowlistStats() {
  const allSources = [
    ...HARDCODED_ALLOWLIST,
    ...loadJsonAllowlist(),
    ...loadCsvAllowlist(),
  ];
  const domainSet = new Set();
  for (const entry of allSources) {
    for (const d of (entry.domains || [])) domainSet.add(normalizeDomain(d));
  }
  return {
    total_entries:  allSources.length,
    total_domains:  domainSet.size,
    hardcoded:      HARDCODED_ALLOWLIST.length,
    from_json:      loadJsonAllowlist().length,
    from_csv:       loadCsvAllowlist().length,
  };
}

// ── Invalidate caches (call after a live CSV/JSON update) ─────────────────────
function reloadAllowlists() {
  _jsonDomains = null;
  _csvDomains  = null;
}

// ── NCUA Validation ────────────────────────────────────────────────────────────
// Returns: { status, confidence, reason, matched_domain, matched_name, match }
//
// status values:
//   'known_legitimate'      — in allowlist; scoring must return 0
//   'unverified_legitimacy' — looks like a CU but reference data unavailable
//   'possible_match'        — found in NCUA DB; analyst review required
//   'no_match_found'        — DB searched, nothing found
//   'not_checked'           — NCUA DB not loaded
//   'error'                 — unexpected error
// ──────────────────────────────────────────────────────────────────────────────
async function validateWithNcua(domain, title) {
  try {
    // ── Step 1: Allowlist check (always runs, highest priority) ──────────────
    const hit = checkAllowlist(domain);
    if (hit.matched) {
      return {
        status:         'known_legitimate',
        confidence:     100,
        reason:         `Domain "${domain}" is in the verified allowlist of known-legitimate credit union or regulatory sites. Risk scoring is suppressed.`,
        matched_domain: hit.domain,
        matched_name:   hit.name,
        match:          null,
      };
    }

    // ── Step 2: Optional NCUA institution DB lookup ───────────────────────────
    const db = getDb();

    let tableExists = false;
    try {
      const row = db.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='ncua_institutions'"
      ).get();
      tableExists = !!row;
    } catch {
      tableExists = false;
    }

    if (!tableExists) {
      return {
        status:         'not_checked',
        confidence:     0,
        reason:         'Official NCUA reference dataset not loaded. Import NCUA data to enable institution lookup. Unable to confirm or deny legitimacy.',
        matched_domain: null,
        matched_name:   null,
        match:          null,
      };
    }

    const countRow = db.prepare('SELECT COUNT(*) as n FROM ncua_institutions').get();
    if (!countRow || countRow.n === 0) {
      return {
        status:         'not_checked',
        confidence:     0,
        reason:         'Official NCUA reference dataset is empty. Import NCUA data to enable institution lookup.',
        matched_domain: null,
        matched_name:   null,
        match:          null,
      };
    }

    const domainBase = (domain || '').replace(/^www\./, '').split('.')[0].toLowerCase();
    const titleWords = (title  || '').toLowerCase().split(/\s+/).filter(w => w.length > 3);
    let match = null;

    if (domainBase) {
      match = db.prepare(
        "SELECT * FROM ncua_institutions WHERE LOWER(website) LIKE ? OR LOWER(cu_name) LIKE ? LIMIT 1"
      ).get(`%${domainBase}%`, `%${domainBase}%`);
    }
    if (!match && titleWords.length > 0) {
      for (const word of titleWords) {
        match = db.prepare(
          "SELECT * FROM ncua_institutions WHERE LOWER(cu_name) LIKE ? LIMIT 1"
        ).get(`%${word}%`);
        if (match) break;
      }
    }

    if (match) {
      return {
        status:         'possible_match',
        confidence:     50,
        reason:         'A possible match was found in the NCUA institution dataset. Analyst verification is required — dataset matches are approximate.',
        matched_domain: match.website ?? null,
        matched_name:   match.cu_name ?? null,
        match: {
          charter_number: match.charter_number ?? null,
          cu_name:        match.cu_name        ?? null,
          city:           match.city            ?? null,
          state:          match.state           ?? null,
          website:        match.website         ?? null,
        },
      };
    }

    return {
      status:         'no_match_found',
      confidence:     0,
      reason:         'No matching institution found in the NCUA dataset. A real credit union should be registered with the NCUA. Consider this a moderate risk signal when combined with other indicators.',
      matched_domain: null,
      matched_name:   null,
      match:          null,
    };

  } catch (err) {
    return {
      status:         'error',
      confidence:     0,
      reason:         `Validation check encountered an error: ${err.message}`,
      matched_domain: null,
      matched_name:   null,
      match:          null,
    };
  }
}

module.exports = { validateWithNcua, getAllowlistStats, reloadAllowlists };
