'use strict';

const path = require('path');
const fs   = require('fs');
const { getDb } = require('../db');

// ── Hardcoded allowlist (always trusted, regardless of DB state) ──────────────
// These entries are immutable — do NOT remove without analyst review.
const HARDCODED_ALLOWLIST = [
  {
    name: 'Navy Federal Credit Union',
    domains: ['navyfederal.org', 'www.navyfederal.org'],
  },
  {
    name: 'National Credit Union Administration (NCUA)',
    domains: ['ncua.gov', 'www.ncua.gov', 'mapping.ncua.gov', 'mycreditunion.gov'],
  },
];

// ── Load JSON-file allowlist (extensible by analysts) ─────────────────────────
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

// ── Normalize domain for comparison ──────────────────────────────────────────
function normalizeDomain(domain) {
  return (domain || '').toLowerCase().replace(/^www\./, '').trim();
}

// ── Allowlist check ───────────────────────────────────────────────────────────
function checkAllowlist(domain) {
  const normalized = normalizeDomain(domain);
  const raw        = (domain || '').toLowerCase();

  // Hardcoded entries first
  for (const entry of HARDCODED_ALLOWLIST) {
    for (const d of entry.domains) {
      if (normalizeDomain(d) === normalized || d.toLowerCase() === raw) {
        return { matched: true, name: entry.name, domain: d };
      }
    }
  }

  // JSON-file entries
  for (const entry of loadJsonAllowlist()) {
    for (const d of (entry.domains || [])) {
      if (normalizeDomain(d) === normalized || d.toLowerCase() === raw) {
        return { matched: true, name: entry.name, domain: d };
      }
    }
  }

  return { matched: false };
}

// ── NCUA Validation ────────────────────────────────────────────────────────────
// Returns: { status, confidence, reason, matched_domain, matched_name, match }
//
// status values:
//   'known_legitimate' — domain is in the allowlist; scoring must return 0
//   'possible_match'   — found in NCUA DB; analyst review still required
//   'no_match_found'   — DB searched, nothing found
//   'not_checked'      — NCUA DB not loaded; unable to validate
//   'error'            — unexpected error during check
// ──────────────────────────────────────────────────────────────────────────────
async function validateWithNcua(domain, title) {
  try {
    // ── Step 1: Allowlist check (highest priority, always runs) ──────────────
    const allowlistHit = checkAllowlist(domain);
    if (allowlistHit.matched) {
      return {
        status:         'known_legitimate',
        confidence:     100,
        reason:         `Domain "${domain}" is a verified, known-legitimate credit union or regulatory site. Risk scoring is suppressed.`,
        matched_domain: allowlistHit.domain,
        matched_name:   allowlistHit.name,
        match:          null,
      };
    }

    // ── Step 2: NCUA institution DB lookup (optional) ─────────────────────────
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
        reason:         'Official NCUA reference dataset not loaded. Import NCUA data to enable institution lookup.',
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

    // Search by domain fragment, then by title keywords
    const domainBase = (domain || '').replace(/^www\./, '').split('.')[0].toLowerCase();
    const titleWords = (title || '').toLowerCase().split(/\s+/).filter(w => w.length > 3);

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
        reason:         'A possible match was found in the NCUA institution dataset. Analyst verification is required before drawing conclusions.',
        matched_domain: match.website ?? null,
        matched_name:   match.cu_name ?? null,
        match: {
          charter_number: match.charter_number ?? null,
          cu_name:        match.cu_name ?? null,
          city:           match.city ?? null,
          state:          match.state ?? null,
          website:        match.website ?? null,
        },
      };
    }

    return {
      status:         'no_match_found',
      confidence:     0,
      reason:         'No matching institution found in the NCUA dataset. This does not confirm fraud — the dataset may be incomplete or the domain may be new.',
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

module.exports = { validateWithNcua };
