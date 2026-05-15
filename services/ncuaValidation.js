'use strict';

const { getDb } = require('../db');

// ── NCUA Validation ────────────────────────────────────────────────────────────
// Checks whether an official NCUA reference dataset has been loaded into the
// database. If not, the function returns an explicit "not_checked" status rather
// than falsely claiming there is no match.
async function validateWithNcua(domain, title) {
  try {
    const db = getDb();

    // Check whether an ncua_institutions table exists and has rows
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
        status: 'not_checked',
        reason: 'Official NCUA reference dataset not loaded. Import NCUA data to enable validation.',
        match: null,
      };
    }

    // Check row count
    const countRow = db.prepare('SELECT COUNT(*) as n FROM ncua_institutions').get();
    if (!countRow || countRow.n === 0) {
      return {
        status: 'not_checked',
        reason: 'Official NCUA reference dataset not loaded. Import NCUA data to enable validation.',
        match: null,
      };
    }

    // Search for a matching institution by domain or name fragment
    const domainBase = (domain || '').replace(/^www\./, '').split('.')[0].toLowerCase();
    const titleWords = (title || '').toLowerCase().split(/\s+/).filter(w => w.length > 3);

    let match = null;

    // Try domain-based match
    if (domainBase) {
      match = db.prepare(
        "SELECT * FROM ncua_institutions WHERE LOWER(website) LIKE ? OR LOWER(cu_name) LIKE ? LIMIT 1"
      ).get(`%${domainBase}%`, `%${domainBase}%`);
    }

    // Try title-based match if no domain match
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
        status: 'possible_match',
        reason: 'A possible match was found in the NCUA institution dataset. Analyst verification required.',
        match: {
          charter_number: match.charter_number ?? null,
          cu_name: match.cu_name ?? null,
          city: match.city ?? null,
          state: match.state ?? null,
          website: match.website ?? null,
        },
      };
    }

    return {
      status: 'no_match_found',
      reason: 'No matching institution found in the loaded NCUA dataset. This does not conclusively confirm the site is fraudulent — dataset may be incomplete.',
      match: null,
    };
  } catch (err) {
    return {
      status: 'error',
      reason: `Validation check encountered an error: ${err.message}`,
      match: null,
    };
  }
}

module.exports = { validateWithNcua };
