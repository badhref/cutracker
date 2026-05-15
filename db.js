// Uses Node.js built-in SQLite (available since Node 22.5, stable in Node 24)
const { DatabaseSync } = require('node:sqlite');
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'breaches.db');

let db;

function getDb() {
  if (!db) {
    db = new DatabaseSync(DB_PATH);
    db.exec('PRAGMA journal_mode = WAL');
    db.exec('PRAGMA foreign_keys = ON');
    initSchema();
  }
  return db;
}

function initSchema() {
  getDb().exec(`
    CREATE TABLE IF NOT EXISTS breaches (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      external_id TEXT UNIQUE,
      organization TEXT NOT NULL,
      organization_type TEXT DEFAULT 'credit_union',
      state TEXT,
      breach_date TEXT,
      discovery_date TEXT,
      notification_date TEXT,
      breach_type TEXT,
      attack_vector TEXT,
      records_affected INTEGER,
      data_types TEXT,
      source TEXT NOT NULL,
      source_url TEXT,
      status TEXT DEFAULT 'active',
      description TEXT,
      is_manual INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS fetch_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source TEXT NOT NULL,
      fetched_at TEXT DEFAULT (datetime('now')),
      records_found INTEGER DEFAULT 0,
      records_new INTEGER DEFAULT 0,
      status TEXT DEFAULT 'success',
      error TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_breaches_org ON breaches(organization);
    CREATE INDEX IF NOT EXISTS idx_breaches_source ON breaches(source);
    CREATE INDEX IF NOT EXISTS idx_breaches_breach_date ON breaches(breach_date);
    CREATE INDEX IF NOT EXISTS idx_breaches_state ON breaches(state);
  `);
}

// ── Breach CRUD ────────────────────────────────────────────────────────────────

function upsertBreach(breach) {
  const db = getDb();

  const existing = breach.external_id
    ? db.prepare('SELECT id FROM breaches WHERE external_id = ?').get(breach.external_id)
    : null;

  if (existing) {
    db.prepare(`
      UPDATE breaches SET
        organization = ?, state = ?, breach_date = ?, discovery_date = ?,
        notification_date = ?, breach_type = ?, attack_vector = ?,
        records_affected = ?, data_types = ?, source_url = ?, status = ?,
        description = ?, updated_at = datetime('now')
      WHERE id = ?
    `).run(
      breach.organization, breach.state ?? null, breach.breach_date ?? null,
      breach.discovery_date ?? null, breach.notification_date ?? null,
      breach.breach_type ?? null, breach.attack_vector ?? null,
      breach.records_affected ?? null, breach.data_types ?? null,
      breach.source_url ?? null, breach.status ?? 'active',
      breach.description ?? null, existing.id
    );
    return { id: existing.id, isNew: false };
  }

  const result = db.prepare(`
    INSERT INTO breaches (external_id, organization, organization_type, state,
      breach_date, discovery_date, notification_date, breach_type, attack_vector,
      records_affected, data_types, source, source_url, status, description, is_manual)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    breach.external_id ?? null,
    breach.organization,
    breach.organization_type ?? 'credit_union',
    breach.state ?? null,
    breach.breach_date ?? null,
    breach.discovery_date ?? null,
    breach.notification_date ?? null,
    breach.breach_type ?? null,
    breach.attack_vector ?? null,
    breach.records_affected ?? null,
    breach.data_types ?? null,
    breach.source,
    breach.source_url ?? null,
    breach.status ?? 'active',
    breach.description ?? null,
    breach.is_manual ?? 0
  );

  return { id: result.lastInsertRowid, isNew: true };
}

function getBreaches(filters = {}) {
  const db = getDb();
  let sql = 'SELECT * FROM breaches WHERE 1=1';
  const params = [];

  if (filters.search) {
    sql += ' AND (organization LIKE ? OR description LIKE ? OR data_types LIKE ?)';
    const s = `%${filters.search}%`;
    params.push(s, s, s);
  }
  if (filters.source) {
    sql += ' AND source = ?';
    params.push(filters.source);
  }
  if (filters.state) {
    sql += ' AND state = ?';
    params.push(filters.state);
  }
  if (filters.breach_type) {
    sql += ' AND breach_type = ?';
    params.push(filters.breach_type);
  }
  if (filters.year) {
    sql += ' AND (breach_date LIKE ? OR notification_date LIKE ?)';
    params.push(`${filters.year}%`, `${filters.year}%`);
  }
  if (filters.min_records) {
    sql += ' AND records_affected >= ?';
    params.push(parseInt(filters.min_records));
  }

  sql += ' ORDER BY COALESCE(breach_date, notification_date, created_at) DESC';

  if (filters.limit) {
    sql += ' LIMIT ?';
    params.push(parseInt(filters.limit));
  }

  return db.prepare(sql).all(...params);
}

function getBreach(id) {
  return getDb().prepare('SELECT * FROM breaches WHERE id = ?').get(id);
}

function deleteBreach(id) {
  return getDb().prepare('DELETE FROM breaches WHERE id = ?').run(id);
}

function getStats() {
  const db = getDb();
  return {
    total: db.prepare('SELECT COUNT(*) as n FROM breaches').get().n,
    totalRecords: db.prepare('SELECT SUM(records_affected) as n FROM breaches').get().n || 0,
    bySource: db.prepare('SELECT source, COUNT(*) as count FROM breaches GROUP BY source ORDER BY count DESC').all(),
    byState: db.prepare('SELECT state, COUNT(*) as count FROM breaches WHERE state IS NOT NULL GROUP BY state ORDER BY count DESC').all(),
    byType: db.prepare('SELECT breach_type, COUNT(*) as count FROM breaches WHERE breach_type IS NOT NULL GROUP BY breach_type ORDER BY count DESC').all(),
    byYear: db.prepare(`
      SELECT substr(COALESCE(breach_date, notification_date, created_at), 1, 4) as year,
             COUNT(*) as count
      FROM breaches
      WHERE year IS NOT NULL AND year != ''
      GROUP BY year ORDER BY year DESC LIMIT 10
    `).all(),
    recentActivity: db.prepare('SELECT * FROM breaches ORDER BY COALESCE(notification_date, created_at) DESC LIMIT 10').all(),
  };
}

function logFetch(source, recordsFound, recordsNew, status, error) {
  getDb().prepare(`
    INSERT INTO fetch_log (source, records_found, records_new, status, error)
    VALUES (?, ?, ?, ?, ?)
  `).run(source, recordsFound, recordsNew, status, error ?? null);
}

function getFetchLog() {
  return getDb().prepare('SELECT * FROM fetch_log ORDER BY fetched_at DESC LIMIT 100').all();
}

// ── Suspected Sites Schema ─────────────────────────────────────────────────────

function initSitesSchema() {
  getDb().exec(`
    CREATE TABLE IF NOT EXISTS ss_suspected_sites (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      url TEXT NOT NULL,
      domain TEXT NOT NULL,
      normalized_url TEXT UNIQUE NOT NULL,
      source TEXT,
      first_seen TEXT DEFAULT (datetime('now')),
      last_seen TEXT DEFAULT (datetime('now')),
      risk_score INTEGER DEFAULT 0,
      risk_level TEXT DEFAULT 'watch',
      analyst_status TEXT DEFAULT 'new',
      title TEXT,
      meta_description TEXT,
      screenshot_path TEXT,
      favicon_hash TEXT,
      html_fingerprint TEXT,
      notes TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS ss_site_evidence (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id INTEGER NOT NULL REFERENCES ss_suspected_sites(id) ON DELETE CASCADE,
      evidence_type TEXT NOT NULL,
      evidence_value TEXT NOT NULL,
      source_page TEXT,
      confidence INTEGER DEFAULT 50,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS ss_site_ai_analysis (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id INTEGER NOT NULL REFERENCES ss_suspected_sites(id) ON DELETE CASCADE,
      model TEXT,
      analysis_json TEXT,
      summary TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS ss_related_sites (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id INTEGER NOT NULL REFERENCES ss_suspected_sites(id) ON DELETE CASCADE,
      related_site_id INTEGER NOT NULL REFERENCES ss_suspected_sites(id) ON DELETE CASCADE,
      similarity_score INTEGER DEFAULT 0,
      shared_indicators_json TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS ss_site_clusters (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cluster_name TEXT NOT NULL,
      description TEXT,
      confidence TEXT DEFAULT 'low',
      first_seen TEXT,
      last_seen TEXT,
      notes TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS ss_cluster_sites (
      cluster_id INTEGER NOT NULL REFERENCES ss_site_clusters(id) ON DELETE CASCADE,
      site_id INTEGER NOT NULL REFERENCES ss_suspected_sites(id) ON DELETE CASCADE,
      PRIMARY KEY (cluster_id, site_id)
    );

    CREATE TABLE IF NOT EXISTS ss_actor_profiles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      profile_name TEXT NOT NULL,
      description TEXT,
      confidence TEXT DEFAULT 'low',
      first_seen TEXT,
      last_seen TEXT,
      notes TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS ss_actor_profile_sites (
      actor_profile_id INTEGER NOT NULL REFERENCES ss_actor_profiles(id) ON DELETE CASCADE,
      site_id INTEGER NOT NULL REFERENCES ss_suspected_sites(id) ON DELETE CASCADE,
      PRIMARY KEY (actor_profile_id, site_id)
    );

    CREATE TABLE IF NOT EXISTS ss_site_audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id INTEGER NOT NULL REFERENCES ss_suspected_sites(id) ON DELETE CASCADE,
      action TEXT NOT NULL,
      details TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_ss_sites_domain ON ss_suspected_sites(domain);
    CREATE INDEX IF NOT EXISTS idx_ss_sites_risk_score ON ss_suspected_sites(risk_score);
    CREATE INDEX IF NOT EXISTS idx_ss_sites_risk_level ON ss_suspected_sites(risk_level);
    CREATE INDEX IF NOT EXISTS idx_ss_sites_analyst_status ON ss_suspected_sites(analyst_status);
    CREATE INDEX IF NOT EXISTS idx_ss_evidence_site ON ss_site_evidence(site_id);
    CREATE INDEX IF NOT EXISTS idx_ss_ai_analysis_site ON ss_site_ai_analysis(site_id);
    CREATE INDEX IF NOT EXISTS idx_ss_audit_site ON ss_site_audit_log(site_id);
  `);
}

// ── Suspected Sites CRUD ───────────────────────────────────────────────────────

function upsertSite(site) {
  const db = getDb();
  const existing = db.prepare(
    'SELECT id FROM ss_suspected_sites WHERE normalized_url = ?'
  ).get(site.normalized_url);

  if (existing) {
    db.prepare(`
      UPDATE ss_suspected_sites SET
        url = ?, domain = ?, source = ?, last_seen = datetime('now'),
        risk_score = ?, risk_level = ?, analyst_status = ?,
        title = ?, meta_description = ?, favicon_hash = ?,
        html_fingerprint = ?, notes = ?, updated_at = datetime('now')
      WHERE id = ?
    `).run(
      site.url, site.domain, site.source ?? null,
      site.risk_score ?? 0, site.risk_level ?? 'watch',
      site.analyst_status ?? 'new',
      site.title ?? null, site.meta_description ?? null,
      site.favicon_hash ?? null, site.html_fingerprint ?? null,
      site.notes ?? null, existing.id
    );
    return { id: existing.id, isNew: false };
  }

  const result = db.prepare(`
    INSERT INTO ss_suspected_sites (
      url, domain, normalized_url, source, risk_score, risk_level,
      analyst_status, title, meta_description, favicon_hash, html_fingerprint, notes
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    site.url, site.domain, site.normalized_url,
    site.source ?? null, site.risk_score ?? 0, site.risk_level ?? 'watch',
    site.analyst_status ?? 'new',
    site.title ?? null, site.meta_description ?? null,
    site.favicon_hash ?? null, site.html_fingerprint ?? null,
    site.notes ?? null
  );

  return { id: result.lastInsertRowid, isNew: true };
}

function getSites(filters = {}) {
  const db = getDb();
  let sql = 'SELECT * FROM ss_suspected_sites WHERE 1=1';
  const params = [];

  if (filters.search) {
    sql += ' AND (domain LIKE ? OR url LIKE ? OR title LIKE ?)';
    const s = `%${filters.search}%`;
    params.push(s, s, s);
  }
  if (filters.risk_level) {
    sql += ' AND risk_level = ?';
    params.push(filters.risk_level);
  }
  if (filters.analyst_status) {
    sql += ' AND analyst_status = ?';
    params.push(filters.analyst_status);
  }
  if (filters.source) {
    sql += ' AND source = ?';
    params.push(filters.source);
  }

  sql += ' ORDER BY risk_score DESC, created_at DESC';

  if (filters.limit) {
    sql += ' LIMIT ?';
    params.push(parseInt(filters.limit));
  }

  return db.prepare(sql).all(...params);
}

function getSite(id) {
  return getDb().prepare('SELECT * FROM ss_suspected_sites WHERE id = ?').get(id);
}

function deleteSite(id) {
  // Cascade is handled by FK ON DELETE CASCADE
  return getDb().prepare('DELETE FROM ss_suspected_sites WHERE id = ?').run(id);
}

function updateSiteScore(id, score, level) {
  return getDb().prepare(`
    UPDATE ss_suspected_sites SET risk_score = ?, risk_level = ?, updated_at = datetime('now')
    WHERE id = ?
  `).run(score, level, id);
}

function updateSiteStatus(id, status) {
  return getDb().prepare(`
    UPDATE ss_suspected_sites SET analyst_status = ?, updated_at = datetime('now')
    WHERE id = ?
  `).run(status, id);
}

function updateSiteAnalysis(id, fields) {
  const db = getDb();
  const sets = [];
  const params = [];

  if (fields.title !== undefined)            { sets.push('title = ?');            params.push(fields.title); }
  if (fields.meta_description !== undefined) { sets.push('meta_description = ?'); params.push(fields.meta_description); }
  if (fields.html_fingerprint !== undefined) { sets.push('html_fingerprint = ?'); params.push(fields.html_fingerprint); }
  if (fields.favicon_hash !== undefined)     { sets.push('favicon_hash = ?');     params.push(fields.favicon_hash); }
  if (fields.notes !== undefined)            { sets.push('notes = ?');            params.push(fields.notes); }

  if (!sets.length) return;

  sets.push("updated_at = datetime('now')");
  params.push(id);

  db.prepare(`UPDATE ss_suspected_sites SET ${sets.join(', ')} WHERE id = ?`).run(...params);
}

function addSiteEvidence(e) {
  return getDb().prepare(`
    INSERT INTO ss_site_evidence (site_id, evidence_type, evidence_value, source_page, confidence)
    VALUES (?, ?, ?, ?, ?)
  `).run(
    e.site_id, e.evidence_type, e.evidence_value,
    e.source_page ?? null, e.confidence ?? 50
  );
}

function getSiteEvidence(siteId) {
  return getDb().prepare(
    'SELECT * FROM ss_site_evidence WHERE site_id = ? ORDER BY created_at DESC'
  ).all(siteId);
}

function addAiAnalysis(a) {
  return getDb().prepare(`
    INSERT INTO ss_site_ai_analysis (site_id, model, analysis_json, summary)
    VALUES (?, ?, ?, ?)
  `).run(a.site_id, a.model ?? null, a.analysis_json ?? null, a.summary ?? null);
}

function getAiAnalysis(siteId) {
  return getDb().prepare(
    'SELECT * FROM ss_site_ai_analysis WHERE site_id = ? ORDER BY created_at DESC LIMIT 1'
  ).get(siteId);
}

function addRelatedSite(r) {
  return getDb().prepare(`
    INSERT INTO ss_related_sites (site_id, related_site_id, similarity_score, shared_indicators_json)
    VALUES (?, ?, ?, ?)
  `).run(
    r.site_id, r.related_site_id,
    r.similarity_score ?? 0,
    r.shared_indicators_json ?? null
  );
}

function getRelatedSites(siteId) {
  return getDb().prepare(`
    SELECT r.*, s.domain, s.url, s.risk_level, s.risk_score, s.analyst_status
    FROM ss_related_sites r
    JOIN ss_suspected_sites s ON s.id = r.related_site_id
    WHERE r.site_id = ?
    ORDER BY r.similarity_score DESC
  `).all(siteId);
}

function auditLog(siteId, action, details) {
  return getDb().prepare(`
    INSERT INTO ss_site_audit_log (site_id, action, details)
    VALUES (?, ?, ?)
  `).run(siteId, action, details ?? null);
}

function getSiteAuditLog(siteId) {
  return getDb().prepare(
    'SELECT * FROM ss_site_audit_log WHERE site_id = ? ORDER BY created_at DESC'
  ).all(siteId);
}

function getClusters() {
  return getDb().prepare('SELECT * FROM ss_site_clusters ORDER BY created_at DESC').all();
}

function getCluster(id) {
  const db = getDb();
  const cluster = db.prepare('SELECT * FROM ss_site_clusters WHERE id = ?').get(id);
  if (!cluster) return null;
  cluster.sites = db.prepare(`
    SELECT s.* FROM ss_suspected_sites s
    JOIN ss_cluster_sites cs ON cs.site_id = s.id
    WHERE cs.cluster_id = ?
    ORDER BY s.risk_score DESC
  `).all(id);
  return cluster;
}

function upsertCluster(c) {
  const db = getDb();
  if (c.id) {
    db.prepare(`
      UPDATE ss_site_clusters SET
        cluster_name = ?, description = ?, confidence = ?,
        first_seen = ?, last_seen = ?, notes = ?
      WHERE id = ?
    `).run(
      c.cluster_name, c.description ?? null, c.confidence ?? 'low',
      c.first_seen ?? null, c.last_seen ?? null, c.notes ?? null, c.id
    );
    return { id: c.id, isNew: false };
  }
  const result = db.prepare(`
    INSERT INTO ss_site_clusters (cluster_name, description, confidence, first_seen, last_seen, notes)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    c.cluster_name, c.description ?? null, c.confidence ?? 'low',
    c.first_seen ?? null, c.last_seen ?? null, c.notes ?? null
  );
  return { id: result.lastInsertRowid, isNew: true };
}

function addSiteToCluster(clusterId, siteId) {
  try {
    return getDb().prepare(
      'INSERT OR IGNORE INTO ss_cluster_sites (cluster_id, site_id) VALUES (?, ?)'
    ).run(clusterId, siteId);
  } catch (e) {
    return null;
  }
}

function getSiteStats() {
  const db = getDb();
  const total = db.prepare('SELECT COUNT(*) as n FROM ss_suspected_sites').get().n;

  // Current risk levels: known_legitimate, watch, unverified, suspicious, high
  // 'critical' is remapped to 'high' for legacy rows scored before the rewrite.
  const high = db.prepare(
    "SELECT COUNT(*) as n FROM ss_suspected_sites WHERE risk_level IN ('high', 'critical')"
  ).get().n;
  const suspicious = db.prepare(
    "SELECT COUNT(*) as n FROM ss_suspected_sites WHERE risk_level = 'suspicious'"
  ).get().n;
  const unverified = db.prepare(
    "SELECT COUNT(*) as n FROM ss_suspected_sites WHERE risk_level = 'unverified'"
  ).get().n;
  const watch = db.prepare(
    "SELECT COUNT(*) as n FROM ss_suspected_sites WHERE risk_level = 'watch'"
  ).get().n;
  const known_legitimate = db.prepare(
    "SELECT COUNT(*) as n FROM ss_suspected_sites WHERE risk_level = 'known_legitimate'"
  ).get().n;

  const newToday = db.prepare(
    "SELECT COUNT(*) as n FROM ss_suspected_sites WHERE date(created_at) = date('now')"
  ).get().n;
  const byStatus = db.prepare(
    'SELECT analyst_status, COUNT(*) as count FROM ss_suspected_sites GROUP BY analyst_status ORDER BY count DESC'
  ).all();
  const bySource = db.prepare(
    'SELECT source, COUNT(*) as count FROM ss_suspected_sites WHERE source IS NOT NULL GROUP BY source ORDER BY count DESC'
  ).all();

  return { total, high, suspicious, unverified, watch, known_legitimate, newToday, byStatus, bySource };
}

module.exports = {
  getDb, upsertBreach, getBreaches, getBreach, deleteBreach, getStats, logFetch, getFetchLog,
  initSitesSchema, upsertSite, getSites, getSite, deleteSite,
  updateSiteScore, updateSiteStatus, updateSiteAnalysis,
  addSiteEvidence, getSiteEvidence, addAiAnalysis, getAiAnalysis,
  addRelatedSite, getRelatedSites, auditLog, getSiteAuditLog,
  getClusters, getCluster, upsertCluster, addSiteToCluster, getSiteStats,
};
