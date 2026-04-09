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

module.exports = { getDb, upsertBreach, getBreaches, getBreach, deleteBreach, getStats, logFetch, getFetchLog };
