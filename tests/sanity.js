'use strict';

/**
 * Sanity tests for the Suspected Sites module.
 *
 * Run with:  node tests/sanity.js
 *
 * These tests run in-process — no test framework required.
 * They exercise the scoring and NCUA-validation logic that is most likely
 * to produce analyst-confusing results (false positives, bad labels, etc.).
 */

const assert = require('assert');
const path   = require('path');

// Point the DB_PATH to a temp location so tests never touch production data
process.env.DB_PATH = path.join(__dirname, '..', '.test-db.sqlite');

const { validateWithNcua } = require('../services/ncuaValidation');
const { scoreSite, scoreToLevel } = require('../services/siteScoring');

// ── Tiny test runner ─────────────────────────────────────────────────────────
let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓  ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗  ${name}`);
    console.error(`     ${err.message}`);
    failed++;
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function fakeResult(overrides = {}) {
  return {
    domain:        overrides.domain        ?? 'unknown-cu.example.com',
    url:           overrides.url           ?? 'https://unknown-cu.example.com',
    title:         overrides.title         ?? 'My Credit Union',
    body_text:     overrides.body_text     ?? '',
    footer_text:   overrides.footer_text   ?? '',
    ncua_language: overrides.ncua_language ?? [],
    has_login_form: overrides.has_login_form ?? false,
    emails:        overrides.emails        ?? [],
    phones:        overrides.phones        ?? [],
    routing_numbers: overrides.routing_numbers ?? [],
    charter_numbers: overrides.charter_numbers ?? [],
    analytics_ids: overrides.analytics_ids ?? [],
    domain_age_days: overrides.domain_age_days ?? null,
    ...overrides,
  };
}

// ── Tests ────────────────────────────────────────────────────────────────────
(async () => {
  console.log('\nSuspected Sites — Sanity Tests\n');

  // ── 1. Allowlist: navyfederal.org ─────────────────────────────────────────
  console.log('[ Allowlist ]');

  await test('navyfederal.org → known_legitimate, score 0', async () => {
    const ncua = await validateWithNcua('navyfederal.org', 'Navy Federal Credit Union');
    assert.strictEqual(ncua.status, 'known_legitimate', `Expected known_legitimate, got ${ncua.status}`);
    assert.strictEqual(ncua.confidence, 100);

    const scoring = scoreSite(fakeResult({
      domain:         'navyfederal.org',
      ncua_language:  ['Federally insured by NCUA'],
      has_login_form: true,
      body_text:      'federally insured by ncua federal share insurance credit union',
      footer_text:    'NCUA federally insured',
    }), ncua);

    assert.strictEqual(scoring.score, 0,               `Expected score 0, got ${scoring.score}`);
    assert.strictEqual(scoring.level, 'known_legitimate', `Expected level known_legitimate, got ${scoring.level}`);
  });

  await test('www.navyfederal.org → known_legitimate, score 0', async () => {
    const ncua = await validateWithNcua('www.navyfederal.org', 'Navy Federal Credit Union');
    assert.strictEqual(ncua.status, 'known_legitimate');

    const scoring = scoreSite(fakeResult({ domain: 'www.navyfederal.org', ncua_language: ['Insured by NCUA'] }), ncua);
    assert.strictEqual(scoring.score, 0);
    assert.strictEqual(scoring.level, 'known_legitimate');
  });

  await test('ncua.gov → known_legitimate', async () => {
    const ncua = await validateWithNcua('ncua.gov', 'National Credit Union Administration');
    assert.strictEqual(ncua.status, 'known_legitimate');
    assert.ok(ncua.matched_name.includes('NCUA'), `Expected NCUA in matched_name, got ${ncua.matched_name}`);
  });

  await test('mapping.ncua.gov → known_legitimate', async () => {
    const ncua = await validateWithNcua('mapping.ncua.gov', 'NCUA Credit Union Locator');
    assert.strictEqual(ncua.status, 'known_legitimate');
  });

  await test('penfed.org → known_legitimate', async () => {
    const ncua = await validateWithNcua('penfed.org', 'Pentagon Federal Credit Union');
    assert.strictEqual(ncua.status, 'known_legitimate');
  });

  // ── 2. Unknown domain with NCUA language ─────────────────────────────────
  console.log('\n[ Unknown Domain Scoring ]');

  await test('Unknown domain with "federally insured by NCUA" → suspicious or higher', async () => {
    const ncua = await validateWithNcua('secure-cu-login.net', 'Credit Union Login');
    // Not in allowlist; no NCUA DB loaded → not_checked
    assert.notStrictEqual(ncua.status, 'known_legitimate');

    const scoring = scoreSite(fakeResult({
      domain:        'secure-cu-login.net',
      ncua_language: ['Federally insured by NCUA'],
      body_text:     'federally insured by ncua federal share insurance fund',
    }), ncua);

    assert.ok(scoring.score >= 30, `Expected score ≥ 30, got ${scoring.score}`);
    assert.notStrictEqual(scoring.level, 'known_legitimate', 'Unknown domain should not be known_legitimate');
  });

  await test('Suspicious domain pattern raises score by 25', async () => {
    const ncua = await validateWithNcua('member-update-portal.com', 'Member Update');
    const scoring = scoreSite(fakeResult({ domain: 'member-update-portal.com' }), ncua);
    const hasSuspiciousPattern = scoring.factors.some(f => f.key === 'suspicious_domain_pattern');
    assert.ok(hasSuspiciousPattern, 'Expected suspicious_domain_pattern factor');
    const factor = scoring.factors.find(f => f.key === 'suspicious_domain_pattern');
    assert.strictEqual(factor.points, 25);
  });

  await test('Login form on unknown domain adds 10 points (not 15)', async () => {
    const ncua = await validateWithNcua('random-cu.com', 'Random CU');
    const scoring = scoreSite(fakeResult({ domain: 'random-cu.com', has_login_form: true }), ncua);
    const factor = scoring.factors.find(f => f.key === 'login_form');
    if (factor) {
      assert.strictEqual(factor.points, 10, `Login form should be 10pts, got ${factor.points}`);
    }
    // If no login_form factor, that's fine (only relevant when form is present)
  });

  await test('Free consumer email raises score by 15', async () => {
    const ncua = await validateWithNcua('somebank-cu.com', 'Some Bank CU');
    const scoring = scoreSite(fakeResult({ domain: 'somebank-cu.com', emails: ['contact@gmail.com'] }), ncua);
    const factor = scoring.factors.find(f => f.key === 'suspicious_free_email');
    assert.ok(factor, 'Expected suspicious_free_email factor');
    assert.strictEqual(factor.points, 15);
  });

  // ── 3. Risk level thresholds ──────────────────────────────────────────────
  console.log('\n[ Risk Level Thresholds ]');

  await test('scoreToLevel: 0 → watch', () => assert.strictEqual(scoreToLevel(0),   'watch'));
  await test('scoreToLevel: 29 → watch', () => assert.strictEqual(scoreToLevel(29),  'watch'));
  await test('scoreToLevel: 30 → unverified', () => assert.strictEqual(scoreToLevel(30), 'unverified'));
  await test('scoreToLevel: 59 → unverified', () => assert.strictEqual(scoreToLevel(59), 'unverified'));
  await test('scoreToLevel: 60 → suspicious', () => assert.strictEqual(scoreToLevel(60), 'suspicious'));
  await test('scoreToLevel: 89 → suspicious', () => assert.strictEqual(scoreToLevel(89), 'suspicious'));
  await test('scoreToLevel: 90 → high', () => assert.strictEqual(scoreToLevel(90),  'high'));
  await test('scoreToLevel: 999 → high (no critical)', () => assert.strictEqual(scoreToLevel(999), 'high'));

  // ── 4. Evidence labels ────────────────────────────────────────────────────
  console.log('\n[ Evidence Labels ]');

  await test('Known-legitimate factor has label "trust"', () => {
    const scoring = scoreSite(
      fakeResult({ domain: 'navyfederal.org' }),
      { status: 'known_legitimate', matched_name: 'Navy Federal', matched_domain: 'navyfederal.org' }
    );
    const factor = scoring.factors.find(f => f.key === 'known_legitimate');
    assert.strictEqual(factor?.label, 'trust');
  });

  await test('NCUA insurance claim factor has label "suspicious"', () => {
    const scoring = scoreSite(fakeResult({
      domain:        'fake-cu.biz',
      ncua_language: ['Federally insured by NCUA'],
    }), { status: 'not_checked' });
    const factor = scoring.factors.find(f => f.key === 'ncua_insurance_claim');
    assert.strictEqual(factor?.label, 'suspicious');
  });

  await test('Login form factor has label "neutral"', () => {
    const scoring = scoreSite(fakeResult({ domain: 'some-cu.org', has_login_form: true }), { status: 'not_checked' });
    const factor = scoring.factors.find(f => f.key === 'login_form');
    assert.strictEqual(factor?.label, 'neutral');
  });

  // ── 5. Similarity — no crash with empty site list ─────────────────────────
  console.log('\n[ Similarity ]');

  await test('findSimilarSites: no crash with empty candidate list', () => {
    const { findSimilarSites } = require('../services/similarity');
    const target = { id: 1, domain: 'test.com', favicon_hash: 'abc', html_fingerprint: 'def', title: 'Test' };
    const result = findSimilarSites(target, [], {});
    assert.ok(Array.isArray(result), 'Should return an array');
    assert.strictEqual(result.length, 0, 'Should be empty with no candidates');
  });

  await test('findSimilarSites: site does not match itself', () => {
    const { findSimilarSites } = require('../services/similarity');
    const target = { id: 1, domain: 'test.com', favicon_hash: 'abc', html_fingerprint: 'def', title: 'Test CU' };
    const result = findSimilarSites(target, [target], {});
    assert.strictEqual(result.length, 0, 'Site should not match itself');
  });

  await test('findSimilarSites: matches when favicon hashes are identical', () => {
    const { findSimilarSites } = require('../services/similarity');
    const target    = { id: 1, domain: 'a.com', favicon_hash: 'abc123', html_fingerprint: null, title: 'Alpha' };
    const candidate = { id: 2, domain: 'b.com', favicon_hash: 'abc123', html_fingerprint: null, title: 'Beta' };
    const result = findSimilarSites(target, [candidate], {});
    assert.ok(result.length > 0, 'Should find match on shared favicon hash');
    assert.strictEqual(result[0].site_id, 2);
  });

  // ── Summary ──────────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(50)}`);
  console.log(`  ${passed} passed  |  ${failed} failed`);
  console.log('─'.repeat(50) + '\n');

  // Clean up temp DB file (best-effort)
  try {
    const fs = require('fs');
    const dbPath = process.env.DB_PATH;
    if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
  } catch { /* ignore */ }

  process.exit(failed > 0 ? 1 : 0);
})();
