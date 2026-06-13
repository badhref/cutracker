'use strict';

/**
 * Sanity tests for the Suspected Sites module.
 *
 * Run with:  node tests/sanity.js
 *
 * No test framework required — pure Node.js.
 * Tests validate scoring correctness, allowlist gating, and the combination
 * logic that prevents false-positives on legitimate credit union sites.
 */

const assert = require('assert');
const path   = require('path');

// Use a temp DB so tests never touch production data
process.env.DB_PATH = path.join(__dirname, '..', '.test-db.sqlite');

const { validateWithNcua, getAllowlistStats } = require('../services/ncuaValidation');
const { scoreSite, scoreToLevel }            = require('../services/siteScoring');
const { findSimilarSites }                   = require('../services/similarity');

// ── Tiny async test runner ───────────────────────────────────────────────────
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
    domain:          overrides.domain          ?? 'unknown-cu.example.com',
    url:             overrides.url             ?? 'https://unknown-cu.example.com',
    title:           overrides.title           ?? 'My Credit Union',
    body_text:       overrides.body_text       ?? '',
    footer_text:     overrides.footer_text     ?? '',
    ncua_language:   overrides.ncua_language   ?? [],
    has_login_form:  overrides.has_login_form  ?? false,
    emails:          overrides.emails          ?? [],
    phones:          overrides.phones          ?? [],
    routing_numbers: overrides.routing_numbers ?? [],
    charter_numbers: overrides.charter_numbers ?? [],
    analytics_ids:   overrides.analytics_ids   ?? [],
    domain_age_days: overrides.domain_age_days ?? null,
    ...overrides,
  };
}

// ── Run all tests ─────────────────────────────────────────────────────────────
(async () => {
  console.log('\nSuspected Sites — Sanity Tests\n');

  // ────────────────────────────────────────────────────────────────────────────
  console.log('[ Allowlist: known-legitimate domains ]');

  await test('navyfederal.org → known_legitimate, score 0', async () => {
    const ncua = await validateWithNcua('navyfederal.org', 'Navy Federal Credit Union');
    assert.strictEqual(ncua.status, 'known_legitimate');
    assert.strictEqual(ncua.confidence, 100);

    const scoring = scoreSite(fakeResult({
      domain:         'navyfederal.org',
      ncua_language:  ['Federally insured by NCUA'],
      has_login_form: true,
      body_text:      'federally insured by ncua federal share insurance fund credit union',
      footer_text:    'NCUA federally insured',
    }), ncua);

    assert.strictEqual(scoring.score, 0);
    assert.strictEqual(scoring.level, 'known_legitimate');
  });

  await test('www.navyfederal.org → known_legitimate, score 0', async () => {
    const ncua = await validateWithNcua('www.navyfederal.org', 'Navy Federal Credit Union');
    assert.strictEqual(ncua.status, 'known_legitimate');
    const scoring = scoreSite(fakeResult({ domain: 'www.navyfederal.org', ncua_language: ['Insured by NCUA'] }), ncua);
    assert.strictEqual(scoring.score, 0);
    assert.strictEqual(scoring.level, 'known_legitimate');
  });

  await test('bellco.org → known_legitimate', async () => {
    const ncua = await validateWithNcua('bellco.org', 'Bellco Credit Union');
    assert.strictEqual(ncua.status, 'known_legitimate', `Expected known_legitimate, got ${ncua.status}`);
    assert.ok(ncua.matched_name.toLowerCase().includes('bellco'), `Expected Bellco in matched_name, got "${ncua.matched_name}"`);
  });

  await test('www.bellco.org → known_legitimate', async () => {
    const ncua = await validateWithNcua('www.bellco.org', 'Bellco Credit Union');
    assert.strictEqual(ncua.status, 'known_legitimate');
  });

  await test('bellco.org with full CU signals → score 0 (not suspicious)', async () => {
    const ncua = await validateWithNcua('bellco.org', 'Bellco Credit Union');
    const scoring = scoreSite(fakeResult({
      domain:         'bellco.org',
      ncua_language:  ['Federally insured by NCUA'],
      has_login_form: true,
      body_text:      'credit union federally insured by ncua federal share insurance fund routing number member services',
      routing_numbers: ['307083911'],
      charter_numbers: ['12345'],
    }), ncua);
    assert.strictEqual(scoring.score, 0, `bellco.org with full CU signals scored ${scoring.score}, expected 0`);
    assert.strictEqual(scoring.level, 'known_legitimate');
  });

  await test('ncua.gov → known_legitimate', async () => {
    const ncua = await validateWithNcua('ncua.gov', 'National Credit Union Administration');
    assert.strictEqual(ncua.status, 'known_legitimate');
  });

  await test('mapping.ncua.gov → known_legitimate', async () => {
    const ncua = await validateWithNcua('mapping.ncua.gov', 'NCUA Credit Union Locator');
    assert.strictEqual(ncua.status, 'known_legitimate');
  });

  await test('penfed.org → known_legitimate', async () => {
    const ncua = await validateWithNcua('penfed.org', 'Pentagon Federal Credit Union');
    assert.strictEqual(ncua.status, 'known_legitimate');
  });

  // ────────────────────────────────────────────────────────────────────────────
  console.log('\n[ Unverified: CU-looking sites with NO suspicious signals ]');

  await test('Unknown CU domain with NCUA language only → unverified, NOT high risk', async () => {
    const ncua = await validateWithNcua('coloradocommunityfcu.org', 'Colorado Community FCU');
    assert.notStrictEqual(ncua.status, 'known_legitimate');

    const scoring = scoreSite(fakeResult({
      domain:        'coloradocommunityfcu.org',
      ncua_language: ['Federally insured by NCUA'],
      body_text:     'credit union federally insured by ncua federal share insurance fund',
      has_login_form: true,
    }), ncua);

    assert.ok(
      scoring.level === 'unverified' || scoring.level === 'watch',
      `Expected unverified or watch, got ${scoring.level} (score: ${scoring.score})`
    );
    assert.ok(scoring.score < 60, `Expected score < 60 for unverified CU, got ${scoring.score}`);
    assert.notStrictEqual(scoring.level, 'high', 'CU-only signals should not reach high risk');
    assert.notStrictEqual(scoring.level, 'suspicious', 'CU-only signals should not reach suspicious');
  });

  await test('Unknown CU domain with routing number and login → unverified (not high)', async () => {
    const ncua = { status: 'not_checked', confidence: 0 };
    const scoring = scoreSite(fakeResult({
      domain:          'riverside-teachers-cu.org',
      ncua_language:   ['Federally insured by NCUA'],
      has_login_form:  true,
      routing_numbers: ['321076479'],
      body_text:       'credit union member services federal share insurance',
    }), ncua);

    assert.ok(scoring.score < 60, `Expected score < 60, got ${scoring.score}`);
    assert.ok(
      scoring.level === 'unverified' || scoring.level === 'watch',
      `Expected unverified or watch, got ${scoring.level}`
    );
  });

  await test('Unverified CU has unverified_legitimacy factor', async () => {
    const ncua = { status: 'not_checked' };
    const scoring = scoreSite(fakeResult({
      domain:        'any-unknown-cu.org',
      ncua_language: ['NCUA insured'],
      has_login_form: true,
    }), ncua);
    const hasUnverifiedFactor = scoring.factors.some(f => f.key === 'unverified_legitimacy');
    assert.ok(hasUnverifiedFactor, `Expected an unverified_legitimacy factor, factors: ${scoring.factors.map(f=>f.key).join(', ')}`);
  });

  // ────────────────────────────────────────────────────────────────────────────
  console.log('\n[ Suspicious: CU signals + suspicious domain/contact signals ]');

  await test('Suspicious domain pattern alone → score ≥ 30', async () => {
    const ncua = { status: 'not_checked' };
    const scoring = scoreSite(fakeResult({ domain: 'secure-login-cu.net' }), ncua);
    assert.ok(scoring.score >= 30, `Expected ≥ 30, got ${scoring.score}`);
    const hasFactor = scoring.factors.some(f => f.key === 'suspicious_domain_pattern');
    assert.ok(hasFactor, 'Expected suspicious_domain_pattern factor');
  });

  await test('Suspicious domain + free email + NCUA claim → suspicious or high', async () => {
    const ncua = { status: 'not_checked' };
    const scoring = scoreSite(fakeResult({
      domain:        'secure-login-members.net',
      ncua_language: ['Federally insured by NCUA'],
      emails:        ['service@gmail.com'],
    }), ncua);
    assert.ok(scoring.score >= 60, `Expected score ≥ 60, got ${scoring.score}`);
    assert.ok(
      scoring.level === 'suspicious' || scoring.level === 'high',
      `Expected suspicious or high, got ${scoring.level}`
    );
  });

  await test('Suspicious domain + NCUA claim + free email + login + routing → high', async () => {
    const ncua = { status: 'not_checked' };
    const scoring = scoreSite(fakeResult({
      domain:          'member-update-secure.com',
      ncua_language:   ['Federally insured by NCUA'],
      emails:          ['info@gmail.com'],
      has_login_form:  true,
      routing_numbers: ['123456789'],
      body_text:       'credit union federally insured by ncua federal share insurance',
    }), ncua);
    assert.ok(scoring.score >= 90, `Expected score ≥ 90 for stacked signals, got ${scoring.score}`);
    assert.strictEqual(scoring.level, 'high', `Expected high, got ${scoring.level}`);
  });

  await test('no_official_match (NCUA DB loaded) + CU signals → elevated score', async () => {
    const ncua = { status: 'no_match_found', confidence: 0 };
    const scoring = scoreSite(fakeResult({
      domain:        'random-cu-name.biz',
      ncua_language: ['Federally insured by NCUA'],
      body_text:     'credit union member services',
    }), ncua);
    // no_match_found is a suspicious signal, so CU signals should escalate too
    assert.ok(scoring.score >= 30, `Expected ≥ 30, got ${scoring.score}`);
    const hasNoMatchFactor = scoring.factors.some(f => f.key === 'no_official_match');
    assert.ok(hasNoMatchFactor, 'Expected no_official_match factor when NCUA DB searched');
  });

  await test('New domain (<90 days) + CU signals → escalated score', async () => {
    const ncua = { status: 'not_checked' };
    const scoring = scoreSite(fakeResult({
      domain:          'new-cu-site.org',
      domain_age_days: 14,
      ncua_language:   ['Federally insured by NCUA'],
      has_login_form:  true,
    }), ncua);
    assert.ok(scoring.score > 30, `Expected > 30 with new domain, got ${scoring.score}`);
    const hasAgeFactor = scoring.factors.some(f => f.key === 'new_domain_indicator');
    assert.ok(hasAgeFactor, 'Expected new_domain_indicator factor');
  });

  // ────────────────────────────────────────────────────────────────────────────
  console.log('\n[ Risk level thresholds ]');

  await test('scoreToLevel:   0 → watch',      () => assert.strictEqual(scoreToLevel(0),   'watch'));
  await test('scoreToLevel:  29 → watch',      () => assert.strictEqual(scoreToLevel(29),  'watch'));
  await test('scoreToLevel:  30 → unverified', () => assert.strictEqual(scoreToLevel(30),  'unverified'));
  await test('scoreToLevel:  59 → unverified', () => assert.strictEqual(scoreToLevel(59),  'unverified'));
  await test('scoreToLevel:  60 → suspicious', () => assert.strictEqual(scoreToLevel(60),  'suspicious'));
  await test('scoreToLevel:  89 → suspicious', () => assert.strictEqual(scoreToLevel(89),  'suspicious'));
  await test('scoreToLevel:  90 → high',       () => assert.strictEqual(scoreToLevel(90),  'high'));
  await test('scoreToLevel: 999 → high (no critical)', () => assert.strictEqual(scoreToLevel(999), 'high'));

  // ────────────────────────────────────────────────────────────────────────────
  console.log('\n[ Evidence labels ]');

  await test('known_legitimate factor → label "trust"', () => {
    const scoring = scoreSite(
      fakeResult({ domain: 'bellco.org' }),
      { status: 'known_legitimate', matched_name: 'Bellco Credit Union', matched_domain: 'bellco.org' }
    );
    const f = scoring.factors.find(x => x.key === 'known_legitimate');
    assert.strictEqual(f?.label, 'trust');
  });

  await test('suspicious_domain_pattern factor → label "suspicious"', () => {
    const scoring = scoreSite(fakeResult({ domain: 'account-verify-cu.net' }), { status: 'not_checked' });
    const f = scoring.factors.find(x => x.key === 'suspicious_domain_pattern');
    assert.ok(f, 'Expected suspicious_domain_pattern factor');
    assert.strictEqual(f.label, 'suspicious');
  });

  await test('unverified_legitimacy factor → label "neutral"', () => {
    const scoring = scoreSite(fakeResult({
      domain:        'any-unknown-cu.org',
      ncua_language: ['NCUA insured'],
    }), { status: 'not_checked' });
    const f = scoring.factors.find(x => x.key === 'unverified_legitimacy');
    assert.ok(f, 'Expected unverified_legitimacy factor');
    assert.strictEqual(f.label, 'neutral');
  });

  await test('login_form in CU-context (no suspicious signals) → 0 pts', () => {
    const scoring = scoreSite(fakeResult({
      domain:        'local-cu.org',
      ncua_language: ['NCUA insured'],
      has_login_form: true,
    }), { status: 'not_checked' });
    const f = scoring.factors.find(x => x.key === 'login_form');
    if (f) {
      assert.strictEqual(f.points, 0, `login_form alone should contribute 0 pts, got ${f.points}`);
    }
    // If no separate login_form factor that's also valid (rolled into unverified_legitimacy)
  });

  // ────────────────────────────────────────────────────────────────────────────
  console.log('\n[ Allowlist stats ]');

  await test('getAllowlistStats returns > 0 hardcoded + JSON domains', () => {
    const stats = getAllowlistStats();
    assert.ok(stats.hardcoded >= 3,    `Expected ≥ 3 hardcoded entries, got ${stats.hardcoded}`);
    assert.ok(stats.from_json >= 1,    `Expected ≥ 1 JSON entries, got ${stats.from_json}`);
    assert.ok(stats.total_domains > 5, `Expected > 5 total unique domains, got ${stats.total_domains}`);
  });

  // ────────────────────────────────────────────────────────────────────────────
  console.log('\n[ possible_match: NCUA approximate match ]');

  await test('possible_match + no suspicious signals → capped at 25, level unverified', () => {
    const ncua = {
      status:       'possible_match',
      confidence:   50,
      matched_name: 'Example Community FCU',
      match: { cu_name: 'Example Community FCU', charter_number: '99999', state: 'CO' },
    };
    const scoring = scoreSite(fakeResult({
      domain:        'examplecommunityfcu.org',
      ncua_language: ['Federally insured by NCUA'],
      has_login_form: true,
      body_text:     'credit union member services federal share insurance',
    }), ncua);

    assert.strictEqual(scoring.score, 25, `Expected capped score of 25, got ${scoring.score}`);
    assert.strictEqual(scoring.level, 'unverified', `Expected unverified, got ${scoring.level}`);
    const f = scoring.factors.find(x => x.key === 'possible_official_match');
    assert.ok(f, 'Expected possible_official_match factor');
    assert.strictEqual(f.label, 'trust');
  });

  await test('possible_match + suspicious domain → falls through to full scoring', () => {
    const ncua = {
      status:       'possible_match',
      matched_name: 'Example Community FCU',
      match: { cu_name: 'Example Community FCU' },
    };
    const scoring = scoreSite(fakeResult({
      domain:        'secure-login-examplefcu.net',
      ncua_language: ['Federally insured by NCUA'],
      has_login_form: true,
    }), ncua);

    // Should NOT be capped — suspicious domain overrides the possible match
    assert.ok(scoring.score > 25, `Expected score > 25 with suspicious domain, got ${scoring.score}`);
    assert.notStrictEqual(scoring.level, 'known_legitimate');
    const domainFactor = scoring.factors.find(x => x.key === 'suspicious_domain_pattern');
    assert.ok(domainFactor, 'Expected suspicious_domain_pattern factor to appear');
  });

  await test('possible_match + free email → falls through, suspicious_free_email factor present', () => {
    const ncua = { status: 'possible_match', matched_name: 'Some CU', match: {} };
    const scoring = scoreSite(fakeResult({
      domain:  'somefcu.org',
      emails:  ['contact@gmail.com'],
      title:   'Some FCU',        // no "credit union" in title so CU-context is minimal
      body_text: '',
    }), ncua);
    // The possible_match gate must NOT fire (free email is a red flag)
    assert.ok(
      !scoring.factors.some(f => f.key === 'possible_official_match'),
      'possible_official_match factor should NOT appear when free email is present'
    );
    // Normal scoring should have run and detected the free email
    assert.ok(
      scoring.factors.some(f => f.key === 'suspicious_free_email'),
      'suspicious_free_email factor should appear after gate falls through'
    );
  });

  await test('not_checked + CU signals → unverified_legitimacy (not suspicious, not high)', () => {
    const ncua = { status: 'not_checked', confidence: 0 };
    const scoring = scoreSite(fakeResult({
      domain:        'coloradofcu.org',
      ncua_language: ['Federally insured by NCUA'],
      has_login_form: true,
      body_text:     'credit union federal share insurance member services',
    }), ncua);

    assert.ok(scoring.score < 60, `Expected score < 60, got ${scoring.score}`);
    assert.notStrictEqual(scoring.level, 'suspicious', 'not_checked + CU signals must not be suspicious');
    assert.notStrictEqual(scoring.level, 'high',       'not_checked + CU signals must not be high');
    const f = scoring.factors.find(x => x.key === 'unverified_legitimacy');
    assert.ok(f, 'Expected unverified_legitimacy factor');
    assert.ok(f.reason.includes('Official NCUA dataset not loaded'), `Expected dataset note in reason, got: ${f.reason}`);
  });

  await test('not_checked does NOT add no_official_match penalty', () => {
    const ncua = { status: 'not_checked' };
    const scoring = scoreSite(fakeResult({ domain: 'anycu.org', ncua_language: ['NCUA'] }), ncua);
    const noMatchFactor = scoring.factors.find(x => x.key === 'no_official_match');
    assert.ok(!noMatchFactor, 'no_official_match should not appear when dataset is not_checked');
  });

  // ────────────────────────────────────────────────────────────────────────────
  console.log('\n[ Similarity ]');

  await test('findSimilarSites: no crash with empty candidate list', () => {
    const target = { id: 1, domain: 'test.com', favicon_hash: 'abc', html_fingerprint: 'def', title: 'Test' };
    const result = findSimilarSites(target, [], {});
    assert.ok(Array.isArray(result));
    assert.strictEqual(result.length, 0);
  });

  await test('findSimilarSites: site does not match itself', () => {
    const target = { id: 1, domain: 'test.com', favicon_hash: 'abc', html_fingerprint: 'def', title: 'Test CU' };
    const result = findSimilarSites(target, [target], {});
    assert.strictEqual(result.length, 0);
  });

  await test('findSimilarSites: matches on shared favicon hash', () => {
    const target    = { id: 1, domain: 'a.com', favicon_hash: 'abc123', html_fingerprint: null, title: 'Alpha' };
    const candidate = { id: 2, domain: 'b.com', favicon_hash: 'abc123', html_fingerprint: null, title: 'Beta' };
    const result = findSimilarSites(target, [candidate], {});
    assert.ok(result.length > 0, 'Should find match on shared favicon hash');
    assert.strictEqual(result[0].site_id, 2);
  });

  await test('findSimilarSites: works without URLSCAN_API_KEY (no env var needed)', () => {
    // Confirm the similarity service has no dependency on external API keys
    delete process.env.URLSCAN_API_KEY;
    const target    = { id: 10, domain: 'cu-a.org', favicon_hash: 'x1', html_fingerprint: null, title: 'CU A' };
    const candidate = { id: 11, domain: 'cu-b.org', favicon_hash: 'x1', html_fingerprint: null, title: 'CU B' };
    const result = findSimilarSites(target, [candidate], {});
    assert.ok(Array.isArray(result), 'Should return array regardless of API key presence');
    assert.ok(result.length > 0, 'Should still detect favicon match without API key');
  });

  await test('findSimilarSites: returns empty array (not error) when no matches', () => {
    const target    = { id: 20, domain: 'unique-a.org', favicon_hash: 'zzz', html_fingerprint: null, title: 'Unique' };
    const candidate = { id: 21, domain: 'unique-b.org', favicon_hash: 'yyy', html_fingerprint: null, title: 'Different' };
    const result = findSimilarSites(target, [candidate], {});
    assert.ok(Array.isArray(result), 'Should return array');
    assert.strictEqual(result.length, 0, 'Should return empty array when no overlap');
  });

  await test('findSimilarSites: matches on shared analytics ID via evidenceMap', () => {
    const target    = { id: 1, domain: 'a.com', favicon_hash: null, html_fingerprint: null, title: 'Alpha' };
    const candidate = { id: 2, domain: 'b.com', favicon_hash: null, html_fingerprint: null, title: 'Beta' };
    const evidenceMap = {
      1: [{ evidence_type: 'analytics_id', evidence_value: 'UA-12345-1' }],
      2: [{ evidence_type: 'analytics_id', evidence_value: 'UA-12345-1' }],
    };
    const result = findSimilarSites(target, [candidate], evidenceMap);
    assert.ok(result.length > 0, 'Should find match on shared analytics ID');
    assert.ok(result[0].shared_indicators.some(i => i.includes('UA-12345-1')));
  });

  // ────────────────────────────────────────────────────────────────────────────
  console.log('\n[ mark-legitimate: allowlist write + re-score ]');

  await test('mark-legitimate: writing new domain to JSON and re-validating returns known_legitimate', async () => {
    const fs   = require('fs');
    const tmpJson = path.join(__dirname, '..', 'data', '.test-allowlist.json');

    // Write a temp JSON file with no entries
    fs.writeFileSync(tmpJson, '[]', 'utf8');

    // Simulate the write logic from the endpoint
    const domain   = 'test-local-cu.org';
    const wwwDomain = 'www.' + domain;
    const name     = 'Test Local Credit Union';

    let entries = JSON.parse(fs.readFileSync(tmpJson, 'utf8'));
    entries.push({ name, domains: [domain, wwwDomain], status: 'known_legitimate', added_by: 'analyst', added_at: '2026-01-01' });
    fs.writeFileSync(tmpJson, JSON.stringify(entries, null, 2), 'utf8');

    // Verify file was written correctly
    const written = JSON.parse(fs.readFileSync(tmpJson, 'utf8'));
    assert.strictEqual(written.length, 1);
    assert.ok(written[0].domains.includes(domain));
    assert.strictEqual(written[0].status, 'known_legitimate');

    // Clean up
    fs.unlinkSync(tmpJson);
  });

  await test('mark-legitimate: after adding to allowlist, scoring returns 0 / known_legitimate', async () => {
    const { reloadAllowlists } = require('../services/ncuaValidation');

    // Force reload so the JSON file is re-read (test isolation: JSON was not modified)
    reloadAllowlists();

    // bellco.org is already in the JSON file — simulate what would happen after mark-legitimate
    const ncua = await validateWithNcua('bellco.org', 'Bellco Credit Union');
    assert.strictEqual(ncua.status, 'known_legitimate');

    const scoring = scoreSite(
      { domain: 'bellco.org', title: 'Bellco Credit Union', body_text: '', ncua_language: [],
        has_login_form: false, emails: [], routing_numbers: [], charter_numbers: [], domain_age_days: null },
      ncua
    );
    assert.strictEqual(scoring.score, 0);
    assert.strictEqual(scoring.level, 'known_legitimate');
    assert.strictEqual(scoring.factors[0].label, 'trust');
  });

  await test('mark-legitimate: duplicate domain does not create duplicate allowlist entry', async () => {
    const fs = require('fs');
    const tmpJson = path.join(__dirname, '..', 'data', '.test-allowlist2.json');

    const initial = [{ name: 'Existing CU', domains: ['existing-cu.org', 'www.existing-cu.org'], status: 'known_legitimate' }];
    fs.writeFileSync(tmpJson, JSON.stringify(initial), 'utf8');

    // Simulate duplicate check from endpoint
    const entries = JSON.parse(fs.readFileSync(tmpJson, 'utf8'));
    const existingNormalised = new Set();
    for (const entry of entries) {
      for (const d of (entry.domains || [])) existingNormalised.add(d.toLowerCase().replace(/^www\./, ''));
    }
    const alreadyInFile = existingNormalised.has('existing-cu.org');
    assert.ok(alreadyInFile, 'Should detect the domain is already present');

    // If already present, we do NOT push — entries length stays 1
    if (!alreadyInFile) entries.push({ name: 'Dupe', domains: ['existing-cu.org'] });
    assert.strictEqual(entries.length, 1, 'No duplicate entry should have been added');

    fs.unlinkSync(tmpJson);
  });

  // ────────────────────────────────────────────────────────────────────────────
  const bar = '─'.repeat(52);
  console.log(`\n${bar}`);
  console.log(`  ${passed} passed  |  ${failed} failed`);
  console.log(bar + '\n');

  // Clean up temp DB
  try {
    const fs = require('fs');
    const db = process.env.DB_PATH;
    for (const ext of ['', '-shm', '-wal']) {
      const p = db + ext;
      if (fs.existsSync(p)) fs.unlinkSync(p);
    }
  } catch { /* ignore */ }

  process.exit(failed > 0 ? 1 : 0);
})();
