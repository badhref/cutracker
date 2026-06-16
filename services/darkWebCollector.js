'use strict';

/**
 * Dark Web Collector
 *
 * READ-ONLY defensive CTI module. Never authenticates, posts, or interacts.
 * Uses clearnet proxies and public APIs for immediate intelligence.
 *
 * Active sources (no auth required):
 *   ransomware.live  — aggregates ransomware leak site victims (JSON API)
 *   URLhaus          — malware URL feed (abuse.ch API)
 *   MalwareBazaar    — malware sample feed (abuse.ch API)
 *   Ahmia            — clearnet dark web search engine (HTML scrape)
 *
 * Tor-required sources (.onion) are catalogued but skipped unless
 * TOR_PROXY env var is set (socks5h://127.0.0.1:9050).
 */

const axios   = require('axios');
const cheerio = require('cheerio');
const { extractIOCs, countIOCs } = require('./iocExtractor');
const db = require('../db');

// ── Financial / high-value keyword list ────────────────────────────────────────
const FINANCIAL_KEYWORDS = [
  'bank', 'credit union', 'fintech', 'payment processor', 'wire transfer',
  'ach', 'swift', 'citrix', 'vpn', 'okta', 'o365', 'office 365', 'zscaler',
  'customer database', 'admin access', 'domain admin', 'stealer logs',
  'initial access', 'rdp', 'ssh access', 'routing number', 'account number',
  'banking', 'financial institution', 'neobank', 'crypto exchange',
  'mortgage', 'loan servicer', 'insurance', 'brokerage',
];

// ── Category detection ─────────────────────────────────────────────────────────
const CATEGORY_RULES = [
  { cat: 'ransomware',      re: /ransomware|encrypt(?:ed|ion)|leak site|victim|ransom(?:ed|note)|extort/i },
  { cat: 'initial_access',  re: /initial.?access|rdp.?access|ssh.?access|citrix.?access|vpn.?access|selling.?access|access.?for.?sale/i },
  { cat: 'credentials',     re: /credential|combolist|combo.?list|account.?dump|password.?dump|stealer|infostealer/i },
  { cat: 'stealer_logs',    re: /stealer.?log|redline|vidar|raccoon|lumma|metastealer|aurora.?stealer/i },
  { cat: 'phishing',        re: /phish(?:ing|.?kit)|spear.?phish|credential.?harvest/i },
  { cat: 'malware',         re: /malware|rat\b|trojan|backdoor|\bc2\b|command.?and.?control|payload|botnet/i },
  { cat: 'financial_fraud', re: /carding|cc.?dump|fullz|bank.?account|wire.?fraud|money.?mule|ach.?fraud/i },
  { cat: 'carding',         re: /card.?dump|cvv\b|bin.?list|cc.?shop/i },
];

function detectCategory(text) {
  for (const { cat, re } of CATEGORY_RULES) {
    if (re.test(text || '')) return cat;
  }
  return 'other';
}

function detectKeywords(text) {
  const lower = (text || '').toLowerCase();
  return FINANCIAL_KEYWORDS.filter(kw => lower.includes(kw.toLowerCase()));
}

// ── Risk scoring ───────────────────────────────────────────────────────────────
function scoreContent({ category, text, iocCount, isNew, discoveredDate }) {
  let score = 0;
  const t = (text || '').toLowerCase();

  // Category bonuses
  if (category === 'ransomware')     score += 5;
  if (category === 'initial_access') score += 4;
  if (category === 'credentials')    score += 3;
  if (category === 'stealer_logs')   score += 3;
  if (category === 'financial_fraud')score += 3;
  if (category === 'carding')        score += 2;

  // Keyword bonuses
  if (/bank|credit union/.test(t))              score += 3;
  if (/fintech|payment processor/.test(t))      score += 3;
  if (/wire transfer|ach\b|swift\b/.test(t))    score += 2;
  if (/initial access|rdp|ssh access/.test(t))  score += 4;
  if (/domain admin|admin access/.test(t))      score += 3;
  if (/stealer log|infostealer/.test(t))        score += 2;

  // IOC presence
  if (iocCount > 0)  score += 2;
  if (iocCount >= 5) score += 1;

  // Freshness (<7 days)
  if (discoveredDate) {
    const ageDays = (Date.now() - new Date(discoveredDate).getTime()) / 86_400_000;
    if (ageDays < 7) score += 2;
  }

  // Duplicate penalty
  if (!isNew) score -= 3;

  return Math.max(0, Math.min(score, 20));
}

function severityFromScore(score) {
  if (score >= 13) return 'CRITICAL';
  if (score >= 8)  return 'HIGH';
  if (score >= 4)  return 'MEDIUM';
  return 'LOW';
}

// ── HTTP helpers ───────────────────────────────────────────────────────────────
const UA = 'Mozilla/5.0 (compatible; SecurityResearchBot/1.0; +https://github.com/badhref/cutracker)';

function httpClient(extraConfig = {}) {
  return axios.create({
    timeout: 25_000,
    headers: { 'User-Agent': UA },
    ...extraConfig,
  });
}

// Tor SOCKS5 proxy (optional — skipped if not configured)
function getTorAgent() {
  const proxy = process.env.TOR_PROXY; // e.g. socks5h://127.0.0.1:9050
  if (!proxy) return null;
  try {
    const { SocksProxyAgent } = require('socks-proxy-agent');
    return new SocksProxyAgent(proxy);
  } catch {
    return null;
  }
}

async function get(url, opts = {}) {
  try {
    const resp = await httpClient(opts).get(url);
    return resp.data;
  } catch (err) {
    console.warn(`[DarkWeb] GET ${url} — ${err.message}`);
    return null;
  }
}

async function post(url, body, opts = {}) {
  try {
    const resp = await httpClient(opts).post(url, body);
    return resp.data;
  } catch (err) {
    console.warn(`[DarkWeb] POST ${url} — ${err.message}`);
    return null;
  }
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Collector: ransomware.live ─────────────────────────────────────────────────
// Public JSON API aggregating ransomware leak site victims. No auth required.
async function collectRansomwareLive() {
  const raw = await get('https://api.ransomware.live/recentvictims');
  if (!Array.isArray(raw)) return [];

  return raw.slice(0, 100).map(v => {
    const victim  = v.victim   || v.post_title || 'Unknown';
    const group   = v.group_name || v.group  || 'Unknown';
    const domain  = v.website  || '';
    const country = v.country  || '';
    const desc    = v.description || '';
    const published = v.published || v.date || new Date().toISOString();

    const title   = `[Ransomware] ${victim} — ${group}`;
    const snippet = `${group} listed ${victim}${country ? ` (${country})` : ''}${domain ? ` — ${domain}` : ''}. Published: ${String(published).slice(0,10)}${desc ? '. ' + desc.slice(0, 200) : ''}`;

    return {
      external_id:     `rl-${group}-${victim}`.toLowerCase().replace(/\s+/g, '-').slice(0, 120),
      source_name:     'ransomware.live',
      title,
      snippet,
      raw_content:     JSON.stringify(v),
      category:        'ransomware',
      url:             v.url || 'https://ransomware.live',
      discovered_date: String(published).slice(0, 19),
    };
  });
}

// ── Collector: URLhaus (abuse.ch) ─────────────────────────────────────────────
async function collectURLhaus() {
  const data = await post(
    'https://urlhaus-api.abuse.ch/v1/urls/recent/',
    new URLSearchParams({ limit: '50' }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );
  const urls = data?.urls || [];

  return urls.map(r => {
    const tags    = (r.tags || []).join(', ');
    const threat  = r.threat   || 'malware';
    const status  = r.url_status || 'unknown';
    const title   = `[URLhaus] ${threat} — ${status} — ${r.host || r.url?.slice(0,60) || 'N/A'}`;
    const snippet = `URL: ${r.url} | Status: ${status} | Tags: ${tags || 'none'} | Added: ${r.date_added || 'N/A'}`;

    return {
      external_id:     `urlhaus-${r.id}`,
      source_name:     'URLhaus',
      title,
      snippet,
      raw_content:     JSON.stringify(r),
      category:        'malware',
      url:             `https://urlhaus.abuse.ch/url/${r.id}/`,
      discovered_date: r.date_added,
    };
  });
}

// ── Collector: MalwareBazaar (abuse.ch) ───────────────────────────────────────
async function collectMalwareBazaar() {
  const data = await post(
    'https://mb-api.abuse.ch/api/v1/',
    new URLSearchParams({ query: 'get_recent', selector: 'time' }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );
  const samples = data?.data || [];

  return samples.slice(0, 40).map(r => {
    const tags    = (r.tags || []).join(', ');
    const sig     = r.signature || r.file_name || 'Unknown';
    const ft      = r.file_type || 'N/A';
    const sha256  = r.sha256_hash || '';
    const title   = `[MalwareBazaar] ${sig} (${ft})`;
    const snippet = `File: ${r.file_name || 'N/A'} | Type: ${ft} | SHA256: ${sha256.slice(0,16)}… | Tags: ${tags || 'none'} | First seen: ${r.first_seen || 'N/A'}`;

    return {
      external_id:     `mbz-${sha256}`,
      source_name:     'MalwareBazaar',
      title,
      snippet,
      raw_content:     JSON.stringify(r),
      category:        detectCategory(`${sig} ${tags}`),
      url:             sha256 ? `https://bazaar.abuse.ch/sample/${sha256}/` : 'https://bazaar.abuse.ch',
      discovered_date: r.first_seen,
    };
  });
}

// ── Collector: Ahmia (clearnet dark web search) ────────────────────────────────
const AHMIA_QUERIES = [
  'credit union ransomware',
  'bank initial access sale',
  'financial stealer logs',
  'ACH wire transfer fraud',
];

async function collectAhmia() {
  const results = [];

  for (const q of AHMIA_QUERIES) {
    const html = await get(`https://ahmia.fi/search/?q=${encodeURIComponent(q)}`);
    if (!html) { await delay(3000); continue; }

    const $ = cheerio.load(html);
    $('li.result, .result').each((i, el) => {
      if (i >= 5) return false; // 5 results per query
      const title   = $(el).find('h4, a').first().text().trim();
      const snippet = $(el).find('p, .desc').first().text().trim();
      const href    = $(el).find('a').attr('href') || '';
      if (!title && !snippet) return;

      const key = Buffer.from(q + title + snippet).toString('base64').slice(0, 40);
      results.push({
        external_id:     `ahmia-${key}`,
        source_name:     'Ahmia',
        title:           title || `Dark web result: ${q}`,
        snippet:         snippet.slice(0, 500) || `Search: "${q}"`,
        raw_content:     $.html(el).slice(0, 5000),
        category:        detectCategory(`${title} ${snippet}`),
        url:             href.startsWith('http') ? href : 'https://ahmia.fi',
        discovered_date: new Date().toISOString(),
      });
    });

    await delay(2500); // be polite
  }

  return results;
}

// ── Orchestrator ───────────────────────────────────────────────────────────────
const COLLECTORS = [
  { name: 'ransomware.live', source: 'ransomware.live', fn: collectRansomwareLive },
  { name: 'URLhaus',         source: 'URLhaus',         fn: collectURLhaus },
  { name: 'MalwareBazaar',   source: 'MalwareBazaar',   fn: collectMalwareBazaar },
  { name: 'Ahmia',           source: 'Ahmia',           fn: collectAhmia },
];

async function runCollection() {
  console.log('[DarkWeb] Collection cycle started');
  const t0 = Date.now();
  let total = 0, newCount = 0;

  for (const col of COLLECTORS) {
    const src = db.getDwSourceByName(col.source);
    if (src && !src.enabled) { console.log(`[DarkWeb] ${col.name} disabled — skipping`); continue; }

    try {
      const items = await col.fn();
      console.log(`[DarkWeb] ${col.name}: ${items.length} items fetched`);

      for (const item of items) {
        const { isNew } = await persistFinding(item);
        total++;
        if (isNew) newCount++;
      }

      // Update last_checked on source
      if (src) db.updateDwSourceChecked(src.id);
    } catch (err) {
      console.error(`[DarkWeb] ${col.name} failed: ${err.message}`);
    }
  }

  const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
  console.log(`[DarkWeb] Cycle done: ${total} processed, ${newCount} new (${elapsed}s)`);
  return { total, newCount };
}

async function persistFinding(item) {
  const fullText = [item.title, item.snippet, item.raw_content || ''].join(' ').slice(0, 20_000);
  const iocMap   = extractIOCs(fullText);
  const iocCount = countIOCs(iocMap);
  const keywords = detectKeywords(fullText);
  const category = item.category || detectCategory(fullText);

  const existing = db.getDwFindingByExternalId(item.external_id);
  const isNew    = !existing;

  const score    = scoreContent({ category, text: fullText, iocCount, isNew, discoveredDate: item.discovered_date });
  const severity = severityFromScore(score);

  let findingId;
  if (existing) {
    db.updateDwFinding(existing.id, { risk_score: score, severity });
    findingId = existing.id;
  } else {
    findingId = db.insertDwFinding({
      external_id:     item.external_id,
      source_name:     item.source_name,
      title:           (item.title  || '').slice(0, 500),
      snippet:         (item.snippet || '').slice(0, 1000),
      raw_content:     (item.raw_content || '').slice(0, 50_000),
      url:             item.url || null,
      risk_score:      score,
      severity,
      category,
      keyword_hits:    JSON.stringify(keywords),
      discovered_date: item.discovered_date || new Date().toISOString(),
    });
  }

  // Store IOCs for new findings only
  if (findingId && isNew) {
    for (const [iocType, values] of Object.entries(iocMap)) {
      for (const val of values) {
        db.insertDwIOC({
          finding_id:  findingId,
          ioc_type:    iocType,
          ioc_value:   val,
          source_name: item.source_name,
        });
      }
    }
  }

  return { isNew, findingId, score, severity };
}

// Allow individual source fetches to be triggered from the API
async function runSingleCollector(sourceName) {
  const col = COLLECTORS.find(c => c.name === sourceName);
  if (!col) throw new Error(`Unknown collector: ${sourceName}`);
  const items = await col.fn();
  let newCount = 0;
  for (const item of items) {
    const { isNew } = await persistFinding(item);
    if (isNew) newCount++;
  }
  return { total: items.length, newCount };
}

module.exports = {
  runCollection,
  runSingleCollector,
  scoreContent,
  severityFromScore,
  detectCategory,
  detectKeywords,
  COLLECTORS,
};
