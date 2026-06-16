'use strict';

/**
 * IOC Extractor
 * Parses free text for indicators of compromise.
 * Patterns are intentionally conservative to minimise false positives.
 */

// Regex patterns — each must have exactly one capture group (m[1])
const PATTERNS = {
  ipv4: /\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b/g,
  domain: /\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|co|uk|de|fr|ru|cn|br|au|jp|ca|nl|se|ch|onion|xyz|info|biz|us|mil|bank))\b/gi,
  url: /\b(https?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]{10,})/gi,
  email: /\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b/g,
  hash_md5:    /\b([a-fA-F0-9]{32})\b/g,
  hash_sha1:   /\b([a-fA-F0-9]{40})\b/g,
  hash_sha256: /\b([a-fA-F0-9]{64})\b/g,
  btc_address: /\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b/g,
  eth_address: /\b(0x[a-fA-F0-9]{40})\b/g,
  cve:         /\b(CVE-\d{4}-\d{4,7})\b/gi,
};

// Private / loopback IPv4 ranges — filter these out
const PRIVATE_RANGES = [
  /^10\./, /^127\./, /^0\./, /^255\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
];

// High-volume false-positive domains to skip
const SKIP_DOMAINS = new Set([
  'example.com','test.com','localhost','google.com','github.com','microsoft.com',
  'apple.com','amazon.com','cloudflare.com','facebook.com','twitter.com',
  'youtube.com','wikipedia.org','w3.org','schema.org','jquery.com',
]);

function isPrivateIP(ip) {
  return PRIVATE_RANGES.some(r => r.test(ip));
}

/**
 * Extract IOCs from a text string.
 * Returns { ioc_type: [values, ...], ... }
 */
function extractIOCs(text) {
  if (!text || typeof text !== 'string') return {};
  // Truncate very long strings to keep regex fast
  const t = text.slice(0, 50_000);
  const results = {};

  for (const [type, pattern] of Object.entries(PATTERNS)) {
    pattern.lastIndex = 0;
    const seen = new Set();
    let m;
    while ((m = pattern.exec(t)) !== null) {
      const val = (m[1] || m[0]).trim();
      if (!val) continue;
      if (type === 'ipv4' && isPrivateIP(val)) continue;
      if (type === 'domain' && SKIP_DOMAINS.has(val.toLowerCase())) continue;
      // Skip single-word entries for domains (must have real TLD)
      if (type === 'domain' && !val.includes('.')) continue;
      seen.add(val);
      if (seen.size >= 50) break; // cap per type
    }
    if (seen.size > 0) results[type] = [...seen];
  }

  return results;
}

function countIOCs(iocMap) {
  return Object.values(iocMap).reduce((n, arr) => n + arr.length, 0);
}

/** Flatten all IOC values into a single array of { type, value } */
function flattenIOCs(iocMap) {
  const out = [];
  for (const [type, values] of Object.entries(iocMap)) {
    for (const value of values) out.push({ type, value });
  }
  return out;
}

module.exports = { extractIOCs, countIOCs, flattenIOCs };
