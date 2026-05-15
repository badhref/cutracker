'use strict';

const axios = require('axios');
const cheerio = require('cheerio');

const USER_AGENT = 'Mozilla/5.0 (compatible; CUInvestigator/1.0)';
const HOME_TIMEOUT = 10000;
const PAGE_TIMEOUT = 5000;
const EXTRA_PATHS = ['/about', '/contact', '/login', '/privacy', '/terms'];

// ── Simple non-crypto hash (djb2) ─────────────────────────────────────────────
function djb2(str) {
  let hash = 5381;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) + hash) ^ str.charCodeAt(i);
    hash = hash >>> 0; // keep unsigned 32-bit
  }
  return hash.toString(16);
}

// ── URL normalisation ─────────────────────────────────────────────────────────
function normalizeUrl(raw) {
  let url = raw.trim();
  if (!/^https?:\/\//i.test(url)) {
    url = 'https://' + url;
  }
  url = url.replace(/\/+$/, '');
  return url;
}

function extractDomain(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return url;
  }
}

// ── Fetch a single page, return { html, status } or null on error ──────────────
async function fetchPage(url, timeout) {
  try {
    const resp = await axios.get(url, {
      headers: { 'User-Agent': USER_AGENT },
      timeout,
      maxRedirects: 5,
      validateStatus: (s) => s < 400,
    });
    return { html: typeof resp.data === 'string' ? resp.data : String(resp.data), status: resp.status };
  } catch {
    return null;
  }
}

// ── Regex helpers ─────────────────────────────────────────────────────────────
const EMAIL_RE = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;
const PHONE_RE = /(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})/g;
const ADDRESS_RE = /\d{2,5}\s+[A-Z][a-z]+(?:\s+[A-Za-z]+){1,4}(?:\s+(?:St|Ave|Blvd|Dr|Rd|Ln|Way|Ct|Pl|Suite|Ste|Floor|Fl)\.?)/g;
const ROUTING_RE = /\b(?:routing(?:\s+number)?[:# ]+)?(\d{9})\b/gi;
const CHARTER_RE = /charter(?:\s+number)?[:\s#]+(\d{4,7})\b/gi;
const GA_RE = /(?:UA|G|AW|GT)-[A-Z0-9\-]+/g;
const PIXEL_RE = /(?:fbq|_fbq|facebook\.com\/tr)[^\s"'<>]{0,60}/g;

// ── Extract data from a single cheerio document ───────────────────────────────
function extractFromDoc($, baseUrl, isFirst) {
  const out = {
    title: null,
    meta_description: null,
    text: '',
    links: [],
    emails: [],
    phones: [],
    addresses: [],
    has_login_form: false,
    favicon_url: null,
    ncua_language: [],
    routing_numbers: [],
    charter_numbers: [],
    footer_text: '',
    analytics_ids: [],
    tracking_pixels: [],
  };

  if (isFirst) {
    out.title = $('title').first().text().trim() || null;
    out.meta_description = $('meta[name="description"]').attr('content') || null;
    // Favicon
    const faviconEl = $('link[rel*="icon"]').first();
    if (faviconEl.length) {
      const href = faviconEl.attr('href') || '';
      out.favicon_url = href ? resolveUrl(href, baseUrl) : null;
    }
  }

  // Full visible text
  $('script, style, noscript').remove();
  out.text = $('body').text().replace(/\s+/g, ' ').trim();

  // Links
  $('a[href]').each((_, el) => {
    const href = $(el).attr('href');
    if (href && !href.startsWith('#') && !href.startsWith('javascript')) {
      out.links.push(resolveUrl(href, baseUrl));
    }
  });

  // Login form detection
  out.has_login_form = $('input[type="password"]').length > 0;

  // Footer text
  out.footer_text = $('footer').text().replace(/\s+/g, ' ').trim();

  // Emails
  const emailMatches = out.text.match(EMAIL_RE) || [];
  out.emails = [...new Set(emailMatches)];

  // Phones
  const phoneMatches = out.text.match(PHONE_RE) || [];
  out.phones = [...new Set(phoneMatches)];

  // Addresses
  const addrMatches = out.text.match(ADDRESS_RE) || [];
  out.addresses = [...new Set(addrMatches)];

  // Routing numbers
  let m;
  const rText = out.text;
  const routingRe = new RegExp(ROUTING_RE.source, 'gi');
  while ((m = routingRe.exec(rText)) !== null) {
    out.routing_numbers.push(m[1]);
  }
  out.routing_numbers = [...new Set(out.routing_numbers)];

  // Charter numbers
  const charterRe = new RegExp(CHARTER_RE.source, 'gi');
  while ((m = charterRe.exec(rText)) !== null) {
    out.charter_numbers.push(m[1]);
  }
  out.charter_numbers = [...new Set(out.charter_numbers)];

  // NCUA language
  const ncuaPatterns = [
    /federally insured by ncua/gi,
    /insured by ncua/gi,
    /national credit union administration/gi,
    /ncua/gi,
    /federal share insurance/gi,
    /share insurance fund/gi,
  ];
  for (const pat of ncuaPatterns) {
    const matches = rText.match(pat);
    if (matches) {
      out.ncua_language.push(...matches.map(s => s.trim()));
    }
  }
  out.ncua_language = [...new Set(out.ncua_language)];

  // Analytics IDs (from raw HTML)
  return out;
}

function resolveUrl(href, base) {
  try {
    return new URL(href, base).href;
  } catch {
    return href;
  }
}

function extractAnalyticsFromHtml(html) {
  const gaMatches = html.match(GA_RE) || [];
  const pixelMatches = html.match(PIXEL_RE) || [];
  return {
    analytics_ids: [...new Set(gaMatches)],
    tracking_pixels: [...new Set(pixelMatches)],
  };
}

// ── Main exported function ────────────────────────────────────────────────────
async function investigateSite(rawUrl) {
  const normalized_url = normalizeUrl(rawUrl);
  const domain = extractDomain(normalized_url);

  const result = {
    url: normalized_url,
    domain,
    normalized_url,
    title: null,
    meta_description: null,
    body_text: '',
    links: [],
    emails: [],
    phones: [],
    addresses: [],
    has_login_form: false,
    favicon_url: null,
    favicon_hash: null,
    html_fingerprint: null,
    ncua_language: [],
    routing_numbers: [],
    charter_numbers: [],
    footer_text: '',
    analytics_ids: [],
    tracking_pixels: [],
    raw_html_length: 0,
    status_code: null,
    error: null,
    pages_crawled: [],
  };

  // Fetch homepage
  const home = await fetchPage(normalized_url, HOME_TIMEOUT);
  if (!home) {
    result.error = 'Failed to fetch homepage';
    return result;
  }

  result.status_code = home.status;
  result.raw_html_length = home.html.length;
  result.pages_crawled.push(normalized_url);

  // Crawl extra paths (up to 5, in parallel, skip failures)
  const extraPages = await Promise.all(
    EXTRA_PATHS.map(async (p) => {
      const pageUrl = normalized_url + p;
      const page = await fetchPage(pageUrl, PAGE_TIMEOUT);
      if (page) return { url: pageUrl, html: page.html };
      return null;
    })
  );

  const successfulExtras = extraPages.filter(Boolean).slice(0, 5);
  for (const ep of successfulExtras) {
    result.pages_crawled.push(ep.url);
  }

  // Extract from all pages
  const allPages = [{ url: normalized_url, html: home.html }, ...successfulExtras];

  for (let i = 0; i < allPages.length; i++) {
    const { url: pageUrl, html } = allPages[i];
    const $ = cheerio.load(html);
    const extracted = extractFromDoc($, pageUrl, i === 0);
    const { analytics_ids, tracking_pixels } = extractAnalyticsFromHtml(html);

    if (i === 0) {
      result.title = extracted.title;
      result.meta_description = extracted.meta_description;
      result.favicon_url = extracted.favicon_url;
    }

    // Merge arrays (de-duplicate)
    result.body_text += ' ' + extracted.text;
    result.links = [...new Set([...result.links, ...extracted.links])];
    result.emails = [...new Set([...result.emails, ...extracted.emails])];
    result.phones = [...new Set([...result.phones, ...extracted.phones])];
    result.addresses = [...new Set([...result.addresses, ...extracted.addresses])];
    result.ncua_language = [...new Set([...result.ncua_language, ...extracted.ncua_language])];
    result.routing_numbers = [...new Set([...result.routing_numbers, ...extracted.routing_numbers])];
    result.charter_numbers = [...new Set([...result.charter_numbers, ...extracted.charter_numbers])];
    result.analytics_ids = [...new Set([...result.analytics_ids, ...analytics_ids])];
    result.tracking_pixels = [...new Set([...result.tracking_pixels, ...tracking_pixels])];

    if (extracted.has_login_form) result.has_login_form = true;
    if (extracted.footer_text) result.footer_text = extracted.footer_text;
  }

  result.body_text = result.body_text.trim();

  // Compute hashes
  if (result.favicon_url) {
    result.favicon_hash = djb2(result.favicon_url);
  }

  const fingerprintSource = `${home.html.length}|${result.title || ''}|${result.body_text.slice(0, 500)}`;
  result.html_fingerprint = djb2(fingerprintSource);

  return result;
}

module.exports = { investigateSite };
