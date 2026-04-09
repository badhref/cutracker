/**
 * DataBreaches.net RSS Fetcher
 * Parses the public RSS feed and filters for credit union mentions.
 * Also fetches BankInfoSecurity and KrebsOnSecurity RSS for financial breach coverage.
 */

const RSSParser = require('rss-parser');
const axios = require('axios');

const SOURCE = 'DataBreaches.net';

const RSS_FEEDS = [
  {
    name: 'DataBreaches.net',
    url: 'https://www.databreaches.net/feed/',
    source: 'DataBreaches.net',
  },
  {
    name: 'BankInfoSecurity',
    url: 'https://www.bankinfosecurity.com/rss',
    source: 'BankInfoSecurity',
  },
  {
    name: 'KrebsOnSecurity',
    url: 'https://krebsonsecurity.com/feed/',
    source: 'KrebsOnSecurity',
  },
  {
    name: 'Dark Reading',
    url: 'https://www.darkreading.com/rss.xml',
    source: 'Dark Reading',
  },
];

const CU_KEYWORDS = [
  'credit union', 'federal credit', 'community credit', 'employees credit',
  'teachers credit', 'members credit', 'ccu', ' fcu', 'nafcu', 'cuna',
  'credit unions'
];

const parser = new RSSParser({
  timeout: 20000,
  headers: { 'User-Agent': 'CreditUnionBreachTracker/1.0 (security-research)' }
});

function isCreditUnion(text) {
  if (!text) return false;
  const lower = text.toLowerCase();
  return CU_KEYWORDS.some(kw => lower.includes(kw));
}

async function fetchFeed(feed) {
  const results = [];
  try {
    const parsed = await parser.parseURL(feed.url);

    for (const item of (parsed.items || [])) {
      const fullText = [item.title, item.content, item.contentSnippet, item.summary].join(' ');
      if (!isCreditUnion(fullText)) continue;

      const org = extractOrgName(item.title || '');
      results.push({
        external_id: `rss-${feed.source.toLowerCase().replace(/\W/g, '')}-${slugify(item.link || item.guid || item.title)}`,
        organization: org || 'Unknown Credit Union',
        breach_date: parseDate(item.pubDate || item.isoDate),
        notification_date: parseDate(item.pubDate || item.isoDate),
        breach_type: detectBreachType(fullText),
        attack_vector: detectAttackVector(fullText),
        records_affected: extractRecordCount(fullText),
        data_types: extractDataTypes(fullText),
        state: extractState(fullText),
        source: feed.source,
        source_url: item.link || feed.url,
        description: truncate(item.title + (item.contentSnippet ? ` — ${item.contentSnippet}` : ''), 500),
        status: 'reported',
      });
    }
  } catch (err) {
    console.warn(`[RSS:${feed.name}] Error: ${err.message}`);
  }
  return results;
}

async function fetchDataBreachRSS() {
  const allResults = [];
  for (const feed of RSS_FEEDS) {
    const items = await fetchFeed(feed);
    allResults.push(...items);
  }
  return allResults;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function extractOrgName(title) {
  // "XYZ Credit Union Suffers Data Breach" → "XYZ Credit Union"
  const match = title.match(/^([A-Z][^:–—-]+(?:credit union|federal credit union|ccu|fcu))/i);
  if (match) return match[1].trim();

  // Try extracting quoted org name
  const quoted = title.match(/["']([^"']+credit union[^"']*?)["']/i);
  if (quoted) return quoted[1].trim();

  // Grab up to the first verb
  const verbMatch = title.match(/^(.+?)\s+(?:breach|hack|attack|suffer|report|disclose|notify|experience)/i);
  if (verbMatch) return verbMatch[1].trim();

  return null;
}

function detectBreachType(text) {
  const t = text.toLowerCase();
  if (t.includes('ransomware')) return 'Ransomware';
  if (t.includes('phishing')) return 'Phishing';
  if (t.includes('hack') || t.includes('unauthorized access')) return 'Unauthorized Access/Hacking';
  if (t.includes('malware')) return 'Malware';
  if (t.includes('sql injection')) return 'SQL Injection';
  if (t.includes('insider') || t.includes('rogue employee')) return 'Insider Threat';
  if (t.includes('third party') || t.includes('vendor') || t.includes('supply chain')) return 'Third-Party/Vendor';
  if (t.includes('accidental') || t.includes('misconfigur') || t.includes('exposed')) return 'Accidental Exposure';
  if (t.includes('theft') || t.includes('stolen device')) return 'Theft';
  if (t.includes('social engineering')) return 'Social Engineering';
  return 'Data Breach';
}

function detectAttackVector(text) {
  const t = text.toLowerCase();
  if (t.includes('email') || t.includes('phishing')) return 'Email/Phishing';
  if (t.includes('web application') || t.includes('website')) return 'Web Application';
  if (t.includes('vpn') || t.includes('remote access')) return 'Remote Access';
  if (t.includes('third party') || t.includes('vendor')) return 'Third-Party';
  if (t.includes('physical') || t.includes('device')) return 'Physical';
  if (t.includes('insider')) return 'Insider';
  return null;
}

function extractRecordCount(text) {
  const patterns = [
    /(\d[\d,]+)\s*(?:million)?\s*(?:individuals?|records?|members?|customers?|accounts?|people)\s*(?:were|was|affected|exposed|compromised|impacted)/i,
    /affected\s+(\d[\d,]+)\s*(?:million)?\s*(?:individuals?|records?|members?)/i,
    /exposed\s+(?:data of|information of)?\s*(\d[\d,]+)/i,
    /(\d[\d,]+)\s*(?:million)?\s*(?:records?|accounts?)\s*(?:were|was)?\s*(?:leaked|breached|stolen|exposed)/i,
  ];

  for (const pat of patterns) {
    const m = text.match(pat);
    if (m) {
      let n = parseInt(m[1].replace(/,/g, ''));
      if (m[0].toLowerCase().includes('million')) n *= 1_000_000;
      return n;
    }
  }
  return null;
}

function extractDataTypes(text) {
  const found = [];
  const t = text.toLowerCase();
  if (t.includes('social security') || t.includes('ssn')) found.push('SSN');
  if (t.includes('account number')) found.push('Account Number');
  if (t.includes('credit card') || t.includes('debit card')) found.push('Payment Card');
  if (t.includes("driver's license") || t.includes('driver license')) found.push("Driver's License");
  if (t.includes('date of birth') || t.includes('dob')) found.push('Date of Birth');
  if (t.includes('address')) found.push('Address');
  if (t.includes('email')) found.push('Email');
  if (t.includes('password') || t.includes('credential')) found.push('Credentials');
  if (t.includes('health') || t.includes('medical')) found.push('Health Information');
  if (t.includes('loan') || t.includes('mortgage')) found.push('Loan Information');
  return found.length ? found.join(', ') : null;
}

function extractState(text) {
  const states = {
    'Alabama': 'AL', 'Alaska': 'AK', 'Arizona': 'AZ', 'Arkansas': 'AR',
    'California': 'CA', 'Colorado': 'CO', 'Connecticut': 'CT', 'Delaware': 'DE',
    'Florida': 'FL', 'Georgia': 'GA', 'Hawaii': 'HI', 'Idaho': 'ID',
    'Illinois': 'IL', 'Indiana': 'IN', 'Iowa': 'IA', 'Kansas': 'KS',
    'Kentucky': 'KY', 'Louisiana': 'LA', 'Maine': 'ME', 'Maryland': 'MD',
    'Massachusetts': 'MA', 'Michigan': 'MI', 'Minnesota': 'MN', 'Mississippi': 'MS',
    'Missouri': 'MO', 'Montana': 'MT', 'Nebraska': 'NE', 'Nevada': 'NV',
    'New Hampshire': 'NH', 'New Jersey': 'NJ', 'New Mexico': 'NM', 'New York': 'NY',
    'North Carolina': 'NC', 'North Dakota': 'ND', 'Ohio': 'OH', 'Oklahoma': 'OK',
    'Oregon': 'OR', 'Pennsylvania': 'PA', 'Rhode Island': 'RI', 'South Carolina': 'SC',
    'South Dakota': 'SD', 'Tennessee': 'TN', 'Texas': 'TX', 'Utah': 'UT',
    'Vermont': 'VT', 'Virginia': 'VA', 'Washington': 'WA', 'West Virginia': 'WV',
    'Wisconsin': 'WI', 'Wyoming': 'WY',
  };
  for (const [name, abbr] of Object.entries(states)) {
    if (text.includes(name)) return abbr;
  }
  return null;
}

function parseDate(str) {
  if (!str) return null;
  const d = new Date(str);
  return isNaN(d.getTime()) ? null : d.toISOString().split('T')[0];
}

function slugify(str) {
  return (str || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 60);
}

function truncate(str, max) {
  if (!str) return null;
  return str.length > max ? str.slice(0, max) + '…' : str;
}

module.exports = { fetchDataBreachRSS, SOURCE };
