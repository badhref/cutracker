/**
 * Maine Attorney General Breach Notifications
 *
 * The page loads ALL breach records inline (no AJAX) in a jQuery DataTable.
 * We fetch the full page, filter rows where org name contains credit-union
 * keywords, then fetch each detail page (UUID-based URL) to get structured
 * breach data: dates, records affected, breach type, state, etc.
 *
 * List URL: https://www.maine.gov/agviewer/content/ag/985235c7-cb95-4be2-8792-a1252b4f8318/list.html
 * Detail:   same base + <uuid>.html
 */

const axios = require('axios');
const cheerio = require('cheerio');

const SOURCE = 'Maine AG';
const BASE_URL = 'https://www.maine.gov/agviewer/content/ag/985235c7-cb95-4be2-8792-a1252b4f8318/';
const LIST_URL = BASE_URL + 'list.html';

const HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml',
};

const CU_KEYWORDS = [
  'credit union', 'federal credit', 'community credit', 'employees credit',
  'teachers credit', 'members credit', ' ccu', ' fcu',
];

function isCreditUnion(name) {
  const lower = (name || '').toLowerCase();
  return CU_KEYWORDS.some(kw => lower.includes(kw));
}

// ── Main entry point ─────────────────────────────────────────────────────────

async function fetchMaineAG() {
  // Step 1: fetch full list (all data is inline — no AJAX needed)
  let listHtml;
  try {
    const resp = await axios.get(LIST_URL, { timeout: 30000, headers: HEADERS });
    listHtml = resp.data;
  } catch (err) {
    console.warn(`[Maine AG] List fetch failed: ${err.message}`);
    return [];
  }

  // Step 2: parse table rows, collect CU entries
  const $ = cheerio.load(listHtml);
  const cuEntries = [];

  $('table tbody tr').each((_, row) => {
    const cells = $(row).find('td');
    if (cells.length < 2) return;

    const dateReported = $(cells[0]).text().trim();
    const org          = $(cells[1]).text().trim();
    const link         = $(cells[1]).find('a').attr('href') || '';

    if (!isCreditUnion(org)) return;

    cuEntries.push({ dateReported, org, link });
  });

  console.log(`[Maine AG] Found ${cuEntries.length} credit union entries in list`);
  if (!cuEntries.length) return [];

  // Step 3: fetch detail pages with limited concurrency (3 at a time)
  const results = [];
  const CONCURRENCY = 3;
  const DELAY_MS = 300;

  for (let i = 0; i < cuEntries.length; i += CONCURRENCY) {
    const batch = cuEntries.slice(i, i + CONCURRENCY);
    const batchResults = await Promise.all(
      batch.map(entry => fetchDetail(entry).catch(() => buildFallback(entry)))
    );
    results.push(...batchResults.filter(Boolean));

    // Polite delay between batches
    if (i + CONCURRENCY < cuEntries.length) {
      await sleep(DELAY_MS);
    }
  }

  return results;
}

// ── Detail page parser ───────────────────────────────────────────────────────

async function fetchDetail(entry) {
  if (!entry.link) return buildFallback(entry);

  const detailUrl = BASE_URL + entry.link;
  let html;
  try {
    const resp = await axios.get(detailUrl, { timeout: 15000, headers: HEADERS });
    html = resp.data;
  } catch {
    return buildFallback(entry);
  }

  const $ = cheerio.load(html);

  // All fields are in <ul class="plain"> <li>Label: <strong>Value</strong></li>
  const fields = {};
  $('ul.plain li').each((_, el) => {
    const full = $(el).text().replace(/\s+/g, ' ').trim();
    const colonIdx = full.indexOf(':');
    if (colonIdx === -1) return;
    const key = full.slice(0, colonIdx).trim();
    const val = full.slice(colonIdx + 1).trim();
    if (key && val) fields[key] = val;
  });

  const org          = fields['Entity Name'] || entry.org;
  const state        = normalizeState(fields['State, or Country if outside the US'] || '');
  const recordsTotal = parseInt((fields['Total number of persons affected (including residents)'] || '').replace(/,/g, '')) || null;
  const breachDate   = parseDate(fields['Date(s) Breach Occured'] || fields['Date(s) Breach Occurred'] || '');
  const discoveryDate = parseDate(fields['Date Breach Discovered'] || '');
  const notifDate    = parseDate(fields['Date(s) of consumer notification'] || entry.dateReported || '');
  const rawBreachDesc = fields['Description of the Breach'] || '';
  const rawDataTypes = fields['Information Acquired - Name or other personal identifier in combination with'] || '';

  return {
    external_id: `maine-${entry.link.replace('.html', '')}`,
    organization: org,
    organization_type: 'credit_union',
    state,
    breach_date: breachDate,
    discovery_date: discoveryDate,
    notification_date: notifDate || parseDate(entry.dateReported),
    breach_type: mapBreachType(rawBreachDesc),
    attack_vector: mapAttackVector(rawBreachDesc),
    records_affected: recordsTotal,
    data_types: mapDataTypes(rawDataTypes) || null,
    source: SOURCE,
    source_url: detailUrl,
    description: buildDescription(org, rawBreachDesc, recordsTotal, state),
    status: 'reported',
    is_manual: 0,
  };
}

// Fallback when detail page is unavailable — use list-page data only
function buildFallback(entry) {
  return {
    external_id: `maine-${slugify(entry.org)}-${(entry.dateReported || '').replace(/-/g, '')}`,
    organization: entry.org,
    organization_type: 'credit_union',
    state: null,
    notification_date: parseDate(entry.dateReported),
    source: SOURCE,
    source_url: LIST_URL,
    description: `Maine AG notification: ${entry.org}`,
    status: 'reported',
    is_manual: 0,
  };
}

// ── Field mappers ────────────────────────────────────────────────────────────

function mapBreachType(desc) {
  const d = desc.toLowerCase();
  if (d.includes('ransomware'))                         return 'Ransomware';
  if (d.includes('phishing'))                           return 'Phishing';
  if (d.includes('external system') || d.includes('hacking') || d.includes('unauthorized')) return 'Unauthorized Access/Hacking';
  if (d.includes('malware'))                            return 'Malware';
  if (d.includes('insider') || d.includes('employee')) return 'Insider Threat';
  if (d.includes('third') || d.includes('vendor'))     return 'Third-Party/Vendor';
  if (d.includes('accidental') || d.includes('error') || d.includes('unintended')) return 'Accidental Exposure';
  if (d.includes('theft') || d.includes('stolen'))     return 'Theft';
  if (d.includes('social engineering'))                 return 'Social Engineering';
  if (desc)                                             return desc.split('\n')[0].trim().slice(0, 80);
  return null;
}

function mapAttackVector(desc) {
  const d = desc.toLowerCase();
  if (d.includes('email') || d.includes('phishing'))   return 'Email/Phishing';
  if (d.includes('web') || d.includes('application'))  return 'Web Application';
  if (d.includes('vpn') || d.includes('remote'))       return 'Remote Access';
  if (d.includes('third') || d.includes('vendor'))     return 'Third-Party';
  if (d.includes('physical') || d.includes('device'))  return 'Physical';
  if (d.includes('insider'))                            return 'Insider';
  return null;
}

function mapDataTypes(raw) {
  if (!raw) return null;
  const found = [];
  const r = raw.toLowerCase();
  if (r.includes('social security') || r.includes('ssn'))          found.push('SSN');
  if (r.includes('financial') || r.includes('account number'))      found.push('Financial Account');
  if (r.includes('credit card') || r.includes('debit'))             found.push('Payment Card');
  if (r.includes("driver") || r.includes("license"))               found.push("Driver's License");
  if (r.includes('date of birth') || r.includes('dob'))            found.push('Date of Birth');
  if (r.includes('medical') || r.includes('health'))               found.push('Health Information');
  if (r.includes('passport'))                                       found.push('Passport');
  if (r.includes('email'))                                          found.push('Email');
  if (r.includes('password') || r.includes('credential'))          found.push('Credentials');
  if (r.includes('address'))                                        found.push('Address');
  // If no specific types found but field has content, return raw (truncated)
  if (!found.length && raw.trim().length > 0) return raw.slice(0, 200);
  return found.length ? found.join(', ') : null;
}

function normalizeState(raw) {
  const r = (raw || '').trim().toUpperCase();
  const abbrs = ['AL','AK','AZ','AR','CA','CO','CT','DE','FL','GA','HI','ID','IL','IN','IA',
    'KS','KY','LA','ME','MD','MA','MI','MN','MS','MO','MT','NE','NV','NH','NJ','NM','NY',
    'NC','ND','OH','OK','OR','PA','RI','SC','SD','TN','TX','UT','VT','VA','WA','WV','WI','WY'];
  if (abbrs.includes(r)) return r;
  // Full name lookup
  const map = { ALABAMA:'AL',ALASKA:'AK',ARIZONA:'AZ',ARKANSAS:'AR',CALIFORNIA:'CA',
    COLORADO:'CO',CONNECTICUT:'CT',DELAWARE:'DE',FLORIDA:'FL',GEORGIA:'GA',HAWAII:'HI',
    IDAHO:'ID',ILLINOIS:'IL',INDIANA:'IN',IOWA:'IA',KANSAS:'KS',KENTUCKY:'KY',
    LOUISIANA:'LA',MAINE:'ME',MARYLAND:'MD',MASSACHUSETTS:'MA',MICHIGAN:'MI',
    MINNESOTA:'MN',MISSISSIPPI:'MS',MISSOURI:'MO',MONTANA:'MT',NEBRASKA:'NE',
    NEVADA:'NV','NEW HAMPSHIRE':'NH','NEW JERSEY':'NJ','NEW MEXICO':'NM','NEW YORK':'NY',
    'NORTH CAROLINA':'NC','NORTH DAKOTA':'ND',OHIO:'OH',OKLAHOMA:'OK',OREGON:'OR',
    PENNSYLVANIA:'PA','RHODE ISLAND':'RI','SOUTH CAROLINA':'SC','SOUTH DAKOTA':'SD',
    TENNESSEE:'TN',TEXAS:'TX',UTAH:'UT',VERMONT:'VT',VIRGINIA:'VA',WASHINGTON:'WA',
    'WEST VIRGINIA':'WV',WISCONSIN:'WI',WYOMING:'WY' };
  return map[r] || (r.length === 2 ? r : null);
}

function parseDate(str) {
  if (!str) return null;
  // Handle MM/DD/YYYY and MM-DD-YYYY formats
  const slash = str.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})$/);
  if (slash) return `${slash[3]}-${slash[1].padStart(2,'0')}-${slash[2].padStart(2,'0')}`;
  // ISO or partial ISO
  const d = new Date(str);
  return isNaN(d.getTime()) ? null : d.toISOString().split('T')[0];
}

function buildDescription(org, breachDesc, records, state) {
  const parts = [`Maine AG notification: ${org}`];
  if (breachDesc)  parts.push(breachDesc.split('\n')[0].trim());
  if (records)     parts.push(`${records.toLocaleString()} individuals affected`);
  if (state)       parts.push(`(${state})`);
  return parts.join(' — ');
}

function slugify(str) {
  return (str || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 50);
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

module.exports = { fetchMaineAG, SOURCE };
