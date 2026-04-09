/**
 * NCUA (National Credit Union Administration) Fetcher
 * Sources:
 *   - NCUA Enforcement Actions: https://www.ncua.gov/regulation-supervision/regulatory-reporting/enforcement-actions
 *   - NCUA Credit Union Locator: https://www.ncua.gov/analysis/credit-union-corporate-call-report-data/quarterly-data
 *
 * Note: NCUA does not publish a formal breach list, but enforcement actions
 * and published letters sometimes reference security incidents.
 * This fetcher parses the enforcement actions page.
 */

const axios = require('axios');
const cheerio = require('cheerio');

const SOURCE = 'NCUA';
const ENFORCEMENT_URL = 'https://www.ncua.gov/regulation-supervision/regulatory-reporting/enforcement-actions';

const BREACH_KEYWORDS = [
  'data breach', 'security incident', 'cyber', 'unauthorized access',
  'hacking', 'ransomware', 'information security', 'data security',
  'breach of', 'security breach'
];

async function fetchNCUA() {
  const results = [];

  try {
    const response = await axios.get(ENFORCEMENT_URL, {
      timeout: 20000,
      headers: {
        'User-Agent': 'CreditUnionBreachTracker/1.0 (security-research)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9',
      }
    });

    const $ = cheerio.load(response.data);

    // NCUA enforcement actions table
    $('table tbody tr, .field-items .field-item').each((i, el) => {
      const text = $(el).text();
      const lowerText = text.toLowerCase();

      // Only include if breach-related keywords present
      const isBreachRelated = BREACH_KEYWORDS.some(kw => lowerText.includes(kw));
      if (!isBreachRelated) return;

      const cells = $(el).find('td');
      if (cells.length === 0) return;

      const orgName = $(cells[0]).text().trim() || $(el).find('.cu-name, h3, h4').first().text().trim();
      const dateText = $(cells[1]).text().trim() || $(cells[2]).text().trim();
      const linkEl = $(el).find('a');
      const detailUrl = linkEl.length
        ? new URL(linkEl.attr('href') || '', ENFORCEMENT_URL).href
        : ENFORCEMENT_URL;

      if (!orgName) return;

      results.push({
        external_id: `ncua-${slugify(orgName)}-${(dateText || '').replace(/\D/g, '').slice(0, 8)}`,
        organization: orgName,
        state: extractState(text),
        notification_date: parseDate(dateText),
        breach_type: detectBreachType(text),
        records_affected: extractRecords(text),
        data_types: extractDataTypes(text),
        source: SOURCE,
        source_url: detailUrl,
        description: truncate(`NCUA Action: ${text}`, 500),
        status: 'regulatory_action',
      });
    });

    // Also try NCUA's data download page for credit union breach filings
    await fetchNCUADataDownload(results);

  } catch (err) {
    console.warn(`[NCUA] Fetch error: ${err.message}`);
  }

  return results;
}

async function fetchNCUADataDownload(results) {
  try {
    // NCUA publishes quarterly call report data — no direct breach list
    // But we can check their recent news/press releases for breach mentions
    const newsResp = await axios.get('https://www.ncua.gov/newsroom', {
      timeout: 15000,
      headers: { 'User-Agent': 'CreditUnionBreachTracker/1.0 (security-research)' }
    });

    const $ = cheerio.load(newsResp.data);

    $('article, .views-row, .news-item').each((i, el) => {
      const text = $(el).text();
      const lowerText = text.toLowerCase();
      const isBreachRelated = BREACH_KEYWORDS.some(kw => lowerText.includes(kw));
      if (!isBreachRelated) return;

      const title = $(el).find('h2, h3, .title, a').first().text().trim();
      const dateText = $(el).find('time, .date').first().text().trim();
      const linkEl = $(el).find('a[href]').first();
      const url = linkEl.length ? new URL(linkEl.attr('href'), 'https://www.ncua.gov').href : 'https://www.ncua.gov/newsroom';

      results.push({
        external_id: `ncua-news-${slugify(title)}`,
        organization: extractOrgFromTitle(title) || 'Credit Union (NCUA)',
        state: extractState(text),
        notification_date: parseDate(dateText),
        breach_type: detectBreachType(text),
        source: SOURCE,
        source_url: url,
        description: truncate(title, 300),
        status: 'regulatory_notice',
      });
    });
  } catch {
    // Ignore newsroom fetch errors
  }
}

function extractOrgFromTitle(title) {
  const match = title.match(/([A-Z][A-Za-z\s]+(?:credit union|fcu|ccu))/i);
  return match ? match[1].trim() : null;
}

function detectBreachType(text) {
  const t = text.toLowerCase();
  if (t.includes('ransomware')) return 'Ransomware';
  if (t.includes('phishing')) return 'Phishing';
  if (t.includes('hack') || t.includes('unauthorized access')) return 'Unauthorized Access/Hacking';
  if (t.includes('malware')) return 'Malware';
  if (t.includes('insider')) return 'Insider Threat';
  if (t.includes('third party') || t.includes('vendor')) return 'Third-Party/Vendor';
  return 'Security Incident';
}

function extractRecords(text) {
  const m = text.match(/(\d[\d,]+)\s*(?:members?|individuals?|records?|accounts?)/i);
  if (m) return parseInt(m[1].replace(/,/g, ''));
  return null;
}

function extractDataTypes(text) {
  const found = [];
  const t = text.toLowerCase();
  if (t.includes('social security') || t.includes('ssn')) found.push('SSN');
  if (t.includes('account')) found.push('Account Information');
  if (t.includes('financial')) found.push('Financial Data');
  if (t.includes('personal') || t.includes('pii')) found.push('PII');
  return found.length ? found.join(', ') : null;
}

function extractState(text) {
  const states = {
    Alabama: 'AL', Alaska: 'AK', Arizona: 'AZ', Arkansas: 'AR', California: 'CA',
    Colorado: 'CO', Connecticut: 'CT', Delaware: 'DE', Florida: 'FL', Georgia: 'GA',
    Hawaii: 'HI', Idaho: 'ID', Illinois: 'IL', Indiana: 'IN', Iowa: 'IA',
    Kansas: 'KS', Kentucky: 'KY', Louisiana: 'LA', Maine: 'ME', Maryland: 'MD',
    Massachusetts: 'MA', Michigan: 'MI', Minnesota: 'MN', Mississippi: 'MS',
    Missouri: 'MO', Montana: 'MT', Nebraska: 'NE', Nevada: 'NV',
    'New Hampshire': 'NH', 'New Jersey': 'NJ', 'New Mexico': 'NM', 'New York': 'NY',
    'North Carolina': 'NC', 'North Dakota': 'ND', Ohio: 'OH', Oklahoma: 'OK',
    Oregon: 'OR', Pennsylvania: 'PA', 'Rhode Island': 'RI', 'South Carolina': 'SC',
    'South Dakota': 'SD', Tennessee: 'TN', Texas: 'TX', Utah: 'UT',
    Vermont: 'VT', Virginia: 'VA', Washington: 'WA', 'West Virginia': 'WV',
    Wisconsin: 'WI', Wyoming: 'WY',
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
  return (str || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 50);
}

function truncate(str, max) {
  if (!str) return null;
  return str.length > max ? str.slice(0, max) + '…' : str;
}

module.exports = { fetchNCUA, SOURCE };
