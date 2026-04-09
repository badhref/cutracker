/**
 * California AG Breach Notifications
 *
 * The page loads ALL records inline (~3.3MB) in a jQuery DataTable.
 * Three columns: Organization Name | Date(s) of Breach | Reported Date
 *
 * List URL: https://oag.ca.gov/privacy/databreach/list
 * Detail:   https://oag.ca.gov/ecrime/databreach/reports/<id>
 *           (detail pages are not machine-readable — all useful data is in the list)
 */

const axios = require('axios');
const cheerio = require('cheerio');

const SOURCE = 'California AG';
const LIST_URL = 'https://oag.ca.gov/privacy/databreach/list';

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

async function fetchCaliforniaAG() {
  let html;
  try {
    const resp = await axios.get(LIST_URL, { timeout: 45000, headers: HEADERS });
    html = resp.data;
  } catch (err) {
    console.warn(`[CA AG] Fetch failed: ${err.message}`);
    return [];
  }

  const $ = cheerio.load(html);
  const results = [];

  // Columns: [0] Organization Name  [1] Date(s) of Breach  [2] Reported Date
  $('table tbody tr').each((_, row) => {
    const cells = $(row).find('td');
    if (cells.length < 3) return;

    const org          = $(cells[0]).text().trim();
    const breachDates  = $(cells[1]).text().trim();   // e.g. "10/20/2025" or "n/a"
    const reportedDate = $(cells[2]).text().trim();   // e.g. "02/04/2026"
    const detailUrl    = $(cells[0]).find('a').attr('href') || LIST_URL;

    if (!isCreditUnion(org)) return;

    // breach date — some entries have multiple dates ("08/10/2025, 08/13/2025"), take the first
    const firstBreachDate = breachDates.split(',')[0].trim();

    // Generate a stable external_id from the detail URL path or org+reported date
    const urlId = detailUrl.match(/reports\/([^/?#]+)/)?.[1];
    const extId = urlId
      ? `ca-ag-${urlId}`
      : `ca-ag-${slugify(org)}-${reportedDate.replace(/\D/g, '')}`;

    results.push({
      external_id: extId,
      organization: org,
      organization_type: 'credit_union',
      state: 'CA',
      breach_date: parseDate(firstBreachDate),
      notification_date: parseDate(reportedDate),
      source: SOURCE,
      source_url: detailUrl,
      description: buildDescription(org, breachDates, reportedDate),
      status: 'reported',
      is_manual: 0,
    });
  });

  console.log(`[CA AG] Found ${results.length} credit union entries`);
  return results;
}

function buildDescription(org, breachDates, reportedDate) {
  const parts = [`California AG notification: ${org}`];
  if (breachDates && breachDates !== 'n/a') parts.push(`Breach: ${breachDates}`);
  if (reportedDate) parts.push(`Reported: ${reportedDate}`);
  return parts.join(' — ');
}

function parseDate(str) {
  if (!str || str === 'n/a') return null;
  // MM/DD/YYYY
  const m = str.trim().match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (m) return `${m[3]}-${m[1].padStart(2, '0')}-${m[2].padStart(2, '0')}`;
  const d = new Date(str);
  return isNaN(d.getTime()) ? null : d.toISOString().split('T')[0];
}

function slugify(str) {
  return (str || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 50);
}

module.exports = { fetchCaliforniaAG, SOURCE };
