/**
 * Identity Theft Resource Center (ITRC) Breach Database
 * ITRC maintains one of the most comprehensive breach databases.
 * They publish annual reports and some data is accessible via their website.
 * URL: https://www.idtheftcenter.org/data-breach-reports/
 */

const axios = require('axios');
const cheerio = require('cheerio');

const SOURCE = 'ITRC';
const BASE_URL = 'https://www.idtheftcenter.org/data-breach-reports/';
const NOTIFIED_URL = 'https://notified.idtheftcenter.org/s/';

const CU_KEYWORDS = [
  'credit union', 'federal credit', 'community credit', 'employees credit',
  'teachers credit', 'members credit', 'ccu', 'fcu', 'credit unions'
];

function isCreditUnion(text) {
  if (!text) return false;
  const lower = text.toLowerCase();
  return CU_KEYWORDS.some(kw => lower.includes(kw));
}

async function fetchITRC() {
  const results = [];

  try {
    // Try ITRC's notified.idtheftcenter.org which has a searchable DB
    const searchResp = await axios.post(
      'https://notified.idtheftcenter.org/s/sfsites/aura',
      new URLSearchParams({
        message: JSON.stringify({
          actions: [{
            id: '1;a',
            descriptor: 'aura://ApexActionController/ACTION$execute',
            callingDescriptor: 'UNKNOWN',
            params: {
              classname: 'DataBreachSearchController',
              method: 'searchBreaches',
              params: {
                searchTerm: 'credit union',
                sectorFilter: 'Financial Services',
                pageSize: 100,
                pageNumber: 1,
              }
            }
          }]
        }),
        aura_context: JSON.stringify({ mode: 'PROD', fwuid: '', app: 'c:app', loaded: {}, dn: [], globals: {}, uad: true }),
        aura_token: 'undefined',
      }),
      {
        timeout: 20000,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'CreditUnionBreachTracker/1.0 (security-research)',
        }
      }
    );

    const body = searchResp.data;
    const actions = body.actions || [];
    for (const action of actions) {
      const records = action.returnValue?.returnValue?.data || action.returnValue?.data || [];
      for (const rec of records) {
        const name = rec.Name || rec.organizationName || '';
        if (!isCreditUnion(name)) continue;
        results.push(mapITRCRecord(rec));
      }
    }

  } catch {
    // ITRC's Salesforce backend may not be accessible — fall back to HTML
  }

  if (results.length === 0) {
    await fetchITRCHtml(results);
  }

  return results;
}

async function fetchITRCHtml(results) {
  try {
    const resp = await axios.get(BASE_URL, {
      timeout: 20000,
      headers: {
        'User-Agent': 'CreditUnionBreachTracker/1.0 (security-research)',
        'Accept': 'text/html',
      }
    });

    const $ = cheerio.load(resp.data);

    $('table tr, .breach-entry, article').each((i, el) => {
      const text = $(el).text();
      if (!isCreditUnion(text)) return;

      const cells = $(el).find('td');
      const orgName = cells.length > 0
        ? $(cells[0]).text().trim()
        : $(el).find('h2, h3, .org-name, strong').first().text().trim();

      if (!orgName) return;

      const dateText = cells.length > 1 ? $(cells[1]).text().trim() : '';
      const sectorText = cells.length > 2 ? $(cells[2]).text().trim() : '';

      results.push({
        external_id: `itrc-${slugify(orgName)}-${dateText.replace(/\D/g, '').slice(0, 8)}`,
        organization: orgName,
        state: extractState(text),
        notification_date: parseDate(dateText),
        breach_type: detectBreachType(text),
        records_affected: extractRecords(text),
        data_types: extractDataTypes(text),
        source: SOURCE,
        source_url: BASE_URL,
        description: truncate(`ITRC: ${text}`, 400),
        status: 'reported',
      });
    });
  } catch (err) {
    console.warn(`[ITRC] HTML fetch error: ${err.message}`);
  }
}

function mapITRCRecord(rec) {
  return {
    external_id: `itrc-${rec.Id || slugify(rec.Name)}`,
    organization: rec.Name || rec.organizationName || 'Unknown',
    state: rec.State__c || rec.state || null,
    breach_date: parseDate(rec.Breach_Date__c || rec.breachDate),
    notification_date: parseDate(rec.Notification_Date__c || rec.notificationDate || rec.Date_Posted__c),
    breach_type: rec.Type_of_Breach__c || rec.breachType || null,
    attack_vector: rec.Attack_Vector__c || null,
    records_affected: parseInt(rec.Records_Affected__c || rec.recordsAffected || '0') || null,
    data_types: rec.Type_of_Info_Compromised__c || rec.dataTypes || null,
    source: SOURCE,
    source_url: rec.URL__c || BASE_URL,
    description: rec.Description__c || rec.summary || null,
    status: 'reported',
  };
}

function detectBreachType(text) {
  const t = text.toLowerCase();
  if (t.includes('ransomware')) return 'Ransomware';
  if (t.includes('phishing')) return 'Phishing';
  if (t.includes('hack') || t.includes('unauthorized')) return 'Unauthorized Access/Hacking';
  if (t.includes('malware')) return 'Malware';
  if (t.includes('insider')) return 'Insider Threat';
  if (t.includes('vendor') || t.includes('third party')) return 'Third-Party/Vendor';
  if (t.includes('accidental') || t.includes('exposed') || t.includes('misconfigur')) return 'Accidental Exposure';
  return 'Data Breach';
}

function extractRecords(text) {
  const m = text.match(/(\d[\d,]+)\s*(?:million)?\s*(?:individuals?|records?|members?|accounts?)/i);
  if (m) {
    let n = parseInt(m[1].replace(/,/g, ''));
    if (m[0].toLowerCase().includes('million')) n *= 1_000_000;
    return n;
  }
  return null;
}

function extractDataTypes(text) {
  const found = [];
  const t = text.toLowerCase();
  if (t.includes('social security') || t.includes('ssn')) found.push('SSN');
  if (t.includes('account number')) found.push('Account Number');
  if (t.includes('credit card') || t.includes('debit card')) found.push('Payment Card');
  if (t.includes("driver's license")) found.push("Driver's License");
  if (t.includes('date of birth')) found.push('Date of Birth');
  if (t.includes('email')) found.push('Email');
  if (t.includes('password')) found.push('Credentials');
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

module.exports = { fetchITRC, SOURCE };
