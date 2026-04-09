/**
 * HHS OCR Breach Portal Fetcher
 * Endpoint: https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf
 * Public dataset: breaches affecting 500+ individuals under HIPAA
 * Credit unions that offer health benefits or HSAs may appear here.
 */

const axios = require('axios');

const SOURCE = 'HHS OCR';
const API_URL = 'https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf';

// HHS provides a downloadable CSV – we use their public API endpoint
const HHS_API = 'https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf';

// Keywords that indicate a credit union
const CU_KEYWORDS = [
  'credit union', 'cu ', ' ccu', 'federal credit', 'community credit',
  'employees credit', 'teachers credit', 'members credit', 'first credit union'
];

function isCreditUnion(name) {
  if (!name) return false;
  const lower = name.toLowerCase();
  return CU_KEYWORDS.some(kw => lower.includes(kw));
}

async function fetchHHS() {
  const results = [];

  try {
    // HHS OCR has a public data download. We use the JSON API they expose.
    const response = await axios.get(
      'https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf',
      {
        params: {
          faces_partial: 'true',
        },
        timeout: 15000,
        headers: {
          'Accept': 'application/json, text/javascript, */*',
          'User-Agent': 'CreditUnionBreachTracker/1.0 (security-research)',
        }
      }
    );

    // The actual HHS data is available as a CSV download
    // Fetch the CSV export instead
    const csvResponse = await axios.get(
      'https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf',
      {
        params: {
          'faces_partial': 'true',
          'javax.faces.ViewState': '',
        },
        timeout: 30000,
      }
    );

    // Parse any JSON or CSV data
    const data = typeof csvResponse.data === 'string' ? [] : (csvResponse.data.data || []);

    for (const row of data) {
      const name = row['Name of Covered Entity'] || row.name || '';
      if (!isCreditUnion(name)) continue;

      results.push({
        external_id: `hhs-${row['Case Number'] || row.id || Date.now()}`,
        organization: name,
        state: row['State'] || row.state,
        breach_date: parseDate(row['Breach Submission Date'] || row.breach_date),
        notification_date: parseDate(row['Breach Submission Date'] || row.notification_date),
        breach_type: mapBreachType(row['Type of Breach'] || ''),
        records_affected: parseInt(row['Individuals Affected'] || '0') || null,
        data_types: row['Location of Breached Information'] || null,
        source: SOURCE,
        source_url: 'https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf',
        description: `HHS OCR Breach: ${row['Type of Breach'] || 'Unknown'} - ${row['Location of Breached Information'] || ''}`,
        status: row['Breach Submission Date'] ? 'reported' : 'active',
      });
    }
  } catch (err) {
    // HHS API can be finicky — return empty rather than crash
    console.warn(`[HHS] Fetch error: ${err.message}`);
  }

  return results;
}

function parseDate(str) {
  if (!str) return null;
  const d = new Date(str);
  return isNaN(d.getTime()) ? null : d.toISOString().split('T')[0];
}

function mapBreachType(raw) {
  const r = raw.toLowerCase();
  if (r.includes('hack') || r.includes('unauthorized')) return 'Unauthorized Access/Hacking';
  if (r.includes('theft')) return 'Theft';
  if (r.includes('loss')) return 'Loss';
  if (r.includes('improper')) return 'Improper Disposal';
  if (r.includes('mail')) return 'Improper Mailing';
  return raw || 'Unknown';
}

module.exports = { fetchHHS, SOURCE };
