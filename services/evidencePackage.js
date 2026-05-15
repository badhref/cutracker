'use strict';

function pad(str, width) {
  return String(str || '').padEnd(width);
}

function line(char, width) {
  return char.repeat(width || 80);
}

function section(title) {
  return `\n${line('=')}\n${title}\n${line('-')}\n`;
}

function fmt(val) {
  return val || '(not available)';
}

// ── Referral guidance by risk level ───────────────────────────────────────────
function getNextSteps(riskLevel) {
  const steps = [];
  if (riskLevel === 'critical' || riskLevel === 'high') {
    steps.push('1. Contact the domain registrar abuse desk to report the suspected fraudulent domain.');
    steps.push('2. Identify and notify the hosting provider via their abuse reporting mechanism.');
    steps.push('3. Consider filing a report with CISA (https://www.cisa.gov/report) for critical infrastructure threats.');
    steps.push('4. File a complaint with the Internet Crime Complaint Center (IC3) at https://www.ic3.gov');
    steps.push('5. Notify the NCUA Office of Inspector General (OIG) at (800) 827-9950 or ncua.gov/about-ncua/oig');
    steps.push('6. Coordinate with your institution\'s legal and compliance teams before any external contact.');
  } else if (riskLevel === 'suspicious') {
    steps.push('1. Collect additional evidence: attempt WHOIS lookup for registrant information.');
    steps.push('2. Review linked pages and any social media presence associated with the domain.');
    steps.push('3. Monitor the site for changes over the next 7-14 days.');
    steps.push('4. Document all findings in the case file before escalation.');
    steps.push('5. Consider requesting a second analyst review before taking further action.');
  } else {
    steps.push('1. Continue passive monitoring of this site for 30 days.');
    steps.push('2. Re-investigate if new evidence emerges or risk score changes.');
    steps.push('3. Mark status as "Needs More Evidence" if you identify new indicators.');
  }
  return steps.join('\n');
}

// ── Main exported function ────────────────────────────────────────────────────
function generateEvidencePackage(site, evidence, aiAnalysis, relatedSites, clusters) {
  const now = new Date().toISOString();
  const lines = [];

  lines.push(line('='));
  lines.push('SUSPECTED SITE INVESTIGATION REPORT');
  lines.push(line('='));
  lines.push(`Generated:     ${now}`);
  lines.push(`Site URL:      ${fmt(site.url)}`);
  lines.push(`Domain:        ${fmt(site.domain)}`);
  lines.push(`Risk Level:    ${(site.risk_level || 'unknown').toUpperCase()}`);
  lines.push(`Risk Score:    ${site.risk_score ?? 0}`);
  lines.push(`Analyst Status: ${fmt(site.analyst_status)}`);
  lines.push('');
  lines.push('IMPORTANT: This report contains a mix of observed facts, algorithmic findings,');
  lines.push('AI-generated observations, and analyst conclusions. All findings require human');
  lines.push('analyst review before any action is taken.');

  // ── SECTION 1: OBSERVED FACTS ──────────────────────────────────────────────
  lines.push(section('SECTION 1: OBSERVED FACTS'));
  lines.push(`URL:              ${fmt(site.url)}`);
  lines.push(`Normalized URL:   ${fmt(site.normalized_url)}`);
  lines.push(`Domain:           ${fmt(site.domain)}`);
  lines.push(`First Seen:       ${fmt(site.first_seen)}`);
  lines.push(`Last Seen:        ${fmt(site.last_seen)}`);
  lines.push(`Source:           ${fmt(site.source)}`);
  lines.push(`Page Title:       ${fmt(site.title)}`);
  lines.push(`Meta Description: ${fmt(site.meta_description)}`);
  lines.push(`Favicon Hash:     ${fmt(site.favicon_hash)}`);
  lines.push(`HTML Fingerprint: ${fmt(site.html_fingerprint)}`);

  const scoringEvidence = (evidence || []).filter(e => e.evidence_type === 'scoring_factor');
  const otherEvidence = (evidence || []).filter(e => e.evidence_type !== 'scoring_factor');

  // ── SECTION 2: DETERMINISTIC FINDINGS ─────────────────────────────────────
  lines.push(section('SECTION 2: DETERMINISTIC FINDINGS (Algorithmic — No Inference)'));
  lines.push(`Overall Risk Score: ${site.risk_score ?? 0} (${(site.risk_level || '').toUpperCase()})`);
  lines.push('');
  lines.push('Scoring Factors:');
  if (scoringEvidence.length === 0) {
    lines.push('  (No scoring factor records found)');
  } else {
    for (const e of scoringEvidence) {
      try {
        const f = JSON.parse(e.evidence_value);
        lines.push(`  [+${pad(f.points, 3)}] ${f.key}`);
        lines.push(`         ${f.reason}`);
      } catch {
        lines.push(`  ${e.evidence_value}`);
      }
    }
  }

  // ── SECTION 3: AI-GENERATED OBSERVATIONS ──────────────────────────────────
  lines.push(section('SECTION 3: AI-GENERATED OBSERVATIONS'));
  lines.push('*** THESE OBSERVATIONS ARE AI-GENERATED AND HAVE NOT BEEN VERIFIED ***');
  lines.push('*** THEY REQUIRE HUMAN ANALYST REVIEW BEFORE ANY ACTION IS TAKEN   ***');
  lines.push('');
  if (!aiAnalysis) {
    lines.push('AI analysis has not been run for this site.');
    lines.push('Use "Run AI Analysis" in the application to generate AI observations.');
  } else {
    let parsed = null;
    try {
      parsed = typeof aiAnalysis.analysis_json === 'string'
        ? JSON.parse(aiAnalysis.analysis_json)
        : aiAnalysis.analysis_json;
    } catch {
      parsed = null;
    }

    lines.push(`Model:           ${fmt(aiAnalysis.model)}`);
    lines.push(`Run At:          ${fmt(aiAnalysis.created_at)}`);
    lines.push('');

    if (parsed) {
      lines.push(`Classification:  ${fmt(parsed.classification)}`);
      lines.push(`Confidence:      ${fmt(parsed.confidence)}`);
      lines.push(`NCUA Claim Detected: ${parsed.ncua_claim_detected ? 'YES' : 'NO'}`);
      lines.push('');
      lines.push('Summary:');
      lines.push(`  ${fmt(parsed.summary)}`);
      lines.push('');
      lines.push('Red Flags Identified:');
      (parsed.red_flags || []).forEach((f, i) => lines.push(`  ${i + 1}. ${f}`));
      if (!parsed.red_flags?.length) lines.push('  (none listed)');
      lines.push('');
      lines.push('Possible Benign Explanations:');
      (parsed.benign_explanations || []).forEach((f, i) => lines.push(`  ${i + 1}. ${f}`));
      if (!parsed.benign_explanations?.length) lines.push('  (none listed)');
      lines.push('');
      lines.push('Recommended Pivots:');
      (parsed.recommended_pivots || []).forEach((f, i) => lines.push(`  ${i + 1}. ${f}`));
      if (!parsed.recommended_pivots?.length) lines.push('  (none listed)');
      lines.push('');
      lines.push(`Recommended Next Action: ${fmt(parsed.recommended_next_action)}`);
      lines.push('');
      lines.push(`Analyst Note: ${fmt(parsed.analyst_note)}`);
    } else {
      lines.push(`Summary: ${fmt(aiAnalysis.summary)}`);
      lines.push('(Full analysis JSON could not be parsed)');
    }
  }

  // ── SECTION 4: ANALYST CONCLUSIONS ────────────────────────────────────────
  lines.push(section('SECTION 4: ANALYST CONCLUSIONS (Human-Entered)'));
  lines.push(`Analyst Status: ${fmt(site.analyst_status)}`);
  lines.push('');
  lines.push('Notes:');
  lines.push(site.notes ? `  ${site.notes}` : '  (no analyst notes recorded)');

  // ── SECTION 5: EXTRACTED INDICATORS ───────────────────────────────────────
  lines.push(section('SECTION 5: EXTRACTED INDICATORS'));

  const indicatorTypes = [
    { type: 'email',          label: 'Email Addresses' },
    { type: 'phone',          label: 'Phone Numbers' },
    { type: 'address',        label: 'Physical Addresses' },
    { type: 'routing_number', label: 'Routing Numbers' },
    { type: 'charter_number', label: 'Charter Numbers' },
    { type: 'analytics_id',   label: 'Analytics IDs' },
    { type: 'login_form',     label: 'Login Form' },
    { type: 'ncua_language',  label: 'NCUA Language Snippets' },
  ];

  for (const { type, label } of indicatorTypes) {
    const items = otherEvidence.filter(e => e.evidence_type === type);
    lines.push(`${label}:`);
    if (items.length === 0) {
      lines.push('  (none detected)');
    } else {
      items.forEach(e => lines.push(`  - ${e.evidence_value}`));
    }
    lines.push('');
  }

  // ── SECTION 6: RELATED SITES ───────────────────────────────────────────────
  lines.push(section('SECTION 6: RELATED SITES (Possible Infrastructure Overlap)'));
  lines.push('NOTE: Similarity scores indicate shared technical indicators only.');
  lines.push('They do NOT constitute confirmed attribution to the same actor.');
  lines.push('');
  if (!relatedSites || relatedSites.length === 0) {
    lines.push('No sites with possible infrastructure overlap have been identified.');
    lines.push('Run "Find Similar Sites" in the application to compare against known sites.');
  } else {
    relatedSites.forEach((r, i) => {
      lines.push(`${i + 1}. ${r.domain || r.url}`);
      lines.push(`   Similarity Score: ${r.similarity_score}`);
      lines.push(`   Risk Level: ${r.risk_level || 'unknown'}`);
      let indicators = [];
      try {
        indicators = typeof r.shared_indicators_json === 'string'
          ? JSON.parse(r.shared_indicators_json)
          : (r.shared_indicators_json || []);
      } catch { indicators = []; }
      if (indicators.length) {
        lines.push(`   Shared Indicators: ${indicators.join(', ')}`);
      }
      lines.push('');
    });
  }

  // ── SECTION 7: RECOMMENDED NEXT STEPS ─────────────────────────────────────
  lines.push(section('SECTION 7: RECOMMENDED NEXT STEPS'));
  lines.push(`Based on risk level: ${(site.risk_level || 'watch').toUpperCase()}`);
  lines.push('');
  lines.push(getNextSteps(site.risk_level));

  // ── DISCLAIMER ─────────────────────────────────────────────────────────────
  lines.push('');
  lines.push(line('='));
  lines.push('DISCLAIMER');
  lines.push(line('-'));
  lines.push('This report contains a mix of observed facts, algorithmic findings,');
  lines.push('AI-generated observations, and analyst conclusions. All findings require human');
  lines.push('analyst review before any action is taken. This report does not constitute');
  lines.push('legal or law enforcement findings. Use of this report for enforcement action');
  lines.push('must be reviewed by qualified legal counsel.');
  lines.push(line('='));

  return lines.join('\n');
}

module.exports = { generateEvidencePackage };
