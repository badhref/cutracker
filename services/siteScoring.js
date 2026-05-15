'use strict';

// ── Risk level thresholds ──────────────────────────────────────────────────────
// known_legitimate is returned directly from the legitimacy gate (not via this fn).
function scoreToLevel(score) {
  if (score >= 90) return 'high';
  if (score >= 60) return 'suspicious';
  if (score >= 30) return 'unverified';
  return 'watch';
}

// ── Suspicious domain pattern detection ───────────────────────────────────────
// Patterns commonly seen in phishing / credential-harvesting domains
const SUSPICIOUS_DOMAIN_PATTERNS = [
  /secure[-_]login/i,
  /member[-_]update/i,
  /account[-_]alert/i,
  /account[-_]verify/i,
  /verify[-_]account/i,
  /online[-_]access/i,
  /online[-_]banking/i,
  /my[-_]account/i,
  /signin[-_]/i,
  /[-_]signin/i,
  /login[-_]/i,
  /[-_]login/i,
  /update[-_]info/i,
  /confirm[-_]/i,
  /[-_]confirm/i,
  /secure[-_]access/i,
  /cuonline/i,
  /cuaccess/i,
  /memberaccess/i,
];

// ── Scoring rules ──────────────────────────────────────────────────────────────
// Accepts an optional ncuaResult (second argument) to gate on legitimacy first.
// If ncuaResult.status === 'known_legitimate', returns score=0 immediately.
function scoreSite(investigationResult, ncuaResult) {
  const r    = investigationResult || {};
  const ncua = ncuaResult || {};

  // ── Legitimacy gate ─────────────────────────────────────────────────────────
  // Known-legitimate domains must never accumulate risk points. Legitimate CUs
  // say "NCUA insured", have login forms, and use credit-union language. That
  // is correct behaviour for a real institution, not a red flag.
  if (ncua.status === 'known_legitimate') {
    return {
      score:   0,
      level:   'known_legitimate',
      factors: [
        {
          key:    'known_legitimate',
          points: 0,
          label:  'trust',
          reason: `Domain verified as a known-legitimate site (${ncua.matched_name || ncua.matched_domain}). Risk scoring suppressed.`,
        },
      ],
    };
  }

  // ── Risk factor accumulation ────────────────────────────────────────────────
  const factors = [];
  const bodyLower   = (r.body_text    || '').toLowerCase();
  const titleLower  = (r.title        || '').toLowerCase();
  const domainLower = (r.domain       || '').toLowerCase();
  const footerLower = (r.footer_text  || '').toLowerCase();

  // suspicious_domain_pattern: +25
  // High-signal indicator — real CUs don't need "secure-login" in the domain
  const suspiciousDomainMatch = SUSPICIOUS_DOMAIN_PATTERNS.find(re => re.test(domainLower));
  if (suspiciousDomainMatch) {
    factors.push({
      key:    'suspicious_domain_pattern',
      points: 25,
      label:  'suspicious',
      reason: `Domain contains a pattern associated with phishing or credential harvesting (matched: ${suspiciousDomainMatch.source})`,
    });
  }

  // ncua_insurance_claim: +35
  // Specific insurance claim language is unusual for unknown domains
  const hasSpecificClaim = (r.ncua_language || []).some(s =>
    /federally insured by ncua/i.test(s) || /insured by ncua/i.test(s)
  );
  if (hasSpecificClaim) {
    factors.push({
      key:    'ncua_insurance_claim',
      points: 35,
      label:  'suspicious',
      reason: 'Page contains specific "federally insured by NCUA" or "insured by NCUA" language on an unverified domain',
    });
  }

  // ncua_mention: +20 (only if not already flagged for specific insurance claim)
  const hasAnyNcua = (r.ncua_language || []).length > 0;
  if (hasAnyNcua && !hasSpecificClaim) {
    factors.push({
      key:    'ncua_mention',
      points: 20,
      label:  'suspicious',
      reason: 'Page mentions NCUA or National Credit Union Administration without a specific federal insurance claim',
    });
  }

  // federal_share_insurance: +20
  const hasFederalShareInsurance =
    bodyLower.includes('federal share insurance') ||
    bodyLower.includes('share insurance fund');
  if (hasFederalShareInsurance) {
    factors.push({
      key:    'federal_share_insurance',
      points: 20,
      label:  'suspicious',
      reason: 'Page mentions "federal share insurance" or "share insurance fund" on an unverified domain',
    });
  }

  // credit_union_mention: +15
  // Only meaningful when combined with other signals — single-indicator for context
  const hasCuMention =
    titleLower.includes('credit union') ||
    titleLower.includes('creditunion') ||
    domainLower.includes('creditunion') ||
    bodyLower.includes('credit union');
  if (hasCuMention) {
    factors.push({
      key:    'credit_union_mention',
      points: 15,
      label:  'neutral',
      reason: 'Title, domain, or page body contains "credit union" — contextual indicator, review with other signals',
    });
  }

  // login_form: +10
  if (r.has_login_form) {
    factors.push({
      key:    'login_form',
      points: 10,
      label:  'neutral',
      reason: 'Password input field detected — possible member login portal (common on both real and fraudulent sites)',
    });
  }

  // routing_number_present: +20
  if ((r.routing_numbers || []).length > 0) {
    factors.push({
      key:    'routing_number_present',
      points: 20,
      label:  'suspicious',
      reason: `Routing number(s) found on page: ${r.routing_numbers.join(', ')}`,
    });
  }

  // charter_number_present: +15
  if ((r.charter_numbers || []).length > 0) {
    factors.push({
      key:    'charter_number_present',
      points: 15,
      label:  'neutral',
      reason: `Charter number(s) found near "charter" keyword: ${r.charter_numbers.join(', ')} — verify against NCUA records`,
    });
  }

  // suspicious_free_email: +15
  const freeEmailDomains = [
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
    'protonmail.com', 'proton.me',
  ];
  const hasFreeEmail = (r.emails || []).some(email =>
    freeEmailDomains.some(d => email.toLowerCase().endsWith('@' + d))
  );
  if (hasFreeEmail) {
    factors.push({
      key:    'suspicious_free_email',
      points: 15,
      label:  'suspicious',
      reason: 'Contact email uses a free consumer email provider (e.g. Gmail, Yahoo) — unusual for a legitimate financial institution',
    });
  }

  // new_domain_indicator: +10
  const domainAgeDays = r.domain_age_days ?? null;
  if (domainAgeDays !== null && domainAgeDays < 90) {
    factors.push({
      key:    'new_domain_indicator',
      points: 10,
      label:  'suspicious',
      reason: `Domain is approximately ${domainAgeDays} days old — recently registered domains may indicate fraudulent activity`,
    });
  }

  // suspicious_footer: +10
  const hasFooterNcua =
    footerLower.length > 0 && (
      footerLower.includes('ncua') ||
      footerLower.includes('federal share insurance') ||
      footerLower.includes('federally insured')
    );
  if (hasFooterNcua) {
    factors.push({
      key:    'suspicious_footer',
      points: 10,
      label:  'neutral',
      reason: 'Footer contains NCUA or federal insurance language — review in context; legitimate CUs display this too',
    });
  }

  const score = factors.reduce((sum, f) => sum + f.points, 0);
  const level = scoreToLevel(score);

  return { score, level, factors };
}

module.exports = { scoreSite, scoreToLevel };
