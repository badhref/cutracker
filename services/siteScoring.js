'use strict';

// ── Risk level thresholds ──────────────────────────────────────────────────────
function scoreToLevel(score) {
  if (score >= 100) return 'critical';
  if (score >= 70)  return 'high';
  if (score >= 40)  return 'suspicious';
  return 'watch';
}

// ── Scoring rules (fully transparent) ─────────────────────────────────────────
function scoreSite(investigationResult) {
  const r = investigationResult || {};
  const factors = [];

  // ncua_insurance_claim: +40
  const hasSpecificClaim = (r.ncua_language || []).some(s =>
    /federally insured by ncua/i.test(s) || /insured by ncua/i.test(s)
  );
  if (hasSpecificClaim) {
    factors.push({
      key: 'ncua_insurance_claim',
      points: 40,
      reason: 'Page contains specific "federally insured by NCUA" or "insured by NCUA" language',
    });
  }

  // ncua_mention: +25 (only if not already counted for specific claim)
  const hasAnyNcua = (r.ncua_language || []).length > 0;
  if (hasAnyNcua && !hasSpecificClaim) {
    factors.push({
      key: 'ncua_mention',
      points: 25,
      reason: 'Page mentions NCUA or National Credit Union Administration without the specific federal insurance claim',
    });
  }

  // federal_share_insurance: +25
  const bodyLower = (r.body_text || '').toLowerCase();
  const hasFederalShareInsurance =
    bodyLower.includes('federal share insurance') ||
    bodyLower.includes('share insurance fund');
  if (hasFederalShareInsurance) {
    factors.push({
      key: 'federal_share_insurance',
      points: 25,
      reason: 'Page mentions "federal share insurance" or "share insurance fund"',
    });
  }

  // credit_union_mention: +20
  const titleLower = (r.title || '').toLowerCase();
  const domainLower = (r.domain || '').toLowerCase();
  const hasCuMention =
    titleLower.includes('credit union') ||
    titleLower.includes('creditunion') ||
    domainLower.includes('credit') ||
    domainLower.includes('creditunion') ||
    domainLower.includes('cu') ||
    bodyLower.includes('credit union');
  if (hasCuMention) {
    factors.push({
      key: 'credit_union_mention',
      points: 20,
      reason: 'Title or domain contains "credit union" or "creditunion"',
    });
  }

  // login_form: +15
  if (r.has_login_form) {
    factors.push({
      key: 'login_form',
      points: 15,
      reason: 'Password input field detected on one or more pages — possible member login portal',
    });
  }

  // routing_number_present: +20
  if ((r.routing_numbers || []).length > 0) {
    factors.push({
      key: 'routing_number_present',
      points: 20,
      reason: `Routing number(s) found on page: ${r.routing_numbers.join(', ')}`,
    });
  }

  // charter_number_present: +15
  if ((r.charter_numbers || []).length > 0) {
    factors.push({
      key: 'charter_number_present',
      points: 15,
      reason: `Charter number(s) found near "charter" keyword: ${r.charter_numbers.join(', ')}`,
    });
  }

  // suspicious_free_email: +15
  const freeEmailDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com', 'proton.me'];
  const hasFreeEmail = (r.emails || []).some(email =>
    freeEmailDomains.some(d => email.toLowerCase().endsWith('@' + d))
  );
  if (hasFreeEmail) {
    factors.push({
      key: 'suspicious_free_email',
      points: 15,
      reason: 'Contact email uses a free consumer email provider (e.g. Gmail, Yahoo, Hotmail, Protonmail) — unusual for a legitimate financial institution',
    });
  }

  // new_domain_indicator: +10 (placeholder — requires external domain age data)
  const domainAgeDays = r.domain_age_days ?? null;
  if (domainAgeDays !== null && domainAgeDays < 90) {
    factors.push({
      key: 'new_domain_indicator',
      points: 10,
      reason: `Domain is approximately ${domainAgeDays} days old — recently registered domains may indicate fraudulent activity`,
    });
  }

  // suspicious_footer: +15
  const footerLower = (r.footer_text || '').toLowerCase();
  const hasFooterNcua =
    footerLower.length > 0 && (
      footerLower.includes('ncua') ||
      footerLower.includes('federal share insurance') ||
      footerLower.includes('federally insured')
    );
  if (hasFooterNcua) {
    factors.push({
      key: 'suspicious_footer',
      points: 15,
      reason: 'Footer contains NCUA or federal insurance language — commonly mimicked by fraudulent sites',
    });
  }

  const score = factors.reduce((sum, f) => sum + f.points, 0);
  const level = scoreToLevel(score);

  return { score, level, factors };
}

module.exports = { scoreSite, scoreToLevel };
