'use strict';

// ── Risk level thresholds ──────────────────────────────────────────────────────
// 'known_legitimate' is returned directly from the legitimacy gate.
// Numeric levels:
//   watch       0–29   — minimal signals, keep an eye on it
//   unverified  30–59  — looks like a CU, legitimacy not confirmed, low urgency
//   suspicious  60–89  — multiple concerning signals, analyst review required
//   high        90+    — strong evidence of fraudulent intent
function scoreToLevel(score) {
  if (score >= 90) return 'high';
  if (score >= 60) return 'suspicious';
  if (score >= 30) return 'unverified';
  return 'watch';
}

// ── Suspicious domain pattern detection ───────────────────────────────────────
// Patterns commonly found in phishing / credential-harvesting domains.
// Real credit unions do not need "secure-login" or "member-update" in their domain.
const SUSPICIOUS_DOMAIN_PATTERNS = [
  /secure[-_]login/i,
  /member[-_]update/i,
  /account[-_]alert/i,
  /account[-_]verify/i,
  /verify[-_]account/i,
  /online[-_]access/i,
  /online[-_]banking/i,
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

// ── Free email domains ─────────────────────────────────────────────────────────
const FREE_EMAIL_DOMAINS = [
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
  'protonmail.com', 'proton.me',
];

// ── Points awarded to CU-context signals when suspicious signals co-exist ─────
// These points ONLY apply when at least one suspicious signal is also present.
// If no suspicious signals: the site is marked 'unverified' at a flat 30 pts.
const CU_CONTEXT_POINTS = {
  ncua_insurance_claim:    20,
  ncua_mention:            10,
  federal_share_insurance: 12,
  credit_union_mention:     5,
  login_form:               8,
  routing_number_present:  12,
  charter_number_present:   5,
};

// ── Main scoring function ──────────────────────────────────────────────────────
// Accepts an optional ncuaResult (second arg) to gate on legitimacy.
//
// Design principle:
//   Credit union language, NCUA insurance claims, login forms, and routing
//   numbers are NORMAL for any real credit union. They should NOT by themselves
//   increase risk. They become meaningful indicators ONLY when combined with
//   overtly suspicious signals (bad domain patterns, free email, very new domain,
//   or a confirmed "no match" in the loaded NCUA dataset).
// ──────────────────────────────────────────────────────────────────────────────
function scoreSite(investigationResult, ncuaResult) {
  const r    = investigationResult || {};
  const ncua = ncuaResult || {};

  // ── Gate 1: known_legitimate — highest priority, always runs first ──────────
  if (ncua.status === 'known_legitimate') {
    return {
      score:   0,
      level:   'known_legitimate',
      factors: [
        {
          key:    'known_legitimate',
          points: 0,
          label:  'trust',
          reason: `Domain is in the verified allowlist (${ncua.matched_name || ncua.matched_domain}). Risk scoring suppressed — legitimate CUs are expected to display NCUA language, login forms, and credit-union terminology.`,
        },
      ],
    };
  }

  const bodyLower   = (r.body_text   || '').toLowerCase();
  const titleLower  = (r.title       || '').toLowerCase();
  const domainLower = (r.domain      || '').toLowerCase();

  // ── Gate 2: possible_match — approximate NCUA institution found ───────────
  // An approximate match in the NCUA dataset is a trust-reducing signal.
  // Cap score at 25 (unverified band) UNLESS overtly suspicious signals exist:
  // suspicious domain pattern or free consumer email. Those two signals are
  // unambiguous and override the positive match.
  if (ncua.status === 'possible_match') {
    const hasBadDomain = SUSPICIOUS_DOMAIN_PATTERNS.some(re => re.test(domainLower));
    const hasFreeEmail = (r.emails || []).some(email =>
      FREE_EMAIL_DOMAINS.some(d => email.toLowerCase().endsWith('@' + d))
    );
    if (!hasBadDomain && !hasFreeEmail) {
      return {
        score:  25,
        level:  'unverified',
        factors: [
          {
            key:    'possible_official_match',
            points: 25,
            label:  'trust',
            reason: `Approximate match found in NCUA institution dataset: "${ncua.matched_name || 'unknown institution'}". Score is capped — this site likely corresponds to a registered credit union. Analyst verification recommended to confirm the match before escalating.`,
          },
        ],
      };
    }
    // Suspicious signals exist alongside the NCUA match — fall through to full
    // scoring. The no_official_match penalty will NOT fire (status !== no_match_found).
  }

  // ── Detect overtly suspicious signals ────────────────────────────────────
  // These are unusual on ANY site, including legitimate credit unions.
  // They add points regardless of CU context.
  const suspiciousFactors = [];

  // suspicious_domain_pattern (+30)
  const suspiciousDomainMatch = SUSPICIOUS_DOMAIN_PATTERNS.find(re => re.test(domainLower));
  if (suspiciousDomainMatch) {
    suspiciousFactors.push({
      key:    'suspicious_domain_pattern',
      points: 30,
      label:  'suspicious',
      reason: `Domain contains a pattern common in phishing/credential-harvesting sites (matched: "${suspiciousDomainMatch.source}"). Legitimate credit unions do not include these patterns in their primary domain.`,
    });
  }

  // suspicious_free_email (+20)
  const hasFreeEmail = (r.emails || []).some(email =>
    FREE_EMAIL_DOMAINS.some(d => email.toLowerCase().endsWith('@' + d))
  );
  if (hasFreeEmail) {
    suspiciousFactors.push({
      key:    'suspicious_free_email',
      points: 20,
      label:  'suspicious',
      reason: 'Contact email uses a free consumer provider (Gmail, Yahoo, etc.). Federally insured financial institutions universally use institutional email addresses.',
    });
  }

  // new_domain_indicator (+15) — requires domain_age_days from external source
  const domainAgeDays = r.domain_age_days ?? null;
  if (domainAgeDays !== null && domainAgeDays < 90) {
    suspiciousFactors.push({
      key:    'new_domain_indicator',
      points: 15,
      label:  'suspicious',
      reason: `Domain registered approximately ${domainAgeDays} day(s) ago. Recently registered domains claiming to be financial institutions are a strong fraud signal.`,
    });
  }

  // no_official_match (+20) — only fires when NCUA DB is loaded and a real
  // search was performed. 'not_checked' means we can't make this inference.
  if (ncua.status === 'no_match_found') {
    suspiciousFactors.push({
      key:    'no_official_match',
      points: 20,
      label:  'suspicious',
      reason: 'NCUA institution database was searched and returned no matching institution. Every federally insured credit union is registered in NCUA records.',
    });
  }

  // ── Detect CU-context signals ─────────────────────────────────────────────
  // These are EXPECTED and NORMAL on legitimate credit union websites.
  // They are NOT suspicious by themselves.
  // They gain risk weight ONLY when suspicious signals also exist.
  const cuContextFactors = [];

  const hasSpecificNcuaClaim = (r.ncua_language || []).some(s =>
    /federally insured by ncua/i.test(s) || /insured by ncua/i.test(s)
  );
  if (hasSpecificNcuaClaim) {
    cuContextFactors.push({
      key:   'ncua_insurance_claim',
      label: 'neutral',
      reason: 'Page states "federally insured by NCUA" — standard disclosure for all federally insured credit unions; suspicious only in combination with other red flags.',
    });
  }

  const hasAnyNcua = (r.ncua_language || []).length > 0;
  if (hasAnyNcua && !hasSpecificNcuaClaim) {
    cuContextFactors.push({
      key:   'ncua_mention',
      label: 'neutral',
      reason: 'Page references NCUA — normal context for credit union websites.',
    });
  }

  const hasFederalShareInsurance =
    bodyLower.includes('federal share insurance') ||
    bodyLower.includes('share insurance fund');
  if (hasFederalShareInsurance) {
    cuContextFactors.push({
      key:   'federal_share_insurance',
      label: 'neutral',
      reason: 'Page mentions federal share insurance — standard language on any NCUA-insured credit union site.',
    });
  }

  const hasCuMention =
    titleLower.includes('credit union') ||
    titleLower.includes('creditunion') ||
    bodyLower.includes('credit union');
  if (hasCuMention) {
    cuContextFactors.push({
      key:   'credit_union_mention',
      label: 'neutral',
      reason: '"Credit union" language in title or body — expected on any credit union site.',
    });
  }

  if (r.has_login_form) {
    cuContextFactors.push({
      key:   'login_form',
      label: 'neutral',
      reason: 'Password input detected — standard for member online banking portals on both legitimate and fraudulent sites.',
    });
  }

  if ((r.routing_numbers || []).length > 0) {
    cuContextFactors.push({
      key:   'routing_number_present',
      label: 'neutral',
      reason: `Routing number(s) found: ${(r.routing_numbers || []).join(', ')}. Legitimate CUs publish these; verify against ABA records.`,
    });
  }

  if ((r.charter_numbers || []).length > 0) {
    cuContextFactors.push({
      key:   'charter_number_present',
      label: 'neutral',
      reason: `Charter number(s) found: ${(r.charter_numbers || []).join(', ')}. Verify against the NCUA charter registry.`,
    });
  }

  // ── Combine signals into final factors list ───────────────────────────────
  const hasSuspicious = suspiciousFactors.length > 0;
  const hasCuContext  = cuContextFactors.length > 0;
  const factors       = [];

  if (hasSuspicious && hasCuContext) {
    // The combination is the problem: credit-union impersonation attempt
    // Suspicious signals get full points; CU signals get escalated weight
    for (const f of suspiciousFactors) {
      factors.push(f);
    }
    for (const f of cuContextFactors) {
      factors.push({
        ...f,
        points: CU_CONTEXT_POINTS[f.key] ?? 5,
        label:  'suspicious',
        reason: f.reason + ' Elevated concern: combined with suspicious domain/contact signals above.',
      });
    }

  } else if (hasSuspicious && !hasCuContext) {
    // Suspicious signals without CU impersonation — score those signals alone
    for (const f of suspiciousFactors) {
      factors.push(f);
    }

  } else if (!hasSuspicious && hasCuContext) {
    // Site looks like a credit union but nothing overtly suspicious detected.
    // Status: unverified_legitimacy — needs human review, NOT high risk.
    // We push a single composite factor to reach the 'unverified' band (30–59).
    const datasetNote = ncua.status === 'not_checked'
      ? ' Official NCUA dataset not loaded — unable to confirm or deny this domain is registered. Classification reflects absence of suspicious signals only.'
      : '';
    factors.push({
      key:    'unverified_legitimacy',
      points: 30,
      label:  'neutral',
      reason: `Site presents credit union characteristics (NCUA language, member services, institutional terminology) but has not been verified against official records. This alone does not indicate fraud — many small or regional credit unions are not yet in the reference dataset.${datasetNote}`,
    });
    // Record each CU signal as informational (0 additional pts)
    for (const f of cuContextFactors) {
      factors.push({ ...f, points: 0 });
    }

  }
  // else: no signals at all → score stays 0, level 'watch'

  const score = factors.reduce((sum, f) => sum + (f.points ?? 0), 0);
  const level = scoreToLevel(score);

  return { score, level, factors };
}

module.exports = { scoreSite, scoreToLevel };
