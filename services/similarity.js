'use strict';

// ── Word overlap similarity (Jaccard-style) ────────────────────────────────────
function wordOverlap(a, b) {
  if (!a || !b) return 0;
  const setA = new Set(a.toLowerCase().split(/\s+/).filter(w => w.length > 2));
  const setB = new Set(b.toLowerCase().split(/\s+/).filter(w => w.length > 2));
  if (setA.size === 0 || setB.size === 0) return 0;
  let shared = 0;
  for (const w of setA) { if (setB.has(w)) shared++; }
  return shared / Math.max(setA.size, setB.size);
}

// ── Simple djb2 hash (same as siteInvestigator) ────────────────────────────────
function djb2(str) {
  let hash = 5381;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) + hash) ^ str.charCodeAt(i);
    hash = hash >>> 0;
  }
  return hash.toString(16);
}

// ── Parse comma-separated evidence values ─────────────────────────────────────
function splitValues(str) {
  if (!str) return [];
  return str.split(/[,|]+/).map(s => s.trim()).filter(Boolean);
}

// ── Compare two sites and compute similarity score ────────────────────────────
function compareSites(target, candidate, targetEvidence, candidateEvidence) {
  const indicators = [];
  let score = 0;

  const getEvidence = (evidence, type) =>
    (evidence || []).filter(e => e.evidence_type === type);

  // favicon_hash: +30
  if (
    target.favicon_hash &&
    candidate.favicon_hash &&
    target.favicon_hash === candidate.favicon_hash
  ) {
    score += 30;
    indicators.push('matching_favicon_hash');
  }

  // html_fingerprint: +25
  if (
    target.html_fingerprint &&
    candidate.html_fingerprint &&
    target.html_fingerprint === candidate.html_fingerprint
  ) {
    score += 25;
    indicators.push('matching_html_fingerprint');
  }

  // phone overlap: +25
  const targetPhones = splitValues(getEvidence(targetEvidence, 'phone').map(e => e.evidence_value).join(','));
  const candidatePhones = splitValues(getEvidence(candidateEvidence, 'phone').map(e => e.evidence_value).join(','));
  const sharedPhones = targetPhones.filter(p => candidatePhones.includes(p));
  if (sharedPhones.length > 0) {
    score += 25;
    indicators.push(`shared_phone(s): ${sharedPhones.join(', ')}`);
  }

  // email overlap: +20
  const targetEmails = splitValues(getEvidence(targetEvidence, 'email').map(e => e.evidence_value).join(','));
  const candidateEmails = splitValues(getEvidence(candidateEvidence, 'email').map(e => e.evidence_value).join(','));
  const sharedEmails = targetEmails.filter(e => candidateEmails.includes(e));
  if (sharedEmails.length > 0) {
    score += 20;
    indicators.push(`shared_email(s): ${sharedEmails.join(', ')}`);
  }

  // analytics_id overlap: +40
  const targetAnalytics = splitValues(getEvidence(targetEvidence, 'analytics_id').map(e => e.evidence_value).join(','));
  const candidateAnalytics = splitValues(getEvidence(candidateEvidence, 'analytics_id').map(e => e.evidence_value).join(','));
  const sharedAnalytics = targetAnalytics.filter(a => candidateAnalytics.includes(a));
  if (sharedAnalytics.length > 0) {
    score += 40;
    indicators.push(`shared_analytics_id(s): ${sharedAnalytics.join(', ')}`);
  }

  // title word overlap >60%: +20
  if (target.title && candidate.title) {
    const overlap = wordOverlap(target.title, candidate.title);
    if (overlap > 0.6) {
      score += 20;
      indicators.push(`similar_title (${Math.round(overlap * 100)}% word overlap)`);
    }
  }

  // footer text hash match: +25
  if (target.footer_text && candidate.footer_text) {
    const targetFooterHash = djb2(target.footer_text.slice(0, 200));
    const candidateFooterHash = djb2(candidate.footer_text.slice(0, 200));
    if (targetFooterHash === candidateFooterHash && target.footer_text.length > 20) {
      score += 25;
      indicators.push('matching_footer_text_hash');
    }
  }

  return { score, shared_indicators: indicators };
}

// ── Main exported function ────────────────────────────────────────────────────
// Note: allSites contains sites with pre-loaded evidence only if the caller
// has enriched them. For lightweight comparison we use only fields on the site
// object itself plus evidence arrays if provided.
function findSimilarSites(target, allSites, evidenceMap) {
  const results = [];

  for (const candidate of allSites) {
    // Skip comparing site to itself
    if (candidate.id === target.id) continue;

    const targetEvidence = evidenceMap?.[target.id] || [];
    const candidateEvidence = evidenceMap?.[candidate.id] || [];

    const { score, shared_indicators } = compareSites(
      target, candidate, targetEvidence, candidateEvidence
    );

    if (score >= 30) {
      results.push({
        site_id: candidate.id,
        domain: candidate.domain,
        url: candidate.url,
        risk_level: candidate.risk_level,
        risk_score: candidate.risk_score,
        similarity_score: score,
        shared_indicators,
        note: 'Possible infrastructure overlap — not a confirmed attribution',
      });
    }
  }

  // Sort by similarity score descending
  results.sort((a, b) => b.similarity_score - a.similarity_score);

  return results;
}

module.exports = { findSimilarSites };
