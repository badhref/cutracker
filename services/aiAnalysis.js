'use strict';

const axios = require('axios');

const OPENAI_API_URL = 'https://api.openai.com/v1/chat/completions';
const MODEL = 'gpt-4o-mini';

const SYSTEM_PROMPT = `You are a financial fraud analyst assistant. Your role is to analyze evidence about suspected fake credit union websites and provide structured analysis to support human analyst review. You must use cautious language, separate facts from inference, and never definitively declare criminal activity. Always recommend analyst review. Your output must be valid JSON with no additional text.`;

function buildUserPrompt(site, evidence, scoringResult, ncuaResult) {
  const bodyText = (site.body_text || '').slice(0, 2000);
  const ncuaSnippets = (evidence || [])
    .filter(e => e.evidence_type === 'ncua_language')
    .map(e => e.evidence_value)
    .join(' | ');
  const scoringFactors = (scoringResult?.factors || [])
    .map(f => `  - ${f.key} (+${f.points} pts): ${f.reason}`)
    .join('\n');

  return `Please analyze the following suspected credit union website and provide a structured JSON response.

SITE INFORMATION:
  URL: ${site.url || site.normalized_url || 'unknown'}
  Domain: ${site.domain || 'unknown'}
  Page Title: ${site.title || 'not available'}
  Meta Description: ${site.meta_description || 'not available'}

EXTRACTED TEXT (first 2000 characters):
${bodyText || 'not available'}

NCUA LANGUAGE FOUND ON PAGE:
${ncuaSnippets || 'none detected'}

ALGORITHMIC RISK SCORING:
  Score: ${scoringResult?.score ?? 0} / 100+ (Level: ${scoringResult?.level ?? 'unknown'})
  Factors:
${scoringFactors || '  none'}

NCUA VALIDATION RESULT:
  Status: ${ncuaResult?.status ?? 'not_checked'}
  Reason: ${ncuaResult?.reason ?? 'N/A'}
  ${ncuaResult?.match ? `Match: ${JSON.stringify(ncuaResult.match)}` : ''}

Respond with ONLY valid JSON in this exact structure:
{
  "classification": "likely_legitimate|possibly_suspicious|likely_suspicious|requires_immediate_review",
  "summary": "2-3 sentence summary using cautious language",
  "ncua_claim_detected": true or false,
  "red_flags": ["array of specific observed concerns"],
  "benign_explanations": ["array of possible innocent explanations"],
  "recommended_pivots": ["suggested next investigation steps"],
  "recommended_next_action": "one clear recommended analyst action",
  "confidence": "low|medium|high",
  "analyst_note": "reminder that this is AI-generated and requires analyst review"
}`;
}

async function runAiAnalysis(site, evidence, scoringResult, ncuaResult) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    return { available: false, reason: 'OPENAI_API_KEY not configured' };
  }

  const userPrompt = buildUserPrompt(site, evidence, scoringResult, ncuaResult);

  try {
    const response = await axios.post(
      OPENAI_API_URL,
      {
        model: MODEL,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: userPrompt },
        ],
        temperature: 0.2,
        max_tokens: 1000,
        response_format: { type: 'json_object' },
      },
      {
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        timeout: 30000,
      }
    );

    const content = response.data?.choices?.[0]?.message?.content;
    if (!content) {
      return { available: true, error: 'Empty response from OpenAI API' };
    }

    let analysis;
    try {
      analysis = JSON.parse(content);
    } catch (parseErr) {
      return { available: true, error: `Failed to parse AI response as JSON: ${parseErr.message}` };
    }

    return { available: true, model: MODEL, analysis };
  } catch (err) {
    const msg = err.response?.data?.error?.message || err.message;
    return { available: true, error: msg };
  }
}

module.exports = { runAiAnalysis };
