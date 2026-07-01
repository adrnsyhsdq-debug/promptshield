'use strict';

/**
 * PromptShield — zero-dependency prompt injection / jailbreak detector.
 *
 * Scans arbitrary text (user input, retrieved documents, tool output) for
 * patterns commonly used to hijack an LLM's instructions, and returns a
 * risk score plus the specific findings that produced it.
 *
 * This is a heuristic scanner, not a guarantee. It is meant as one layer
 * in a defense-in-depth setup — e.g. flag-and-review untrusted content
 * before it reaches a system prompt or an autonomous agent loop.
 */

// --- Rule definitions -------------------------------------------------
// Each rule: id, category, weight (0-10), regex, description.
// Weights are heuristic severities, not a formal probability model.
const RULES = [
  // --- Instruction override ---
  {
    id: 'override-instructions',
    category: 'instruction-override',
    weight: 9,
    pattern: /\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b[^.\n]{0,40}\b(instructions?|rules?|prompt|context)\b/i,
    description: "Attempts to make the model ignore or forget prior instructions."
  },
  {
    id: 'override-system',
    category: 'instruction-override',
    weight: 9,
    pattern: /\b(new|updated|real|actual)\s+(system\s+)?(instructions?|rules?|prompt)\s*(:|are|is)/i,
    description: "Claims to supply new/updated system instructions."
  },
  {
    id: 'override-from-now',
    category: 'instruction-override',
    weight: 6,
    pattern: /\bfrom\s+now\s+on\b.{0,60}\b(you|act|respond|behave)\b/i,
    description: "Attempts to redefine ongoing behavior mid-conversation."
  },

  // --- Role manipulation / jailbreak framing ---
  {
    id: 'role-you-are-now',
    category: 'role-manipulation',
    weight: 7,
    pattern: /\byou\s+are\s+now\b/i,
    description: "Attempts to reassign the model's identity or persona."
  },
  {
    id: 'role-dan-style',
    category: 'role-manipulation',
    weight: 8,
    pattern: /\b(DAN|do\s+anything\s+now|developer\s+mode|jailbreak(ed)?|unfiltered\s+mode|no\s+restrictions?\s+mode)\b/i,
    description: "References known jailbreak personas or 'unrestricted mode' framing."
  },
  {
    id: 'role-pretend-no-rules',
    category: 'role-manipulation',
    weight: 8,
    pattern: /\bpretend\b[^.\n]{0,40}\b(no|without)\b[^.\n]{0,20}\b(rules?|restrictions?|guidelines?|filters?)\b/i,
    description: "Asks the model to roleplay as having no rules or filters."
  },
  {
    id: 'role-hypothetical-bypass',
    category: 'role-manipulation',
    weight: 5,
    pattern: /\bin\s+a\s+hypothetical\s+(world|scenario|story)\s+where\s+(there\s+are\s+)?no\s+(rules|restrictions|laws|ethics)/i,
    description: "Uses a hypothetical framing to argue normal constraints don't apply."
  },

  // --- Exfiltration attempts ---
  {
    id: 'exfil-system-prompt',
    category: 'exfiltration',
    weight: 8,
    pattern: /\b(print|reveal|repeat|show|output|leak|tell\s+me)\b[^.\n]{0,30}\b(system\s+prompt|your\s+instructions|initial\s+prompt|hidden\s+prompt)\b/i,
    description: "Attempts to extract the system prompt or hidden instructions."
  },
  {
    id: 'exfil-api-key',
    category: 'exfiltration',
    weight: 9,
    pattern: /(\b(api\s*key|secret\s*key|access\s*token|credentials?)\b[^.\n]{0,30}\b(reveal|show|print|leak|send|output)\b)|(\b(reveal|show|print|leak|send|output)\b[^.\n]{0,30}\b(api\s*key|secret\s*key|access\s*token|credentials?)\b)/i,
    description: "Attempts to extract secrets or credentials."
  },

  // --- Delimiter / context escape ---
  {
    id: 'escape-fake-delimiter',
    category: 'context-escape',
    weight: 6,
    pattern: /(\[\/?system\]|<\/?system>|###\s*system|---\s*end\s+of\s+(context|document|instructions)\s*---)/i,
    description: "Uses fake delimiters to simulate the end of context or a new system block."
  },
  {
    id: 'escape-end-user-message',
    category: 'context-escape',
    weight: 6,
    pattern: /\b(end\s+of\s+(user\s+)?message|user\s+message\s+ends?\s+here)\b.{0,60}\b(system|assistant|ai)\b/i,
    description: "Simulates the end of the user turn to inject a fake system/assistant turn."
  },

  // --- Obfuscation ---
  {
    id: 'obfuscation-zero-width',
    category: 'obfuscation',
    weight: 7,
    pattern: /[\u200B\u200C\u200D\u2060\uFEFF]/,
    description: "Contains zero-width or invisible Unicode characters, often used to hide injected text."
  },
  {
    id: 'obfuscation-base64-blob',
    category: 'obfuscation',
    weight: 3,
    pattern: /\b[A-Za-z0-9+/]{60,}={0,2}\b/,
    description: "Contains a long Base64-like blob; decode and re-scan before trusting."
  },
  {
    id: 'obfuscation-excessive-homoglyph',
    category: 'obfuscation',
    weight: 4,
    pattern: /[\u0430\u0435\u043E\u0440\u0441\u0445]{3,}/i,
    description: "Contains clusters of Cyrillic homoglyphs mixed into Latin text, often used to evade keyword filters."
  }
];

/**
 * Analyze a piece of text for prompt-injection risk.
 * @param {string} text
 * @param {{threshold?: number}} [options]
 * @returns {{score: number, riskLevel: 'low'|'medium'|'high'|'critical', findings: Array<object>, safe: boolean}}
 */
function analyzePrompt(text, options = {}) {
  if (typeof text !== 'string') {
    throw new TypeError('analyzePrompt expects a string');
  }

  const threshold = options.threshold ?? 12;
  const findings = [];

  for (const rule of RULES) {
    const match = text.match(rule.pattern);
    if (match) {
      findings.push({
        id: rule.id,
        category: rule.category,
        weight: rule.weight,
        description: rule.description,
        matchedText: match[0].slice(0, 120)
      });
    }
  }

  const score = findings.reduce((sum, f) => sum + f.weight, 0);
  const riskLevel = scoreToRiskLevel(score);

  return {
    score,
    riskLevel,
    findings,
    safe: score < threshold
  };
}

function scoreToRiskLevel(score) {
  if (score >= 20) return 'critical';
  if (score >= 12) return 'high';
  if (score >= 6) return 'medium';
  if (score > 0) return 'low';
  return 'none';
}

/**
 * Convenience helper: returns true if text should be blocked at the given threshold.
 * @param {string} text
 * @param {number} [threshold=12]
 */
function isLikelyInjection(text, threshold = 12) {
  return analyzePrompt(text, { threshold }).safe === false;
}

module.exports = { analyzePrompt, isLikelyInjection, RULES };
