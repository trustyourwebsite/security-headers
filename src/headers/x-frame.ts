import type { HeaderResult } from '../types.js';

const HEADER = 'x-frame-options';

/**
 * Analyzes the X-Frame-Options header.
 * @param headers - Lowercase response headers
 * @returns Header analysis result
 */
export function analyzeXFrame(headers: Record<string, string>): HeaderResult {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return {
      name: 'X-Frame-Options',
      status: 'fail',
      value: null,
      message: 'MISSING — Page can be embedded in iframes (clickjacking risk)',
      severity: 'medium',
      score: 0,
      maxScore: 10,
      remediation: 'Add X-Frame-Options: DENY or SAMEORIGIN',
    };
  }

  const normalized = value.toUpperCase().trim();

  if (normalized === 'DENY') {
    return {
      name: 'X-Frame-Options',
      status: 'pass',
      value,
      message: 'DENY — Page cannot be framed',
      severity: 'medium',
      score: 10,
      maxScore: 10,
    };
  }

  if (normalized === 'SAMEORIGIN') {
    return {
      name: 'X-Frame-Options',
      status: 'pass',
      value,
      message: 'SAMEORIGIN — Only same-origin framing allowed',
      severity: 'medium',
      score: 10,
      maxScore: 10,
    };
  }

  if (normalized.startsWith('ALLOW-FROM')) {
    return {
      name: 'X-Frame-Options',
      status: 'warn',
      value,
      message:
        'ALLOW-FROM is deprecated and not supported by modern browsers',
      severity: 'medium',
      score: 5,
      maxScore: 10,
      remediation:
        'Use CSP frame-ancestors directive instead of ALLOW-FROM',
    };
  }

  return {
    name: 'X-Frame-Options',
    status: 'warn',
    value,
    message: `Unexpected value "${value}" — should be DENY or SAMEORIGIN`,
    severity: 'medium',
    score: 3,
    maxScore: 10,
    remediation: 'Set X-Frame-Options: DENY or SAMEORIGIN',
  };
}
