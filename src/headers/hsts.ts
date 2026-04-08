import type { HeaderResult } from '../types.js';

const HEADER = 'strict-transport-security';
const MIN_MAX_AGE = 31536000; // 1 year

/**
 * Analyzes the Strict-Transport-Security header.
 * @param headers - Lowercase response headers
 * @returns Header analysis result
 */
export function analyzeHsts(headers: Record<string, string>): HeaderResult {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return {
      name: 'Strict-Transport-Security',
      status: 'fail',
      value: null,
      message: 'MISSING — HSTS header not set',
      severity: 'high',
      score: 0,
      maxScore: 15,
      remediation:
        'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    };
  }

  const maxAgeMatch = value.match(/max-age=(\d+)/i);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
  const hasIncludeSubDomains = /includeSubDomains/i.test(value);
  const hasPreload = /preload/i.test(value);

  if (maxAge < MIN_MAX_AGE) {
    return {
      name: 'Strict-Transport-Security',
      status: 'warn',
      value,
      message: `max-age=${maxAge} is below recommended minimum of ${MIN_MAX_AGE}`,
      severity: 'high',
      score: 5,
      maxScore: 15,
      remediation: `Increase max-age to at least ${MIN_MAX_AGE} (1 year)`,
    };
  }

  let score = 10;
  const issues: string[] = [];

  if (!hasIncludeSubDomains) {
    issues.push('missing includeSubDomains');
  } else {
    score += 3;
  }

  if (!hasPreload) {
    issues.push('missing preload');
  } else {
    score += 2;
  }

  if (issues.length > 0) {
    return {
      name: 'Strict-Transport-Security',
      status: 'warn',
      value,
      message: `Good max-age but ${issues.join(', ')}`,
      severity: 'high',
      score,
      maxScore: 15,
      remediation: `Add ${issues.join(' and ')} directives`,
    };
  }

  return {
    name: 'Strict-Transport-Security',
    status: 'pass',
    value,
    message: `Excellent — max-age=${maxAge}, includeSubDomains, preload`,
    severity: 'high',
    score: 15,
    maxScore: 15,
  };
}
