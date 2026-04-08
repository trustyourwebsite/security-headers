import type { HeaderResult } from '../types.js';

const HEADER = 'x-content-type-options';

/**
 * Analyzes the X-Content-Type-Options header.
 * @param headers - Lowercase response headers
 * @returns Header analysis result
 */
export function analyzeXContentType(
  headers: Record<string, string>
): HeaderResult {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return {
      name: 'X-Content-Type-Options',
      status: 'fail',
      value: null,
      message: 'MISSING — Browsers may MIME-sniff responses',
      severity: 'medium',
      score: 0,
      maxScore: 10,
      remediation: 'Add X-Content-Type-Options: nosniff',
    };
  }

  if (value.toLowerCase().trim() === 'nosniff') {
    return {
      name: 'X-Content-Type-Options',
      status: 'pass',
      value,
      message: 'nosniff',
      severity: 'medium',
      score: 10,
      maxScore: 10,
    };
  }

  return {
    name: 'X-Content-Type-Options',
    status: 'warn',
    value,
    message: `Unexpected value "${value}" — should be "nosniff"`,
    severity: 'medium',
    score: 3,
    maxScore: 10,
    remediation: 'Set X-Content-Type-Options: nosniff',
  };
}
