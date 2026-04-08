import type { HeaderResult } from '../types.js';

const HEADER = 'referrer-policy';

const GOOD_VALUES = new Set([
  'no-referrer',
  'strict-origin',
  'strict-origin-when-cross-origin',
  'same-origin',
]);

const ACCEPTABLE_VALUES = new Set([
  'origin',
  'origin-when-cross-origin',
  'no-referrer-when-downgrade',
]);

/**
 * Analyzes the Referrer-Policy header.
 * @param headers - Lowercase response headers
 * @returns Header analysis result
 */
export function analyzeReferrerPolicy(
  headers: Record<string, string>
): HeaderResult {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return {
      name: 'Referrer-Policy',
      status: 'fail',
      value: null,
      message: 'MISSING — Full URL may be sent as referrer to third parties',
      severity: 'medium',
      score: 0,
      maxScore: 10,
      remediation:
        'Add Referrer-Policy: strict-origin-when-cross-origin',
    };
  }

  // Referrer-Policy can contain comma-separated fallback values; use the last one
  const policies = value
    .split(',')
    .map((p) => p.trim().toLowerCase())
    .filter(Boolean);
  const effectivePolicy = policies[policies.length - 1];

  if (effectivePolicy === 'unsafe-url') {
    return {
      name: 'Referrer-Policy',
      status: 'fail',
      value,
      message:
        'unsafe-url sends full URL including path and query to all origins',
      severity: 'medium',
      score: 0,
      maxScore: 10,
      remediation:
        'Change to strict-origin-when-cross-origin or no-referrer',
    };
  }

  if (GOOD_VALUES.has(effectivePolicy)) {
    return {
      name: 'Referrer-Policy',
      status: 'pass',
      value,
      message: effectivePolicy,
      severity: 'medium',
      score: 10,
      maxScore: 10,
    };
  }

  if (ACCEPTABLE_VALUES.has(effectivePolicy)) {
    return {
      name: 'Referrer-Policy',
      status: 'warn',
      value,
      message: `${effectivePolicy} — Consider strict-origin-when-cross-origin for better privacy`,
      severity: 'medium',
      score: 7,
      maxScore: 10,
      remediation:
        'Consider upgrading to strict-origin-when-cross-origin',
    };
  }

  return {
    name: 'Referrer-Policy',
    status: 'warn',
    value,
    message: `Unrecognized policy "${effectivePolicy}"`,
    severity: 'medium',
    score: 3,
    maxScore: 10,
    remediation:
      'Use a standard value: strict-origin-when-cross-origin, no-referrer, or same-origin',
  };
}
