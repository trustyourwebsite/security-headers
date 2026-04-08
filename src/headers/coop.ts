import type { HeaderResult } from '../types.js';

const HEADER = 'cross-origin-opener-policy';

/**
 * Analyzes the Cross-Origin-Opener-Policy header.
 * @param headers - Lowercase response headers
 * @returns Header analysis result
 */
export function analyzeCoop(headers: Record<string, string>): HeaderResult {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return {
      name: 'Cross-Origin-Opener-Policy',
      status: 'fail',
      value: null,
      message: 'MISSING — Cross-origin windows may access this page',
      severity: 'medium',
      score: 0,
      maxScore: 8,
      remediation: 'Add Cross-Origin-Opener-Policy: same-origin',
    };
  }

  const normalized = value.toLowerCase().trim();

  if (normalized === 'same-origin') {
    return {
      name: 'Cross-Origin-Opener-Policy',
      status: 'pass',
      value,
      message: 'same-origin — Fully isolated from cross-origin windows',
      severity: 'medium',
      score: 8,
      maxScore: 8,
    };
  }

  if (normalized === 'same-origin-allow-popups') {
    return {
      name: 'Cross-Origin-Opener-Policy',
      status: 'warn',
      value,
      message:
        'same-origin-allow-popups — Partial isolation (popups can retain opener)',
      severity: 'medium',
      score: 5,
      maxScore: 8,
      remediation:
        'Consider same-origin for full isolation unless you need popup communication',
    };
  }

  if (normalized === 'unsafe-none') {
    return {
      name: 'Cross-Origin-Opener-Policy',
      status: 'fail',
      value,
      message: 'unsafe-none — No cross-origin isolation',
      severity: 'medium',
      score: 0,
      maxScore: 8,
      remediation: 'Change to same-origin or same-origin-allow-popups',
    };
  }

  return {
    name: 'Cross-Origin-Opener-Policy',
    status: 'warn',
    value,
    message: `Unexpected value "${value}"`,
    severity: 'medium',
    score: 3,
    maxScore: 8,
    remediation: 'Set Cross-Origin-Opener-Policy: same-origin',
  };
}
