import type { HeaderResult } from '../types.js';

const HEADER = 'cross-origin-resource-policy';

/**
 * Analyzes the Cross-Origin-Resource-Policy header.
 * @param headers - Lowercase response headers
 * @returns Header analysis result
 */
export function analyzeCorp(headers: Record<string, string>): HeaderResult {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return {
      name: 'Cross-Origin-Resource-Policy',
      status: 'warn',
      value: null,
      message: 'MISSING — Resources can be embedded by any origin',
      severity: 'low',
      score: 0,
      maxScore: 5,
      remediation:
        'Add Cross-Origin-Resource-Policy: same-origin or same-site',
    };
  }

  const normalized = value.toLowerCase().trim();

  if (normalized === 'same-origin') {
    return {
      name: 'Cross-Origin-Resource-Policy',
      status: 'pass',
      value,
      message: 'same-origin — Resources restricted to same origin',
      severity: 'low',
      score: 5,
      maxScore: 5,
    };
  }

  if (normalized === 'same-site') {
    return {
      name: 'Cross-Origin-Resource-Policy',
      status: 'pass',
      value,
      message: 'same-site — Resources restricted to same site',
      severity: 'low',
      score: 5,
      maxScore: 5,
    };
  }

  if (normalized === 'cross-origin') {
    return {
      name: 'Cross-Origin-Resource-Policy',
      status: 'warn',
      value,
      message:
        'cross-origin — Resources can be loaded by any origin (least restrictive)',
      severity: 'low',
      score: 2,
      maxScore: 5,
      remediation:
        'Consider restricting to same-origin or same-site if resources are not meant to be public',
    };
  }

  return {
    name: 'Cross-Origin-Resource-Policy',
    status: 'warn',
    value,
    message: `Unexpected value "${value}"`,
    severity: 'low',
    score: 1,
    maxScore: 5,
    remediation:
      'Set Cross-Origin-Resource-Policy: same-origin or same-site',
  };
}
