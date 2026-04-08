import type { HeaderResult } from '../types.js';

const HEADER = 'cross-origin-embedder-policy';

/**
 * Analyzes the Cross-Origin-Embedder-Policy header.
 * @param headers - Lowercase response headers
 * @returns Header analysis result
 */
export function analyzeCoep(headers: Record<string, string>): HeaderResult {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return {
      name: 'Cross-Origin-Embedder-Policy',
      status: 'warn',
      value: null,
      message:
        'MISSING — Page cannot use SharedArrayBuffer or high-resolution timers',
      severity: 'low',
      score: 0,
      maxScore: 5,
      remediation:
        'Add Cross-Origin-Embedder-Policy: require-corp for cross-origin isolation',
    };
  }

  const normalized = value.toLowerCase().trim();

  if (normalized === 'require-corp') {
    return {
      name: 'Cross-Origin-Embedder-Policy',
      status: 'pass',
      value,
      message: 'require-corp — Full cross-origin isolation enabled',
      severity: 'low',
      score: 5,
      maxScore: 5,
    };
  }

  if (normalized === 'credentialless') {
    return {
      name: 'Cross-Origin-Embedder-Policy',
      status: 'pass',
      value,
      message: 'credentialless — Cross-origin isolation without CORP requirements',
      severity: 'low',
      score: 4,
      maxScore: 5,
    };
  }

  if (normalized === 'unsafe-none') {
    return {
      name: 'Cross-Origin-Embedder-Policy',
      status: 'warn',
      value,
      message: 'unsafe-none — No cross-origin embedding restrictions',
      severity: 'low',
      score: 0,
      maxScore: 5,
      remediation: 'Change to require-corp or credentialless',
    };
  }

  return {
    name: 'Cross-Origin-Embedder-Policy',
    status: 'warn',
    value,
    message: `Unexpected value "${value}"`,
    severity: 'low',
    score: 1,
    maxScore: 5,
    remediation:
      'Set Cross-Origin-Embedder-Policy: require-corp',
  };
}
