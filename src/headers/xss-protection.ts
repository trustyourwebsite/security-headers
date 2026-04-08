import type { HeaderResult } from '../types.js';

const HEADER = 'x-xss-protection';

/**
 * Analyzes the X-XSS-Protection header.
 * This header is deprecated but should not be set to dangerous values.
 * Best practice: set to "0" to disable the buggy XSS auditor.
 * @param headers - Lowercase response headers
 * @returns Header analysis result
 */
export function analyzeXssProtection(
  headers: Record<string, string>
): HeaderResult {
  const value = headers[HEADER] ?? null;

  if (!value) {
    // Not having it is fine — it's deprecated
    return {
      name: 'X-XSS-Protection',
      status: 'info',
      value: null,
      message: 'Not set (deprecated header — absence is acceptable)',
      severity: 'low',
      score: 5,
      maxScore: 5,
    };
  }

  const normalized = value.trim();

  // "0" is the correct modern value — disables the buggy auditor
  if (normalized === '0') {
    return {
      name: 'X-XSS-Protection',
      status: 'pass',
      value,
      message: '0 (correctly disabled — relies on CSP instead)',
      severity: 'low',
      score: 5,
      maxScore: 5,
    };
  }

  // "1; mode=block" was the old recommended value
  if (normalized.startsWith('1') && /mode=block/i.test(normalized)) {
    return {
      name: 'X-XSS-Protection',
      status: 'warn',
      value,
      message:
        'Enabled with mode=block — deprecated, may cause information leaks in older browsers',
      severity: 'low',
      score: 3,
      maxScore: 5,
      remediation:
        'Set X-XSS-Protection: 0 and rely on Content-Security-Policy instead',
    };
  }

  // "1" without mode=block is dangerous
  if (normalized.startsWith('1')) {
    return {
      name: 'X-XSS-Protection',
      status: 'fail',
      value,
      message:
        'Enabled without mode=block — can introduce XSS vulnerabilities via selective script removal',
      severity: 'low',
      score: 0,
      maxScore: 5,
      remediation:
        'Set X-XSS-Protection: 0 and rely on Content-Security-Policy instead',
    };
  }

  return {
    name: 'X-XSS-Protection',
    status: 'warn',
    value,
    message: `Unexpected value "${value}"`,
    severity: 'low',
    score: 2,
    maxScore: 5,
    remediation: 'Set X-XSS-Protection: 0 or remove the header entirely',
  };
}
