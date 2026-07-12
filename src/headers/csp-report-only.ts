import type { HeaderResult } from '../types.js';

const HEADER = 'content-security-policy-report-only';
const ENFORCING_HEADER = 'content-security-policy';

/**
 * Analyzes the Content-Security-Policy-Report-Only header.
 * Report-only mode monitors violations but does NOT enforce the policy, so a
 * site relying on it alone has no CSP protection. This analyzer is purely
 * informational: it never contributes to (or deducts from) the score, so a site
 * that also ships a real enforcing Content-Security-Policy is not punished for
 * additionally running a report-only policy.
 * @param headers - Lowercase response headers
 * @returns Header analysis result
 */
export function analyzeCspReportOnly(
  headers: Record<string, string>
): HeaderResult {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return {
      name: 'Content-Security-Policy-Report-Only',
      status: 'info',
      value: null,
      message: 'No Content-Security-Policy-Report-Only header present',
      severity: 'low',
      score: 0,
      maxScore: 0,
    };
  }

  const hasEnforcing = Boolean(headers[ENFORCING_HEADER]);

  const message = hasEnforcing
    ? 'Report-only policy present alongside an enforcing Content-Security-Policy — monitors violations but is not itself enforced'
    : 'Report-only mode monitors violations but does NOT enforce the policy — no CSP protection is applied';

  return {
    name: 'Content-Security-Policy-Report-Only',
    status: hasEnforcing ? 'info' : 'warn',
    value,
    message,
    severity: 'low',
    score: 0,
    maxScore: 0,
    remediation: hasEnforcing
      ? undefined
      : 'Once the policy no longer triggers violations, move it into an enforcing Content-Security-Policy header',
  };
}
