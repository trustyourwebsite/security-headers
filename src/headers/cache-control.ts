import type { HeaderResult } from '../types.js';

const HEADER = 'cache-control';

/**
 * Analyzes the Cache-Control header for security implications.
 * Primarily checks that sensitive pages aren't cached insecurely.
 * @param headers - Lowercase response headers
 * @returns Header analysis result
 */
export function analyzeCacheControl(
  headers: Record<string, string>
): HeaderResult {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return {
      name: 'Cache-Control',
      status: 'warn',
      value: null,
      message: 'MISSING — Default caching behavior may store sensitive responses',
      severity: 'low',
      score: 0,
      maxScore: 7,
      remediation:
        'Add Cache-Control header. For HTML pages: no-store or private, no-cache. For static assets: public, max-age with immutable.',
    };
  }

  const normalized = value.toLowerCase();
  const hasNoStore = normalized.includes('no-store');
  const hasPrivate = normalized.includes('private');
  const hasNoCache = normalized.includes('no-cache');
  const hasPublic = normalized.includes('public');

  // Best: no-store prevents caching entirely
  if (hasNoStore) {
    return {
      name: 'Cache-Control',
      status: 'pass',
      value,
      message: 'no-store — Sensitive responses are not cached',
      severity: 'low',
      score: 7,
      maxScore: 7,
    };
  }

  // Good: private with no-cache
  if (hasPrivate && hasNoCache) {
    return {
      name: 'Cache-Control',
      status: 'pass',
      value,
      message: 'private, no-cache — Responses are not shared-cached and must revalidate',
      severity: 'low',
      score: 6,
      maxScore: 7,
    };
  }

  // Acceptable: private only
  if (hasPrivate) {
    return {
      name: 'Cache-Control',
      status: 'pass',
      value,
      message: 'private — Responses are not stored in shared caches',
      severity: 'low',
      score: 5,
      maxScore: 7,
    };
  }

  // Public caching — fine for static assets, risky for HTML
  if (hasPublic) {
    return {
      name: 'Cache-Control',
      status: 'warn',
      value,
      message: 'public — Ensure sensitive pages use private or no-store instead',
      severity: 'low',
      score: 3,
      maxScore: 7,
      remediation:
        'If this is a page with user data, change to Cache-Control: no-store or private',
    };
  }

  // Has some value but not a clear security configuration
  return {
    name: 'Cache-Control',
    status: 'warn',
    value,
    message: `Set but may allow caching of sensitive data: ${value}`,
    severity: 'low',
    score: 3,
    maxScore: 7,
    remediation:
      'For sensitive pages, add no-store. For static assets, use public, max-age=31536000, immutable.',
  };
}
