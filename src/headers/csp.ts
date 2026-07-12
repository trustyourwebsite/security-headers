import type { HeaderResult } from '../types.js';

const HEADER = 'content-security-policy';

const DANGEROUS_DIRECTIVES: Record<string, string[]> = {
  'script-src': ["'unsafe-inline'", "'unsafe-eval'", 'data:', '*'],
  'style-src': ["'unsafe-inline'"],
  'object-src': ['*'],
  'base-uri': ['*'],
  'default-src': ["'unsafe-inline'", "'unsafe-eval'", '*'],
};

interface CspDirective {
  name: string;
  values: string[];
}

/**
 * Returns true when a directive is locked down to `'none'`, which blocks all
 * sources. Such a directive is the strongest possible configuration and must
 * never be penalized as dangerous or missing.
 * @param values - Parsed directive source values (lowercased)
 * @returns True when the only value is `'none'`
 */
function isNone(values: string[]): boolean {
  return values.length === 1 && values[0] === "'none'";
}

/**
 * Returns true when a source list contains a nonce or hash source expression,
 * e.g. `'nonce-abc123'` or `'sha256-...'`. These are legitimate, secure ways to
 * allow specific inline scripts/styles and cause browsers to ignore any
 * accompanying `'unsafe-inline'` backwards-compat fallback (CSP2+).
 * @param values - Parsed directive source values (lowercased)
 * @returns True when a nonce or hash source is present
 */
function hasNonceOrHash(values: string[]): boolean {
  return values.some(
    (v) =>
      v.startsWith("'nonce-") ||
      v.startsWith("'sha256-") ||
      v.startsWith("'sha384-") ||
      v.startsWith("'sha512-")
  );
}

/**
 * Parses a CSP header string into individual directives.
 * @param csp - Raw CSP header value
 * @returns Parsed directives
 */
export function parseCsp(csp: string): CspDirective[] {
  return csp
    .split(';')
    .map((d) => d.trim())
    .filter(Boolean)
    .map((directive) => {
      const parts = directive.split(/\s+/);
      return {
        name: parts[0].toLowerCase(),
        values: parts.slice(1).map((v) => v.toLowerCase()),
      };
    });
}

/**
 * Analyzes the Content-Security-Policy header.
 * @param headers - Lowercase response headers
 * @returns Header analysis result
 */
export function analyzeCsp(headers: Record<string, string>): HeaderResult {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return {
      name: 'Content-Security-Policy',
      status: 'fail',
      value: null,
      message: 'MISSING — No Content-Security-Policy header',
      severity: 'high',
      score: 0,
      maxScore: 15,
      remediation:
        "Add a Content-Security-Policy header to prevent XSS and data injection attacks. Start with: default-src 'self'",
    };
  }

  const directives = parseCsp(value);
  const directiveMap = new Map(directives.map((d) => [d.name, d.values]));

  const warnings: string[] = [];
  let score = 10; // Base score for having CSP

  // Check for dangerous values in critical directives
  for (const [directive, dangerousValues] of Object.entries(
    DANGEROUS_DIRECTIVES
  )) {
    const values = directiveMap.get(directive);
    if (!values) continue;

    // 'none' blocks everything — it is the strongest configuration, never dangerous
    if (isNone(values)) continue;

    // A nonce or hash makes 'unsafe-inline' inert in modern browsers, so it is
    // no longer a real weakness for that directive
    const nonceOrHash = hasNonceOrHash(values);

    for (const dangerous of dangerousValues) {
      if (dangerous === '*') {
        if (values.includes('*')) {
          warnings.push(`${directive} allows wildcard (*)`);
          score -= 3;
        }
      } else if (
        dangerous === "'unsafe-inline'" &&
        nonceOrHash
      ) {
        // 'unsafe-inline' is ignored by browsers when a nonce/hash is present
        continue;
      } else if (values.includes(dangerous)) {
        warnings.push(`${directive} contains ${dangerous}`);
        // unsafe-inline in style-src is nearly universal and far less dangerous than in script-src
        const penalty = directive === 'style-src' && dangerous === "'unsafe-inline'" ? 1 : 2;
        score -= penalty;
      }
    }
  }

  // Credit nonce/hash based inline handling in script-src / style-src as a
  // secure mechanism rather than requiring 'unsafe-inline'
  for (const directive of ['script-src', 'style-src']) {
    const values = directiveMap.get(directive);
    if (values && hasNonceOrHash(values)) {
      score += 1;
    }
  }

  // Check for default-src fallback
  if (!directiveMap.has('default-src')) {
    warnings.push("no default-src directive (scripts may load from anywhere if script-src isn't set)");
    score -= 2;
  }

  // Check for frame-ancestors (clickjacking protection via CSP).
  // Only reward a real allowlist / 'self' / 'none' — a wildcard or 'unsafe-inline'
  // provides no clickjacking protection and must not earn the bonus.
  const frameAncestors = directiveMap.get('frame-ancestors');
  if (frameAncestors) {
    const weakFrameAncestors =
      frameAncestors.includes('*') || frameAncestors.includes("'unsafe-inline'");
    if (weakFrameAncestors) {
      warnings.push('frame-ancestors is too permissive (does not restrict framing)');
    } else {
      score += 2;
    }
  }

  // Check for upgrade-insecure-requests
  if (directiveMap.has('upgrade-insecure-requests')) {
    score += 1;
  }

  // Check for report-uri or report-to
  if (directiveMap.has('report-uri') || directiveMap.has('report-to')) {
    score += 2;
  }

  // Clamp score
  score = Math.max(0, Math.min(score, 15));

  if (warnings.length > 0) {
    return {
      name: 'Content-Security-Policy',
      status: 'warn',
      value,
      message: `Present but has issues: ${warnings.join('; ')}`,
      severity: 'high',
      score,
      maxScore: 15,
      remediation: `Fix CSP issues: ${warnings.join('. ')}`,
    };
  }

  return {
    name: 'Content-Security-Policy',
    status: 'pass',
    value,
    message: 'Well-configured Content-Security-Policy',
    severity: 'high',
    score,
    maxScore: 15,
  };
}
