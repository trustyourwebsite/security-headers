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

    for (const dangerous of dangerousValues) {
      if (dangerous === '*') {
        if (values.includes('*')) {
          warnings.push(`${directive} allows wildcard (*)"`);
          score -= 3;
        }
      } else if (values.includes(dangerous)) {
        warnings.push(`${directive} contains ${dangerous}`);
        score -= 2;
      }
    }
  }

  // Check for default-src fallback
  if (!directiveMap.has('default-src')) {
    warnings.push("no default-src directive (scripts may load from anywhere if script-src isn't set)");
    score -= 2;
  }

  // Check for frame-ancestors (clickjacking protection via CSP)
  if (directiveMap.has('frame-ancestors')) {
    score += 2;
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
