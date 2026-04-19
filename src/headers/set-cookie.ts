import type { HeaderResult } from '../types.js';

interface CookieAttributes {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
}

/**
 * Parses a single Set-Cookie header string into its attributes.
 * @param setCookie - Raw Set-Cookie header value
 * @returns Parsed cookie attributes
 */
export function parseCookieAttributes(setCookie: string): CookieAttributes {
  const parts = setCookie.split(';').map((p) => p.trim());
  const nameValue = parts[0] ?? '';
  const name = nameValue.split('=')[0] ?? '';

  let secure = false;
  let httpOnly = false;
  let sameSite: string | null = null;

  for (const part of parts.slice(1)) {
    const lower = part.toLowerCase();
    if (lower === 'secure') {
      secure = true;
    } else if (lower === 'httponly') {
      httpOnly = true;
    } else if (lower.startsWith('samesite=')) {
      sameSite = lower.split('=')[1] ?? null;
    }
  }

  return { name, secure, httpOnly, sameSite };
}

/**
 * Analyzes Set-Cookie headers for security best practices.
 * Checks for Secure, HttpOnly, and SameSite attributes.
 * @param setCookieHeaders - Array of raw Set-Cookie header values
 * @param finalUrl - The final URL (used to detect localhost)
 * @returns Header analysis result
 */
export function analyzeSetCookie(
  setCookieHeaders: string[],
  finalUrl: string
): HeaderResult {
  if (setCookieHeaders.length === 0) {
    return {
      name: 'Set-Cookie',
      status: 'info',
      value: null,
      message: 'No Set-Cookie headers present',
      severity: 'low',
      score: 0,
      maxScore: 0,
    };
  }

  const isLocalhost = (() => {
    try {
      const hostname = new URL(finalUrl).hostname;
      return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
    } catch {
      return false;
    }
  })();

  const warnings: string[] = [];
  let issueCount = 0;
  const totalCookies = setCookieHeaders.length;

  for (const header of setCookieHeaders) {
    const cookie = parseCookieAttributes(header);
    const prefix = cookie.name ? `Cookie "${cookie.name}"` : 'Cookie';

    if (!cookie.secure && !isLocalhost) {
      warnings.push(`${prefix}: missing Secure flag`);
      issueCount++;
    }

    if (!cookie.httpOnly) {
      warnings.push(`${prefix}: missing HttpOnly flag`);
      issueCount++;
    }

    if (!cookie.sameSite) {
      warnings.push(`${prefix}: missing SameSite attribute`);
      issueCount++;
    } else if (cookie.sameSite === 'none' && !cookie.secure) {
      warnings.push(`${prefix}: SameSite=None requires Secure flag`);
      issueCount++;
    }
  }

  const joinedValue = setCookieHeaders
    .map((h) => h.split(';')[0])
    .join('; ');

  if (issueCount === 0) {
    return {
      name: 'Set-Cookie',
      status: 'pass',
      value: joinedValue,
      message: `All ${totalCookies} cookie(s) have Secure, HttpOnly, and proper SameSite attributes`,
      severity: 'low',
      score: 5,
      maxScore: 5,
    };
  }

  // Some issues but not catastrophic
  const maxPossibleIssues = totalCookies * 3; // 3 checks per cookie
  const issueRatio = issueCount / maxPossibleIssues;

  if (issueRatio <= 0.5) {
    return {
      name: 'Set-Cookie',
      status: 'warn',
      value: joinedValue,
      message: `Some cookies missing security attributes: ${warnings.join('; ')}`,
      severity: 'low',
      score: 3,
      maxScore: 5,
      remediation: `Fix cookie attributes: ${warnings.join('. ')}`,
    };
  }

  return {
    name: 'Set-Cookie',
    status: 'warn',
    value: joinedValue,
    message: `Cookies have significant security issues: ${warnings.join('; ')}`,
    severity: 'low',
    score: 0,
    maxScore: 5,
    remediation: `Fix cookie attributes: ${warnings.join('. ')}`,
  };
}
