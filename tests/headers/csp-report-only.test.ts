import { describe, it, expect } from 'vitest';
import { analyzeCspReportOnly } from '../../src/headers/csp-report-only.js';

describe('analyzeCspReportOnly', () => {
  it('is informational and scoreless when the header is absent', () => {
    const result = analyzeCspReportOnly({});
    expect(result.status).toBe('info');
    expect(result.value).toBeNull();
    expect(result.maxScore).toBe(0);
    expect(result.score).toBe(0);
  });

  it('warns when report-only is present without an enforcing CSP', () => {
    const result = analyzeCspReportOnly({
      'content-security-policy-report-only': "default-src 'self'",
    });
    expect(result.status).toBe('warn');
    expect(result.message).toContain('does NOT enforce');
    expect(result.remediation).toBeDefined();
    // Must never affect the score
    expect(result.maxScore).toBe(0);
    expect(result.score).toBe(0);
  });

  it('is informational (not punishing) when a real enforcing CSP also exists', () => {
    const result = analyzeCspReportOnly({
      'content-security-policy': "default-src 'self'",
      'content-security-policy-report-only': "script-src 'none'",
    });
    expect(result.status).toBe('info');
    expect(result.message).toContain('enforcing');
    expect(result.remediation).toBeUndefined();
    expect(result.maxScore).toBe(0);
    expect(result.score).toBe(0);
  });
});
