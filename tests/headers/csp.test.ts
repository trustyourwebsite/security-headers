import { describe, it, expect } from 'vitest';
import { analyzeCsp, parseCsp } from '../../src/headers/csp.js';

describe('parseCsp', () => {
  it('parses multiple directives', () => {
    const directives = parseCsp("default-src 'self'; script-src 'none'; img-src *");
    expect(directives).toHaveLength(3);
    expect(directives[0].name).toBe('default-src');
    expect(directives[0].values).toEqual(["'self'"]);
    expect(directives[2].name).toBe('img-src');
    expect(directives[2].values).toEqual(['*']);
  });

  it('handles empty string', () => {
    expect(parseCsp('')).toHaveLength(0);
  });
});

describe('analyzeCsp', () => {
  it('fails when header is missing', () => {
    const result = analyzeCsp({});
    expect(result.status).toBe('fail');
    expect(result.score).toBe(0);
  });

  it('passes with good CSP', () => {
    const result = analyzeCsp({
      'content-security-policy':
        "default-src 'self'; script-src 'self'; frame-ancestors 'none'; upgrade-insecure-requests; report-uri /csp-report",
    });
    expect(result.status).toBe('pass');
    expect(result.score).toBeGreaterThan(10);
  });

  it('warns about unsafe-inline in script-src', () => {
    const result = analyzeCsp({
      'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'",
    });
    expect(result.status).toBe('warn');
    expect(result.message).toContain('unsafe-inline');
  });

  it('warns about unsafe-eval in script-src', () => {
    const result = analyzeCsp({
      'content-security-policy': "default-src 'self'; script-src 'unsafe-eval'",
    });
    expect(result.status).toBe('warn');
    expect(result.message).toContain('unsafe-eval');
  });

  it('warns about wildcard in default-src', () => {
    const result = analyzeCsp({
      'content-security-policy': 'default-src *',
    });
    expect(result.status).toBe('warn');
    expect(result.message).toContain('wildcard');
  });

  it('deducts for missing default-src', () => {
    const result = analyzeCsp({
      'content-security-policy': "script-src 'self'",
    });
    expect(result.message).toContain('default-src');
  });

  it("treats 'none' as safe, not dangerous", () => {
    const result = analyzeCsp({
      'content-security-policy':
        "default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'",
    });
    expect(result.status).toBe('pass');
    // No warnings should mention script-src / object-src / base-uri being dangerous
    expect(result.message).not.toContain('contains');
    expect(result.message).not.toContain('wildcard');
  });

  it("does not penalize default-src 'none'", () => {
    const result = analyzeCsp({
      'content-security-policy': "default-src 'none'",
    });
    expect(result.status).toBe('pass');
    expect(result.message).not.toContain('wildcard');
  });

  it('does not reward frame-ancestors *', () => {
    const withWildcard = analyzeCsp({
      'content-security-policy': "default-src 'self'; frame-ancestors *",
    });
    const withoutFrameAncestors = analyzeCsp({
      'content-security-policy': "default-src 'self'",
    });
    // The wildcard frame-ancestors must not earn the +2 bonus
    expect(withWildcard.score).toBeLessThanOrEqual(withoutFrameAncestors.score);
    expect(withWildcard.status).toBe('warn');
    expect(withWildcard.message).toContain('frame-ancestors');
  });

  it("rewards frame-ancestors 'self'", () => {
    const withSelf = analyzeCsp({
      'content-security-policy': "default-src 'self'; frame-ancestors 'self'",
    });
    const withoutFrameAncestors = analyzeCsp({
      'content-security-policy': "default-src 'self'",
    });
    expect(withSelf.score).toBeGreaterThan(withoutFrameAncestors.score);
  });

  it('credits a nonce in script-src instead of penalizing unsafe-inline', () => {
    const result = analyzeCsp({
      'content-security-policy':
        "default-src 'self'; script-src 'self' 'nonce-abc123' 'unsafe-inline'",
    });
    // unsafe-inline is inert alongside a nonce, so it must not be flagged
    expect(result.status).toBe('pass');
    expect(result.message).not.toContain('unsafe-inline');
  });

  it('credits a sha256 hash in script-src', () => {
    const result = analyzeCsp({
      'content-security-policy':
        "default-src 'self'; script-src 'self' 'sha256-abc123' 'unsafe-inline'",
    });
    expect(result.status).toBe('pass');
    expect(result.message).not.toContain('unsafe-inline');
  });
});
