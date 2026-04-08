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
});
