import { describe, it, expect } from 'vitest';
import {
  analyzeSetCookie,
  parseCookieAttributes,
} from '../../src/headers/set-cookie.js';

const URL = 'https://example.com';

describe('parseCookieAttributes', () => {
  it('parses name and all security attributes', () => {
    const attrs = parseCookieAttributes(
      'sid=abc123; Path=/; Secure; HttpOnly; SameSite=Strict'
    );
    expect(attrs.name).toBe('sid');
    expect(attrs.secure).toBe(true);
    expect(attrs.httpOnly).toBe(true);
    expect(attrs.sameSite).toBe('strict');
  });

  it('reports missing attributes as false/null', () => {
    const attrs = parseCookieAttributes('sid=abc123');
    expect(attrs.secure).toBe(false);
    expect(attrs.httpOnly).toBe(false);
    expect(attrs.sameSite).toBeNull();
  });
});

describe('analyzeSetCookie', () => {
  it('is informational when no cookies are set', () => {
    const result = analyzeSetCookie([], URL);
    expect(result.status).toBe('info');
    expect(result.maxScore).toBe(0);
  });

  it('passes when all attributes are present', () => {
    const result = analyzeSetCookie(
      ['sid=abc; Secure; HttpOnly; SameSite=Strict'],
      URL
    );
    expect(result.status).toBe('pass');
    expect(result.score).toBe(5);
  });

  it('warns when Secure is missing', () => {
    const result = analyzeSetCookie(
      ['sid=abc; HttpOnly; SameSite=Strict'],
      URL
    );
    expect(result.status).toBe('warn');
    expect(result.message).toContain('Secure');
  });

  it('warns when HttpOnly is missing', () => {
    const result = analyzeSetCookie(
      ['sid=abc; Secure; SameSite=Strict'],
      URL
    );
    expect(result.status).toBe('warn');
    expect(result.message).toContain('HttpOnly');
  });

  it('warns when SameSite is missing', () => {
    const result = analyzeSetCookie(['sid=abc; Secure; HttpOnly'], URL);
    expect(result.status).toBe('warn');
    expect(result.message).toContain('SameSite');
  });

  it('warns when SameSite=None lacks Secure', () => {
    const result = analyzeSetCookie(
      ['sid=abc; HttpOnly; SameSite=None'],
      URL
    );
    expect(result.status).toBe('warn');
    expect(result.message).toContain('SameSite=None requires Secure');
  });

  it('does not require Secure on localhost', () => {
    const result = analyzeSetCookie(
      ['sid=abc; HttpOnly; SameSite=Strict'],
      'http://localhost:3000'
    );
    expect(result.status).toBe('pass');
  });

  it('flags a cookie with no security attributes at all', () => {
    const result = analyzeSetCookie(['sid=abc'], URL);
    expect(result.status).toBe('warn');
    expect(result.score).toBe(0);
  });
});
