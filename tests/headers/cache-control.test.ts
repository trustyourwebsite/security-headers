import { describe, it, expect } from 'vitest';
import { analyzeCacheControl } from '../../src/headers/cache-control.js';

describe('analyzeCacheControl', () => {
  it('warns when missing', () => {
    const result = analyzeCacheControl({});
    expect(result.status).toBe('warn');
    expect(result.score).toBe(0);
  });

  it('passes with no-store (full marks)', () => {
    const result = analyzeCacheControl({ 'cache-control': 'no-store' });
    expect(result.status).toBe('pass');
    expect(result.score).toBe(7);
  });

  it('passes with private, no-cache', () => {
    const result = analyzeCacheControl({
      'cache-control': 'private, no-cache',
    });
    expect(result.status).toBe('pass');
    expect(result.score).toBe(6);
  });

  it('passes with private only', () => {
    const result = analyzeCacheControl({ 'cache-control': 'private' });
    expect(result.status).toBe('pass');
    expect(result.score).toBe(5);
  });

  it('warns on public caching', () => {
    const result = analyzeCacheControl({
      'cache-control': 'public, max-age=31536000',
    });
    expect(result.status).toBe('warn');
    expect(result.message).toContain('public');
  });

  it('warns on an unclear directive', () => {
    const result = analyzeCacheControl({ 'cache-control': 'max-age=600' });
    expect(result.status).toBe('warn');
    expect(result.remediation).toBeDefined();
  });
});
