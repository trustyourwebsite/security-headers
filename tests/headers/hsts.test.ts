import { describe, it, expect } from 'vitest';
import { analyzeHsts } from '../../src/headers/hsts.js';

describe('analyzeHsts', () => {
  it('fails when header is missing', () => {
    const result = analyzeHsts({});
    expect(result.status).toBe('fail');
    expect(result.score).toBe(0);
  });

  it('passes with full HSTS header', () => {
    const result = analyzeHsts({
      'strict-transport-security':
        'max-age=31536000; includeSubDomains; preload',
    });
    expect(result.status).toBe('pass');
    expect(result.score).toBe(15);
  });

  it('warns when max-age is too low', () => {
    const result = analyzeHsts({
      'strict-transport-security': 'max-age=3600',
    });
    expect(result.status).toBe('warn');
    expect(result.score).toBe(5);
  });

  it('warns when missing includeSubDomains', () => {
    const result = analyzeHsts({
      'strict-transport-security': 'max-age=31536000; preload',
    });
    expect(result.status).toBe('warn');
    expect(result.message).toContain('includeSubDomains');
  });

  it('warns when missing preload', () => {
    const result = analyzeHsts({
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
    });
    expect(result.status).toBe('warn');
    expect(result.score).toBe(13);
  });

  it('gives partial score for good max-age only', () => {
    const result = analyzeHsts({
      'strict-transport-security': 'max-age=63072000',
    });
    expect(result.status).toBe('warn');
    expect(result.score).toBe(10);
  });
});
