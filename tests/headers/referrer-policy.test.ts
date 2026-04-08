import { describe, it, expect } from 'vitest';
import { analyzeReferrerPolicy } from '../../src/headers/referrer-policy.js';

describe('analyzeReferrerPolicy', () => {
  it('fails when missing', () => {
    const result = analyzeReferrerPolicy({});
    expect(result.status).toBe('fail');
  });

  it('passes with strict-origin-when-cross-origin', () => {
    const result = analyzeReferrerPolicy({
      'referrer-policy': 'strict-origin-when-cross-origin',
    });
    expect(result.status).toBe('pass');
    expect(result.score).toBe(10);
  });

  it('passes with no-referrer', () => {
    const result = analyzeReferrerPolicy({ 'referrer-policy': 'no-referrer' });
    expect(result.status).toBe('pass');
  });

  it('warns with no-referrer-when-downgrade', () => {
    const result = analyzeReferrerPolicy({
      'referrer-policy': 'no-referrer-when-downgrade',
    });
    expect(result.status).toBe('warn');
  });

  it('fails with unsafe-url', () => {
    const result = analyzeReferrerPolicy({ 'referrer-policy': 'unsafe-url' });
    expect(result.status).toBe('fail');
  });

  it('uses last value in comma-separated list', () => {
    const result = analyzeReferrerPolicy({
      'referrer-policy': 'no-referrer-when-downgrade, strict-origin-when-cross-origin',
    });
    expect(result.status).toBe('pass');
  });
});
