import { describe, it, expect } from 'vitest';
import { analyzeXssProtection } from '../../src/headers/xss-protection.js';

describe('analyzeXssProtection', () => {
  it('gives info status when not set', () => {
    const result = analyzeXssProtection({});
    expect(result.status).toBe('info');
    expect(result.score).toBe(5);
  });

  it('passes with 0 (correctly disabled)', () => {
    const result = analyzeXssProtection({ 'x-xss-protection': '0' });
    expect(result.status).toBe('pass');
    expect(result.score).toBe(5);
  });

  it('warns with 1; mode=block', () => {
    const result = analyzeXssProtection({
      'x-xss-protection': '1; mode=block',
    });
    expect(result.status).toBe('warn');
  });

  it('fails with 1 without mode=block', () => {
    const result = analyzeXssProtection({ 'x-xss-protection': '1' });
    expect(result.status).toBe('fail');
  });
});
