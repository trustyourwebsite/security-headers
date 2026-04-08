import { describe, it, expect } from 'vitest';
import { analyzeXFrame } from '../../src/headers/x-frame.js';

describe('analyzeXFrame', () => {
  it('fails when missing', () => {
    const result = analyzeXFrame({});
    expect(result.status).toBe('fail');
  });

  it('passes with DENY', () => {
    const result = analyzeXFrame({ 'x-frame-options': 'DENY' });
    expect(result.status).toBe('pass');
    expect(result.score).toBe(10);
  });

  it('passes with SAMEORIGIN', () => {
    const result = analyzeXFrame({ 'x-frame-options': 'SAMEORIGIN' });
    expect(result.status).toBe('pass');
  });

  it('warns with ALLOW-FROM', () => {
    const result = analyzeXFrame({
      'x-frame-options': 'ALLOW-FROM https://example.com',
    });
    expect(result.status).toBe('warn');
    expect(result.message).toContain('deprecated');
  });
});
