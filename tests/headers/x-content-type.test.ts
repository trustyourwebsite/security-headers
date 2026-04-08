import { describe, it, expect } from 'vitest';
import { analyzeXContentType } from '../../src/headers/x-content-type.js';

describe('analyzeXContentType', () => {
  it('fails when missing', () => {
    const result = analyzeXContentType({});
    expect(result.status).toBe('fail');
    expect(result.score).toBe(0);
  });

  it('passes with nosniff', () => {
    const result = analyzeXContentType({ 'x-content-type-options': 'nosniff' });
    expect(result.status).toBe('pass');
    expect(result.score).toBe(10);
  });

  it('warns with unexpected value', () => {
    const result = analyzeXContentType({ 'x-content-type-options': 'invalid' });
    expect(result.status).toBe('warn');
  });
});
