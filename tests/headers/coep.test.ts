import { describe, it, expect } from 'vitest';
import { analyzeCoep } from '../../src/headers/coep.js';

describe('analyzeCoep', () => {
  it('warns when missing', () => {
    const result = analyzeCoep({});
    expect(result.status).toBe('warn');
    expect(result.score).toBe(0);
  });

  it('passes with require-corp (full marks)', () => {
    const result = analyzeCoep({
      'cross-origin-embedder-policy': 'require-corp',
    });
    expect(result.status).toBe('pass');
    expect(result.score).toBe(5);
  });

  it('passes with credentialless', () => {
    const result = analyzeCoep({
      'cross-origin-embedder-policy': 'credentialless',
    });
    expect(result.status).toBe('pass');
    expect(result.score).toBe(4);
  });

  it('warns with unsafe-none', () => {
    const result = analyzeCoep({
      'cross-origin-embedder-policy': 'unsafe-none',
    });
    expect(result.status).toBe('warn');
    expect(result.score).toBe(0);
  });

  it('warns on an unexpected value', () => {
    const result = analyzeCoep({
      'cross-origin-embedder-policy': 'bogus',
    });
    expect(result.status).toBe('warn');
    expect(result.remediation).toBeDefined();
  });
});
