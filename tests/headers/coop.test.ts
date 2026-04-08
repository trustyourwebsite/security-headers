import { describe, it, expect } from 'vitest';
import { analyzeCoop } from '../../src/headers/coop.js';

describe('analyzeCoop', () => {
  it('fails when missing', () => {
    const result = analyzeCoop({});
    expect(result.status).toBe('fail');
  });

  it('passes with same-origin', () => {
    const result = analyzeCoop({
      'cross-origin-opener-policy': 'same-origin',
    });
    expect(result.status).toBe('pass');
    expect(result.score).toBe(8);
  });

  it('warns with same-origin-allow-popups', () => {
    const result = analyzeCoop({
      'cross-origin-opener-policy': 'same-origin-allow-popups',
    });
    expect(result.status).toBe('warn');
    expect(result.score).toBe(5);
  });

  it('fails with unsafe-none', () => {
    const result = analyzeCoop({
      'cross-origin-opener-policy': 'unsafe-none',
    });
    expect(result.status).toBe('fail');
  });
});
