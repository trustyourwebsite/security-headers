import { describe, it, expect } from 'vitest';
import { analyzeCorp } from '../../src/headers/corp.js';

describe('analyzeCorp', () => {
  it('warns when missing', () => {
    const result = analyzeCorp({});
    expect(result.status).toBe('warn');
    expect(result.score).toBe(0);
  });

  it('passes with same-origin (full marks)', () => {
    const result = analyzeCorp({
      'cross-origin-resource-policy': 'same-origin',
    });
    expect(result.status).toBe('pass');
    expect(result.score).toBe(5);
  });

  it('passes with same-site', () => {
    const result = analyzeCorp({
      'cross-origin-resource-policy': 'same-site',
    });
    expect(result.status).toBe('pass');
    expect(result.score).toBe(5);
  });

  it('warns with cross-origin (least restrictive)', () => {
    const result = analyzeCorp({
      'cross-origin-resource-policy': 'cross-origin',
    });
    expect(result.status).toBe('warn');
    expect(result.score).toBe(2);
  });

  it('warns on an unexpected value', () => {
    const result = analyzeCorp({
      'cross-origin-resource-policy': 'bogus',
    });
    expect(result.status).toBe('warn');
    expect(result.remediation).toBeDefined();
  });
});
