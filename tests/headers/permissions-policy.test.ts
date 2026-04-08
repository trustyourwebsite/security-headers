import { describe, it, expect } from 'vitest';
import { analyzePermissionsPolicy } from '../../src/headers/permissions-policy.js';

describe('analyzePermissionsPolicy', () => {
  it('fails when missing', () => {
    const result = analyzePermissionsPolicy({});
    expect(result.status).toBe('fail');
    expect(result.score).toBe(0);
  });

  it('passes with well-configured policy', () => {
    const result = analyzePermissionsPolicy({
      'permissions-policy':
        'camera=(), microphone=(), geolocation=(), payment=()',
    });
    expect(result.status).toBe('pass');
    expect(result.score).toBeGreaterThanOrEqual(9);
  });

  it('warns when dangerous features are allowed for all', () => {
    const result = analyzePermissionsPolicy({
      'permissions-policy': 'camera=(*)',
    });
    expect(result.status).toBe('warn');
    expect(result.message).toContain('camera');
  });

  it('warns when present but no dangerous features restricted', () => {
    const result = analyzePermissionsPolicy({
      'permissions-policy': 'autoplay=()',
    });
    expect(result.status).toBe('warn');
  });
});
