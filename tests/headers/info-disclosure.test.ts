import { describe, it, expect } from 'vitest';
import { analyzeInfoDisclosure } from '../../src/headers/info-disclosure.js';

describe('analyzeInfoDisclosure', () => {
  it('returns empty array when no disclosure headers', () => {
    const result = analyzeInfoDisclosure({});
    expect(result).toHaveLength(0);
  });

  it('detects Server header with version', () => {
    const result = analyzeInfoDisclosure({ server: 'nginx/1.24.0' });
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('Server');
    expect(result[0].message).toContain('version');
  });

  it('detects Server header without version', () => {
    const result = analyzeInfoDisclosure({ server: 'nginx' });
    expect(result).toHaveLength(1);
    expect(result[0].message).toContain('removing');
  });

  it('detects X-Powered-By', () => {
    const result = analyzeInfoDisclosure({ 'x-powered-by': 'Express' });
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe('X-Powered-By');
  });

  it('detects multiple disclosure headers', () => {
    const result = analyzeInfoDisclosure({
      server: 'Apache/2.4.51',
      'x-powered-by': 'PHP/8.1',
      'x-aspnet-version': '4.0.30319',
    });
    expect(result).toHaveLength(3);
  });
});
