import { describe, it, expect } from 'vitest';
import { formatSarif } from '../src/formatters/sarif.js';
import type { ScanResult } from '../src/types.js';

const mockResult: ScanResult = {
  url: 'https://example.com',
  grade: 'B',
  score: 72,
  headers: [
    {
      name: 'Strict-Transport-Security',
      status: 'pass',
      value: 'max-age=31536000; includeSubDomains',
      message: 'max-age=31536000; includeSubDomains',
      severity: 'high',
      score: 13,
      maxScore: 15,
    },
    {
      name: 'Content-Security-Policy',
      status: 'fail',
      value: null,
      message: 'MISSING',
      severity: 'high',
      score: 0,
      maxScore: 15,
      remediation: 'Add Content-Security-Policy header',
    },
    {
      name: 'Referrer-Policy',
      status: 'warn',
      value: 'no-referrer-when-downgrade',
      message: 'Consider strict-origin-when-cross-origin',
      severity: 'medium',
      score: 3,
      maxScore: 7,
      remediation: 'Use strict-origin-when-cross-origin',
    },
    {
      name: 'Content-Security-Policy-Report-Only',
      status: 'info',
      value: null,
      message: 'No Content-Security-Policy-Report-Only header present',
      severity: 'low',
      score: 0,
      maxScore: 0,
    },
  ],
  infoDisclosure: [
    {
      name: 'Server',
      value: 'nginx/1.24.0',
      message: 'Server: nginx/1.24.0 — Remove version number',
    },
  ],
  rawHeaders: {},
  redirectChain: [],
  tlsVersion: 'TLSv1.3',
  wafBlocked: false,
  wafVendor: null,
  timestamp: '2024-01-01T00:00:00.000Z',
};

describe('formatSarif', () => {
  it('outputs valid SARIF 2.1.0 JSON', () => {
    const sarif = JSON.parse(formatSarif(mockResult));
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-schema-2.1.0.json');
    expect(Array.isArray(sarif.runs)).toBe(true);
    expect(sarif.runs).toHaveLength(1);
  });

  it('declares the tool driver with rules', () => {
    const sarif = JSON.parse(formatSarif(mockResult));
    const driver = sarif.runs[0].tool.driver;
    expect(driver.name).toBe('security-headers');
    expect(Array.isArray(driver.rules)).toBe(true);
    // One rule per distinct header check plus the info-disclosure rule
    const ruleIds = driver.rules.map((r: { id: string }) => r.id);
    expect(ruleIds).toContain('security-headers/content-security-policy');
    expect(ruleIds).toContain('security-headers/information-disclosure');
  });

  it('emits results with correct levels for fail and warn', () => {
    const sarif = JSON.parse(formatSarif(mockResult));
    const results = sarif.runs[0].results as Array<{
      ruleId: string;
      level: string;
      message: { text: string };
      locations: unknown[];
    }>;

    const csp = results.find(
      (r) => r.ruleId === 'security-headers/content-security-policy'
    );
    expect(csp?.level).toBe('error');

    const referrer = results.find(
      (r) => r.ruleId === 'security-headers/referrer-policy'
    );
    expect(referrer?.level).toBe('warning');
  });

  it('does not emit a result for passing headers', () => {
    const sarif = JSON.parse(formatSarif(mockResult));
    const results = sarif.runs[0].results as Array<{ ruleId: string }>;
    expect(
      results.some(
        (r) => r.ruleId === 'security-headers/strict-transport-security'
      )
    ).toBe(false);
  });

  it('skips scoreless informational findings with no value or remediation', () => {
    const sarif = JSON.parse(formatSarif(mockResult));
    const results = sarif.runs[0].results as Array<{ ruleId: string }>;
    expect(
      results.some(
        (r) =>
          r.ruleId === 'security-headers/content-security-policy-report-only'
      )
    ).toBe(false);
  });

  it('reports information-disclosure findings as notes', () => {
    const sarif = JSON.parse(formatSarif(mockResult));
    const results = sarif.runs[0].results as Array<{
      ruleId: string;
      level: string;
      message: { text: string };
    }>;
    const info = results.find(
      (r) => r.ruleId === 'security-headers/information-disclosure'
    );
    expect(info?.level).toBe('note');
    expect(info?.message.text).toContain('nginx');
  });

  it('includes the scanned URL as a result location', () => {
    const sarif = JSON.parse(formatSarif(mockResult));
    const results = sarif.runs[0].results as Array<{
      locations: Array<{
        physicalLocation: { artifactLocation: { uri: string } };
      }>;
    }>;
    expect(
      results[0].locations[0].physicalLocation.artifactLocation.uri
    ).toBe('https://example.com');
  });
});
