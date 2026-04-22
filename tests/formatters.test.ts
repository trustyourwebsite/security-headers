import { describe, it, expect } from 'vitest';
import { formatTable } from '../src/formatters/table.js';
import { formatJson } from '../src/formatters/json.js';
import { formatCsv } from '../src/formatters/csv.js';
import { formatText } from '../src/formatters/text.js';
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
  timestamp: '2024-01-01T00:00:00.000Z',
};

describe('formatTable', () => {
  it('includes grade, score, and URL', () => {
    const output = formatTable(mockResult);
    expect(output).toContain('B (72/100)');
    expect(output).toContain('https://example.com');
    expect(output).toContain('TLSv1.3');
  });

  it('includes trustyourwebsite.com link', () => {
    expect(formatTable(mockResult)).toContain('trustyourwebsite.com');
  });

  it('shows info disclosure warnings', () => {
    expect(formatTable(mockResult)).toContain('nginx/1.24.0');
  });

  it('shows recommendations', () => {
    const output = formatTable(mockResult);
    expect(output).toContain('Content-Security-Policy');
  });
});

describe('formatJson', () => {
  it('outputs valid JSON', () => {
    const output = formatJson(mockResult);
    const parsed = JSON.parse(output);
    expect(parsed.grade).toBe('B');
    expect(parsed.score).toBe(72);
  });
});

describe('formatCsv', () => {
  it('has header row', () => {
    const output = formatCsv(mockResult);
    const lines = output.split('\n');
    expect(lines[0]).toContain('Header,Status');
  });

  it('includes data rows', () => {
    const output = formatCsv(mockResult);
    expect(output).toContain('Strict-Transport-Security');
    expect(output).toContain('Content-Security-Policy');
  });
});

describe('formatText', () => {
  it('includes grade and URL', () => {
    const output = formatText(mockResult);
    expect(output).toContain('B (72/100)');
    expect(output).toContain('trustyourwebsite.com');
  });

  it('shows PASS/FAIL labels', () => {
    const output = formatText(mockResult);
    expect(output).toContain('[PASS]');
    expect(output).toContain('[FAIL]');
  });
});
