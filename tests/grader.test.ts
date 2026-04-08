import { describe, it, expect } from 'vitest';
import { calculateScore, scoreToGrade, gradeRank } from '../src/grader.js';
import type { HeaderResult, InfoDisclosureResult } from '../src/types.js';

function makeHeader(
  overrides: Partial<HeaderResult> = {}
): HeaderResult {
  return {
    name: 'Test-Header',
    status: 'pass',
    value: 'test',
    message: 'test',
    severity: 'medium',
    score: 10,
    maxScore: 10,
    ...overrides,
  };
}

describe('calculateScore', () => {
  it('returns 100 when all headers have max score and no info disclosure', () => {
    const headers = [
      makeHeader({ score: 10, maxScore: 10 }),
      makeHeader({ score: 15, maxScore: 15 }),
    ];
    expect(calculateScore(headers, [])).toBe(100);
  });

  it('returns 0 when all scores are 0', () => {
    const headers = [
      makeHeader({ score: 0, maxScore: 10 }),
      makeHeader({ score: 0, maxScore: 15 }),
    ];
    expect(calculateScore(headers, [])).toBe(0);
  });

  it('deducts for info disclosure headers', () => {
    const headers = [makeHeader({ score: 10, maxScore: 10 })];
    const info: InfoDisclosureResult[] = [
      { name: 'Server', value: 'nginx/1.0', message: 'test' },
    ];
    expect(calculateScore(headers, info)).toBe(98);
  });

  it('caps info disclosure deduction at 8 points', () => {
    const headers = [makeHeader({ score: 10, maxScore: 10 })];
    const info: InfoDisclosureResult[] = Array(10).fill({
      name: 'X',
      value: 'x',
      message: 'x',
    });
    expect(calculateScore(headers, info)).toBe(92);
  });
});

describe('scoreToGrade', () => {
  it('returns A+ for 90+ with no fails', () => {
    const headers = [makeHeader({ status: 'pass' })];
    expect(scoreToGrade(95, headers)).toBe('A+');
  });

  it('downgrades from A+ when there are any fails', () => {
    const headers = [
      makeHeader({ status: 'pass' }),
      makeHeader({ status: 'fail', severity: 'low' }),
    ];
    expect(scoreToGrade(92, headers)).not.toBe('A+');
  });

  it('returns A for 80-89 with no critical fails', () => {
    const headers = [makeHeader({ status: 'pass' })];
    expect(scoreToGrade(85, headers)).toBe('A');
  });

  it('returns F for scores below 35', () => {
    const headers = [makeHeader({ status: 'fail', severity: 'high' })];
    expect(scoreToGrade(20, headers)).toBe('F');
  });

  it('returns correct grades for boundary values', () => {
    const noFails = [makeHeader({ status: 'pass' })];
    expect(scoreToGrade(90, noFails)).toBe('A+');
    expect(scoreToGrade(80, noFails)).toBe('A');
    expect(scoreToGrade(65, noFails)).toBe('B');
    expect(scoreToGrade(50, noFails)).toBe('C');
    expect(scoreToGrade(35, noFails)).toBe('D');
    expect(scoreToGrade(34, noFails)).toBe('F');
  });
});

describe('gradeRank', () => {
  it('ranks A+ highest', () => {
    expect(gradeRank('A+')).toBeGreaterThan(gradeRank('A'));
    expect(gradeRank('A')).toBeGreaterThan(gradeRank('B'));
    expect(gradeRank('B')).toBeGreaterThan(gradeRank('C'));
    expect(gradeRank('C')).toBeGreaterThan(gradeRank('D'));
    expect(gradeRank('D')).toBeGreaterThan(gradeRank('F'));
  });
});
