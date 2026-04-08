import type { Grade, HeaderResult, InfoDisclosureResult } from './types.js';

/**
 * Calculates overall numeric score from individual header results.
 * Info disclosure findings apply small deductions.
 * @param headerResults - Array of header analysis results
 * @param infoDisclosure - Array of information disclosure findings
 * @returns Numeric score (0-100)
 */
export function calculateScore(
  headerResults: HeaderResult[],
  infoDisclosure: InfoDisclosureResult[]
): number {
  const maxTotal = headerResults.reduce((sum, h) => sum + h.maxScore, 0);
  const earnedTotal = headerResults.reduce((sum, h) => sum + h.score, 0);

  if (maxTotal === 0) return 0;

  // Scale to 0-100
  let score = Math.round((earnedTotal / maxTotal) * 100);

  // Small deductions for info disclosure (2 points each, max 8)
  const infoDeduction = Math.min(infoDisclosure.length * 2, 8);
  score = Math.max(0, score - infoDeduction);

  return Math.min(100, score);
}

/**
 * Converts a numeric score to a letter grade.
 * A+ requires no fails at all.
 * A requires no critical (high severity) fails.
 * @param score - Numeric score 0-100
 * @param headerResults - Header results used for fail-based gating
 * @returns Letter grade
 */
export function scoreToGrade(
  score: number,
  headerResults: HeaderResult[]
): Grade {
  const hasFails = headerResults.some((h) => h.status === 'fail');
  const hasCriticalFails = headerResults.some(
    (h) => h.status === 'fail' && h.severity === 'high'
  );

  if (score >= 90 && !hasFails) return 'A+';
  if (score >= 80 && !hasCriticalFails) return 'A';
  if (score >= 65) return 'B';
  if (score >= 50) return 'C';
  if (score >= 35) return 'D';
  return 'F';
}

/**
 * Returns numeric ordering for grades (higher = better).
 * Used for CI threshold comparison.
 * @param grade - Letter grade
 * @returns Numeric rank
 */
export function gradeRank(grade: Grade): number {
  const ranks: Record<Grade, number> = {
    'A+': 6,
    A: 5,
    B: 4,
    C: 3,
    D: 2,
    F: 1,
  };
  return ranks[grade];
}
