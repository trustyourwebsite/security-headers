import type { ScanResult } from '../types.js';

const STATUS_ICONS: Record<string, string> = {
  pass: '\u2713',
  warn: '\u26A0',
  fail: '\u2717',
  info: '\u2139',
};

/**
 * Formats a scan result as a human-readable table.
 * @param result - Scan result to format
 * @returns Formatted string for terminal output
 */
export function formatTable(result: ScanResult): string {
  const lines: string[] = [];

  lines.push('Security Headers Report');
  lines.push('=======================');
  lines.push(`URL:    ${result.url}`);
  lines.push(`Grade:  ${result.grade} (${result.score}/100)`);
  if (result.tlsVersion) {
    lines.push(`TLS:    ${result.tlsVersion}`);
  }
  if (result.redirectChain.length > 0) {
    lines.push(
      `Redirects: ${result.redirectChain.length} hop(s)`
    );
  }
  lines.push('');

  // Header results
  lines.push('Headers:');
  for (const header of result.headers) {
    const icon = STATUS_ICONS[header.status] ?? '?';
    const detail = header.value
      ? header.message
      : header.message;
    lines.push(`  ${icon} ${header.name.padEnd(35)} ${detail}`);
  }

  // Info disclosure
  if (result.infoDisclosure.length > 0) {
    lines.push('');
    lines.push('Information Disclosure:');
    for (const info of result.infoDisclosure) {
      lines.push(`  ${STATUS_ICONS.warn} ${info.message}`);
    }
  }

  // Recommendations (only for warn/fail)
  const recommendations = result.headers
    .filter((h) => h.remediation)
    .sort((a, b) => {
      const severityOrder = { high: 0, medium: 1, low: 2 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });

  if (recommendations.length > 0) {
    lines.push('');
    lines.push('Recommendations:');
    recommendations.forEach((h, i) => {
      const priority = h.severity.toUpperCase();
      lines.push(`  ${i + 1}. ${h.remediation} (${priority} priority)`);
    });
  }

  lines.push('');
  lines.push(
    'Full website compliance scan \u2192 https://trustyourwebsite.com'
  );

  return lines.join('\n');
}
