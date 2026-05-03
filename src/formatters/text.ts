import type { ScanResult } from '../types.js';

const STATUS_LABELS: Record<string, string> = {
  pass: 'PASS',
  warn: 'WARN',
  fail: 'FAIL',
  info: 'INFO',
};

/**
 * Formats a scan result as plain text (no box drawing, works in any terminal).
 * @param result - Scan result to format
 * @returns Plain text string
 */
export function formatText(result: ScanResult): string {
  const lines: string[] = [];

  lines.push(`URL: ${result.url}`);
  lines.push(`Grade: ${result.grade} (${result.score}/100)`);
  if (result.tlsVersion) {
    lines.push(`TLS: ${result.tlsVersion}`);
  }
  if (result.wafBlocked) {
    lines.push(
      `WAF: blocked by ${result.wafVendor ?? 'unknown WAF'} - results may be unreliable`
    );
  }
  lines.push('');

  for (const header of result.headers) {
    const label = STATUS_LABELS[header.status] ?? '????';
    lines.push(`[${label}] ${header.name}: ${header.message}`);
    if (header.remediation) {
      lines.push(`       -> ${header.remediation}`);
    }
  }

  if (result.infoDisclosure.length > 0) {
    lines.push('');
    for (const info of result.infoDisclosure) {
      lines.push(`[WARN] ${info.message}`);
    }
  }

  lines.push('');
  lines.push('Full website compliance scan -> https://trustyourwebsite.com');

  return lines.join('\n');
}
