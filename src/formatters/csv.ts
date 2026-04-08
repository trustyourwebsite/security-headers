import type { ScanResult } from '../types.js';

/**
 * Escapes a value for CSV output.
 * @param val - Value to escape
 * @returns CSV-safe string
 */
function escapeCsv(val: string): string {
  if (val.includes(',') || val.includes('"') || val.includes('\n')) {
    return `"${val.replace(/"/g, '""')}"`;
  }
  return val;
}

/**
 * Formats a scan result as CSV.
 * @param result - Scan result to format
 * @returns CSV string with headers
 */
export function formatCsv(result: ScanResult): string {
  const lines: string[] = [];

  // Header row
  lines.push(
    'Header,Status,Severity,Score,MaxScore,Value,Message,Remediation'
  );

  for (const header of result.headers) {
    lines.push(
      [
        escapeCsv(header.name),
        header.status,
        header.severity,
        String(header.score),
        String(header.maxScore),
        escapeCsv(header.value ?? 'MISSING'),
        escapeCsv(header.message),
        escapeCsv(header.remediation ?? ''),
      ].join(',')
    );
  }

  // Info disclosure as separate rows
  for (const info of result.infoDisclosure) {
    lines.push(
      [
        escapeCsv(info.name),
        'warn',
        'low',
        '0',
        '0',
        escapeCsv(info.value),
        escapeCsv(info.message),
        escapeCsv(`Remove ${info.name} header`),
      ].join(',')
    );
  }

  return lines.join('\n');
}
