import type { ScanResult } from '../types.js';

/**
 * Formats a scan result as JSON.
 * @param result - Scan result to format
 * @returns Pretty-printed JSON string
 */
export function formatJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
