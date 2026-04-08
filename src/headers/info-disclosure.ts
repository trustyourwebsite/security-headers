import type { InfoDisclosureResult } from '../types.js';

/** Headers that reveal server/framework details and should be removed */
const INFO_HEADERS: Record<string, string> = {
  server: 'Server',
  'x-powered-by': 'X-Powered-By',
  'x-aspnet-version': 'X-AspNet-Version',
  'x-aspnetmvc-version': 'X-AspNetMvc-Version',
};

/**
 * Checks for information disclosure headers that reveal server/framework details.
 * @param headers - Lowercase response headers
 * @returns Array of information disclosure findings
 */
export function analyzeInfoDisclosure(
  headers: Record<string, string>
): InfoDisclosureResult[] {
  const results: InfoDisclosureResult[] = [];

  for (const [key, displayName] of Object.entries(INFO_HEADERS)) {
    const value = headers[key];
    if (!value) continue;

    // Server header without version is less concerning
    if (key === 'server' && !/\d/.test(value)) {
      results.push({
        name: displayName,
        value,
        message: `${displayName}: ${value} — Consider removing the header entirely`,
      });
    } else if (key === 'server') {
      results.push({
        name: displayName,
        value,
        message: `${displayName}: ${value} — Remove version number to prevent targeted attacks`,
      });
    } else {
      results.push({
        name: displayName,
        value,
        message: `${displayName}: ${value} — Remove this header to avoid revealing technology stack`,
      });
    }
  }

  return results;
}
