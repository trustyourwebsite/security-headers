import type { HeaderResult, ScanResult } from '../types.js';

/** SARIF result severity levels. */
type SarifLevel = 'error' | 'warning' | 'note' | 'none';

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  helpUri?: string;
}

interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations: Array<{
    physicalLocation: { artifactLocation: { uri: string } };
  }>;
}

const TOOL_NAME = 'security-headers';
const TOOL_URI = 'https://github.com/trustyourwebsite/security-headers';
const SARIF_SCHEMA =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

/**
 * Turns a header name into a stable, SARIF-friendly rule id
 * (e.g. "Content-Security-Policy" -> "security-headers/content-security-policy").
 * @param headerName - The human-readable header name
 * @returns A namespaced, lowercased rule id
 */
function ruleIdFor(headerName: string): string {
  return `${TOOL_NAME}/${headerName.toLowerCase()}`;
}

/**
 * Maps a header result status to a SARIF result level.
 * @param status - The header analysis status
 * @returns The corresponding SARIF level
 */
function levelForStatus(status: HeaderResult['status']): SarifLevel {
  switch (status) {
    case 'fail':
      return 'error';
    case 'warn':
      return 'warning';
    case 'info':
      return 'note';
    case 'pass':
    default:
      return 'none';
  }
}

/**
 * Formats a scan result as SARIF 2.1.0 JSON.
 * Emits one rule per header check and one result per failing/warning
 * (and noteworthy informational) header, plus information-disclosure findings.
 * @param result - Scan result to format
 * @returns Pretty-printed SARIF 2.1.0 JSON string
 */
export function formatSarif(result: ScanResult): string {
  const rules: SarifRule[] = [];
  const seenRuleIds = new Set<string>();
  const results: SarifResult[] = [];

  const location = {
    physicalLocation: { artifactLocation: { uri: result.url } },
  };

  for (const header of result.headers) {
    const ruleId = ruleIdFor(header.name);
    if (!seenRuleIds.has(ruleId)) {
      seenRuleIds.add(ruleId);
      rules.push({
        id: ruleId,
        name: header.name.replace(/-/g, ''),
        shortDescription: { text: `${header.name} security header check` },
        helpUri: TOOL_URI,
      });
    }

    // Only surface findings that need attention; passing headers add no result.
    // Informational findings are reported only when they carry a real message
    // (i.e. the header is present or there is remediation advice).
    if (header.status === 'pass') continue;
    if (header.status === 'info' && header.value === null && !header.remediation) {
      continue;
    }

    const text = header.remediation
      ? `${header.message}. ${header.remediation}`
      : header.message;

    results.push({
      ruleId,
      level: levelForStatus(header.status),
      message: { text },
      locations: [location],
    });
  }

  // Information-disclosure findings are advisory notes.
  const infoRuleId = `${TOOL_NAME}/information-disclosure`;
  if (result.infoDisclosure.length > 0 && !seenRuleIds.has(infoRuleId)) {
    seenRuleIds.add(infoRuleId);
    rules.push({
      id: infoRuleId,
      name: 'InformationDisclosure',
      shortDescription: { text: 'Response header leaks software details' },
      helpUri: TOOL_URI,
    });
  }
  for (const info of result.infoDisclosure) {
    results.push({
      ruleId: infoRuleId,
      level: 'note',
      message: { text: info.message },
      locations: [location],
    });
  }

  const sarif = {
    version: '2.1.0',
    $schema: SARIF_SCHEMA,
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            informationUri: TOOL_URI,
            rules,
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
