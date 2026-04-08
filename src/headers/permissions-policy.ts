import type { HeaderResult } from '../types.js';

const HEADER = 'permissions-policy';

const DANGEROUS_FEATURES = [
  'camera',
  'microphone',
  'geolocation',
  'payment',
  'usb',
  'bluetooth',
  'midi',
];

/**
 * Analyzes the Permissions-Policy header.
 * @param headers - Lowercase response headers
 * @returns Header analysis result
 */
export function analyzePermissionsPolicy(
  headers: Record<string, string>
): HeaderResult {
  const value = headers[HEADER] ?? null;

  if (!value) {
    return {
      name: 'Permissions-Policy',
      status: 'fail',
      value: null,
      message: 'MISSING — Browser features are not restricted',
      severity: 'medium',
      score: 0,
      maxScore: 10,
      remediation:
        'Add Permissions-Policy to restrict access to sensitive browser features like camera, microphone, and geolocation',
    };
  }

  // Parse directives: feature=(allowlist), feature=()
  const directives = value.split(',').map((d) => d.trim());
  const restrictedFeatures: string[] = [];
  const unrestricted: string[] = [];

  for (const directive of directives) {
    const match = directive.match(/^([a-z-]+)=\(([^)]*)\)/);
    if (match) {
      const feature = match[1];
      const allowlist = match[2].trim();

      if (DANGEROUS_FEATURES.includes(feature)) {
        if (allowlist === '' || allowlist === 'self' || allowlist === '"self"') {
          restrictedFeatures.push(feature);
        } else if (allowlist === '*') {
          unrestricted.push(feature);
        } else {
          restrictedFeatures.push(feature);
        }
      }
    }
  }

  if (unrestricted.length > 0) {
    return {
      name: 'Permissions-Policy',
      status: 'warn',
      value,
      message: `Dangerous features allowed for all origins: ${unrestricted.join(', ')}`,
      severity: 'medium',
      score: 5,
      maxScore: 10,
      remediation: `Restrict ${unrestricted.join(', ')} to self or disable them entirely`,
    };
  }

  const score = Math.min(10, 5 + restrictedFeatures.length);

  if (restrictedFeatures.length === 0) {
    return {
      name: 'Permissions-Policy',
      status: 'warn',
      value,
      message: 'Header present but does not restrict dangerous features',
      severity: 'medium',
      score: 5,
      maxScore: 10,
      remediation: `Add restrictions for: ${DANGEROUS_FEATURES.join(', ')}`,
    };
  }

  if (restrictedFeatures.length < 3) {
    return {
      name: 'Permissions-Policy',
      status: 'warn',
      value,
      message: `Partially configured — restricts ${restrictedFeatures.join(', ')}`,
      severity: 'medium',
      score,
      maxScore: 10,
      remediation: `Also restrict: ${DANGEROUS_FEATURES.filter((f) => !restrictedFeatures.includes(f)).join(', ')}`,
    };
  }

  return {
    name: 'Permissions-Policy',
    status: 'pass',
    value,
    message: `Well-configured — restricts ${restrictedFeatures.join(', ')}`,
    severity: 'medium',
    score,
    maxScore: 10,
  };
}
