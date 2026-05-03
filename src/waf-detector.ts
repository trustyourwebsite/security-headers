export interface WafDetection {
  /** True when the response looks like a WAF/bot-protection block */
  blocked: boolean;
  /** Detected WAF vendor when known, otherwise null */
  vendor: string | null;
}

const BLOCKING_STATUS = new Set([401, 403, 406, 429, 503]);

/**
 * Heuristic check for whether an HTTP response looks like a WAF / bot-protection block.
 * Conservative on purpose: only flag when status code is in a typical block range AND
 * a recognizable WAF signature is present, otherwise prefer false negatives over
 * mislabeling a genuinely badly-configured site.
 */
export function detectWaf(
  statusCode: number,
  headers: Record<string, string>
): WafDetection {
  if (!BLOCKING_STATUS.has(statusCode)) {
    return { blocked: false, vendor: null };
  }

  const server = headers['server'] ?? '';

  if (headers['x-blocked-by-waf'] || /AkamaiGHost/i.test(server)) {
    return { blocked: true, vendor: 'Akamai' };
  }

  if (
    headers['cf-mitigated'] ||
    (headers['cf-ray'] && (statusCode === 403 || statusCode === 429 || statusCode === 503)) ||
    (/cloudflare/i.test(server) && (statusCode === 403 || statusCode === 503))
  ) {
    return { blocked: true, vendor: 'Cloudflare' };
  }

  if (headers['x-amzn-waf-action'] || /awselb|aws.*waf/i.test(server)) {
    return { blocked: true, vendor: 'AWS WAF' };
  }

  if (headers['x-sucuri-id'] || /sucuri/i.test(server)) {
    return { blocked: true, vendor: 'Sucuri' };
  }

  if (headers['x-iinfo'] || /imperva|incapsula/i.test(server)) {
    return { blocked: true, vendor: 'Imperva' };
  }

  if (
    /fastly/i.test(headers['x-cdn'] ?? '') &&
    (statusCode === 403 || statusCode === 429)
  ) {
    return { blocked: true, vendor: 'Fastly' };
  }

  if (statusCode === 403 || statusCode === 429) {
    return { blocked: true, vendor: null };
  }

  return { blocked: false, vendor: null };
}
