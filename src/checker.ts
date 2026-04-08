import type { CheckOptions, ScanResult } from './types.js';
import { fetchHeaders } from './http-client.js';
import {
  analyzeHsts,
  analyzeCsp,
  analyzeXContentType,
  analyzeXFrame,
  analyzeReferrerPolicy,
  analyzePermissionsPolicy,
  analyzeXssProtection,
  analyzeCoop,
  analyzeCorp,
  analyzeCoep,
  analyzeCacheControl,
  analyzeInfoDisclosure,
} from './headers/index.js';
import { calculateScore, scoreToGrade } from './grader.js';

/**
 * Scans a URL and analyzes its security headers.
 * This is the main library entry point.
 * @param url - The URL to scan
 * @param options - Scan options (redirects, timeout, etc.)
 * @returns Full scan result with grade, score, and header analysis
 */
export async function checkHeaders(
  url: string,
  options: CheckOptions = {}
): Promise<ScanResult> {
  const response = await fetchHeaders(url, options);

  const headerResults = [
    analyzeHsts(response.headers),
    analyzeCsp(response.headers),
    analyzeXContentType(response.headers),
    analyzeXFrame(response.headers),
    analyzeReferrerPolicy(response.headers),
    analyzePermissionsPolicy(response.headers),
    analyzeXssProtection(response.headers),
    analyzeCoop(response.headers),
    analyzeCorp(response.headers),
    analyzeCoep(response.headers),
    analyzeCacheControl(response.headers),
  ];

  const infoDisclosure = analyzeInfoDisclosure(response.headers);
  const score = calculateScore(headerResults, infoDisclosure);
  const grade = scoreToGrade(score, headerResults);

  return {
    url: response.finalUrl,
    grade,
    score,
    headers: headerResults,
    infoDisclosure,
    rawHeaders: response.headers,
    redirectChain: response.redirectChain,
    tlsVersion: response.tlsVersion,
    timestamp: new Date().toISOString(),
  };
}
