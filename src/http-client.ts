import * as https from 'node:https';
import * as http from 'node:http';
import type { TLSSocket } from 'node:tls';
import type { CheckOptions } from './types.js';

export interface HttpResponse {
  /** Final status code */
  statusCode: number;
  /** Lowercase response headers */
  headers: Record<string, string>;
  /** Raw Set-Cookie header values (preserved as array) */
  setCookieHeaders: string[];
  /** Chain of URLs visited during redirects */
  redirectChain: string[];
  /** TLS protocol version (e.g. "TLSv1.3") */
  tlsVersion: string | null;
  /** The final URL after redirects */
  finalUrl: string;
}

const DEFAULT_USER_AGENT = '@trustyourwebsite/security-headers/1.0.0';
const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);

/**
 * Performs an HTTP(S) GET request, optionally following redirects.
 * Zero-dependency: uses only Node.js stdlib.
 * @param url - Target URL to fetch
 * @param options - Request options
 * @returns HTTP response with headers and metadata
 */
export function fetchHeaders(
  url: string,
  options: CheckOptions = {}
): Promise<HttpResponse> {
  const {
    followRedirects = true,
    maxRedirects = 5,
    timeout = 10000,
    userAgent = DEFAULT_USER_AGENT,
  } = options;

  return new Promise((resolve, reject) => {
    const redirectChain: string[] = [];
    let tlsVersion: string | null = null;

    function doRequest(currentUrl: string, redirectsLeft: number): void {
      const parsedUrl = new URL(currentUrl);
      const isHttps = parsedUrl.protocol === 'https:';
      const lib = isHttps ? https : http;

      const requestOptions = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method: 'GET',
        headers: {
          'User-Agent': userAgent,
          Accept: '*/*',
        },
        timeout,
      };

      const req = lib.request(requestOptions, (res) => {
        // Capture TLS version from the first HTTPS response
        if (isHttps && !tlsVersion) {
          const socket = res.socket as TLSSocket;
          if (socket.getProtocol) {
            tlsVersion = socket.getProtocol();
          }
        }

        // Consume the response body to free the socket
        res.resume();

        const statusCode = res.statusCode ?? 0;

        // Handle redirects
        if (
          followRedirects &&
          REDIRECT_CODES.has(statusCode) &&
          res.headers.location
        ) {
          if (redirectsLeft <= 0) {
            reject(new Error(`Too many redirects (max ${maxRedirects})`));
            return;
          }

          redirectChain.push(currentUrl);
          const nextUrl = new URL(res.headers.location, currentUrl).href;
          doRequest(nextUrl, redirectsLeft - 1);
          return;
        }

        // Normalize headers to lowercase keys with string values
        const headers: Record<string, string> = {};
        for (const [key, val] of Object.entries(res.headers)) {
          if (val !== undefined) {
            headers[key.toLowerCase()] = Array.isArray(val)
              ? val.join(', ')
              : val;
          }
        }

        // Preserve Set-Cookie headers as array (they get joined with ', ' above)
        const setCookieHeaders: string[] = [];
        const rawSetCookie = res.headers['set-cookie'];
        if (rawSetCookie) {
          setCookieHeaders.push(...rawSetCookie);
        }

        resolve({
          statusCode,
          headers,
          setCookieHeaders,
          redirectChain,
          tlsVersion,
          finalUrl: currentUrl,
        });
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Request timed out after ${timeout}ms`));
      });

      req.on('error', (err) => {
        reject(
          new Error(`Failed to fetch ${currentUrl}: ${err.message}`)
        );
      });

      req.end();
    }

    doRequest(url, maxRedirects);
  });
}
