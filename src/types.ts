export type Grade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';

export type HeaderStatus = 'pass' | 'warn' | 'fail' | 'info';

export type Severity = 'high' | 'medium' | 'low';

export type OutputFormat = 'json' | 'text' | 'table' | 'csv';

export interface HeaderResult {
  /** Header name (e.g. "Strict-Transport-Security") */
  name: string;
  /** Whether the header passed, warned, or failed */
  status: HeaderStatus;
  /** The raw header value, or null if missing */
  value: string | null;
  /** Human-readable description of the finding */
  message: string;
  /** How much this header matters for the overall score */
  severity: Severity;
  /** Points earned for this header (0 to max for severity) */
  score: number;
  /** Maximum possible points for this header */
  maxScore: number;
  /** Actionable fix suggestion when status is warn or fail */
  remediation?: string;
}

export interface InfoDisclosureResult {
  /** Header name that discloses info (e.g. "Server") */
  name: string;
  /** The raw header value */
  value: string;
  /** Human-readable warning message */
  message: string;
}

export interface ScanResult {
  /** The final URL after redirects */
  url: string;
  /** Overall letter grade */
  grade: Grade;
  /** Numeric score 0-100 */
  score: number;
  /** Individual header analysis results */
  headers: HeaderResult[];
  /** Information disclosure findings */
  infoDisclosure: InfoDisclosureResult[];
  /** All raw response headers */
  rawHeaders: Record<string, string>;
  /** Chain of URLs if redirects occurred */
  redirectChain: string[];
  /** TLS version used (e.g. "TLSv1.3") */
  tlsVersion: string | null;
  /** Timestamp of the scan */
  timestamp: string;
}

export interface CheckOptions {
  /** Follow HTTP redirects (default: true) */
  followRedirects?: boolean;
  /** Maximum number of redirects to follow (default: 5) */
  maxRedirects?: number;
  /** Request timeout in milliseconds (default: 10000) */
  timeout?: number;
  /** Custom User-Agent string */
  userAgent?: string;
}

export interface CliOptions extends CheckOptions {
  /** Output format */
  format?: OutputFormat;
  /** Save report to file */
  output?: string;
  /** Enable CI mode (exit code 1 if below min-grade) */
  ci?: boolean;
  /** Minimum acceptable grade for CI mode */
  minGrade?: Grade;
}

/** A function that analyzes a specific header and returns a result */
export type HeaderAnalyzer = (headers: Record<string, string>) => HeaderResult;
