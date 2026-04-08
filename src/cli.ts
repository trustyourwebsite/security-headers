#!/usr/bin/env node

import * as fs from 'node:fs';
import * as process from 'node:process';
import type { CliOptions, Grade, OutputFormat } from './types.js';
import { checkHeaders } from './checker.js';
import { gradeRank } from './grader.js';
import { formatTable } from './formatters/table.js';
import { formatJson } from './formatters/json.js';
import { formatCsv } from './formatters/csv.js';
import { formatText } from './formatters/text.js';

const VALID_FORMATS = new Set(['json', 'text', 'table', 'csv']);
const VALID_GRADES = new Set(['A+', 'A', 'B', 'C', 'D', 'F']);

const HELP = `
@trustyourwebsite/security-headers
===================================
Zero-dependency security headers checker with A+ to F grading.

Usage:
  security-headers <url> [options]

Options:
  --format <format>       Output format: json, text, table, csv (default: table)
  --follow-redirects      Follow HTTP redirects (default: true)
  --no-follow-redirects   Do not follow redirects
  --max-redirects <n>     Maximum redirect hops (default: 5)
  --timeout <ms>          Request timeout in milliseconds (default: 10000)
  --output <file>         Save report to file
  --ci                    Exit with code 1 if grade below threshold
  --min-grade <grade>     Minimum grade for CI mode (default: B)
  --user-agent <string>   Custom User-Agent string
  --help                  Show this help
  --version               Show version

Examples:
  security-headers https://example.com
  security-headers https://example.com --format json
  security-headers https://example.com --ci --min-grade A
  security-headers https://example.com --output report.json --format json

Full website compliance scan -> https://trustyourwebsite.nl
`;

/**
 * Parses CLI arguments into structured options.
 * @param argv - Process arguments (starting after node and script path)
 * @returns Parsed CLI options and target URL
 */
function parseArgs(argv: string[]): { url: string; options: CliOptions } {
  const options: CliOptions = {};
  let url = '';

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];

    switch (arg) {
      case '--help':
      case '-h':
        process.stdout.write(HELP);
        process.exit(0);
        break;

      case '--version':
      case '-v':
        process.stdout.write('1.0.0\n');
        process.exit(0);
        break;

      case '--format':
      case '-f': {
        const format = argv[++i];
        if (!format || !VALID_FORMATS.has(format)) {
          process.stderr.write(
            `Error: --format must be one of: ${[...VALID_FORMATS].join(', ')}\n`
          );
          process.exit(1);
        }
        options.format = format as OutputFormat;
        break;
      }

      case '--follow-redirects':
        options.followRedirects = true;
        break;

      case '--no-follow-redirects':
        options.followRedirects = false;
        break;

      case '--max-redirects': {
        const n = parseInt(argv[++i], 10);
        if (isNaN(n) || n < 0) {
          process.stderr.write('Error: --max-redirects must be a positive number\n');
          process.exit(1);
        }
        options.maxRedirects = n;
        break;
      }

      case '--timeout': {
        const t = parseInt(argv[++i], 10);
        if (isNaN(t) || t <= 0) {
          process.stderr.write('Error: --timeout must be a positive number\n');
          process.exit(1);
        }
        options.timeout = t;
        break;
      }

      case '--output':
      case '-o':
        options.output = argv[++i];
        if (!options.output) {
          process.stderr.write('Error: --output requires a file path\n');
          process.exit(1);
        }
        break;

      case '--ci':
        options.ci = true;
        break;

      case '--min-grade': {
        const grade = argv[++i];
        if (!grade || !VALID_GRADES.has(grade)) {
          process.stderr.write(
            `Error: --min-grade must be one of: ${[...VALID_GRADES].join(', ')}\n`
          );
          process.exit(1);
        }
        options.minGrade = grade as Grade;
        break;
      }

      case '--user-agent':
        options.userAgent = argv[++i];
        if (!options.userAgent) {
          process.stderr.write('Error: --user-agent requires a value\n');
          process.exit(1);
        }
        break;

      default:
        if (arg.startsWith('-')) {
          process.stderr.write(`Unknown option: ${arg}\nUse --help for usage information.\n`);
          process.exit(1);
        }
        url = arg;
        break;
    }
  }

  return { url, options };
}

/**
 * Formats a scan result using the specified output format.
 * @param result - Scan result to format
 * @param format - Output format
 * @returns Formatted string
 */
function formatOutput(
  result: Awaited<ReturnType<typeof checkHeaders>>,
  format: OutputFormat
): string {
  switch (format) {
    case 'json':
      return formatJson(result);
    case 'csv':
      return formatCsv(result);
    case 'text':
      return formatText(result);
    case 'table':
    default:
      return formatTable(result);
  }
}

async function main(): Promise<void> {
  const { url, options } = parseArgs(process.argv.slice(2));

  if (!url) {
    process.stderr.write(
      'Error: URL is required.\nUsage: security-headers <url> [options]\nUse --help for more information.\n'
    );
    process.exit(1);
  }

  // Validate URL
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      process.stderr.write('Error: URL must use http:// or https:// protocol\n');
      process.exit(1);
    }
  } catch {
    process.stderr.write(`Error: Invalid URL "${url}"\n`);
    process.exit(1);
  }

  try {
    const result = await checkHeaders(url, {
      followRedirects: options.followRedirects,
      maxRedirects: options.maxRedirects,
      timeout: options.timeout,
      userAgent: options.userAgent,
    });

    const format = options.format ?? 'table';
    const output = formatOutput(result, format);

    // Write to file or stdout
    if (options.output) {
      fs.writeFileSync(options.output, output, 'utf-8');
      process.stdout.write(`Report saved to ${options.output}\n`);
    } else {
      process.stdout.write(output + '\n');
    }

    // CI mode: exit with code 1 if grade is below threshold
    if (options.ci) {
      const minGrade = options.minGrade ?? 'B';
      if (gradeRank(result.grade) < gradeRank(minGrade)) {
        process.stderr.write(
          `CI check failed: grade ${result.grade} is below minimum ${minGrade}\n`
        );
        process.exit(1);
      }
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`Error: ${message}\n`);
    process.exit(1);
  }
}

main();
