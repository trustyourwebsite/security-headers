# @trustyourwebsite/security-headers

Zero-dependency Node.js tool that grades website security headers (HSTS, CSP, X-Frame-Options, etc.) with A+ to F scoring. CI-friendly with configurable minimum grade threshold.

Built by [TrustYourWebsite](https://trustyourwebsite.nl) — automated website compliance scanning for EU small businesses.

## Quick Start

```bash
npx @trustyourwebsite/security-headers https://example.com
```

## Installation

```bash
# Global install
npm install -g @trustyourwebsite/security-headers

# Or as a dev dependency
npm install --save-dev @trustyourwebsite/security-headers
```

## CLI Usage

```bash
# Basic scan
security-headers https://example.com

# JSON output
security-headers https://example.com --format json

# Save report to file
security-headers https://example.com --format json --output report.json

# CI mode — fail if grade below B
security-headers https://example.com --ci --min-grade B

# All options
security-headers https://example.com \
  --format table \
  --follow-redirects \
  --max-redirects 5 \
  --timeout 10000 \
  --user-agent "MyBot/1.0"
```

### CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `--format` | `table` | Output format: `json`, `text`, `table`, `csv` |
| `--follow-redirects` | `true` | Follow HTTP redirects |
| `--no-follow-redirects` | | Do not follow redirects |
| `--max-redirects` | `5` | Maximum redirect hops |
| `--timeout` | `10000` | Request timeout in milliseconds |
| `--output` | | Save report to file |
| `--ci` | | Exit code 1 if grade below threshold |
| `--min-grade` | `B` | Minimum grade for CI mode |
| `--user-agent` | | Custom User-Agent string |

## Library Usage

```typescript
import { checkHeaders } from '@trustyourwebsite/security-headers';

const result = await checkHeaders('https://example.com', {
  followRedirects: true,
  timeout: 10000,
});

console.log(result.grade);  // 'A+' | 'A' | 'B' | 'C' | 'D' | 'F'
console.log(result.score);  // 0-100
console.log(result.headers); // HeaderResult[]
```

## Output Example

```
Security Headers Report
=======================
URL:    https://example.com
Grade:  B (72/100)
TLS:    TLS 1.3

Headers:
  ✓ Strict-Transport-Security        max-age=31536000; includeSubDomains
  ✗ Content-Security-Policy           MISSING — Add CSP to prevent XSS attacks
  ✓ X-Content-Type-Options            nosniff
  ✓ X-Frame-Options                   DENY
  ⚠ Referrer-Policy                   no-referrer-when-downgrade — Consider strict-origin-when-cross-origin
  ✗ Permissions-Policy                MISSING — Restrict access to browser features
  ✓ X-XSS-Protection                  0 (correctly disabled)
  ✗ Cross-Origin-Opener-Policy        MISSING

Information Disclosure:
  ⚠ Server: nginx/1.24.0 — Remove version number
  ⚠ X-Powered-By: Express — Remove this header

Recommendations:
  1. Add Content-Security-Policy header (HIGH priority)
  2. Add Permissions-Policy header (MEDIUM priority)
  3. Remove server version from Server header (LOW priority)

Full website compliance scan → https://trustyourwebsite.nl
```

## Headers Checked

| Header | Weight | What We Check |
|--------|--------|---------------|
| `Strict-Transport-Security` | High | max-age >= 1 year, includeSubDomains, preload |
| `Content-Security-Policy` | High | Dangerous values (unsafe-inline, unsafe-eval, wildcards), directives |
| `X-Content-Type-Options` | Medium | Must be `nosniff` |
| `X-Frame-Options` | Medium | DENY or SAMEORIGIN |
| `Referrer-Policy` | Medium | Privacy-respecting values |
| `Permissions-Policy` | Medium | Dangerous features restricted |
| `Cross-Origin-Opener-Policy` | Medium | same-origin preferred |
| `Cross-Origin-Resource-Policy` | Low | same-origin or same-site |
| `Cross-Origin-Embedder-Policy` | Low | require-corp for isolation |
| `Cache-Control` | Low | no-store or private for sensitive pages |
| `X-XSS-Protection` | Low | Deprecated — should be `0` or absent |

We also check for **information disclosure** headers that should be removed:
- `Server` (reveals software version)
- `X-Powered-By` (reveals framework)
- `X-AspNet-Version` / `X-AspNetMvc-Version`

## Grading System

| Grade | Score | Conditions |
|-------|-------|------------|
| A+ | 90-100 | No fails of any kind |
| A | 80-89 | No critical (high severity) fails |
| B | 65-79 | |
| C | 50-64 | |
| D | 35-49 | |
| F | 0-34 | |

## CI/CD Integration

### GitHub Actions

```yaml
- name: Check security headers
  run: npx @trustyourwebsite/security-headers https://your-site.com --ci --min-grade B
```

### GitLab CI

```yaml
security-headers:
  script:
    - npx @trustyourwebsite/security-headers https://your-site.com --ci --min-grade B
```

## Design Decisions

- **Zero runtime dependencies.** Uses only Node.js built-in modules (`node:https`, `node:http`, `node:tls`, `node:fs`). Security tools should have minimal attack surface.
- **Robust CSP parser.** Parses all CSP directives and flags dangerous values with specific remediation advice.
- **CI-first.** `--ci` mode with exit codes makes it easy to add to any pipeline.

## Requirements

- Node.js 18+

## Related

- [TrustYourWebsite](https://trustyourwebsite.nl) — Full website compliance scanning for EU businesses
- [@trustyourwebsite/dns-auth-check](https://github.com/trustyourwebsite/dns-auth-check) — SPF, DKIM, DMARC, BIMI and MTA-STS email authentication auditor
- [@trustyourwebsite/cookie-consent-validator](https://github.com/trustyourwebsite/cookie-consent-validator) — Verify cookie consent banners actually stop tracking on "Reject All"

## License

MIT

---

Built by [TrustYourWebsite](https://trustyourwebsite.nl) — we help EU small businesses stay compliant with automated website scanning. [Get a free compliance scan](https://trustyourwebsite.nl).
