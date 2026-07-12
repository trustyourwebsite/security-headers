# Examples

## CLI usage

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

## Output example

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
```

## Programmatic usage

```typescript
import { checkHeaders } from '@trustyourwebsite/security-headers';

const result = await checkHeaders('https://example.com', {
  followRedirects: true,
  timeout: 10000,
});

console.log(result.grade);  // 'A+' | 'A' | 'B' | 'C' | 'D' | 'F'
console.log(result.score);  // 0-100
```

## CI/CD integration

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
