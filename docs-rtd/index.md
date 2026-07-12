# @trustyourwebsite/security-headers

Built and maintained by [TrustYourWebsite](https://trustyourwebsite.com), a compliance scanner for EU websites.

US business? The same scanner runs at [getuptocode.com](https://getuptocode.com) (Get Up to Code), focused on ADA accessibility and privacy lawsuit risk.

Zero-dependency Node.js tool that grades website security headers (HSTS, CSP, X-Frame-Options, and more) with A+ to F scoring. CI-friendly, with a configurable minimum-grade threshold.

## Installation

```bash
# Global install
npm install -g @trustyourwebsite/security-headers

# Or as a dev dependency
npm install --save-dev @trustyourwebsite/security-headers
```

## Quick start

Run it once, no install required:

```bash
npx @trustyourwebsite/security-headers https://example.com
```

## Headers checked

| Header | Weight | What we check |
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

It also flags **information disclosure** headers that should be removed: `Server`, `X-Powered-By`, `X-AspNet-Version` and `X-AspNetMvc-Version`.

## Grading system

| Grade | Score | Conditions |
|-------|-------|------------|
| A+ | 90-100 | No fails of any kind |
| A | 80-89 | No critical (high severity) fails |
| B | 65-79 | |
| C | 50-64 | |
| D | 35-49 | |
| F | 0-34 | |

## Design decisions

- **Zero runtime dependencies.** Uses only Node.js built-in modules (`node:https`, `node:http`, `node:tls`, `node:fs`). Security tools should have minimal attack surface.
- **Robust CSP parser.** Parses all CSP directives and flags dangerous values with specific remediation advice.
- **CI-first.** `--ci` mode with exit codes makes it easy to add to any pipeline.

## Requirements

- Node.js 18+

See the [API Reference](api.md) for every option and export, or [Examples](examples.md) for CLI and CI/CD recipes.
