# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] — 2026-07-12

### Added
- **SARIF 2.1.0 output** (`--format sarif`) for GitHub code-scanning and CI ingestion.
- **`Content-Security-Policy-Report-Only` analyzer**: detects report-only policies and warns when report-only is the *only* CSP present (monitoring, not enforcement).
- `detectWaf` is now exported from the package entry point for library consumers.

### Changed
- **CSP scoring**: a directive set to `'none'` is recognized as fully locked-down (never penalized); `'nonce-…'` / `'sha256|384|512-…'` sources are credited and suppress the (browser-ignored) `'unsafe-inline'` penalty; `frame-ancestors` only earns its bonus for a real allowlist / `'self'` / `'none'`.
- **Publishing hardened**: npm provenance attestation on release, a conditional `exports` map, `prepublishOnly` now runs lint + tests + build, and CI runs a non-blocking dependency audit.

### Fixed
- `frame-ancestors *` (and `'unsafe-inline'`) no longer incorrectly earned clickjacking-protection points.
- Corrected a stray quote in the CSP wildcard warning message.


## [1.1.1] — 2026-05-20

### Added
- **WAF detection**: scans now surface `wafBlocked` and `wafVendor` on `ScanResult` when a Web Application Firewall intercepts the probe, so a blocked request is no longer mistaken for a missing header set.

### Changed
- Updated the `homepage` field and all TrustYourWebsite links to the canonical trustyourwebsite.com domain.

### Docs
- Added a GitHub Pages landing site under `/docs`.


## [1.1.0] — 2026-04-19

### Added
- **Set-Cookie validation**: new analyzer checks cookies for `Secure`, `HttpOnly`, and `SameSite` attributes. Flags missing security attributes with actionable remediation advice.

### Changed
- **CSP scoring**: `unsafe-inline` in `style-src` now receives a reduced penalty (-1) compared to `script-src` (-2), reflecting that style-src unsafe-inline is nearly universal and far less dangerous than script-src.
- **CLI version**: `--version` flag now reads the version dynamically from package.json instead of being hardcoded.

### Fixed
- `--version` was hardcoded to `1.0.0` and would never update. Now reads from package.json.
- HTTP client now preserves individual `Set-Cookie` headers as an array instead of joining them with commas (which corrupted cookie date fields).


## [1.0.1] — 2026-04-18

### Changed
- Expanded npm keywords for better discoverability (added x-frame-options, web-security, http-headers, auditor, cli, nodejs, typescript, zero-dependencies, owasp, gdpr).
- Replaced the placeholder `"TrustYourWebsite Editorial"` `author` field with the canonical `TrustYourWebsite <info@trustyourwebsite.com> (https://trustyourwebsite.com)` contact, matching the other @trustyourwebsite packages.
- Added `"sideEffects": false` to help bundlers tree-shake unused checks.
- Added `"publishConfig": { "access": "public" }` so scoped public publishing is explicit.
- The published tarball now includes `README.md` and `LICENSE` alongside `dist/`.
- Normalized `repository.url` to the `git+https://...git` form npm expects.

### Docs
- Added a `## Related` section linking the sibling [@trustyourwebsite/dns-auth-check](https://github.com/trustyourwebsite/dns-auth-check) and [@trustyourwebsite/cookie-consent-validator](https://github.com/trustyourwebsite/cookie-consent-validator) packages.

No runtime behaviour changes. Safe drop-in upgrade from 1.0.0.

## [1.0.0] — 2026-04-08

Initial public release.

- Scores HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-Content-Type-Options and related headers.
- CSP parser flags dangerous directives (`unsafe-inline`, `unsafe-eval`, wildcards).
- A+ to F grading with configurable minimum grade threshold.
- JSON, text and table output.
- CI mode with exit codes suitable for any pipeline.
