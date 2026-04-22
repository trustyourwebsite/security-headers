# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
