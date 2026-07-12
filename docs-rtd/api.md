# API Reference

## CLI options

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

## Exit codes

- `0` — grade meets or exceeds the threshold (or `--ci` not set).
- `1` — in `--ci` mode, the grade is below `--min-grade`.

## Library exports

```typescript
import { checkHeaders } from '@trustyourwebsite/security-headers';

const result = await checkHeaders('https://example.com', {
  followRedirects: true,
  timeout: 10000,
});

console.log(result.grade);   // 'A+' | 'A' | 'B' | 'C' | 'D' | 'F'
console.log(result.score);   // 0-100
console.log(result.headers); // HeaderResult[]
```

`checkHeaders(url, options)` resolves to a result object with:

- `grade` — overall letter grade, `A+` through `F`.
- `score` — numeric score from 0 to 100.
- `headers` — per-header results (`HeaderResult[]`), including present/missing status and remediation advice.
