# Header Sentry

Header Sentry inspects captured HTTP response headers and highlights common security gaps.

## Quick start

```bash
npx tsc --project tsconfig.json
node dist/app.js --input headers.txt
```

## Input

Provide a text file with one `Header: value` per line. Case-insensitive keys are supported.

## Output

- Missing or weak security headers.
- CSP risk flags (unsafe-inline / unsafe-eval).
- Suggested fixes for each finding.
