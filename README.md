# Header Sentry

![TypeScript](https://img.shields.io/badge/TypeScript-5%2B-3178C6?logo=typescript&logoColor=white)

**Review captured HTTP response headers for common security gaps.**

Header Sentry checks security headers, reports missing or weak settings, and highlights risky CSP sources. It works with saved header output, so it can be used during configuration review without making network requests.

## Quick start

Requires Node.js and the TypeScript compiler.

```bash
npx tsc --project tsconfig.json
node dist/app.js --input headers.txt
```

Provide one `Header: value` entry per line. Header names are matched without regard to case.

## Checks

- HSTS, Content Security Policy, and frame protection
- Content type and referrer policies
- COOP, CORP, and COEP headers

The report includes the observed value or a short suggestion. It is a configuration aid, not a live security scan.

## License

[MIT](LICENSE)
