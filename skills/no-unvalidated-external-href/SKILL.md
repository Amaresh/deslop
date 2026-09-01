---
name: no-unvalidated-external-href
description: >-
  Do not put an untrusted expression into href without an http(s) allowlist. Use only when editing JSX/TSX links. Do not use for static href strings or resource <link rel> tags.
disable-model-invocation: false
paths: '**/*.{ts,tsx}'
license: MIT
metadata:
  pack: stopthatslop-ts-node-v1
  engine_rule_id: typescript.security.no-unvalidated-external-href
  globs: "**/*.{ts,tsx}"
---

# No unvalidated external href

`href={userInput}` is javascript: XSS waiting for a payload.

## Do

```tsx
function isHttp(url: string): boolean {
  return url.startsWith("https:") || url.startsWith("http:");
}
return isHttp(href) ? <a href={href}>{label}</a> : <span>{label}</span>;
```

## Do not

```tsx
return <a href={href}>{label}</a>;
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack ts --rule typescript.security.no-unvalidated-external-href
```

