---
name: no-fetch-without-abort-timeout
description: >-
  Do not call fetch without an abort signal timeout. Pair every fetch with
  AbortSignal.timeout or an AbortController plus setTimeout. Use only when
  editing TypeScript/JavaScript fetch calls in Node or browser code. Do not use
  for axios/got (they carry their own timeout options) or WebSocket connects.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-ts-node-v1
  engine_rule_id: typescript.http.no-fetch-without-abort-timeout
  globs: "**/*.ts"
---

# Every fetch needs a timeout

Node's `fetch` has no default request timeout. A stalled upstream pins the
socket and, on a server, one of your concurrency slots per such request until
the process is restarted.

## Do

```typescript
const response = await fetch("https://partner.example.com/quote", {
  signal: AbortSignal.timeout(5_000),
});
```

For cancellation you need to trigger yourself, use a controller:

```typescript
const controller = new AbortController();
const timer = setTimeout(() => controller.abort(), 5_000);
try {
  return await fetch(url, { signal: controller.signal });
} finally {
  clearTimeout(timer);
}
```

## Do not

```typescript
const response = await fetch("https://partner.example.com/quote");
```

`AbortSignal.timeout` requires Node 17.3+ / modern browsers; on older runtimes,
use the controller form.

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack ts --rule typescript.http.no-fetch-without-abort-timeout
```
