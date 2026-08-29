---
name: no-unguarded-json-parse-on-external-input
description: >-
  Do not call JSON.parse on network, request-body, or file input without
  try/catch or a schema parser. Use only when editing TypeScript/JavaScript
  that parses untrusted JSON. Do not use for JSON.parse on literals you wrote,
  build-time config you control, or after a content-type check that already
  guarantees validity.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-ts-node-v1
  engine_rule_id: typescript.reliability.no-unguarded-json-parse-on-external-input
  globs: "**/*.ts"
---

# No unguarded JSON.parse on external input

Malformed input throws `SyntaxError`, which becomes a 500, a crashed worker,
or an unhandled rejection depending on where it lands. Agents assume the happy
path because the sample response happened to be valid JSON.

## Do

```typescript
import { z } from "zod";

const Payload = z.object({ orderId: z.string() });

export async function handleWebhook(request: Request): Promise<void> {
  const raw = await request.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new WebhookError("invalid JSON body");
  }
  const payload = Payload.parse(parsed);
  await fulfill(payload.orderId);
}
```

## Do not

```typescript
export async function handleWebhook(request: Request): Promise<void> {
  const payload = await request.json(); // throws on any malformed body
  await fulfill(payload.orderId);
}
```

Prefer `response.json()` guarded the same way for upstream API responses —
HTML error pages from proxies arrive as text and parse as nothing.

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack ts --rule typescript.reliability.no-unguarded-json-parse-on-external-input
```
