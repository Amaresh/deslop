---
name: no-unvalidated-env-at-module-top-level
description: >-
  Do not read process.env at module top level without validation or fail-fast
  checks. Read env lazily through a validated config module. Use only when
  editing TypeScript/Node configuration code and module initializers. Do not
  use for test fixtures, scripts with documented required env, or values with
  genuine non-secret defaults validated elsewhere.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-ts-node-v1
  engine_rule_id: typescript.node.no-unvalidated-env-at-module-top-level
  globs: "**/*.ts"
---

# No unvalidated env access at import time

`const API_KEY = process.env.API_KEY ?? ""` at module top level means the app
boots successfully with an empty credential and fails later, somewhere
unrelated, with a 401 from a third party. Agents sprinkle this pattern to make
modules importable without errors.

## Do

```typescript
// config.ts
function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required env var: ${name}`);
  }
  return value;
}

export const config = {
  stripeKey: requireEnv("STRIPE_API_KEY"),
  port: Number(process.env.PORT ?? 3000),
};
```

The process refuses to start when a required var is missing; that is the
correct behavior.

## Do not

```typescript
// stripe.ts (top level)
export const API_KEY = process.env.STRIPE_API_KEY ?? "";
export const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET as string;
```

`as string` on `process.env` is the same slop: it silences the type checker,
not the missing variable.

## Enforce

This skill is teach-only. No engine detector exists yet; CI must not fail on
it.
