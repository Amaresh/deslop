---
name: no-or-default-for-nonzero-number
description: >-
  Do not write `n || 1` (or other nonzero numeric defaults) when 0 is a valid value. Use ?? or an explicit null check. Use only when editing TypeScript numeric defaults. Do not use for boolean coercion, string fallbacks, or `|| 0` NaN guards.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-ts-node-v1
  engine_rule_id: typescript.correctness.no-or-default-for-nonzero-number
  globs: "**/*.{ts,tsx}"
---

# Do not use `||` to default a number that can be zero

`count || 1` turns a legitimate 0 into 1. Pagination, ports, and money all break.

## Do

```ts
const pageSize = requested ?? 20;
```

## Do not

```ts
const pageSize = requested || 20;
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack ts --rule typescript.correctness.no-or-default-for-nonzero-number
```

