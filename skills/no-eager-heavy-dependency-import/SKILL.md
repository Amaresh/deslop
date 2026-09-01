---
name: no-eager-heavy-dependency-import
description: >-
  Do not statically import lodash, moment, or similar heavy packages at module top level. Dynamic-import them on the path that needs them. Use only when editing TS/JS modules. Do not use for types-only imports or already-lazy routes.
disable-model-invocation: false
paths: '**/*.{ts,tsx}'
license: MIT
metadata:
  pack: stopthatslop-ts-node-v1
  engine_rule_id: typescript.performance.no-eager-heavy-dependency-import
  globs: "**/*.{ts,tsx}"
---

# Do not eagerly import heavy dependencies

A top-level `import _ from "lodash"` pays for the whole library on every cold start.

## Do

```ts
export async function format(value: unknown) {
  const { default: pick } = await import("lodash/pick.js");
  return pick(value, ["id"]);
}
```

## Do not

```ts
import pick from "lodash/pick.js";
export function format(value: unknown) {
  return pick(value, ["id"]);
}
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack ts --rule typescript.performance.no-eager-heavy-dependency-import
```

