---
name: no-node-builtin-in-client-module
description: >-
  Do not import Node builtins (`node:fs`, `fs`, `path`, `child_process`) in a
  `'use client'` module. They cannot ship in the browser bundle. Use only when
  editing Client Components. Do not use for server modules, tests, or type-only
  imports.
disable-model-invocation: false
paths: '**/*.{ts,tsx,js,jsx}'
license: MIT
metadata:
  pack: stopthatslop-ts-node-v1
  engine_rule_id: typescript.web.no-node-builtin-in-client-module
  globs: "**/*.{ts,tsx,js,jsx}"
---

# Do not import Node builtins in `'use client'` modules

`'use client'` is a browser graph. `node:fs` / `path` / `child_process` will
fail at runtime or blow up the bundler. Keep those imports in a server module.

## Do

```tsx
'use client'
export function Page() {
  return <main>Ready</main>
}
```

```ts
import { readFile } from "node:fs/promises"
export async function loadConfig(path: string) {
  return readFile(path, "utf8")
}
```

## Do not

```tsx
'use client'
import { readFileSync } from "node:fs"
export function Page() {
  return <pre>{readFileSync("/etc/hosts", "utf8")}</pre>
}
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack ts --rule typescript.web.no-node-builtin-in-client-module
```
