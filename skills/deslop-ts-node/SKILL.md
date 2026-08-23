---
name: deslop-ts-node
description: >-
  TypeScript/Node/React architecture pack. Use when editing TypeScript async
  code, Express handlers, env access, React form inputs, or timers. One pack,
  several invariants. Apply only the section that matches the files in scope.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-ts-node-v1
  kind: pack-index
---

# deslop-ts-node

Do not apply every section. Match the file in front of you.

Every rule in this pack is teach-only until an agent-written sample fails
`scripts/check.py`. No engine detectors exist for these rules yet.

## Any `async` call site

Do not leave promises floating. Await them, or handle them explicitly with
`.catch`, `void`, or `Promise.all`.

## Any `fetch(` call

Pair it with an `AbortSignal.timeout(...)` (or a controller with `setTimeout`)
so a stalled upstream cannot hang the request forever.

## Express handlers (`app.get(`, `router.post(` etc.)

Do not write empty catch blocks. Catch, log, and return the error response.

## Module top level (`process.env.` at import time)

Read env vars lazily and validate them; do not bake `process.env.X ?? ""`
defaults at module load.

## Anywhere external text is parsed

Guard `JSON.parse` on external input with try/catch or a schema parser.

## Array indexing in strict TypeScript

Do not paper over `noUncheckedIndexedAccess` with `[i]!`; bounds-check first.

## React inputs (`<input`, `<textarea`, `<select`)

Give every input both `value` and `onChange`, or neither plus a ref. Never mix.

## Timers (`setInterval(`)

Store the handle and clear it in the cleanup path (`useEffect` return,
`clearInterval`).
