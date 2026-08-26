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

Eight rules are CI-gated (`enforcement: checker`): fetch abort timeout, empty
Express catch, unguarded `JSON.parse`, mixed controlled inputs, unvalidated
href, orphaned effect timers, eager heavy imports, and `||` numeric defaults.
Needs Node so `deslop check` can run the TypeScript parser. The rest of this
pack is still teach-only.

## Any `async` call site

Do not leave promises floating. Await them, or handle them explicitly with
`.catch`, `void`, or `Promise.all`. (Teach-only — needs types.)

## Any `fetch(` call

Pair it with `AbortSignal.timeout(...)` (or a controller with `setTimeout`).

## Express handlers (`app.get(`, `router.post(` etc.)

Do not write empty catch blocks. Catch, log, and return the error response.

## Module top level (`process.env.` at import time)

Read env vars lazily and validate them. (Teach-only.)

## Anywhere external text is parsed

Guard `JSON.parse` on external input with try/catch or a schema parser.

## Array indexing in strict TypeScript

Do not paper over `noUncheckedIndexedAccess` with `[i]!`. (Teach-only.)

## React inputs (`<input`, `<textarea`, `<select`)

Give every input both `value` and `onChange`, or neither plus a ref. Never mix.

## Timers (`setInterval(`)

Store the handle and clear it in the cleanup path. Effect `setTimeout` without
cleanup is a separate gated rule (`no-orphaned-effect-timeouts`).
