---
name: stopthatslop-ts-node
description: >-
  TypeScript/Node/React architecture pack. Use when editing TypeScript async
  code, Express handlers, env access, React form inputs, or timers. One pack,
  several invariants. Apply only the section that matches the files in scope.
disable-model-invocation: false
paths:
- '**/*.ts'
- '**/*.tsx'
- '**/*.{ts,tsx}'
- '**/*.{ts,tsx,js,jsx}'
license: MIT
metadata:
  pack: stopthatslop-ts-node-v1
  kind: pack-index
---

# stopthatslop-ts-node

Do not apply every section. Match the file in front of you.

Nine rules are CI-gated (`enforcement: checker`): fetch abort timeout, empty
Express catch, unguarded `JSON.parse`, mixed controlled inputs, unvalidated
href, orphaned effect timers, eager heavy imports, `||` numeric defaults, and
Node builtins in `'use client'` modules.
Needs Node so `stopthatslop check` can run the TypeScript parser. The rest of this
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

## Client Components (`'use client'`)

Do not import `node:fs`, `path`, `child_process`, or other Node builtins.
Those stay in a server module.
