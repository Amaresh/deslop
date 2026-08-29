---
name: no-non-null-array-index
description: >-
  Do not silence noUncheckedIndexedAccess with items[i]!. Bounds-check, use
  .at() with an undefined branch, or return early. Use only when editing
  TypeScript with strict index access on arrays and records. Do not use for
  Map.get (already T | undefined), tuple types of known length, or literals
  where the index is provably in range.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-ts-node-v1
  engine_rule_id: typescript.strictness.no-non-null-array-index-access
  globs: "**/*.ts"
---

# No `[i]!` to beat the type checker

`items[i]!` tells TypeScript the element exists without checking anything.
Agents bolt it on to make `strict` pass quickly; the runtime crash just moves
to production.

## Do

```typescript
function firstPending(items: Task[]): Task | undefined {
  return items.find((task) => task.status === "pending");
}

const [head, ...rest] = queue;
if (!head) {
  return { ok: false, reason: "empty queue" };
}
```

Or check explicitly:

```typescript
const next = candidates.at(0);
if (next === undefined) throw new EmptyQueueError();
```

## Do not

```typescript
function firstPending(items: Task[]): Task {
  return items.find((task) => task.status === "pending")!; // lie
}

process(queue[0]!); // throws TypeError when queue is empty
```

If you truly know the invariant (just checked `length`, fixed-size tuple),
prefer a guard or destructure so the knowledge is visible to reviewers instead
of hidden in a `!`.

## Enforce

This skill is teach-only. No engine detector exists yet; CI must not fail on
it.
