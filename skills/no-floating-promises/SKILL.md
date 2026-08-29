---
name: no-floating-promises
description: >-
  Do not leave async calls unawaited. Await them, or handle explicitly with
  .catch, void, or Promise.all. Use only when editing TypeScript/JavaScript
  call sites of async functions or promises. Do not use for Python coroutines,
  Java futures, or deliberate fire-and-forget with an attached error handler.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-ts-node-v1
  engine_rule_id: typescript.reliability.no-floating-promises
  globs: "**/*.ts"
---

# No floating promises

An unawaited promise discards its rejection: the write "happened" in review
and silently failed in production. Agents emit this constantly when they
convert a function to `async` and forget one call site.

## Do

```typescript
export async function registerUser(input: SignupInput): Promise<User> {
  const user = await db.users.insert(input);
  await mailer.sendWelcome(user.email);
  return user;
}
```

## Do not

```typescript
export async function registerUser(input: SignupInput): Promise<User> {
  const user = await db.users.insert(input);
  mailer.sendWelcome(user.email); // rejection vanishes; ordering not guaranteed
  return user;
}
```

If fire-and-forget is genuinely intended, make it explicit so reviewers and
linters can tell the difference:

```typescript
void mailer.sendWelcome(user.email).catch((err) => logger.error(err));
```

## Enforce

This skill is teach-only. No engine detector exists yet; CI must not fail on
it.
