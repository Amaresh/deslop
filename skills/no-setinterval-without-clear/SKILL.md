---
name: no-setinterval-without-clear
description: >-
  Do not call setInterval without storing the handle and clearing it in the
  cleanup path (useEffect return, teardown, dispose). Use only when editing
  TypeScript/JavaScript timers in components or long-lived objects. Do not use
  for setTimeout one-shots without cancellation needs, worker threads, or
  cron-style schedulers with their own lifecycle.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-ts-node-v1
  engine_rule_id: typescript.reliability.no-setinterval-without-clear
  globs: "**/*.ts"
---

# Every setInterval needs a clearInterval

An uncleared interval keeps firing after unmount or shutdown: duplicate polls,
zombie state updates on dead components, leaked handles in tests. Agents write
the `setInterval` line and forget the cleanup half of the pattern.

## Do

```tsx
useEffect(() => {
  const id = setInterval(pollStatus, 10_000);
  return () => clearInterval(id);
}, []);
```

With async work, guard against overlap too:

```tsx
useEffect(() => {
  let cancelled = false;
  const id = setInterval(async () => {
    const status = await fetchStatus();
    if (!cancelled) setStatus(status);
  }, 10_000);
  return () => {
    cancelled = true;
    clearInterval(id);
  };
}, []);
```

## Do not

```tsx
useEffect(() => {
  setInterval(pollStatus, 10_000); // handle dropped, fires forever
}, []);
```

```typescript
class Dashboard {
  start() {
    setInterval(() => this.refresh(), 5_000); // stop() never clears it
  }
}
```

## Enforce

This skill is teach-only. No engine detector exists yet; CI must not fail on
it.
