---
name: no-orphaned-effect-timeouts
description: >-
  Do not call setTimeout/setInterval inside useEffect without clearing them in the cleanup. Use only when editing React effects. Do not use for timers in event handlers or non-React code.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-ts-node-v1
  engine_rule_id: typescript.ui.no-orphaned-effect-timeouts
  globs: "**/*.{ts,tsx}"
---

# Clear effect timers on cleanup

An uncleared timeout setState's after unmount. That is a leak and a warning, then a bug.

## Do

```tsx
useEffect(() => {
  const id = setTimeout(() => setReady(true), 300);
  return () => clearTimeout(id);
}, []);
```

## Do not

```tsx
useEffect(() => {
  setTimeout(() => setReady(true), 300);
}, []);
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack ts --rule typescript.ui.no-orphaned-effect-timeouts
```

