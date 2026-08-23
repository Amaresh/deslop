---
name: no-empty-catch-in-express-handlers
description: >-
  Do not swallow errors in Express handlers with empty catch blocks. Catch,
  log, and pass the error to next() or return a 500. Use only when editing
  Express/Koa route handlers and middleware. Do not use for React event
  handlers, Python except blocks, or validation errors intentionally mapped
  to 4xx responses.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-ts-node-v1
  engine_rule_id: typescript.express.no-empty-catch-in-route-handler
  globs: "**/*.ts"
---

# No empty catch in Express handlers

An empty catch turns every downstream failure into a request that hangs until
the client gives up, because Express never learns the handler failed. Agents
add `catch {}` to silence "unhandled promise" warnings instead of fixing the
flow.

## Do

```typescript
router.get("/orders/:id", async (req, res, next) => {
  try {
    const order = await orders.find(req.params.id);
    if (!order) {
      res.status(404).json({ error: "not found" });
      return;
    }
    res.json(order);
  } catch (err) {
    next(err);
  }
});
```

## Do not

```typescript
router.get("/orders/:id", async (req, res) => {
  try {
    const order = await orders.find(req.params.id);
    res.json(order);
  } catch {}
});
```

If the project targets Express 5 or uses `express-async-errors`, plain
`async` handlers without try/catch are fine — the point is that errors reach
the error middleware, never a silent `{}`.

## Enforce

This skill is teach-only. No engine detector exists yet; CI must not fail on
it.
