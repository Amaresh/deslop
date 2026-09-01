---
name: no-handler-rooted-background-context
description: >-
  Do not pass context.Background() from an HTTP handler. Use r.Context(). Use only when editing Go HTTP handlers. Do not use for process startup or tests.
disable-model-invocation: false
paths: '**/*.go'
license: MIT
metadata:
  pack: stopthatslop-go-v1
  engine_rule_id: go.architecture.no-handler-rooted-background-context
  globs: "**/*.go"
---

# Handlers use the request context

`context.Background()` ignores cancellation when the client hangs up.

## Do

```go
row, err := h.store.Invoice(r.Context(), id)
```

## Do not

```go
row, err := h.store.Invoice(context.Background(), id)
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack go --rule go.architecture.no-handler-rooted-background-context
```

