---
name: no-handler-detached-goroutine
description: >-
  Do not start a goroutine from an HTTP handler without a context from the request. Use only when editing Go HTTP handlers. Do not use for process-wide workers started at main.
disable-model-invocation: false
paths: '**/*.go'
license: MIT
metadata:
  pack: stopthatslop-go-v1
  engine_rule_id: go.architecture.no-handler-detached-goroutine
  globs: "**/*.go"
---

# No detached goroutines in handlers

`go doWork()` from a handler outlives the request and drops cancellation.

## Do

```go
go func() {
    doWork(r.Context())
}()
```

## Do not

```go
go doWork()
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack go --rule go.architecture.no-handler-detached-goroutine
```

