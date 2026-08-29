---
name: no-handler-direct-sql-execution
description: >-
  Do not call Query/Exec/Begin from an HTTP handler. Move SQL to a store. Use only when editing Go HTTP handlers. Do not use for store packages or tests.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-go-v1
  engine_rule_id: go.architecture.no-handler-direct-sql-execution
  globs: "**/*.go"
---

# Handlers do not run SQL

Handler SQL skips the persistence boundary and makes the handler untestable.

## Do

```go
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
    row, err := h.store.Invoice(r.Context(), id)
}
```

## Do not

```go
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
    row := h.db.QueryRow(`SELECT id FROM invoices WHERE id = $1`, id)
}
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack go --rule go.architecture.no-handler-direct-sql-execution
```

