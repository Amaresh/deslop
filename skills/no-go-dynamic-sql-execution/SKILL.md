---
name: no-go-dynamic-sql-execution
description: >-
  Do not execute SQL built with fmt.Sprintf or concatenation. Use bound parameters. Use only when editing Go Query/Exec calls. Do not use for migrations or tests.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-go-v1
  engine_rule_id: go.security.no-dynamic-sql-execution
  globs: "**/*.go"
---

# No dynamic SQL in Go

Sprintf SQL is injection. Use placeholders.

## Do

```go
rows, err := db.Query(`SELECT id FROM invoices WHERE status = $1`, status)
```

## Do not

```go
rows, err := db.Query(fmt.Sprintf("SELECT id FROM invoices WHERE status = '%s'", status))
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack go --rule go.security.no-dynamic-sql-execution
```

