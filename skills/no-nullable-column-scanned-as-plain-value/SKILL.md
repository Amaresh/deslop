---
name: no-nullable-column-scanned-as-plain-value
description: >-
  Do not Scan a nullable / outer-join column into a plain scalar. Use sql.Null* or a pointer. Use only when editing Go database/sql Scan calls. Do not use for non-nullable columns or tests.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-go-v1
  engine_rule_id: go.reliability.no-nullable-column-scanned-as-plain-value
  globs: "**/*.go"
---

# Scan nullable columns into Null types

LEFT JOIN columns are NULL. Scanning into `string` is `sql: Scan error`.

## Do

```go
var email sql.NullString
err := row.Scan(&id, &email)
```

## Do not

```go
var email string
err := db.QueryRow(`SELECT u.id, p.email FROM users u LEFT JOIN profiles p ON p.user_id = u.id`).Scan(&id, &email)
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack go --rule go.reliability.no-nullable-column-scanned-as-plain-value
```

