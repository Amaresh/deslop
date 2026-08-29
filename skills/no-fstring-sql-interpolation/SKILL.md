---
name: no-fstring-sql-interpolation
description: >-
  Do not build SQL by interpolating values with f-strings, .format(), or +.
  Use bound parameters. Use only when editing Python code that composes SQL or
  Cypher queries. Do not use for ORM query builders, identifiers assembled from
  a trusted allowlist, or non-SQL string templates.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-python-fastapi-v1
  engine_rule_id: python.sql.no-fstring-sql-interpolation
  globs: "**/*.py"
---

# No f-string SQL interpolation

Interpolated values are an injection surface and a plan-cache killer. Agents
write `f"... WHERE email = '{email}'"` because it reads nicely. Bound
parameters read nearly as well and are safe.

## Do

```python
def find_user(conn, email: str) -> dict | None:
    row = conn.execute(
        "SELECT id, email FROM users WHERE email = %s",
        (email,),
    ).fetchone()
    return dict(row) if row else None
```

## Do not

```python
def find_user(conn, email: str) -> dict | None:
    row = conn.execute(
        f"SELECT id, email FROM users WHERE email = '{email}'"
    ).fetchone()
    return dict(row) if row else None
```

The same rule covers `.format()`, `%` formatting, and string concatenation of
user-controlled values into any query text.

## Enforce

This skill is teach-only. No engine detector exists yet; CI must not fail on
it.
