---
name: no-dynamic-sql-execution
description: >-
  Do not execute SQL built with f-strings, format, or concatenation. Use bound parameters. Use only when editing Python DB calls. Do not use for migrations, test fixtures, or query-builder APIs that are not execute.
disable-model-invocation: false
paths: '**/*.py'
license: MIT
metadata:
  pack: stopthatslop-python-fastapi-v1
  engine_rule_id: python.security.no-dynamic-sql-execution
  globs: "**/*.py"
---

# No dynamic SQL string execution

Agents glue SQL together with f-strings. That is injection and a broken plan cache.

## Do

```python
cur.execute("SELECT id FROM invoices WHERE status = %s", (status,))
```

## Do not

```python
cur.execute(f"SELECT id FROM invoices WHERE status = '{status}'")
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack python --rule python.security.no-dynamic-sql-execution
```

