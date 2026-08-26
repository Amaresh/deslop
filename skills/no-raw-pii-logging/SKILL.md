---
name: no-raw-pii-logging
description: >-
  Do not log email, phone, or similar PII fields in plaintext. Use only when editing Python logging calls. Do not use for audit trails that are required to store the value, or test doubles.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-python-fastapi-v1
  engine_rule_id: python.security.no-raw-pii-logging
  globs: "**/*.py"
---

# No raw PII in logs

Log files outlive the request. Email and phone in `logger.info` become a breach later.

## Do

```python
logger.info("notified user %s", user.id)
```

## Do not

```python
logger.info("notified %s", user.email)
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack python --rule python.security.no-raw-pii-logging
```

