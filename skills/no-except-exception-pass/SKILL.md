---
name: no-except-exception-pass
description: >-
  Do not swallow errors with `except Exception: pass`. Catch the narrowest
  exception and log, return an error value, or re-raise. Use only when editing
  Python try/except blocks. Do not use for Java, TypeScript catch blocks, or
  for deliberate no-op fallbacks that carry a comment and a narrow exception.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-python-fastapi-v1
  engine_rule_id: python.reliability.no-except-exception-pass-swallow
  globs: "**/*.py"
---

# No `except Exception: pass`

Silent swallows turn "the webhook never fired" and "the row was never saved"
into undebuggable production mysteries. Agents emit this pattern constantly to
make sample code look robust.

## Do

```python
import logging

import httpx

logger = logging.getLogger(__name__)


def notify_partner(payload: dict) -> bool:
    try:
        httpx.post("https://partner.example.com/hook", json=payload, timeout=5.0)
    except httpx.HTTPError:
        logger.exception("partner notification failed")
        return False
    return True
```

## Do not

```python
def notify_partner(payload: dict) -> None:
    try:
        httpx.post("https://partner.example.com/hook", json=payload, timeout=5.0)
    except Exception:
        pass
```

If the failure is truly expected and irrelevant, say so with a narrow
exception type and a comment naming the expected case — `except
KeyError: pass` on a cache lookup, not `except Exception` on a payment call.

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack python --rule python.reliability.no-except-exception-pass-swallow
```
