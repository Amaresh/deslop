---
name: no-httpx-asyncclient-without-timeout
description: >-
  Do not construct httpx.AsyncClient (or requests.Session) without an explicit
  timeout. Use only when editing Python HTTP client construction. Do not use
  for route handlers, retry policy design, or non-HTTP IO.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-python-fastapi-v1
  engine_rule_id: python.http.no-httpx-client-without-explicit-timeout
  globs: "**/*.py"
---

# httpx clients need explicit timeouts

Agents love `httpx.AsyncClient()` with no arguments. Without `timeout=`, a slow
upstream holds connections and worker concurrency indefinitely; with
`timeout=None` it does so forever by contract.

## Do

```python
import httpx

_client = httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0))
```

## Do not

```python
import httpx

_client = httpx.AsyncClient()  # 5s default nobody agreed to, often widened later
```

```python
_client = httpx.AsyncClient(timeout=None)  # hangs forever on a stalled upstream
```

Set the timeout at construction, where every caller inherits it, not per call
where the next agent-added call site silently drops it.

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack python --rule python.http.no-httpx-client-without-explicit-timeout
```
