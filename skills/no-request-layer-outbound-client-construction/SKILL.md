---
name: no-request-layer-outbound-client-construction
description: >-
  Do not construct httpx.Client/AsyncClient or requests.Session inside a route handler. Inject a shared client from lifespan. Use only when editing Python route functions. Do not use for scripts, workers, or tests.
disable-model-invocation: false
paths: '**/*.py'
license: MIT
metadata:
  pack: stopthatslop-python-fastapi-v1
  engine_rule_id: python.architecture.no-request-layer-outbound-client-construction
  globs: "**/*.py"
---

# Do not construct HTTP clients inside routes

Per-request `AsyncClient()` skips the connection pool and leaks sockets under load.

## Do

```python
@router.get("/quote")
async def quote(client: httpx.AsyncClient) -> dict:
    response = await client.get("https://market.example.com/x")
    return response.json()
```

## Do not

```python
@router.get("/quote")
async def quote() -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.get("https://market.example.com/x")
    return response.json()
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack python --rule python.architecture.no-request-layer-outbound-client-construction
```

