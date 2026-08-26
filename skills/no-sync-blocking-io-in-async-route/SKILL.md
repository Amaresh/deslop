---
name: no-sync-blocking-io-in-async-route
description: >-
  Do not call sync blocking IO (requests, time.sleep, sync DB drivers) inside
  an async def FastAPI route. Use only when editing Python async route handlers
  or functions awaited from them. Do not use for sync (def) routes, background
  workers, or CLI scripts.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-python-fastapi-v1
  engine_rule_id: python.asyncio.no-sync-blocking-io-in-async-def-route
  globs: "**/*.py"
---

# No sync blocking calls inside `async def`

A blocking call inside `async def` freezes the entire event loop: every other
request on the worker stalls until the call returns. This is the single most
common way agents turn a FastAPI service into a single-user service.

## Do

```python
import httpx

from fastapi import APIRouter

router = APIRouter()


@router.get("/quotes")
async def get_quote(symbol: str) -> dict:
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.get(f"https://market.example.com/{symbol}")
    return response.json()
```

## Do not

```python
import requests

from fastapi import APIRouter

router = APIRouter()


@router.get("/quotes")
async def get_quote(symbol: str) -> dict:
    response = requests.get(f"https://market.example.com/{symbol}")  # blocks loop
    return response.json()
```

The same applies to `time.sleep` (use `asyncio.sleep`), `pandas.read_sql` on a
sync engine (use an async driver), and `boto3` (use aioboto3 or offload to a
worker).

If blocking IO is unavoidable in this codepath, declare the route as plain
`def` so Starlette runs it on the threadpool — that is a deliberate choice,
not an accident of leaving `async` on.

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack python --rule python.asyncio.no-sync-blocking-io-in-async-def-route
```
