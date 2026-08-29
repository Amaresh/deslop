---
name: stopthatslop-python-fastapi
description: >-
  FastAPI/Pydantic architecture pack. Use when editing Python async route
  handlers, Pydantic models, httpx clients, or app settings. One pack, several
  invariants. Apply only the section that matches the files in scope.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-python-fastapi-v1
  kind: pack-index
---

# stopthatslop-python-fastapi

Do not apply every section. Match the file in front of you.

Eight rules are CI-gated (`enforcement: checker`): blocking IO in `async def`,
httpx timeout, `except Exception: pass`, dynamic SQL, unguarded `request.json`,
raw PII logs, HTTP client construction in routes, and `requests` without timeout.
The rest of this pack is still teach-only.

## `**/routes.py`, `**/api/**/*.py` (async handlers)

Do not call sync blocking IO (`requests`, `time.sleep`, sync DB drivers,
`boto3`) inside `async def`. Use `httpx.AsyncClient`, `asyncio.sleep`, or
`run_in_executor`. Do not construct `httpx.AsyncClient` inside the route —
inject it from lifespan.

## `**/clients.py`, any `httpx.AsyncClient(...)`

Construct the client with an explicit `timeout=`. The httpx default is five
seconds, but agents routinely widen it to `None` or omit it on shared clients.

## Anywhere a `try` appears

Do not write `except Exception: pass`. Catch the narrow exception and log or
re-raise.

## `**/db.py`, `**/repositories.py`

Do not execute SQL built with f-strings or concatenation. Use bound parameters.

## `**/models.py`, `**/schemas.py` (Pydantic)

Do not mutate validated model fields after construction to sneak values past
validators. Validate the value you actually want. (Teach-only.)

## `**/tasks.py`, anywhere `asyncio.create_task(` appears

Keep a reference to the task and handle cancellation. (Teach-only.)

## `**/config.py`, `**/settings.py`

Do not bake secrets as default values in settings classes or function
signatures. (Teach-only.)

## Route decorators (`@router.get(` etc.)

Declare `response_model=` (or return annotated response types). (Teach-only.)
