---
name: deslop-python-fastapi
description: >-
  FastAPI/Pydantic architecture pack. Use when editing Python async route
  handlers, Pydantic models, httpx clients, or app settings. One pack, several
  invariants. Apply only the section that matches the files in scope.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-python-fastapi-v1
  kind: pack-index
---

# deslop-python-fastapi

Do not apply every section. Match the file in front of you.

Every rule in this pack is teach-only until an agent-written sample fails
`scripts/check.py`. No engine detectors exist for these rules yet.

## `**/routes.py`, `**/api/**/*.py` (async handlers)

Do not call sync blocking IO (`requests`, `time.sleep`, sync DB drivers,
`boto3`) inside `async def`. Use `httpx.AsyncClient`, `asyncio.sleep`, or
`run_in_executor`.

## `**/clients.py`, any `httpx.AsyncClient(...)`

Construct the client with an explicit `timeout=`. The httpx default is five
seconds, but agents routinely widen it to `None` or omit it on shared clients.

## Anywhere a `try` appears

Do not write `except Exception: pass`. Catch the narrow exception and log or
re-raise.

## `**/db.py`, `**/repositories.py`

Do not build SQL with f-strings or `.format()`. Use bound parameters.

## `**/models.py`, `**/schemas.py` (Pydantic)

Do not mutate validated model fields after construction to sneak values past
validators. Validate the value you actually want.

## `**/tasks.py`, anywhere `asyncio.create_task(` appears

Keep a reference to the task and handle cancellation. Bare fire-and-forget
tasks are silently garbage collected and swallow errors.

## `**/config.py`, `**/settings.py`

Do not bake secrets as default values in settings classes or function
signatures.

## Route decorators (`@router.get(` etc.)

Declare `response_model=` (or return annotated response types). Omitting it
leaks internal columns and ORM internals into API responses.
