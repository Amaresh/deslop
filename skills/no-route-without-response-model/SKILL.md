---
name: no-route-without-response-model
description: >-
  Do not declare FastAPI routes without response_model (or an annotated return
  type). Declare the response shape so internal fields cannot leak. Use only
  when editing FastAPI route decorators. Do not use for non-FastAPI frameworks,
  websockets, or raw Response returns with a documented reason.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-python-fastapi-v1
  engine_rule_id: python.fastapi.no-route-without-response-model
  globs: "**/*.py"
---

# Routes declare their response model

Without `response_model=`, FastAPI serializes whatever the handler returns.
The moment the ORM object or internal record gains a field — `hashed_password`,
`internal_notes`, `is_admin` — it is in the API response.

## Do

```python
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class UserOut(BaseModel):
    id: int
    email: str


@router.get("/users/{user_id}", response_model=UserOut)
async def get_user(user_id: int) -> UserOut:
    return await users.get(user_id)
```

## Do not

```python
@router.get("/users/{user_id}")
async def get_user(user_id: int) -> dict:
    return await users.get(user_id)  # whatever the row has, the wire gets
```

Returning `dict` with a hand-picked subset instead of a declared model is the
same slop one refactor later, when someone adds a key to the dict and forgets
the route contract.

## Enforce

This skill is teach-only. No engine detector exists yet; CI must not fail on
it.
