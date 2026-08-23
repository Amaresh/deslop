---
name: no-post-validation-model-mutation
description: >-
  Do not mutate a validated Pydantic model's fields after construction to
  bypass validators. Normalize input before validation or in the validator
  itself. Use only when editing Python code that constructs or post-processes
  Pydantic models. Do not use for dataclasses, TypedDicts, or ORM models.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-python-fastapi-v1
  engine_rule_id: python.pydantic.no-post-validation-model-mutation
  globs: "**/*.py"
---

# No mutation after Pydantic validation

Assigning `model.field = ...` after construction skips every validator on that
field. Agents do this to "fix up" values after `Model(**data)`, producing
instances that violate the model's own invariants.

## Do

Normalize before validation, or in a field validator:

```python
from pydantic import BaseModel, field_validator


class SignupRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.strip().lower()
```

## Do not

```python
request = SignupRequest(email=user_input)
if request.email != request.email.strip().lower():
    request.email = request.email.strip().lower()  # validators never ran on this
```

If you need a genuinely different value after validation (a computed column, a
server-set owner), put it in a separate constructor, a `model_copy(update=...)`
that re-validates with `model_config["validate_assignment"]`, or an explicit
non-validated DTO — not a silent attribute write.

## Enforce

This skill is teach-only. No engine detector exists yet; CI must not fail on
it.
