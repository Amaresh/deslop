---
name: no-secret-defaults-in-settings
description: >-
  Do not bake secret values (API keys, tokens, passwords, connection strings
  with credentials) as default values in settings classes, function signatures,
  or fallback expressions. Require them from the environment and fail fast when
  missing. Use only when editing Python configuration or settings code. Do not
  use for non-secret defaults like timeouts, URLs without credentials, or
  feature flags.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-python-fastapi-v1
  engine_rule_id: python.security.no-secret-values-as-config-defaults
  globs: "**/*.py"
---

# No secrets baked as defaults

A default like `api_key: str = "sk-live-..."` ships the credential into source
control, wheels, and every stack trace that prints config. Agents copy these
defaults into new services because it makes the sample "run out of the box".

## Do

```python
from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    stripe_api_key: str
    database_url: str

    model_config = {"env_file": ".env"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
```

The app refuses to start if `STRIPE_API_KEY` is unset — that is the correct
behavior.

## Do not

```python
class Settings(BaseSettings):
    stripe_api_key: str = "sk_live_51HxYz..."  # committed secret
    database_url: str = os.getenv(
        "DATABASE_URL", "postgres://admin:admin@localhost/db"
    )
```

## Enforce

This skill is teach-only. No engine detector exists yet; CI must not fail on
it.
