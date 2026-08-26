---
name: no-route-request-json-without-invalid-json-guard
description: >-
  Do not call Flask/Starlette request.json in a route without catching invalid JSON. Use only when editing Python request handlers that parse JSON bodies. Do not use for FastAPI pydantic body params or tests.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-python-fastapi-v1
  engine_rule_id: python.reliability.no-route-request-json-without-invalid-json-guard
  globs: "**/*.py"
---

# Guard `request.json` on untrusted bodies

`request.json` raises on truncated bodies. Uncaught, that is a 500 instead of 400.

## Do

```python
from flask import Flask, request

app = Flask(__name__)

@app.post("/hook")
def hook():
    try:
        payload = request.get_json(force=True)
    except Exception:
        return {"error": "invalid json"}, 400
    return {"ok": True}
```

## Do not

```python
@app.post("/hook")
def hook():
    payload = request.json
    return payload
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack python --rule python.reliability.no-route-request-json-without-invalid-json-guard
```

