---
name: no-requests-call-without-timeout
description: >-
  Do not call requests.get/post/put/patch/delete/head without timeout=. Use only when editing Python requests calls. Do not use for httpx (use the httpx timeout skill) or test mocks.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-python-fastapi-v1
  engine_rule_id: python.http.no-requests-call-without-timeout
  globs: "**/*.py"
---

# Every `requests` call needs a timeout

`requests` waits forever by default. One hung socket pins a worker.

## Do

```python
response = requests.get(url, timeout=5)
```

## Do not

```python
response = requests.get(url)
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack python --rule python.http.no-requests-call-without-timeout
```

