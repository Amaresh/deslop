---
name: no-handler-direct-outbound-http
description: >-
  Do not call http.Get/Post/Head or client.Do from an HTTP handler. Inject a client. Use only when editing Go HTTP handlers. Do not use for dedicated HTTP client packages.
disable-model-invocation: false
paths: '**/*.go'
license: MIT
metadata:
  pack: stopthatslop-go-v1
  engine_rule_id: go.architecture.no-handler-direct-outbound-http
  globs: "**/*.go"
---

# Handlers do not call outbound HTTP

`http.Get` in a handler has no timeout shaping and couples the request path to a URL.

## Do

```go
body, err := h.partners.Fetch(r.Context(), id)
```

## Do not

```go
resp, err := http.Get("https://partner.example.com/" + id)
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack go --rule go.architecture.no-handler-direct-outbound-http
```

