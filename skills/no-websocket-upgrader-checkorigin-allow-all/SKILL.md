---
name: no-websocket-upgrader-checkorigin-allow-all
description: >-
  Do not set websocket.Upgrader CheckOrigin to a function that always returns true. Use only when editing Go websocket upgraders. Do not use for tests that intentionally allow all origins.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-go-v1
  engine_rule_id: go.security.no-websocket-upgrader-checkorigin-allow-all
  globs: "**/*.go"
---

# WebSocket CheckOrigin must not allow all

`CheckOrigin: func(*http.Request) bool { return true }` is cross-site websocket hijack.

## Do

```go
upgrader := websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        return r.Header.Get("Origin") == allowed
    },
}
```

## Do not

```go
upgrader := websocket.Upgrader{
    CheckOrigin: func(*http.Request) bool { return true },
}
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack go --rule go.security.no-websocket-upgrader-checkorigin-allow-all
```

