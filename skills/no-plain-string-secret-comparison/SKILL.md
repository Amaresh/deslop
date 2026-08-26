---
name: no-plain-string-secret-comparison
description: >-
  Do not compare request secrets with ==, !=, EqualFold, or bytes.Equal. Use crypto/subtle. Use only when editing Go secret checks. Do not use for non-secret string compares or tests.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-go-v1
  engine_rule_id: go.security.no-plain-string-secret-comparison
  globs: "**/*.go"
---

# Compare secrets in constant time

`header == secret` leaks via timing. Agents write it because it looks obvious.

## Do

```go
return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
```

## Do not

```go
return r.Header.Get("X-Agent-Secret") == secret
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack go --rule go.security.no-plain-string-secret-comparison
```

