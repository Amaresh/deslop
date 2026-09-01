---
name: no-java-raw-pii-logging
description: >-
  Do not log email, phone, or similar PII fields in plaintext. Use only when editing Java logging calls. Do not use for required audit logs or tests.
disable-model-invocation: false
paths: '**/*.java'
license: MIT
metadata:
  pack: stopthatslop-java-spring-v1
  engine_rule_id: java.security.no-raw-pii-logging
  globs: "**/*.java"
---

# No raw PII in Java logs

Same invariant as the Python skill. Log an id, not the email.

## Do

```java
log.info("notified user {}", user.getId());
```

## Do not

```java
log.info("notified {}", user.getEmail());
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack java --rule java.security.no-raw-pii-logging
```

