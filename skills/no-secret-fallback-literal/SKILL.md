---
name: no-secret-fallback-literal
description: >-
  Do not default API keys, tokens, or passwords to a string literal when env/config is missing. Fail closed. Use only when editing Java config/secret reads. Do not use for non-secret defaults or tests.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-java-spring-v1
  engine_rule_id: java.security.no-secret-fallback-literal
  globs: "**/*.java"
---

# No secret fallback literals

`getenv("API_KEY") != null ? getenv("API_KEY") : "dev-secret"` ships the secret.

## Do

```java
String apiKey = requiredEnv("API_KEY");
```

## Do not

```java
String apiKey = System.getenv().getOrDefault("API_KEY", "dev-secret");
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack java --rule java.security.no-secret-fallback-literal
```

