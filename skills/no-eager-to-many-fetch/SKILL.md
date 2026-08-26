---
name: no-eager-to-many-fetch
description: >-
  Do not map OneToMany/ManyToMany as FetchType.EAGER. Use only when editing JPA entity associations. Do not use for to-one relations that are required for every read.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-java-spring-v1
  engine_rule_id: java.performance.no-eager-to-many-fetch
  globs: "**/*.java"
---

# No EAGER to-many JPA fetch

EAGER to-many cartesian-products the parent. Fetch it when the use case needs it.

## Do

```java
@OneToMany(mappedBy = "invoice")
private List<Line> lines;
```

## Do not

```java
@OneToMany(mappedBy = "invoice", fetch = FetchType.EAGER)
private List<Line> lines;
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack java --rule java.performance.no-eager-to-many-fetch
```

