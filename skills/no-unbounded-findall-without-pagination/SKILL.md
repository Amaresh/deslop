---
name: no-unbounded-findall-without-pagination
description: >-
  Do not call repository.findAll() from a web/service path without pagination. Use only when editing Spring service/controller Java. Do not use for tests, CLI importers, or ModuleFinder.findAll.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-java-spring-v1
  engine_rule_id: java.reliability.no-unbounded-findall-without-pagination
  globs: "**/*.java"
---

# No unbounded findAll in request paths

`findAll()` loads the table. Agents use it as the default list endpoint.

## Do

```java
return invoices.findAll(PageRequest.of(page, size));
```

## Do not

```java
return invoices.findAll();
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack java --rule java.reliability.no-unbounded-findall-without-pagination
```

