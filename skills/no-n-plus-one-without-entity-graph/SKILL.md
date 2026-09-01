---
name: no-n-plus-one-without-entity-graph
description: >-
  Do not call a collection finder then lazily touch to-many associations in a loop. Use @EntityGraph or a fetch join. Use only when editing Spring Data repositories and callers. Do not use for eager-named finders (WithGraph, JoinFetch) or tests.
disable-model-invocation: false
paths: '**/*.java'
license: MIT
metadata:
  pack: stopthatslop-java-spring-v1
  engine_rule_id: java.performance.no-n-plus-one-without-entity-graph
  globs: "**/*.java"
---

# No N+1 finder without an entity graph

`findAll()` plus `invoice.getLines().size()` in a loop is N+1. Agents write it constantly.

## Do

```java
@EntityGraph(attributePaths = "lines")
List<Invoice> findAll();
```

## Do not

```java
for (Invoice invoice : invoiceRepository.findAll()) {
    total += invoice.getLines().size();
}
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack java --rule java.performance.no-n-plus-one-without-entity-graph
```

