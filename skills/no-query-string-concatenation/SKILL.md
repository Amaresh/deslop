---
name: no-query-string-concatenation
description: >-
  Do not build JPQL or SQL with + concatenation. Use parameters. Use only when editing Java query strings. Do not use for log messages that happen to contain the word from.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-java-spring-v1
  engine_rule_id: java.jpa.no-query-string-concatenation
  globs: "**/*.java"
---

# No JPQL/SQL string concatenation

Concatenated JPQL is injection and a parser surprise. Bind the parameter.

## Do

```java
@Query("SELECT i FROM Invoice i WHERE i.status = :status")
List<Invoice> findByStatus(@Param("status") String status);
```

## Do not

```java
entityManager.createQuery("SELECT i FROM Invoice i WHERE i.status = '" + status + "'");
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack java --rule java.jpa.no-query-string-concatenation
```

