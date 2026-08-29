---
name: stopthatslop-java-spring
description: >-
  Spring/JPA architecture pack. Use when editing Java *Repository.java,
  *Service.java, *Controller.java, or JPA entities. One pack, several
  invariants. Apply only the section that matches the files in scope.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-java-spring-v1
  kind: pack-index
---

# stopthatslop-java-spring

Do not apply every section. Match the file in front of you.

CI gates eleven rules (`enforcement: checker`): three via the Java engine
(JPQL optional-filter, `RestTemplate` timeouts, `@Transactional` external IO)
and eight portable AST checkers (N+1, query concat, uploads, secret fallbacks,
PII logs, EAGER to-many, controller→repository, unbounded `findAll`).
The AST checkers need a JDK so `stopthatslop check` can run JavaParser.

## `*Repository.java`

Optional JPQL string filters: empty-string sentinel, not `:param IS NULL OR` with `LOWER`.

```java
@Query("SELECT i FROM Invoice i WHERE :status = '' OR LOWER(i.status) = LOWER(:status)")
```

No concatenated JPQL. Page `findAll`. Fetch graphs instead of N+1.

## `*Service.java`

1. **Timeouts:** do not leave `new RestTemplate()` without `setRequestFactory` timeout shaping.
2. **Transactions:** do not call HTTP / S3 / messaging from a `@Transactional` method.

## `*Controller.java`

Do not inject a repository. Do not accept uploads without size/type checks.

## Entities

No `FetchType.EAGER` on to-many associations. No secret string fallbacks. No raw PII in logs.
