---
name: no-jpql-null-or-lower
description: >-
  Avoid JPQL `:param IS NULL OR` combined with LOWER on optional filters.
  Use only when editing Spring Data @Query methods or *Repository.java optional
  string filters. Do not use for general JPA, transactions, HTTP, or schedulers.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-java-spring-v1
  engine_rule_id: java.reliability.no-jpql-null-or-lower-on-optional-filter
  globs: "**/*Repository.java"
---

# No JPQL null-or-LOWER optional filters

PostgreSQL can 500 when JPQL does `:param IS NULL OR LOWER(column) = LOWER(:param)` (typed as bytea).

## Do

```java
@Query("SELECT i FROM Invoice i WHERE :status = '' OR LOWER(i.status) = LOWER(:status)")
List<Invoice> findByStatus(@Param("status") String status);
```

Pass `""` for “no filter”.

## Do not

```java
@Query("SELECT i FROM Invoice i WHERE :status IS NULL OR LOWER(i.status) = LOWER(:status)")
List<Invoice> findByStatus(String status);
```

## Enforce

This skill does not block a merge. CI runs the pack checker:

```bash
python scripts/check.py --repo-root . --rule java.reliability.no-jpql-null-or-lower-on-optional-filter
```
