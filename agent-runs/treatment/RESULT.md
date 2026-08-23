# Result

Read skill: `skills/no-jpql-null-or-lower/SKILL.md`.

Invariant: avoid JPQL `:param IS NULL OR` combined with `LOWER` on optional filters; use `:param = ''` and pass an empty string for “no filter” instead.

JPQL used:

```sql
SELECT c FROM Customer c WHERE :status = '' OR LOWER(c.status) = LOWER(:status)
```

Created `CustomerRepository` extending `JpaRepository<Customer, Long>` with `findByStatus(@Param("status") String status)`.
