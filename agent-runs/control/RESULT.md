# CustomerRepository

JPQL:

```sql
SELECT c FROM Customer c WHERE (:status IS NULL OR LOWER(c.status) = LOWER(:status))
```

The `:status IS NULL` branch makes the predicate true for every row when the caller passes `null`, so no status filter is applied and all customers are returned.

When a status is provided, `LOWER(c.status) = LOWER(:status)` compares both sides in lowercase for case-insensitive matching.

A single `@Query` keeps the optional-filter and case-insensitivity logic in one place instead of relying on derived query method names or Specifications.
