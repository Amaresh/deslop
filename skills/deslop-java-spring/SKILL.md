---
name: deslop-java-spring
description: >-
  Spring/JPA architecture pack. Use when editing Java *Repository.java or
  *Service.java. One pack, several invariants. Apply only the section that
  matches the files in scope.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-java-spring-v1
  kind: pack-index
---

# deslop-java-spring

Do not apply every section. Match the file in front of you.

CI gates all three rules (`enforcement: checker`): JPQL optional-filter,
`new RestTemplate()` without timeout shaping, and HTTP/S3/messaging inside
`@Transactional`.

## `*Repository.java`

Optional JPQL string filters: empty-string sentinel, not `:param IS NULL OR` with `LOWER`.

```java
@Query("SELECT i FROM Invoice i WHERE :status = '' OR LOWER(i.status) = LOWER(:status)")
```

## `*Service.java` — both apply, they are different bugs

1. **Timeouts:** do not leave `new RestTemplate()` without `setRequestFactory` timeout shaping.
2. **Transactions:** do not call HTTP / S3 / messaging from a `@Transactional` method. Persist in the transaction; send after commit.

```java
@Service
class PaymentSyncService {
    private final RestTemplate restTemplate;
    private final InvoiceRepository invoices;

    PaymentSyncService() {
        this.restTemplate = new RestTemplate();
        this.restTemplate.setRequestFactory(buildRequestFactory());
    }

    @Transactional
    void persistInvoice(Invoice invoice) {
        invoices.save(invoice);
    }

    void notifyPartner(Invoice invoice) {
        restTemplate.postForEntity("/notify", invoice, Void.class);
    }
}
```
