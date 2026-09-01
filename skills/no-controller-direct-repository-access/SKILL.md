---
name: no-controller-direct-repository-access
description: >-
  Do not inject a *Repository or *Dao into a @Controller/@RestController. Route through a service. Use only when editing Spring controllers. Do not use for @ControllerAdvice without a repository, or tests.
disable-model-invocation: false
paths: '**/*Controller.java'
license: MIT
metadata:
  pack: stopthatslop-java-spring-v1
  engine_rule_id: java.architecture.no-controller-direct-repository-access
  globs: "**/*Controller.java"
---

# Controllers do not inject repositories

Controllers that call repositories skip the transaction and policy boundary.

## Do

```java
@RestController
class InvoiceController {
    private final InvoiceService invoices;
}
```

## Do not

```java
@RestController
class InvoiceController {
    private final InvoiceRepository invoices;
}
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack java --rule java.architecture.no-controller-direct-repository-access
```

