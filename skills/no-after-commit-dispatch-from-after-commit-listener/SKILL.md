---
name: no-after-commit-dispatch-from-after-commit-listener
description: >-
  Do not re-register after-commit work from an AFTER_COMMIT
  @TransactionalEventListener. Spring 7 runs that phase in afterCompletion
  after sync is unbound, so the callback is dropped. Use only when editing
  Spring transactional event listeners. Do not use for BEFORE_COMMIT
  listeners, ordinary @EventListener methods, or non-Spring code.
disable-model-invocation: false
paths: '**/*.java'
license: MIT
metadata:
  pack: stopthatslop-java-spring-v1
  engine_rule_id: java.reliability.no-after-commit-dispatch-from-after-commit-listener
  globs: "**/*.java"
---

# Do not re-dispatch after-commit work from AFTER_COMMIT listeners

`@TransactionalEventListener` defaults to `AFTER_COMMIT`. Spring 7 runs that
phase in `afterCompletion`, after transaction synchronization is unbound.
`dispatchAfterCommit*` / `scheduleAfterCommit*` / `registerSynchronization`
from that method never run.

## Do

```java
@TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
void onPaid(InvoicePaidEvent event) {
    notificationSender.send(event.invoiceId());
}
```

## Do not

```java
@TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
void onPaid(InvoicePaidEvent event) {
    sideEffectExecutor.dispatchAfterCommitCoalescing(
        "invoice-paid", () -> notificationSender.send(event.invoiceId()));
}
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack java --rule java.reliability.no-after-commit-dispatch-from-after-commit-listener
```
