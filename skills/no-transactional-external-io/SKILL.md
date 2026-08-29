---
name: no-transactional-external-io
description: >-
  Do not call HTTP, S3, or messaging clients from a @Transactional service method.
  Use only when a Java *Service.java method is annotated @Transactional and performs
  outbound IO. Do not use for RestTemplate construction, JPQL, or schedulers.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-java-spring-v1
  engine_rule_id: java.architecture.no-service-layer-transactional-external-io
  globs: "**/*Service.java"
---

# No external IO inside `@Transactional`

Keep the transaction on persistence. Send messaging-client, S3, RestClient, or payouts after commit (or from a non-transactional method).

## Do

```java
@Transactional
void persistQueuedPaymentLink() { /* db only */ }

void sendQueuedPaymentLink() {
    messagingClient.send(phone, "sms", "template");
}
```

## Do not

```java
@Transactional
void processQueuedPaymentLink() {
    messagingClient.send(phone, "sms", "template");
}
```

`@Transactional(readOnly = true)` preview paths are out of scope for this skill.

## Enforce

```bash
python scripts/check.py --repo-root . --rule java.architecture.no-service-layer-transactional-external-io
```
