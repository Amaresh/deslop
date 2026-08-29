---
name: no-rest-template-without-timeout
description: >-
  Do not construct RestTemplate in a Java service without request-factory timeout
  shaping. Use only when editing new RestTemplate() in *Service.java. Do not use
  for @Transactional IO, JPQL, listeners, or schedulers.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-java-spring-v1
  engine_rule_id: java.architecture.no-service-layer-rest-template-without-timeout-shaping
  globs: "**/*Service.java"
---

# RestTemplate needs timeout shaping

A bare `new RestTemplate()` inherits infinite connect/read timeouts. Inject a timeout-configured client, or set a request factory.

## Do

```java
this.restTemplate = new RestTemplate();
this.restTemplate.setRequestFactory(buildRequestFactory());
```

## Do not

```java
private final RestTemplate restTemplate = new RestTemplate();
```

This skill is only about **construction**. Outbound calls inside `@Transactional` are `no-transactional-external-io`.

## Enforce

```bash
python scripts/check.py --repo-root . --rule java.architecture.no-service-layer-rest-template-without-timeout-shaping
```
