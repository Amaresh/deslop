---
name: no-file-upload-without-validation
description: >-
  Do not accept MultipartFile/Part without size, type, or name checks. Use only when editing Java upload endpoints. Do not use for internally generated files or tests.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-java-spring-v1
  engine_rule_id: java.correctness.no-file-upload-without-validation
  globs: "**/*.java"
---

# Validate file uploads

Unchecked uploads become disk bombs and stored XSS.

## Do

```java
@PostMapping("/docs")
void upload(MultipartFile file) {
    if (file.getSize() > MAX_BYTES) {
        throw new IllegalArgumentException("too large");
    }
    store.save(file);
}
```

## Do not

```java
@PostMapping("/docs")
void upload(MultipartFile file) {
    store.save(file);
}
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack java --rule java.correctness.no-file-upload-without-validation
```

