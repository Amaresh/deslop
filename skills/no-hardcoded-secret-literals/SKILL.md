---
name: no-hardcoded-secret-literals
description: >-
  Do not embed API keys, tokens, or passwords as Kotlin string literals. Read them from BuildConfig/local properties. Use only when editing Kotlin app code. Do not use for tests or placeholder empty strings.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-android-v1
  engine_rule_id: android.security.no-hardcoded-secret-literals
  globs: "**/*.kt"
---

# No hardcoded secret literals

A key in source ships in the APK.

## Do

```kotlin
val apiKey = BuildConfig.MAPS_KEY
```

## Do not

```kotlin
val apiKey = "AIzaSyDeadBeef..."
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack android --rule android.security.no-hardcoded-secret-literals
```

