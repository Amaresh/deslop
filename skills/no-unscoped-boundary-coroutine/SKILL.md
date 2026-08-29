---
name: no-unscoped-boundary-coroutine
description: >-
  Do not launch GlobalScope coroutines from composables, ViewModels, or Activities. Use viewModelScope / lifecycleScope. Use only when editing Kotlin Android UI. Do not use for process-wide daemons started in Application.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-android-v1
  engine_rule_id: android.reliability.no-unscoped-boundary-coroutine
  globs: "**/*.kt"
---

# No GlobalScope at UI/network boundaries

`GlobalScope.launch` outlives the screen. The job still touches UI after dispose.

## Do

```kotlin
viewModelScope.launch { repo.refresh() }
```

## Do not

```kotlin
GlobalScope.launch { repo.refresh() }
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack android --rule android.reliability.no-unscoped-boundary-coroutine
```

