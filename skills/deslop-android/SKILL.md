---
name: deslop-android
description: >-
  Android / Compose reliability pack. Use when editing Kotlin composables,
  ViewModels, or Activities. One pack, several invariants. Apply only the
  section that matches the files in scope.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-android-v1
  kind: pack-index
---

# deslop-android

Do not apply every section. Match the file in front of you.

CI gates all three rules (`enforcement: checker`).

## Secrets

Do not embed API keys as string literals. Read `BuildConfig` / local properties.

## Coroutines

No `GlobalScope` at UI boundaries. No `runBlocking` on the UI / Compose path.
Use `viewModelScope`, `lifecycleScope`, or `LaunchedEffect`.
