---
name: no-runblocking-hotpath
description: >-
  Do not call runBlocking from composables, Activities, or other UI entrypoints. Use only when editing Kotlin Android UI. Do not use for tests or isolated workers.
disable-model-invocation: true
license: MIT
metadata:
  pack: stopthatslop-android-v1
  engine_rule_id: android.reliability.no-runblocking-hotpath
  globs: "**/*.kt"
---

# No runBlocking on the UI/hot path

`runBlocking` on the main thread is a freeze. Agents add it to "make async compile".

## Do

```kotlin
LaunchedEffect(Unit) { repo.load() }
```

## Do not

```kotlin
@Composable
fun Screen() {
    val data = runBlocking { repo.load() }
}
```

## Enforce

CI gates this rule (`enforcement: checker`):

```bash
python3 scripts/check.py --repo-root . --pack android --rule android.reliability.no-runblocking-hotpath
```

