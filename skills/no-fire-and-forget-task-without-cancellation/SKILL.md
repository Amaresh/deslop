---
name: no-fire-and-forget-task-without-cancellation
description: >-
  Do not spawn asyncio background tasks with create_task and drop the
  reference. Keep the task, surface its errors, and cancel it on shutdown.
  Use only when editing Python asyncio task spawning or FastAPI startup/shutdown
  hooks. Do not use for thread pools, Celery workers, or sync threads.
disable-model-invocation: true
license: MIT
metadata:
  pack: deslop-python-fastapi-v1
  engine_rule_id: python.asyncio.no-fire-and-forget-task-without-cancellation
  globs: "**/*.py"
---

# Background tasks need a kept reference and a cancellation path

`asyncio.create_task(...)` whose result is discarded can be garbage collected
mid-flight, and its exceptions vanish. On shutdown nobody cancels it, so the
process hangs or dies mid-write.

## Do

```python
import asyncio

from fastapi import FastAPI

app = FastAPI()
_background: set[asyncio.Task] = set()


def spawn(coro) -> None:
    task = asyncio.create_task(coro)
    _background.add(task)
    task.add_done_callback(_background.discard)


@app.on_event("shutdown")
async def shutdown() -> None:
    for task in _background:
        task.cancel()
    await asyncio.gather(*_background, return_exceptions=True)
```

## Do not

```python
@app.post("/events")
async def record(event: dict) -> dict:
    asyncio.create_task(persist(event))  # reference dropped, GC may kill it
    return {"ok": True}
```

If you only need work after the response, prefer `BackgroundTasks` from
FastAPI — it is awaited as part of the response cycle and needs none of this
plumbing.

## Enforce

This skill is teach-only. No engine detector exists yet; CI must not fail on
it.
