"""Detector: android.reliability.no-unscoped-boundary-coroutine

`GlobalScope.launch` / `GlobalScope.async` start work that nothing will
cancel. Flag both trailing-lambda and parenthesized forms.

The optional CoroutineScope(Dispatchers.*).launch extra is omitted:
ktast cannot see `.launch` chained after `CoroutineScope(...)`, and
GlobalScope-only is the FP-quiet slice.
"""
from __future__ import annotations

from common import Finding
from ktast_client import is_skipped, load_facts

LANG = "android"
RULE_ID = "android.reliability.no-unscoped-boundary-coroutine"

_GS = frozenset({"GlobalScope.launch", "GlobalScope.async"})


def _is_global_scope(name: str) -> bool:
    if name in _GS:
        return True
    return name.endswith(".GlobalScope.launch") or name.endswith(
        ".GlobalScope.async"
    )


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename):
        return []
    facts = load_facts(source, filename)
    if not facts:
        return []
    out: list[Finding] = []
    seen: set[int] = set()
    for call in facts.get("calls") or []:
        name = call.get("name") or ""
        if not _is_global_scope(name):
            continue
        line = int(call.get("line") or 1)
        if line in seen:
            continue
        seen.add(line)
        kind = "async" if name.endswith("async") else "launch"
        out.append(Finding(
            line=line,
            message=f"GlobalScope.{kind} is unscoped; use viewModelScope, "
                    "lifecycleScope, rememberCoroutineScope, or goAsync",
            rule_id=RULE_ID,
        ))
    return out
