"""Detector: typescript.ui.no-orphaned-effect-timeouts

`setTimeout` / `setInterval` inside a `useEffect` or `useLayoutEffect`
callback must be cleared: the effect must return a cleanup that calls
`clearTimeout` / `clearInterval` (or `AbortController.abort`).

Timeouts in nested functions (event handlers), present cleanup, and test
files are silent.

AST-facts implementation (tsast effects).
"""
from __future__ import annotations

from common import Finding
from tsast_client import is_out_of_scope, load_facts

LANG = "ts"
RULE_ID = "typescript.ui.no-orphaned-effect-timeouts"


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_out_of_scope(filename):
        return []
    facts = load_facts(source, filename)
    if facts is None:
        return []
    out: list[Finding] = []
    seen: set[int] = set()
    for effect in facts.get("effects") or []:
        if not (effect.get("has_timeout") or effect.get("has_interval")):
            continue
        if effect.get("has_cleanup_timer") or effect.get("has_cleanup_abort"):
            continue
        line = int(effect.get("line") or 1)
        if line in seen:
            continue
        seen.add(line)
        kind = effect.get("kind") or "useEffect"
        which = "setInterval" if effect.get("has_interval") else "setTimeout"
        out.append(Finding(
            line=line,
            message=f"{kind} calls {which} without returning a cleanup that "
                    "calls clearTimeout/clearInterval (or AbortController.abort)",
            rule_id=RULE_ID,
        ))
    return out
