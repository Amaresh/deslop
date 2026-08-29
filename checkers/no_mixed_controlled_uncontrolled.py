"""Detector: typescript.react.no-mixed-controlled-uncontrolled

Portable React: the same JSX / createElement node must not set both
`value` and `defaultValue`, or both `checked` and `defaultChecked`.

Spreads are unknown (omitted from jsx facts) so `{...props}` plus one
explicit control prop is silent. `value` without `defaultValue` is silent.

Does not flag React Flow `defaultEdges`.

AST-facts implementation (tsast jsx).
"""
from __future__ import annotations

from common import Finding
from tsast_client import is_out_of_scope, load_facts

LANG = "ts"
RULE_ID = "typescript.react.no-mixed-controlled-uncontrolled"

_PAIRS = (
    ("value", "defaultValue"),
    ("checked", "defaultChecked"),
)


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_out_of_scope(filename):
        return []
    facts = load_facts(source, filename)
    if facts is None:
        return []
    out: list[Finding] = []
    seen: set[int] = set()
    for el in facts.get("jsx") or []:
        names = {a.get("name") for a in (el.get("attrs") or []) if a.get("name")}
        mixed = None
        for a, b in _PAIRS:
            if a in names and b in names:
                mixed = (a, b)
                break
        if not mixed:
            continue
        line = int(el.get("line") or 1)
        if line in seen:
            continue
        seen.add(line)
        tag = el.get("tag") or "element"
        out.append(Finding(
            line=line,
            message=f"<{tag}> sets both `{mixed[0]}` and `{mixed[1]}`; pick "
                    "controlled or uncontrolled, not both",
            rule_id=RULE_ID,
        ))
    return out
