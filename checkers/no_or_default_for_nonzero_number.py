"""Detector: typescript.correctness.no-or-default-for-nonzero-number

`x || <nonzero-number>` treats 0 as missing. Use `??` when 0 is a valid
value (timeouts, ports, precision, counts). `x || 0` is out of scope
(NaN-guard, equivalent to `?? 0` for finite numbers). Non-literal defaults
are silenced.

AST-facts implementation (tsast binaries).
"""
from __future__ import annotations

from common import Finding
from tsast_client import is_out_of_scope, load_facts

LANG = "ts"
RULE_ID = "typescript.correctness.no-or-default-for-nonzero-number"


def _nonzero_number(raw: str | None) -> bool:
    if raw is None or raw == "":
        return False
    try:
        return float(raw) != 0.0
    except ValueError:
        return False


_NUMBER_CALLEES = frozenset({"Number", "parseInt", "parseFloat"})


def _left_in_scope(node: dict) -> bool:
    kind = node.get("left_kind") or "other"
    if kind in {"identifier", "property"}:
        return True
    if kind == "call":
        callee = node.get("left_callee") or ""
        return callee in _NUMBER_CALLEES or callee.endswith(".Number")
    return False


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_out_of_scope(filename):
        return []
    facts = load_facts(source, filename)
    if facts is None:
        return []
    out: list[Finding] = []
    seen: set[int] = set()
    for node in facts.get("binaries") or []:
        if node.get("op") != "||":
            continue
        if node.get("right_kind") != "number":
            continue
        if not _nonzero_number(node.get("right_value")):
            continue
        if not _left_in_scope(node):
            continue
        line = int(node.get("line") or 1)
        if line in seen:
            continue
        seen.add(line)
        default = node.get("right_value")
        out.append(Finding(
            line=line,
            message=f"`|| {default}` treats 0 as missing; use `?? {default}` "
                    "so an explicit zero is preserved",
            rule_id=RULE_ID,
        ))
    return out
