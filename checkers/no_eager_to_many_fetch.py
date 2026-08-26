"""Detector: java.performance.no-eager-to-many-fetch

@OneToMany / @ManyToMany with FetchType.EAGER loads the whole collection on
every entity read (often an N+1 amplifier). Default LAZY + an explicit
@EntityGraph / JOIN FETCH on the query that needs the collection is the
fix. @ManyToOne / @OneToOne defaults are out of scope.
"""
from __future__ import annotations

from common import Finding, is_skipped
from javaast_client import load_facts

LANG = "java"
RULE_ID = "java.performance.no-eager-to-many-fetch"

_TO_MANY = frozenset({"OneToMany", "ManyToMany"})


def _is_eager(members: dict) -> bool:
    raw = str((members or {}).get("fetch") or "")
    return "EAGER" in raw


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename, lang="java"):
        return []
    facts = load_facts(source, filename)
    if not facts:
        return []
    out: list[Finding] = []
    seen: set[int] = set()
    for ann in facts.get("annotations") or []:
        if (ann.get("name") or "") not in _TO_MANY:
            continue
        if not _is_eager(ann.get("members") or {}):
            continue
        line = int(ann.get("line") or 1)
        if line in seen:
            continue
        seen.add(line)
        kind = ann.get("name")
        out.append(Finding(
            line=line,
            message=f"@{kind}(fetch = EAGER) loads the collection on every "
                    "read; prefer LAZY plus EntityGraph/JOIN FETCH where needed",
            rule_id=RULE_ID,
        ))
    return out
