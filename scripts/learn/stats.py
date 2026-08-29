"""Shared types and output formatting for stopthatslop learn."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict


@dataclass
class Evidence:
    file: str
    line: int
    excerpt: str


@dataclass
class Candidate:
    rule_id: str
    stack: str
    invariant: str
    evidence: list[Evidence] = field(default_factory=list)
    matched: int = 0
    total: int = 0
    enforcement: str = "teach-only"   # or "checker-candidate"
    confidence: str = "low"           # high | medium | low
    source: str = "frequency"         # frequency | fix-churn | llm-induction

    @property
    def ratio(self) -> float:
        return self.matched / self.total if self.total else 0.0


def to_yaml(candidates: list[Candidate]) -> str:
    lines = ["candidates:"]
    for c in candidates:
        lines.append(f"  - rule_id: {c.rule_id}")
        lines.append(f"    stack: {c.stack}")
        lines.append(f"    invariant: >-")
        lines.append(f"      {c.invariant}")
        lines.append(f"    adoption:")
        lines.append(f"      matched: {c.matched}")
        lines.append(f"      total: {c.total}")
        lines.append(f"      ratio: {c.ratio:.3f}")
        lines.append(f"    enforcement: {c.enforcement}")
        lines.append(f"    confidence: {c.confidence}")
        lines.append(f"    source: {c.source}")
        lines.append(f"    evidence:")
        for e in c.evidence[:6]:
            lines.append(f"      - file: {e.file}")
            lines.append(f"        line: {e.line}")
            lines.append(f"        excerpt: >-")
            lines.append(f"          {e.excerpt}")
    return "\n".join(lines) + "\n"


def to_json(candidates: list[Candidate]) -> str:
    return json.dumps([asdict(c) for c in candidates], indent=2)
