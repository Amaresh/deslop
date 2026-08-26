"""Detector: typescript.express.no-empty-catch-in-route-handler

Empty catch blocks in Express/Koa/Hono route or middleware handlers.
Empty = no statements (comments / `// ignore` only). Nested helpers,
parsers, and codecs are out of scope unless they themselves look like
handlers.

AST-facts implementation (tsast-facts).

Interface: detect(source: str, filename: str = "<inline>") -> list[Finding]
"""
from __future__ import annotations

from common import Finding
from tsast_client import is_out_of_scope, load_facts

LANG = "ts"
RULE_ID = "typescript.express.no-empty-catch-in-route-handler"


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_out_of_scope(filename):
        return []
    facts = load_facts(source, filename)
    if facts is None:
        return []
    findings: list[Finding] = []
    for clause in facts.get("catch_clauses") or []:
        if not clause.get("body_empty"):
            continue
        if not clause.get("in_handler"):
            continue
        # Feature-detection getters (c.executionCtx) have no call in the try
        # body; empty catch there is not swallowing a route failure.
        if clause.get("try_has_call") is False:
            continue
        findings.append(Finding(
            line=int(clause.get("line") or 1),
            message="empty catch in a route/middleware handler swallows failures; "
                    "log, rethrow, or send an error response",
            rule_id=RULE_ID,
        ))
    return findings
