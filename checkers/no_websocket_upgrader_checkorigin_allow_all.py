"""Detector: go.security.no-websocket-upgrader-checkorigin-allow-all

A websocket.Upgrader must validate Origin in CheckOrigin; a body that
always returns literal `true` allows cross-origin websocket hijacking.

AST-facts implementation (goast-facts): composite_literals of type
websocket.Upgrader carry CheckOrigin as either a func-literal line range
(analysed against source for unconditional `return true`) or a named
helper resolved via named_funcs_index / fields_detailed
(always_returns_true). Helpers that compare Origin/Host against an
allowlist return non-literal booleans and are structurally excluded.

Interface: detect(source: str, filename: str = "<inline>") -> list[Finding]
"""
from __future__ import annotations

import re

from common import Finding
from goast_client import load_facts

RULE_ID = "go.security.no-websocket-upgrader-checkorigin-allow-all"

_UPGRADER_TYPES = {"websocket.Upgrader", "Upgrader"}
_RETURN_RE = re.compile(r"\breturn\b([^;{}]+)")
_COMMENT_RE = re.compile(r"//.*$")


def _body_all_returns_true(body: str) -> bool:
    """True iff the body has >=1 return statement and every one is literal true.

    Any real Origin/Host guard shows up as `return <expr>` or
    `return false`, which breaks the all-true condition — so a separate
    guard heuristic is unnecessary.
    """
    results = []
    for line in body.splitlines():
        code = _COMMENT_RE.sub("", line)
        for m in _RETURN_RE.finditer(code):
            results.append(m.group(1).strip())
    return bool(results) and all(r == "true" for r in results)


def _checkorigin_finding(detail: dict, cl: dict,
                         named: dict, helper_lines: dict):
    kind = detail.get("kind")
    if kind == "func_literal":
        a, b = detail.get("lines", [0, 0])
        body = "\n".join(cl["_lines"][max(a - 1, 0):b])
        if not _body_all_returns_true(body):
            return None
        line = a or cl.get("line", 0)
    elif kind == "func_ref":
        ref = detail.get("ref_name", "")
        always_true = detail.get("always_returns_true")
        if always_true is None:
            nf = named.get(ref) or {}
            always_true = nf.get("always_returns_true")
        if always_true is not True:
            return None
        line = helper_lines.get(ref, cl.get("line", 0))
    else:
        return None  # expr values are not CheckOrigin implementations
    return Finding(
        line=line,
        message="websocket.Upgrader CheckOrigin returns true unconditionally "
                "(cross-origin hijacking risk); validate the Origin header",
        rule_id=RULE_ID,
    )


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    facts = load_facts(source, filename)
    if facts is None:
        return []
    named = facts.get("named_funcs_index", {})
    helper_lines = {
        name: nf.get("line_start", 0)
        for name, nf in named.items()
        if isinstance(nf, dict)
    }
    lines = source.splitlines()
    findings: list[Finding] = []
    for cl in facts.get("composite_literals", []):
        ctype = str(cl.get("type", "")).lstrip("*")
        if ctype not in _UPGRADER_TYPES:
            continue
        detail = cl.get("fields_detailed", {}).get("CheckOrigin")
        if detail is None:
            continue  # no CheckOrigin at all: library default rejects cross-origin
        cl["_lines"] = lines
        f = _checkorigin_finding(detail, cl, named, helper_lines)
        if f:
            findings.append(f)
    return findings
