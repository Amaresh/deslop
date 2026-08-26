"""Detector: go.architecture.no-handler-detached-goroutine

HTTP handlers must not launch goroutines that are not clearly tied to
request context. Pass r.Context() (or ctx / Done()) into the launched
call or func-lit so cancel propagates.

Lifecycle roots (Listen, Shutdown, exit/stop, NotifyContext, WithTimeout
on the same go statement) are silenced — process accept/exit loops are
not request-scoped.
"""
from __future__ import annotations

import re

from common import Finding
from goast_client import is_skipped, load_facts
from no_handler_rooted_background_context import _is_handler

LANG = "go"
RULE_ID = "go.architecture.no-handler-detached-goroutine"

_LIFECYCLE = re.compile(
    r"(?i)(listen|shutdown|exit|stop|notifycontext|withtimeout|"
    r"withtimeoutcause|withcancel|withdeadline|notify)"
)
_CTX_IDENT = re.compile(r"\bctx\b")


def _receives_context(gs: dict) -> bool:
    if gs.get("has_context"):
        return True
    text = gs.get("call_summary") or ""
    if "Context()" in text or ".Done()" in text:
        return True
    return bool(_CTX_IDENT.search(text))


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename):
        return []
    facts = load_facts(source, filename)
    if not facts:
        return []
    out: list[Finding] = []
    seen: set[int] = set()
    for fn in facts.get("functions") or []:
        if not _is_handler(fn):
            continue
        for gs in fn.get("go_stmts") or []:
            if _receives_context(gs):
                continue
            summary = gs.get("call_summary") or ""
            if _LIFECYCLE.search(summary):
                continue
            line = int(gs.get("line") or 1)
            if line in seen:
                continue
            seen.add(line)
            out.append(Finding(
                line=line,
                message="go statement in HTTP handler does not receive "
                        "request context; pass r.Context()",
                rule_id=RULE_ID,
            ))
    return out
