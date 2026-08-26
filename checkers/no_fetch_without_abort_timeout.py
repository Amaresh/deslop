"""Detector: typescript.http.no-fetch-without-abort-timeout

Every global `fetch(` call must pass a `signal` option (AbortSignal.timeout,
AbortController.signal, or `{ signal: ... }`). Local `fetch` bindings, axios/ky/got,
and unresolvable options identifiers are excluded (unknown ≠ missing).

AST-facts implementation (tsast-facts).

Interface: detect(source: str, filename: str = "<inline>") -> list[Finding]
"""
from __future__ import annotations

from common import Finding
from tsast_client import is_out_of_scope, load_facts

LANG = "ts"
RULE_ID = "typescript.http.no-fetch-without-abort-timeout"

_FETCH_NAMES = {
    "fetch",
    "window.fetch",
    "globalThis.fetch",
    "global.fetch",
    "self.fetch",
}


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_out_of_scope(filename):
        return []
    facts = load_facts(source, filename)
    if facts is None:
        return []
    findings: list[Finding] = []
    for call in facts.get("calls") or []:
        if call.get("name") not in _FETCH_NAMES:
            continue
        if call.get("callee_is_local"):
            continue
        if call.get("has_signal_option") or call.get("resolved_signal"):
            continue
        if call.get("options_unknown"):
            continue
        findings.append(Finding(
            line=int(call.get("line") or 1),
            message="fetch() is missing an AbortSignal (pass signal via "
                    "AbortSignal.timeout, AbortController.signal, or { signal })",
            rule_id=RULE_ID,
        ))
    return findings
