"""Detector: go.architecture.no-handler-direct-outbound-http

HTTP handlers must not call the context-free net/http helpers (http.Get,
Post, Head, PostForm). Those ignore request cancellation and have no
deadline. http.NewRequestWithContext / client.Do are out of scope.
"""
from __future__ import annotations

from common import Finding
from goast_client import is_skipped, load_facts
from no_handler_rooted_background_context import _is_handler

LANG = "go"
RULE_ID = "go.architecture.no-handler-direct-outbound-http"

_BARE_HTTP = frozenset({
    "http.Get", "http.Post", "http.Head", "http.PostForm",
})


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
        for call in fn.get("calls") or []:
            name = call.get("name") or ""
            if name not in _BARE_HTTP:
                continue
            line = int(call.get("line") or 1)
            if line in seen:
                continue
            seen.add(line)
            out.append(Finding(
                line=line,
                message=f"{name} in HTTP handler has no request context or "
                        "deadline; use http.NewRequestWithContext",
                rule_id=RULE_ID,
            ))
    return out
