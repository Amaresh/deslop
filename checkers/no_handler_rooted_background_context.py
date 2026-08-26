"""Detector: go.architecture.no-handler-rooted-background-context

HTTP handlers (ServeHTTP or ResponseWriter+*http.Request params) must not
start work from context.Background()/TODO(). Propagate r.Context().

Lifecycle roots (Listen, Shutdown, exit/stop, NotifyContext, WithTimeout
on the same call) are silenced — process exit and accept loops are not
request-scoped.
"""
from __future__ import annotations

import re

from common import Finding
from goast_client import is_skipped, load_facts

LANG = "go"
RULE_ID = "go.architecture.no-handler-rooted-background-context"

_BG = frozenset({"context.Background", "context.TODO"})
_LIFECYCLE = re.compile(
    r"(?i)(listen|shutdown|exit|stop|notifycontext|withtimeout|"
    r"withtimeoutcause|withcancel|withdeadline|notify)"
)


def _is_handler(fn: dict) -> bool:
    name = fn.get("name") or ""
    if name == "ServeHTTP":
        return True
    params = " ".join(fn.get("params") or [])
    return "ResponseWriter" in params and (
        "*http.Request" in params or "*Request" in params
    )


def _lifecycle_lines(fn: dict) -> set[int]:
    lines: set[int] = set()
    for call in fn.get("calls") or []:
        if not _LIFECYCLE.search(call.get("name") or ""):
            continue
        joined = " ".join(call.get("args_summary") or [])
        if "context.Background" in joined or "context.TODO" in joined:
            lines.add(int(call.get("line") or 0))
    return lines


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
        skip_lines = _lifecycle_lines(fn)
        for call in fn.get("calls") or []:
            name = call.get("name") or ""
            if name not in _BG:
                continue
            line = int(call.get("line") or 1)
            if line in skip_lines or line in seen:
                continue
            seen.add(line)
            out.append(Finding(
                line=line,
                message=f"{name}() in HTTP handler; use r.Context() so cancel "
                        "propagates",
                rule_id=RULE_ID,
            ))
    return out
