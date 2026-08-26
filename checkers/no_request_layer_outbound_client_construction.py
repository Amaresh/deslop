"""Detector: python.architecture.no-request-layer-outbound-client-construction

Route handlers (Flask/FastAPI/Starlette decorator) must not construct
httpx.Client / AsyncClient or requests.Session. Build the client in a
lifespan/factory and inject it. Per-request construction is both an
architecture leak and a connection-pool tax.
"""
from __future__ import annotations

import re

from common import Finding, is_skipped
from pyast_client import load_facts

LANG = "python"
RULE_ID = "python.architecture.no-request-layer-outbound-client-construction"

_ROUTE_ATTR = (
    "get", "post", "put", "patch", "delete", "route", "api_route", "websocket",
)
_ROUTE_DECORATOR_RE = re.compile(
    r"(?:^|\.)(" + "|".join(_ROUTE_ATTR) + r")\s*\(",
)
_CTORS = frozenset({
    "httpx.Client",
    "httpx.AsyncClient",
    "requests.Session",
    "requests.sessions.Session",
})


def _is_route(fn: dict) -> bool:
    for dec in fn.get("decorators") or []:
        if _ROUTE_DECORATOR_RE.search(dec or ""):
            return True
    return False


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename, lang="python"):
        return []
    facts = load_facts(source, filename)
    if not facts:
        return []
    out: list[Finding] = []
    seen: set[int] = set()
    for fn in facts.get("functions") or []:
        if not _is_route(fn):
            continue
        for call in fn.get("calls") or []:
            name = call.get("name") or ""
            if name not in _CTORS:
                continue
            line = int(call.get("line") or 1)
            if line in seen:
                continue
            seen.add(line)
            out.append(Finding(
                line=line,
                message=f"{name} constructed inside a route handler; inject a "
                        "shared client from lifespan/factory",
                rule_id=RULE_ID,
            ))
    return out
