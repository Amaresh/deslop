"""Detector: python.reliability.no-route-request-json-without-invalid-json-guard

HTTP route handlers must not parse request.json / await request.json() /
Request.json outside a try. Invalid JSON otherwise becomes a 500.

Route heuristic: same decorator regex as
no_sync_blocking_io_in_async_def_route (_is_route), applied to sync and
async def, including Flask @app.route / @bp.route.

Silence: in_try (covers JSONDecodeError handlers), helpers that are not
decorated as routes.

AST-facts implementation (pyast).
"""
from __future__ import annotations

import re

from common import Finding, is_skipped
from pyast_client import load_facts

LANG = "python"
RULE_ID = "python.reliability.no-route-request-json-without-invalid-json-guard"

_ROUTE_ATTR = (
    "get", "post", "put", "patch", "delete", "route", "api_route", "websocket",
)
_ROUTE_DECORATOR_RE = re.compile(
    r"(?:^|\.)(" + "|".join(_ROUTE_ATTR) + r")\s*\(",
)


def _is_route(fn: dict) -> bool:
    for dec in fn.get("decorators") or []:
        if _ROUTE_DECORATOR_RE.search(dec or ""):
            return True
    return False


def _is_request_json(name: str) -> bool:
    if not name.endswith(".json"):
        return False
    recv = name[: -len(".json")]
    recv_leaf = recv.rsplit(".", 1)[-1] if recv else ""
    return recv_leaf in {"request", "Request"}


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
            if not _is_request_json(name):
                continue
            if call.get("in_try"):
                continue
            line = int(call.get("line") or 1)
            if line in seen:
                continue
            seen.add(line)
            out.append(Finding(
                line=line,
                message=f"{name} parses request JSON outside try; "
                        "guard JSONDecodeError with a 400",
                rule_id=RULE_ID,
            ))
    return out
