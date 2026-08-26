"""Detector: python.asyncio.no-sync-blocking-io-in-async-def-route

Async route handlers must not call sync blocking IO (requests.*, time.sleep,
urllib.request.urlopen/urlretrieve, http.client, boto3, pandas.read_sql,
psycopg2, sqlite3.connect+execute).

Scope is async def functions whose decorator is an HTTP verb / route /
websocket (not plain helpers, not sync def routes). Nested sync helpers
inside a route are not attributed to the handler (FP-bias).
"""
from __future__ import annotations

import re

from common import Finding, is_skipped
from pyast_client import load_facts

LANG = "python"
RULE_ID = "python.asyncio.no-sync-blocking-io-in-async-def-route"

_ROUTE_ATTR = (
    "get", "post", "put", "patch", "delete", "route", "api_route", "websocket",
)
# Word-boundary on the decorator method: `router.get(` matches, `router` alone
# does not (avoids substring "route" inside "router").
_ROUTE_DECORATOR_RE = re.compile(
    r"(?:^|\.)(" + "|".join(_ROUTE_ATTR) + r")\s*\(",
)

_REQUESTS_METHODS = frozenset({
    "get", "post", "put", "patch", "delete", "request", "head",
})
_URLLIB_IO = frozenset({
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
})
_SAFE_PREFIXES = (
    "httpx.",
    "asyncio.",
    "aiofiles.",
    "aiohttp.",
)


def _is_route(fn: dict) -> bool:
    if not fn.get("async"):
        return False
    for dec in fn.get("decorators") or []:
        if _ROUTE_DECORATOR_RE.search(dec or ""):
            return True
    return False


def _blocking_message(name: str, calls: list[dict]) -> str | None:
    if not name:
        return None
    if name.startswith(_SAFE_PREFIXES) or name in {
        "asyncio.sleep", "sleep",
    }:
        # `sleep` after `from asyncio import sleep` resolves to asyncio.sleep.
        if name == "asyncio.sleep" or name.startswith("asyncio."):
            return None
        if name.startswith("httpx.") or name.startswith("aiofiles."):
            return None
        if name.startswith("aiohttp."):
            return None

    if name == "time.sleep":
        return "sync blocking call time.sleep in async route handler"
    if name.startswith("requests."):
        meth = name.rsplit(".", 1)[-1]
        if meth in _REQUESTS_METHODS:
            return f"sync blocking call {name} in async route handler"
        return None
    if name in _URLLIB_IO:
        return f"sync blocking call {name} in async route handler"
    if name == "http.client" or name.startswith("http.client."):
        return f"sync blocking call {name} in async route handler"
    if name == "boto3" or name.startswith("boto3."):
        return f"sync blocking call {name} in async route handler"
    if name == "pandas.read_sql" or name.endswith(".read_sql"):
        if name == "pandas.read_sql" or name.startswith("pandas."):
            return f"sync blocking call {name} in async route handler"
    if name == "psycopg2" or name.startswith("psycopg2."):
        return f"sync blocking call {name} in async route handler"
    if name == "sqlite3.connect" or name.endswith("sqlite3.connect"):
        if _has_execute(calls):
            return "sqlite3.connect with execute in async route handler"
    return None


def _has_execute(calls: list[dict]) -> bool:
    for c in calls:
        n = c.get("name") or ""
        if n == "execute" or n.endswith(".execute"):
            return True
    return False


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename, lang="python"):
        return []
    facts = load_facts(source, filename)
    if not facts:
        return []
    out: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    for fn in facts.get("functions") or []:
        if not _is_route(fn):
            continue
        calls = fn.get("calls") or []
        for call in calls:
            name = call.get("name") or ""
            msg = _blocking_message(name, calls)
            if not msg:
                continue
            line = int(call.get("line") or fn.get("line_start") or 1)
            key = (line, name)
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(line=line, message=msg, rule_id=RULE_ID))
    return out
