"""Detector: python.http.no-httpx-client-without-explicit-timeout

Construction of httpx.AsyncClient / httpx.Client must pass an explicit
timeout= keyword. timeout=None is a finding. Per-call helpers such as
httpx.get(..., timeout=5) are out of scope (construction only).
"""
from __future__ import annotations

from common import Finding, is_skipped
from pyast_client import load_facts

LANG = "python"
RULE_ID = "python.http.no-httpx-client-without-explicit-timeout"

_CLIENTS = frozenset({"httpx.AsyncClient", "httpx.Client"})


def _is_httpx_client_ctor(name: str) -> bool:
    return name in _CLIENTS


def _timeout_ok(call: dict) -> bool:
    keywords = call.get("keywords") or []
    if "timeout" not in keywords:
        return False
    values = call.get("keyword_values") or {}
    raw = values.get("timeout")
    if raw is None:
        return True
    return raw.strip() != "None"


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename, lang="python"):
        return []
    facts = load_facts(source, filename)
    if not facts:
        return []
    out: list[Finding] = []
    seen: set[int] = set()
    for call in facts.get("calls") or []:
        name = call.get("name") or ""
        if not _is_httpx_client_ctor(name):
            continue
        if _timeout_ok(call):
            continue
        line = int(call.get("line") or 1)
        if line in seen:
            continue
        seen.add(line)
        values = call.get("keyword_values") or {}
        if (call.get("keywords") and "timeout" in call["keywords"]
                and (values.get("timeout") or "").strip() == "None"):
            msg = f"{name} constructed with timeout=None"
        else:
            msg = f"{name} constructed without explicit timeout="
        out.append(Finding(line=line, message=msg, rule_id=RULE_ID))
    return out
