"""Detector: python.http.no-requests-call-without-timeout

`requests.get/post/put/patch/delete/head/options/request` must pass an
explicit timeout= keyword. timeout=None is a hang. Spreading *args/**kwargs
is silenced (timeout may be inside). Session.get and urllib are out of scope
without types.

AST-facts implementation (pyast). FP-biased.
"""
from __future__ import annotations

from common import Finding, is_skipped
from pyast_client import load_facts

LANG = "python"
RULE_ID = "python.http.no-requests-call-without-timeout"

_METHODS = frozenset({
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "requests.head",
    "requests.options",
    "requests.request",
    "requests.api.get",
    "requests.api.post",
    "requests.api.put",
    "requests.api.patch",
    "requests.api.delete",
    "requests.api.head",
    "requests.api.options",
    "requests.api.request",
})


def _is_requests_call(name: str) -> bool:
    return name in _METHODS


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
        if not _is_requests_call(name):
            continue
        if call.get("has_starargs") or call.get("has_kwargs"):
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
            msg = f"{name} called with timeout=None"
        else:
            msg = f"{name} called without explicit timeout="
        out.append(Finding(line=line, message=msg, rule_id=RULE_ID))
    return out
