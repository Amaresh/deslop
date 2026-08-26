"""Detector: typescript.reliability.no-unguarded-json-parse-on-external-input

JSON.parse on non-literal external input must sit in a try block or be
immediately passed to a schema parser. Fetch/Request `.json()` with no
arguments is the same class of parse and must be in a try.
`JSON.parse` inside `catch` is not a guard.

AST-facts implementation (tsast-facts).

Interface: detect(source: str, filename: str = "<inline>") -> list[Finding]
"""
from __future__ import annotations

from common import Finding
from tsast_client import is_out_of_scope, load_facts

LANG = "ts"
RULE_ID = "typescript.reliability.no-unguarded-json-parse-on-external-input"

_SCHEMA_LAST = {
    "parse", "safeParse", "parseAsync", "safeParseAsync",
    "parseJson", "decode", "fromJson", "parseUnknown", "decodeUnknown",
}
_JSON_METHODS = {"request.json", "req.json", "response.json", "res.json"}
# Hono `c.res.json()` reads the outbound Response to re-serialize it; not inbound.
_EXTERNAL_NAMES = {
    "body", "payload", "raw", "rawbody", "raw_body", "webhook",
    "req", "request", "query", "searchparams", "event",
}
_EXTERNAL_NEEDLES = (
    ".text", ".body", "req.", "request.", "response.", "res.",
    "event.data", "payload", "webhook", "rawbody", "raw_body",
)


def _schema_wrap(wrapped_by: str | None) -> bool:
    if not wrapped_by:
        return False
    last = wrapped_by.rsplit(".", 1)[-1]
    return last in _SCHEMA_LAST


def _looks_external(call: dict) -> bool:
    if call.get("in_handler"):
        return True
    name = (call.get("first_arg_name") or "").replace("\\", "/")
    last = name.split(".")[-1].lower()
    if last in _EXTERNAL_NAMES:
        return True
    origins = call.get("arg_origins") or []
    origin0 = origins[0] if origins else None
    blob = " ".join(
        [str(origin0 or ""), name, " ".join(call.get("args_summary") or [])]
    ).lower()
    return any(n in blob for n in _EXTERNAL_NEEDLES)


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_out_of_scope(filename):
        return []
    facts = load_facts(source, filename)
    if facts is None:
        return []
    findings: list[Finding] = []
    for call in facts.get("calls") or []:
        name = call.get("name") or ""
        if call.get("in_try"):
            continue
        if name == "c.res.json":
            continue
        if name in _JSON_METHODS or name.endswith(".request.json") \
                or name.endswith(".req.json") or name.endswith(".response.json"):
            if int(call.get("arg_count") or 0) != 0:
                continue
            findings.append(Finding(
                line=int(call.get("line") or 1),
                message=f"{name}() parses external JSON outside try; wrap in try/catch",
                rule_id=RULE_ID,
            ))
            continue
        if name != "JSON.parse":
            continue
        if call.get("first_arg_kind") == "string_literal":
            continue
        if call.get("stringify_roundtrip"):
            continue
        if _schema_wrap(call.get("wrapped_by")):
            continue
        if not _looks_external(call):
            continue
        findings.append(Finding(
            line=int(call.get("line") or 1),
            message="JSON.parse of external input is unguarded; wrap in try or pass "
                    "immediately to a schema parser",
            rule_id=RULE_ID,
        ))
    return findings
