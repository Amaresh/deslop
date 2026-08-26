"""Detector: python.security.no-raw-pii-logging

logging / logger / log .{debug,info,warning,warn,error,exception,critical}
must not emit an identifier whose name is exactly a PII token:
email, phone, phone_number, mobile, ssn, national_id, msisdn,
date_of_birth, dob (case-insensitive).

Also flags that ident inside f-string / .format interpolations.
Silence: call summary contains redact/mask/hash/anonymize; ident is
email_hash / phone_hash; string literals; substring names (gmail_client).

AST-facts implementation (pyast). FP-biased: exact ident names only.
"""
from __future__ import annotations

import re

from common import Finding, is_skipped
from pyast_client import load_facts

LANG = "python"
RULE_ID = "python.security.no-raw-pii-logging"

_LOG_METHODS = frozenset({
    "debug", "info", "warning", "warn", "error", "exception", "critical",
})
_LOG_RECEIVERS = frozenset({"logging", "logger", "log"})
_PII = frozenset({
    "email", "phone", "phone_number", "mobile", "ssn", "national_id",
    "msisdn", "date_of_birth", "dob",
})
_HASHED = frozenset({"email_hash", "phone_hash"})
_REDACT_NEEDLES = ("redact", "mask", "hash", "anonymize")

_BARE_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_BRACE_IDENT = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_FORMAT_CALL = re.compile(r"\.format\((.*)\)\s*$")


def _is_log_call(name: str) -> bool:
    if "." not in name:
        return False
    recv, meth = name.rsplit(".", 1)
    if meth.lower() not in _LOG_METHODS:
        return False
    recv_leaf = recv.rsplit(".", 1)[-1].lower()
    return recv_leaf in _LOG_RECEIVERS


def _call_blob(call: dict) -> str:
    parts = list(call.get("args_summary") or [])
    summary = call.get("first_arg_summary") or ""
    if summary:
        parts.append(summary)
    return " ".join(parts)


def _is_redacted(call: dict) -> bool:
    blob = _call_blob(call).lower()
    return any(needle in blob for needle in _REDACT_NEEDLES)


def _maybe_pii(ident: str) -> str | None:
    low = ident.lower()
    if low in _HASHED:
        return None
    if low in _PII:
        return ident
    return None


def _pii_from_format_args(summary: str) -> list[str]:
    matched = _FORMAT_CALL.search(summary or "")
    if not matched:
        return []
    found: list[str] = []
    for part in matched.group(1).split(","):
        token = part.strip()
        if not token:
            continue
        if "=" in token:
            token = token.split("=", 1)[-1].strip()
        if _BARE_IDENT.match(token):
            hit = _maybe_pii(token)
            if hit:
                found.append(hit)
    return found


def _pii_idents(call: dict) -> list[str]:
    found: list[str] = []
    for arg in call.get("args_summary") or []:
        token = (arg or "").strip()
        if _BARE_IDENT.match(token):
            hit = _maybe_pii(token)
            if hit:
                found.append(hit)
    kind = call.get("first_arg_kind")
    summary = call.get("first_arg_summary") or ""
    if kind == "fstring":
        for match in _BRACE_IDENT.finditer(summary):
            hit = _maybe_pii(match.group(1))
            if hit:
                found.append(hit)
    elif kind == "format":
        found.extend(_pii_from_format_args(summary))
        for match in _BRACE_IDENT.finditer(summary):
            hit = _maybe_pii(match.group(1))
            if hit:
                found.append(hit)
    return found


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
        if not _is_log_call(name):
            continue
        if _is_redacted(call):
            continue
        idents = _pii_idents(call)
        if not idents:
            continue
        line = int(call.get("line") or 1)
        if line in seen:
            continue
        seen.add(line)
        ident = idents[0]
        out.append(Finding(
            line=line,
            message=f"{name} logs raw PII identifier '{ident}'",
            rule_id=RULE_ID,
        ))
    return out
