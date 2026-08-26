"""Detector: java.security.no-raw-pii-logging

Flag logger/log/LOG .{debug,info,warn,warning,error,trace} when an argument
identifier token is exactly a PII name (email, phone, phoneNumber, mobile,
ssn, nationalId, dateOfBirth). String contents, Message.EMAIL-style
constants, and redact/mask/hash wrappers are out of scope.

AST-facts implementation (JavaAstFacts calls + args_summary).
"""
from __future__ import annotations

import re

from common import Finding, is_skipped
from javaast_client import load_facts

LANG = "java"
RULE_ID = "java.security.no-raw-pii-logging"

_LOG_LEVELS = frozenset({"debug", "info", "warn", "warning", "error", "trace"})
_LOGGERS = frozenset({"log", "logger"})
_PII = frozenset({
    "email", "phone", "phonenumber", "mobile", "ssn", "nationalid", "dateofbirth",
})
_STRING_LIT = re.compile(r'"(?:\\.|[^"\\])*"')
_TEXT_BLOCK = re.compile(r'"""[\s\S]*?"""')
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_REDACT = re.compile(r"(?i)\b(redact\w*|mask\w*|hashed?)\b")


def _is_log_call(name: str) -> bool:
    raw = name or ""
    if "." not in raw:
        return False
    recv, _, meth = raw.rpartition(".")
    if meth.lower() not in _LOG_LEVELS:
        return False
    simple = recv.rsplit(".", 1)[-1]
    return simple.lower() in _LOGGERS


def _strip_lits(text: str) -> str:
    return _STRING_LIT.sub('""', _TEXT_BLOCK.sub('""', text or ""))


def _has_redaction(args: list) -> bool:
    blob = " ".join(str(a) for a in args)
    stripped = _strip_lits(blob)
    for tok in _IDENT.findall(stripped):
        low = tok.lower()
        if low in {"hashcode", "hashmap", "hashset"}:
            continue
        if _REDACT.fullmatch(tok):
            return True
    return False


def _pii_tokens(arg: str) -> list[str]:
    stripped = _strip_lits(arg)
    hits: list[str] = []
    for m in _IDENT.finditer(stripped):
        tok = m.group()
        if tok.casefold() not in _PII:
            continue
        prev = stripped[:m.start()].rstrip()
        if prev.endswith(".") and tok.isupper():
            continue
        hits.append(tok)
    return hits


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename, lang="java"):
        return []
    facts = load_facts(source, filename)
    if not facts:
        return []
    out: list[Finding] = []
    seen: set[int] = set()
    for meth in facts.get("methods") or []:
        for call in meth.get("calls") or []:
            if not _is_log_call(call.get("name") or ""):
                continue
            args = list(call.get("args_summary") or [])
            if _has_redaction(args):
                continue
            tokens: list[str] = []
            for arg in args:
                tokens.extend(_pii_tokens(str(arg)))
            if not tokens:
                continue
            line = int(call.get("line") or meth.get("line_start") or 1)
            if line in seen:
                continue
            seen.add(line)
            shown = tokens[0]
            out.append(Finding(
                line=line,
                message=f"log call emits raw PII identifier '{shown}'; "
                        "redact, mask, or hash before logging",
                rule_id=RULE_ID,
            ))
    return out
