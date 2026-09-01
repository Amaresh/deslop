"""Detector: java.reliability.no-after-commit-dispatch-from-after-commit-listener

Spring 7 runs @TransactionalEventListener AFTER_COMMIT in afterCompletion,
after transaction synchronization is unbound. Re-registering after-commit
work from that listener (dispatchAfterCommit*, scheduleAfterCommit*,
registerSynchronization) is dropped.

Default phase is AFTER_COMMIT. BEFORE_COMMIT / AFTER_ROLLBACK are out of
scope. Regex, not JavaParser — the pattern is annotation + call in the
method body.
"""
from __future__ import annotations

import re

from common import Finding, is_skipped

LANG = "java"
RULE_ID = "java.reliability.no-after-commit-dispatch-from-after-commit-listener"

_LISTENER = re.compile(
    r"@TransactionalEventListener\b(?:\s*\((?P<args>[^)]*)\))?"
)
_SKIP_PHASE = re.compile(
    r"\bphase\s*=\s*TransactionPhase\s*\.\s*(?:BEFORE_COMMIT|AFTER_ROLLBACK)\b"
)
_AFTER_COMMIT_HELPER = re.compile(
    r"\b(?P<callback>(?:schedule|dispatch)AfterCommit[A-Za-z0-9_]*)\s*\("
)
_REGISTER_SYNC = re.compile(
    r"\b(?:TransactionSynchronizationManager\s*\.\s*)?register(?:Synchronization|AfterCommit)\s*\("
)


def _strip_java_comments(source: str) -> str:
    out: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        c = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if c in "\"'":
            quote = c
            out.append(c)
            i += 1
            while i < n:
                ch = source[i]
                out.append(ch)
                if ch == "\\" and i + 1 < n:
                    out.append(source[i + 1])
                    i += 2
                    continue
                i += 1
                if ch == quote:
                    break
            continue
        if c == "/" and nxt == "/":
            while i < n and source[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if c == "/" and nxt == "*":
            i += 2
            out.extend("  ")
            while i < n - 1 and not (source[i] == "*" and source[i + 1] == "/"):
                out.append("\n" if source[i] == "\n" else " ")
                i += 1
            if i < n - 1:
                out.extend("  ")
                i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _scan_block(source: str, brace_index: int) -> str | None:
    if brace_index >= len(source) or source[brace_index] != "{":
        return None
    depth = 0
    i = brace_index
    n = len(source)
    while i < n:
        c = source[i]
        if c in "\"'":
            quote = c
            i += 1
            while i < n:
                if source[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if source[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return source[brace_index + 1 : i]
        i += 1
    return None


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename, lang="java"):
        return []
    scannable = _strip_java_comments(source)
    out: list[Finding] = []
    seen: set[int] = set()
    for annotation in _LISTENER.finditer(scannable):
        args = annotation.group("args") or ""
        if _SKIP_PHASE.search(args):
            continue
        search_start = annotation.end()
        brace = scannable.find("{", search_start, search_start + 600)
        if brace == -1:
            continue
        if scannable.find(";", search_start, brace) != -1:
            continue
        body = _scan_block(scannable, brace)
        if body is None:
            continue
        body_start_line = scannable.count("\n", 0, brace) + 1
        for pattern in (_AFTER_COMMIT_HELPER, _REGISTER_SYNC):
            for call in pattern.finditer(body):
                line = body_start_line + body.count("\n", 0, call.start())
                if line in seen:
                    continue
                seen.add(line)
                kind = call.groupdict().get("callback") or call.group(0).rstrip("(").strip()
                out.append(Finding(
                    line=line,
                    message=(
                        f"AFTER_COMMIT @TransactionalEventListener calls `{kind}` "
                        "which needs active transaction synchronization; Spring 7 "
                        "runs AFTER_COMMIT in afterCompletion after sync is unbound"
                    ),
                    rule_id=RULE_ID,
                ))
    return out
