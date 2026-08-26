"""Detector: android.security.no-hardcoded-secret-literals

High-confidence only. Flag a string_lit when:

- its value contains a well-known secret prefix (sk_live_, sk_test_, AIza,
  AKIA, ghp_, github_pat_, xox[baprs]-, -----BEGIN), length >= 16
  (PEM BEGIN is enough), or
- it is assigned on the same facts line (or the previous line) to an
  identifier matching api_key / secret / password / private_key /
  access_token / auth_token, length >= 16, and is not a placeholder.

UI copy (whitespace in the identifier-path value), Timber tags, short
demo keys, and BuildConfig / YOUR_ / example / dummy values are silenced.
"""
from __future__ import annotations

import re

from common import Finding
from ktast_client import is_skipped, load_facts

LANG = "android"
RULE_ID = "android.security.no-hardcoded-secret-literals"

_PREFIX = re.compile(
    r"(sk_live_|sk_test_|AIza|AKIA|ghp_|github_pat_|xox[baprs]-|-----BEGIN)"
)
_SECRET_IDENT = re.compile(
    r"(?i)(?:api_?key|secret(?![a-z])|password|private_?key|"
    r"access_?token|auth_?token)"
)
_UI_IDENT = re.compile(
    r"(?i)(hint|label|title|message|text|description|prompt|error|"
    r"caption|placeholder|copy|tag|header|subtitle)$"
)
_PLACEHOLDER = re.compile(
    r"(?i)(YOUR_|CHANGE_?ME|changeme|example|dummy|xxx|TODO|"
    r"BuildConfig|placeholder|redacted|not_a_real)"
)
_EMPTY = re.compile(r"(?i)^(empty|none|null|n/?a)?$")
_ASSIGN_IDENT = re.compile(
    r"([A-Za-z_][\w]*)\s*(?::\s*[\w.<>,?\s*]+)?\s*="
)


def _placeholder(value: str) -> bool:
    if _EMPTY.match(value.strip()):
        return True
    return bool(_PLACEHOLDER.search(value))


def _prefix_hit(value: str) -> bool:
    if not _PREFIX.search(value):
        return False
    if value.lstrip().startswith("-----BEGIN"):
        return not _placeholder(value)
    if len(value) < 16:
        return False
    return not _placeholder(value)


def _secret_ident(name: str) -> bool:
    if not name or _UI_IDENT.search(name):
        return False
    return bool(_SECRET_IDENT.search(name))


def _assigned_ident(window: str) -> str | None:
    ident = None
    for m in _ASSIGN_IDENT.finditer(window):
        ident = m.group(1)
    if ident and _secret_ident(ident):
        return ident
    return None


def _ident_hit(value: str, window: str) -> bool:
    if len(value) < 16:
        return False
    if _placeholder(value):
        return False
    if any(ch.isspace() for ch in value):
        return False
    return _assigned_ident(window) is not None


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename):
        return []
    facts = load_facts(source, filename)
    if not facts:
        return []
    lines = source.splitlines()
    out: list[Finding] = []
    seen: set[int] = set()
    for lit in facts.get("string_lits") or []:
        value = lit.get("value") or ""
        line = int(lit.get("line") or 1)
        if line in seen:
            continue
        prev = lines[line - 2] if line >= 2 else ""
        cur = lines[line - 1] if 1 <= line <= len(lines) else ""
        window = prev + "\n" + cur
        prefix = _prefix_hit(value)
        ident = _ident_hit(value, window)
        if not prefix and not ident:
            continue
        seen.add(line)
        if prefix:
            msg = "hardcoded secret-shaped literal; load from BuildConfig/secrets"
        else:
            name = _assigned_ident(window) or "secret"
            msg = f"hardcoded {name} literal; load from BuildConfig/secrets"
        out.append(Finding(line=line, message=msg, rule_id=RULE_ID))
    return out
