"""Detector: python.security.no-dynamic-sql-execution

SQL execution surfaces must not interpolate or concatenate query text.
Flag cursor/connection/conn/Cursor/session .execute, plus executemany /
executescript and sqlalchemy.text(), when the SQL argument is an f-string,
string concat, or .format() of a non-literal fragment.

Silence: 100% string-literal SQL (including adjacent-literal concat and
bound-param templates with %s / ? / :name), *args/**kwargs (timeout-style
FP bias), and a Name first arg (no local-assignment chase).

AST-facts implementation (pyast). Filename avoids colliding with a Go
no_dynamic_sql_execution detector.
"""
from __future__ import annotations

import re

from common import Finding, is_skipped
from pyast_client import load_facts

LANG = "python"
RULE_ID = "python.security.no-dynamic-sql-execution"

_EXECUTE_METHODS = frozenset({"execute", "executemany", "executescript"})
_EXECUTE_RECEIVERS = frozenset({"cursor", "connection", "conn", "session"})
_DYNAMIC_KINDS = frozenset({"fstring", "concat", "format"})
# Session/cursor administration, not SELECT/INSERT SQLi.
_ADMIN_PREFIX = (
    "set ", "alter session", "fetch ", "close ", "begin", "commit",
    "rollback", "declare ",
)
_PRAGMA_SECRET = re.compile(r"\b(key|rekey|password|hexkey)\s*=")
_KIND_LABEL = {
    "fstring": "f-string",
    "concat": "string concatenation",
    "format": "str.format",
}


def _admin_sql(summary: str) -> bool:
    text = summary.strip()
    if len(text) > 1 and text[0] in "fF" and text[1] in "'\"":
        text = text[1:]
    text = text.strip().strip("'\"")
    text = text.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r")
    text = text.lower().lstrip()
    if text.startswith(_ADMIN_PREFIX):
        return True
    if text.startswith("pragma "):
        return not _PRAGMA_SECRET.search(text)
    return False


def _is_sqlalchemy_text(name: str) -> bool:
    if not name.endswith(".text"):
        return False
    return name == "sqlalchemy.text" or name.startswith("sqlalchemy.")


def _is_sql_surface(name: str) -> bool:
    if not name:
        return False
    if _is_sqlalchemy_text(name):
        return True
    if "." not in name:
        return False
    recv, meth = name.rsplit(".", 1)
    if meth not in _EXECUTE_METHODS:
        return False
    if meth in {"executemany", "executescript"}:
        return True
    recv_leaf = recv.rsplit(".", 1)[-1]
    return recv_leaf.lower() in _EXECUTE_RECEIVERS


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
        if not _is_sql_surface(name):
            continue
        if call.get("has_starargs") or call.get("has_kwargs"):
            continue
        kind = call.get("first_arg_kind")
        if kind not in _DYNAMIC_KINDS:
            continue
        summary = call.get("first_arg_summary") or ""
        if _admin_sql(summary):
            continue
        line = int(call.get("line") or 1)
        if line in seen:
            continue
        seen.add(line)
        label = _KIND_LABEL[kind]
        out.append(Finding(
            line=line,
            message=f"{name} interpolates SQL via {label}; use bound parameters",
            rule_id=RULE_ID,
        ))
    return out
