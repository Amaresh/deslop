"""Detector: go.security.no-dynamic-sql-execution

Query/Exec/QueryRow (and *Context variants) must not build SQL with
string concatenation, fmt.Sprintf, or strings.Builder. Use a single
literal with ? / $1 placeholders and bound arguments.

FP-biased: only the SQL-shaped argument is inspected (so `limit+1` as a
bound arg is ignored). Raw/interpreted literals with placeholders and
no `+` are silent.
"""
from __future__ import annotations

import re

from common import Finding
from goast_client import is_skipped, load_facts

LANG = "go"
RULE_ID = "go.security.no-dynamic-sql-execution"

_SQL_CALLEES = frozenset({
    "Query", "QueryContext", "QueryRow", "QueryRowContext",
    "Exec", "ExecContext",
})
_CTX_METHODS = frozenset({
    "QueryContext", "ExecContext", "QueryRowContext",
})
_SQL_VERB = re.compile(r"(?is)\b(SELECT|INSERT|UPDATE|DELETE)\b")
_INTERP = re.compile(r'"(?:\\.|[^"\\])*"')
_RAW = re.compile(r"`[^`]*`")
_IDENT_AFTER_PLUS = re.compile(r"\+\s*[A-Za-z_($]")


def _callee_last(name: str) -> str:
    head = (name or "").split("(", 1)[0]
    return head.rsplit(".", 1)[-1].strip()


def _expanded_args(fn: dict, args: list) -> list[str]:
    out = [a or "" for a in args]
    lhs_map = {}
    for asg in fn.get("assigns") or []:
        lhs_map[asg.get("lhs") or ""] = asg.get("rhs_summary") or ""
    for a in args:
        ident = (a or "").strip()
        if ident in lhs_map:
            out.append(lhs_map[ident])
    return out


def _sql_candidates(last: str, args: list[str]) -> list[str]:
    """Prefer the SQL slot; always include any arg that already looks like SQL."""
    out = [a for a in args if _SQL_VERB.search(a or "")]
    if out:
        return out
    if last in _CTX_METHODS and len(args) > 1:
        return [args[1]]
    if args:
        return [args[0]]
    return []


def _strip_lits(summary: str) -> str:
    return _INTERP.sub('""', _RAW.sub("``", summary))


def _is_dynamic(summary: str) -> bool:
    if "fmt.Sprintf" in summary or "strings.Builder" in summary:
        return True
    return bool(_IDENT_AFTER_PLUS.search(_strip_lits(summary)))


def _builder_feeds_sql(fn: dict, call: dict) -> bool:
    args = call.get("args_summary") or []
    if not any(".String()" in (a or "") for a in args):
        return False
    for c in fn.get("calls") or []:
        name = c.get("name") or ""
        if not name.endswith("WriteString"):
            continue
        joined = " ".join(c.get("args_summary") or [])
        if _SQL_VERB.search(joined):
            return True
    return False


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename):
        return []
    facts = load_facts(source, filename)
    if not facts:
        return []
    out: list[Finding] = []
    seen: set[int] = set()
    for fn in facts.get("functions") or []:
        for call in fn.get("calls") or []:
            last = _callee_last(call.get("name") or "")
            if last not in _SQL_CALLEES:
                continue
            args = _expanded_args(fn, call.get("args_summary") or [])
            candidates = _sql_candidates(last, args)
            dynamic = any(
                _SQL_VERB.search(c or "") and _is_dynamic(c)
                for c in candidates
            )
            if not dynamic:
                dynamic = _builder_feeds_sql(fn, call)
            if not dynamic:
                continue
            line = int(call.get("line") or 1)
            if line in seen:
                continue
            seen.add(line)
            name = call.get("name") or last
            out.append(Finding(
                line=line,
                message=f"{name} builds SQL with concatenation/sprintf/"
                        "strings.Builder; use a literal with ?/$1",
                rule_id=RULE_ID,
            ))
    return out
