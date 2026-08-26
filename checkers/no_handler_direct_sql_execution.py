"""Detector: go.architecture.no-handler-direct-sql-execution

HTTP handlers must not run database/sql-shaped Query/Exec/Begin themselves.
Move SQL to a store/repository so the request path stays an HTTP adapter.

Last-segment match on {Query, QueryContext, QueryRow, QueryRowContext, Exec,
ExecContext, Begin, BeginTx}. Begin* always counts; Query/Exec* only when an
argument (or same-function assign feeding an argument) looks like SQL.
That keeps r.URL.Query() and repo.Query(ctx, id) silent.
"""
from __future__ import annotations

import re

from common import Finding
from goast_client import is_skipped, load_facts
from no_handler_rooted_background_context import _is_handler

LANG = "go"
RULE_ID = "go.architecture.no-handler-direct-sql-execution"

_SQL_CALLEES = frozenset({
    "Query", "QueryContext", "QueryRow", "QueryRowContext",
    "Exec", "ExecContext", "Begin", "BeginTx",
})
_BEGIN = frozenset({"Begin", "BeginTx"})
_SQL_VERB = re.compile(r"(?is)\b(SELECT|INSERT|UPDATE|DELETE)\b")


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


def _looks_like_sql(text: str) -> bool:
    return bool(_SQL_VERB.search(text or ""))


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename):
        return []
    facts = load_facts(source, filename)
    if not facts:
        return []
    out: list[Finding] = []
    seen: set[int] = set()
    for fn in facts.get("functions") or []:
        if not _is_handler(fn):
            continue
        for call in fn.get("calls") or []:
            last = _callee_last(call.get("name") or "")
            if last not in _SQL_CALLEES:
                continue
            args = _expanded_args(fn, call.get("args_summary") or [])
            if last not in _BEGIN and not any(_looks_like_sql(a) for a in args):
                continue
            line = int(call.get("line") or 1)
            if line in seen:
                continue
            seen.add(line)
            name = call.get("name") or last
            out.append(Finding(
                line=line,
                message=f"{name} in HTTP handler runs SQL on the request "
                        "path; move Query/Exec/Begin to a store",
                rule_id=RULE_ID,
            ))
    return out
