"""Detector: java.jpa.no-query-string-concatenation

@Query text and EntityManager.createQuery/createNativeQuery arguments must
not be built with `+` concatenation of identifiers/parameters. Named
`:params` inside a single literal (or literal-only concat) are fine.

AST-facts implementation (JavaAstFacts). FP-biased: numeric `+` is ignored;
plain `"hello " + name` is ignored unless the concat is in a query annotation,
a createQuery argument, or a literal side looks like SQL/JPQL.

Interface: detect(source: str, filename: str = "<inline>") -> list[Finding]
"""
from __future__ import annotations

import re

from common import Finding, is_skipped
from javaast_client import load_facts

LANG = "java"
RULE_ID = "java.jpa.no-query-string-concatenation"

_SQL_START = re.compile(
    r"(?is)^\s*(SELECT|INSERT|UPDATE|DELETE)\b"
)
_SQL_PAIR = re.compile(
    r"(?is)\b(SELECT|INSERT|UPDATE|DELETE)\b.*\b(FROM|INTO|WHERE|SET|VALUES)\b"
)
# JPQL `from Entity` — PascalCase entity (must include a lowercase letter so
# English "from IO failure" does not match).
_JPQL_FROM = re.compile(r"(?s)\b(?:from|FROM)\s+[A-Z][a-z][A-Za-z0-9_]*\b")
_STRING_LIT = re.compile(r'"(?:\\.|[^"\\])*"')
_TEXT_BLOCK = re.compile(r'"""[\s\S]*?"""')


def _strip_lits(summary: str) -> str:
    stripped = _TEXT_BLOCK.sub('""', summary)
    return _STRING_LIT.sub('""', stripped)


def _concat_has_identifier(summary: str) -> bool:
    stripped = _strip_lits(summary)
    return bool(re.search(r"\+\s*[A-Za-z_$(]", stripped))


def _literals(summary: str) -> str:
    blocks = _TEXT_BLOCK.findall(summary)
    lits = _STRING_LIT.findall(_TEXT_BLOCK.sub(" ", summary))
    return " ".join(blocks + lits)


def _looks_like_sql(summary: str) -> bool:
    text = _literals(summary)
    inner = " ".join(t.strip().strip('"') for t in [text] if t)
    if _SQL_START.search(inner) or _SQL_PAIR.search(inner):
        return True
    return bool(_JPQL_FROM.search(inner))


def _query_ann_concat(facts: dict) -> set[int]:
    """Lines of @Query/@NativeQuery members that themselves contain `+`."""
    lines: set[int] = set()
    for ann in facts.get("annotations") or []:
        if (ann.get("name") or "") not in {"Query", "NativeQuery", "NamedQuery"}:
            continue
        members = ann.get("members") or {}
        for key, val in members.items():
            if key not in {"value", "countQuery"}:
                continue
            if "+" not in str(val):
                continue
            if _concat_has_identifier(str(val)):
                lines.add(int(ann.get("line") or 0))
    return lines


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename, lang="java"):
        return []
    facts = load_facts(source, filename)
    if facts is None:
        return []
    findings: list[Finding] = []
    seen: set[int] = set()
    for concat in facts.get("string_concats") or []:
        summary = concat.get("summary") or ""
        if not _concat_has_identifier(summary):
            continue
        in_query = bool(concat.get("in_query_ann"))
        in_create = bool(concat.get("in_create_query"))
        if not (in_query or in_create or _looks_like_sql(summary)):
            continue
        line = int(concat.get("line") or 0)
        if line in seen:
            continue
        seen.add(line)
        where = (
            "@Query" if in_query else
            "EntityManager.createQuery/createNativeQuery" if in_create else
            "SQL/JPQL string"
        )
        findings.append(Finding(
            line=line,
            message=(
                f"{where} is built with string concatenation; use named "
                ":parameters or a single literal"
            ),
            rule_id=RULE_ID,
        ))
    for line in _query_ann_concat(facts):
        if line in seen:
            continue
        seen.add(line)
        findings.append(Finding(
            line=line,
            message=(
                "@Query is built with string concatenation; use named "
                ":parameters or a single literal"
            ),
            rule_id=RULE_ID,
        ))
    return findings
