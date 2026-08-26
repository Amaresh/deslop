"""Detector: java.reliability.no-unbounded-findall-without-pagination

Zero-arg `findAll()` on a Spring Data-style repository loads the full table.
`findAll(Pageable)` / `findAll(Sort)` (any args) and JPMS
`ModuleFinder.findAll()` are out of scope.

AST-facts implementation (JavaAstFacts). A call is in scope only when the
receiver looks like a repository: field type ends in Repository/Dao, or the
owner identifier ends in repository/dao/repo.
"""
from __future__ import annotations

import re

from common import Finding, is_skipped
from javaast_client import load_facts

LANG = "java"
RULE_ID = "java.reliability.no-unbounded-findall-without-pagination"

_REPO_TYPE = re.compile(r"(Repository|Dao)$")
_REPO_OWNER = re.compile(r"(?i)(repository|dao|repo)$")


def _field_types(facts: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for field in facts.get("fields") or []:
        name = field.get("name") or ""
        typ = field.get("type") or ""
        if name:
            out[name] = typ.rsplit(".", 1)[-1]
    return out


def _owner_method(call_name: str) -> tuple[str, str]:
    raw = (call_name or "").replace("()", "")
    parts = [p for p in raw.split(".") if p]
    if not parts:
        return "", ""
    method = parts[-1]
    owner = parts[-2] if len(parts) >= 2 else ""
    if owner == "this" and len(parts) >= 3:
        owner = parts[-3]
    return owner, method


def _looks_repository(owner: str, field_types: dict[str, str]) -> bool:
    typ = field_types.get(owner) or ""
    if _REPO_TYPE.search(typ):
        return True
    return bool(_REPO_OWNER.search(owner))


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename, lang="java"):
        return []
    facts = load_facts(source, filename)
    if not facts:
        return []
    field_types = _field_types(facts)
    out: list[Finding] = []
    seen: set[int] = set()
    for method in facts.get("methods") or []:
        for call in method.get("calls") or []:
            owner, meth = _owner_method(call.get("name") or "")
            if meth != "findAll":
                continue
            args = call.get("args_summary") or []
            if args:
                continue
            if not _looks_repository(owner, field_types):
                continue
            line = int(call.get("line") or 1)
            if line in seen:
                continue
            seen.add(line)
            shown = owner + ".findAll()" if owner else "findAll()"
            out.append(Finding(
                line=line,
                message=f"{shown} loads the full table; pass Pageable or a scoped query",
                rule_id=RULE_ID,
            ))
    return out
