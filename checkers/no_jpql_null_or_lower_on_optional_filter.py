"""Detector: java.reliability.no-jpql-null-or-lower-on-optional-filter

PostgreSQL can 500 on JPQL `:param IS NULL OR LOWER(column) = LOWER(:param)`
(typed as bytea). Prefer an empty-string sentinel (`:param = ''`).

JavaParser (JavaAstFacts) locates `@Query` and String constants. Concat
resolution covers the documented spellings: a single `@Query` string,
`"…" + "…"`, text blocks, same-file `QUERY + "WHERE…"`, and cross-file
`Queries.WHERE` / `QUERY + Queries.WHERE`.

Interface: detect(source: str, filename: str = "<inline>") -> list[Finding]
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from common import Finding, is_skipped
from javaast_client import load_facts

LANG = "java"
RULE_ID = "java.reliability.no-jpql-null-or-lower-on-optional-filter"

_JPQL_NULL_OR_LOWER = re.compile(
    r":\w+\s+IS\s+NULL\s+OR[\s\S]*?LOWER\s*\(|"
    r"LOWER\s*\([^)]+\)\s*=\s*LOWER\s*\(\s*:\w+\s*\)[\s\S]*?:\w+\s+IS\s+NULL\s+OR",
    re.IGNORECASE,
)
_QUERY_PREFIX = re.compile(r"@Query\s*\(\s*(?:value\s*=\s*)?", re.DOTALL)
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_STRING_CONST_PREFIX = re.compile(
    r"(?:(?:public|protected|private|static|final)\s+)*String\s+(\w+)\s*=\s*"
)
_QUERY_EXPR_KEYWORDS = frozenset(
    {"true", "false", "null", "value", "countQuery", "nativeQuery", "name"}
)
_MESSAGE = (
    "JPQL optional filter combines `:param IS NULL OR` with LOWER; "
    "prefer empty-string sentinels (`:param = ''`)."
)
_ROOT_MARKERS = (
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    ".git",
)


def _strip_java_comments(source: str) -> str:
    return re.sub(
        r"//.*?$|/\*.*?\*/",
        lambda match: re.sub(r"[^\n]", " ", match.group(0)),
        source,
        flags=re.MULTILINE | re.DOTALL,
    )


def _skip_ws(source: str, index: int) -> int:
    length = len(source)
    while index < length and source[index] in " \t\n\r":
        index += 1
    return index


def _read_string_literal(source: str, index: int) -> tuple[str, int] | None:
    if index >= len(source):
        return None
    if source.startswith('"""', index):
        end = source.find('"""', index + 3)
        if end < 0:
            return None
        return source[index + 3 : end], end + 3
    quote = source[index]
    if quote not in {'"', "'"}:
        return None
    chars: list[str] = []
    cursor = index + 1
    while cursor < len(source):
        char = source[cursor]
        if char == "\\":
            if cursor + 1 >= len(source):
                break
            chars.append(source[cursor + 1])
            cursor += 2
            continue
        if char == quote:
            return "".join(chars), cursor + 1
        chars.append(char)
        cursor += 1
    return None


def _read_identifier(source: str, index: int) -> tuple[str, str, int] | None:
    match = _IDENTIFIER.match(source, index)
    if match is None:
        return None
    parts = [match.group(0)]
    cursor = match.end()
    while True:
        dotted = _skip_ws(source, cursor)
        if dotted >= len(source) or source[dotted] != ".":
            break
        dotted = _skip_ws(source, dotted + 1)
        nxt = _IDENTIFIER.match(source, dotted)
        if nxt is None:
            break
        parts.append(nxt.group(0))
        cursor = nxt.end()
    return parts[-1], ".".join(parts), cursor


def _read_concat_string_expr(
    source: str, index: int, constants: dict[str, str]
) -> tuple[str, int] | None:
    pieces: list[str] = []
    position = _skip_ws(source, index)
    while True:
        position = _skip_ws(source, position)
        lit = _read_string_literal(source, position)
        if lit is not None:
            chunk, position = lit
            pieces.append(chunk)
        else:
            ident = _read_identifier(source, position)
            if ident is None:
                break
            simple, dotted, position = ident
            if simple in _QUERY_EXPR_KEYWORDS:
                break
            resolved = constants.get(dotted) or constants.get(simple)
            if resolved is not None:
                pieces.append(resolved)
        position = _skip_ws(source, position)
        if position < len(source) and source[position] == "+":
            position += 1
            continue
        break
    if not pieces:
        return None
    return "".join(pieces), position


def _resolve_expr(expr: str, constants: dict[str, str]) -> str | None:
    parsed = _read_concat_string_expr(expr, 0, constants)
    if parsed is None:
        return None
    body, _ = parsed
    return body or None


def _collect_constants_from_source(source: str) -> dict[str, str]:
    constants: dict[str, str] = {}
    matches = list(_STRING_CONST_PREFIX.finditer(source))
    for _ in range(len(matches) + 1):
        changed = False
        for match in matches:
            expr = _read_concat_string_expr(source, match.end(), constants)
            if expr is None:
                continue
            body, _ = expr
            name = match.group(1)
            if constants.get(name) != body:
                constants[name] = body
                changed = True
        if not changed:
            break
    return constants


def _collect_constants_from_facts(facts: dict) -> dict[str, str]:
    items = list(facts.get("string_constants") or [])
    constants: dict[str, str] = {}
    for _ in range(len(items) + 2):
        changed = False
        for item in items:
            name = str(item.get("name") or "")
            if not name:
                continue
            owner = str(item.get("owner") or "").rsplit(".", 1)[-1]
            value = item.get("value")
            if not value:
                value = _resolve_expr(str(item.get("expr") or ""), constants)
            if not value:
                continue
            for key in (name, f"{owner}.{name}" if owner else name):
                if constants.get(key) != value:
                    constants[key] = value
                    changed = True
        if not changed:
            break
    return constants


def _constants_for_source(source: str, facts: dict | None) -> dict[str, str]:
    if facts:
        found = _collect_constants_from_facts(facts)
        if found:
            return found
    return _collect_constants_from_source(_strip_java_comments(source))


def _java_scan_root(filename: str) -> Path | None:
    path = Path(filename)
    try:
        if not path.is_file():
            return None
        resolved = path.resolve()
    except OSError:
        return None
    for parent in (resolved.parent, *resolved.parents):
        for marker in _ROOT_MARKERS:
            if (parent / marker).exists():
                return parent
        if parent.parent == parent:
            break
    return resolved.parent


def _type_name(facts: dict | None, path: Path) -> str:
    if facts:
        classes = facts.get("classes") or []
        if classes:
            return str(classes[0].get("name") or path.stem)
    return path.stem


@lru_cache(maxsize=8)
def _scan_repo_constants(root: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted(Path(root).rglob("*.java")):
        rel = path.as_posix()
        if is_skipped(rel, lang="java"):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        abs_path = str(path.resolve())
        facts = load_facts(source, filename=abs_path)
        local = _constants_for_source(source, facts)
        if not local:
            continue
        type_name = _type_name(facts, path)
        for name, body in local.items():
            out[name] = body
            if "." not in name:
                out[f"{type_name}.{name}"] = body
    return out


def _query_bodies_from_facts(
    facts: dict, constants: dict[str, str]
) -> list[tuple[str, int]]:
    bodies: list[tuple[str, int]] = []
    for ann in facts.get("annotations") or []:
        if (ann.get("name") or "") != "Query":
            continue
        members = ann.get("members") or {}
        line = int(ann.get("line") or 0)
        resolved = members.get("value_resolved")
        if resolved:
            bodies.append((str(resolved), line))
            continue
        expr = str(members.get("value") or "")
        if not expr:
            continue
        body = _resolve_expr(expr, constants)
        if body:
            bodies.append((body, line))
    return bodies


def _query_bodies_from_source(
    source: str, constants: dict[str, str]
) -> list[tuple[str, int]]:
    scannable = _strip_java_comments(source)
    bodies: list[tuple[str, int]] = []
    for match in _QUERY_PREFIX.finditer(scannable):
        parsed = _read_concat_string_expr(scannable, match.end(), constants)
        if parsed is None:
            continue
        body, _ = parsed
        if not body:
            continue
        line = scannable.count("\n", 0, match.start()) + 1
        bodies.append((body, line))
    return bodies


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename, lang="java"):
        return []
    facts = load_facts(source, filename)
    root = _java_scan_root(filename)
    constants = dict(_scan_repo_constants(str(root))) if root is not None else {}
    constants.update(_constants_for_source(source, facts))
    if facts:
        bodies = _query_bodies_from_facts(facts, constants)
    else:
        bodies = _query_bodies_from_source(source, constants)
    findings: list[Finding] = []
    seen: set[int] = set()
    for body, line in bodies:
        if not _JPQL_NULL_OR_LOWER.search(body):
            continue
        if line in seen:
            continue
        seen.add(line)
        findings.append(Finding(line=line, message=_MESSAGE, rule_id=RULE_ID))
    return findings
