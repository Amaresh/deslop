"""Detector: go.reliability.no-nullable-column-scanned-as-plain-value

Columns that can be NULL (outer joins, nullable schema columns) must be
scanned into sql.Null* types or pointers, never plain scalars.

AST-facts implementation (goast-facts): each Scan call is tied to its own
SQL statement — either via the chained callee text (db.QueryRow(`...`).Scan)
or via the assignment that produced the receiver (rows := db.Query(`...`)).

Ordinal mapping: when the SELECT list can be parsed and its item count
matches the Scan argument count, a plain-scalar target is flagged only if
its ordinal position selects from the nullable side of an outer join
(LEFT JOIN → right alias; RIGHT JOIN → FROM-side alias; FULL → both).
When mapping is impossible (SELECT *, mismatched counts, unparseable SQL),
the call is exempt — FP-biased by design.

Interface: detect(source: str, filename: str = "<inline>") -> list[Finding]
"""
from __future__ import annotations

import re

from common import Finding
from goast_client import load_facts

RULE_ID = "go.reliability.no-nullable-column-scanned-as-plain-value"

JOIN_SQL_RE = re.compile(r"(?i)\b(left|right|full)(\s+outer)?\s+join\b")
_SELECT_RE = re.compile(r"(?is)\bselect\b(.*?)\bfrom\b")
_JOIN_RE = re.compile(
    r"(?is)\b(left|right|full)(\s+outer)?\s+join\s+([`\w]+)(?:\s+as)?\s+([`\w]+)")
_FROM_FIRST_ALIAS_RE = re.compile(r"(?is)\bfrom\s+[`\w]+(?:\s+as)?\s+([`\w]+)")
_PLAIN_TYPES = {
    "string", "int", "int8", "int16", "int32", "int64",
    "uint", "uint8", "uint16", "uint32", "uint64",
    "float32", "float64", "bool", "byte", "rune", "time.Time",
}
_ARG_RE = re.compile(r"^&(?:[\w.]*\.)?([A-Za-z_]\w*)$")


# --------------------------------------------------------------------------
# statement / join analysis
# --------------------------------------------------------------------------

def _statement_sql(fn: dict, call: dict) -> str:
    """SQL text of the statement feeding this Scan call, '' if untraceable."""
    name = call.get("name", "")
    m = re.search(r"[\.\s]Scan$", name)
    if not m:
        return ""
    chain = name[: m.start()]  # full callee chain; goast preserves query text
    if chain and JOIN_SQL_RE.search(chain):
        return chain
    recv = chain.rsplit(".", 1)[-1] if chain else ""
    for asg in fn.get("assigns", []):
        lhss = [x.strip() for x in asg.get("lhs", "").split(",")]
        if recv in lhss:
            rhs = asg.get("rhs_summary", "")
            if rhs:
                return rhs
    return ""


def _split_top_comma(text: str) -> list[str]:
    parts, depth, cur, in_bt = [], 0, "", False
    for ch in text:
        if ch == "`":
            in_bt = not in_bt
            cur += ch
        elif not in_bt and ch == "(":
            depth += 1
            cur += ch
        elif not in_bt and ch == ")":
            depth -= 1
            cur += ch
        elif ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return parts


def _nullable_side_aliases(sql: str) -> dict[str, str]:
    """Map table/alias -> which join makes its columns NULL-able."""
    out: dict[str, str] = {}
    for m in _JOIN_RE.finditer(sql):
        side = m.group(1).lower()
        table, alias = sql[m.start(3):m.end(3)], sql[m.start(4):m.end(4)]
        if side == "left":
            out[alias] = side          # right side of LEFT JOIN is nullable
        elif side == "right":
            out[table] = side          # left side of RIGHT JOIN is nullable
            fm = _FROM_FIRST_ALIAS_RE.search(sql[: m.start()])
            if fm:
                out[fm.group(1)] = side
        else:  # full
            out[alias] = side
            out[table] = side
    return out


def _item_mentions(item: str, name: str) -> bool:
    return bool(re.search(r"(?i)(^|[.\s`(])" + re.escape(name) + r"\b", item))


# --------------------------------------------------------------------------
# scan-target classification
# --------------------------------------------------------------------------

def _declared_vars(fn: dict) -> tuple[set[str], set[str]]:
    """(plain_scalar_vars, null_aware_vars) declared in this function."""
    plain: set[str] = set()
    null: set[str] = set()
    for decl in fn.get("grouped_var_decls", []):
        typ = decl.get("type", "")
        for name in decl.get("names", []):
            if typ.startswith("sql.Null") or typ.startswith("*"):
                null.add(name)
            elif typ in _PLAIN_TYPES:
                plain.add(name)
    for asg in fn.get("assigns", []):
        rhs = asg.get("rhs_summary", "").strip()
        if re.fullmatch(r'"[^"]*"', rhs):
            for lhs in asg.get("lhs", "").split(","):
                lhs = lhs.strip()
                if lhs and lhs != "_":
                    plain.add(lhs)
    return plain - null, null


def _scan_targets(call: dict, plain: set[str], null: set[str]):
    """[(index, name, 'plain'|'null')] for &name-style args; None for others."""
    targets = []
    for i, arg in enumerate(call.get("args_summary", [])):
        m = _ARG_RE.match(arg.strip())
        if not m:
            continue
        name = m.group(1)
        if name in plain:
            targets.append((i, name, "plain"))
        elif name in null:
            targets.append((i, name, "null"))
    return targets


# --------------------------------------------------------------------------
# main analysis
# --------------------------------------------------------------------------

def _statement_flags(fn: dict, call: dict, plain: set[str], null: set[str]):
    """Finding-worthy plain targets for this Scan, or [] if not guilty."""
    sql = _statement_sql(fn, call)
    if not sql or not JOIN_SQL_RE.search(sql):
        return []

    m = _SELECT_RE.search(sql)
    if not m:
        return []  # cannot map ordinals safely: FP-biased exempt
    items = [i.strip() for i in _split_top_comma(m.group(1))]
    if "*" in items:
        return []
    args = call.get("args_summary", [])
    if len(args) != len(items):
        return []

    nullable = _nullable_side_aliases(sql)
    if not nullable:
        return []

    guilty = []
    for i, name, kind in _scan_targets(call, plain, null):
        if kind != "plain" or i >= len(items):
            continue
        item = items[i]
        if any(_item_mentions(item, n) for n in nullable):
            guilty.append(name)
    return guilty


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    facts = load_facts(source, filename)
    if facts is None:
        return []
    findings: list[Finding] = []
    seen_lines: set[int] = set()
    for fn in facts.get("functions", []):
        plain, null = _declared_vars(fn)
        for call in fn.get("calls", []):
            line = call.get("line", 0)
            if line in seen_lines:
                continue
            names = _statement_flags(fn, call, plain, null)
            if names:
                seen_lines.add(line)
                findings.append(Finding(
                    line=line,
                    message="OUTER JOIN result column scanned into plain "
                            f"scalar(s) {sorted(set(names))}; use sql.Null* "
                            "or pointers for nullable columns",
                    rule_id=RULE_ID,
                ))
    return findings
