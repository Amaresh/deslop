"""Detector: typescript.security.no-unvalidated-external-href

JSX / createElement `href` (and `to` on `<a>`) must be a safe literal
(`/`, `#`, `?`, `mailto:`, `tel:`, `http://`, `https://`) or a template
whose cooked prefix is one of those. Identifier/call/template hrefs need
a same-function scheme allowlist (`startsWith("http")` or `/^https?:/`
`.test`) on that expression.

PascalCase / constant property access (`Routes.foo`) is silenced (FP-biased).
Spreads are unknown and omitted from jsx facts.

AST-facts implementation (tsast jsx).
"""
from __future__ import annotations

import re

from common import Finding
from tsast_client import is_out_of_scope, load_facts

LANG = "ts"
RULE_ID = "typescript.security.no-unvalidated-external-href"

_SAFE_PREFIXES = ("/", "#", "?", "mailto:", "tel:", "http://", "https://")
_CONSTANT_IDENT = re.compile(r"^[A-Z][A-Z0-9_]+$")
_PASCAL = re.compile(r"^[A-Z][A-Za-z0-9]*$")
_USER_DERIVED = re.compile(
    r"(?i)\b(user|query|searchParams|searchParam|params|param|"
    r"window\.location|location\.(href|search|hash)|document\.location)\b",
)


def _safe_literal(val: str | None, *, empty_ok: bool) -> bool:
    if val is None:
        return False
    if val == "":
        return empty_ok
    return any(val.startswith(p) for p in _SAFE_PREFIXES)


def _constant_ident(name: str) -> bool:
    return bool(_CONSTANT_IDENT.fullmatch(name or ""))


def _pascal_or_constant_root(summary: str) -> bool:
    root = (summary or "").split(".")[0].split("[")[0].strip()
    if not root:
        return False
    return bool(_PASCAL.fullmatch(root)) or _constant_ident(root)


def _resource_link(el: dict) -> bool:
    if (el.get("tag") or "").lower() != "link":
        return False
    for attr in el.get("attrs") or []:
        if (attr.get("name") or "") != "rel":
            continue
        rel = (attr.get("value_summary") or "").lower()
        if rel in {"stylesheet", "prefetch", "preload", "modulepreload", "icon"}:
            return True
    return False


def _is_href_attr(name: str, tag: str) -> bool:
    if name == "href" or name.endswith(":href"):
        return True
    return name == "to" and (tag or "").lower() == "a"


def _silence_expr(attr: dict) -> bool:
    if attr.get("has_scheme_allowlist"):
        return True
    kind = attr.get("kind") or "other"
    summary = attr.get("value_summary") or ""
    if kind == "identifier" and _constant_ident(summary):
        return True
    if kind == "property" and _pascal_or_constant_root(summary):
        return True
    if kind in {"property", "other"} and not _USER_DERIVED.search(summary):
        # FP-biased: non-user property / ternary / concat stays quiet.
        return True
    return False


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_out_of_scope(filename):
        return []
    facts = load_facts(source, filename)
    if facts is None:
        return []
    out: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    for el in facts.get("jsx") or []:
        tag = el.get("tag") or ""
        if _resource_link(el):
            continue
        line = int(el.get("line") or 1)
        for attr in el.get("attrs") or []:
            name = attr.get("name") or ""
            if not _is_href_attr(name, tag):
                continue
            kind = attr.get("kind") or "other"
            summary = attr.get("value_summary") or ""
            if kind == "string_literal":
                if _safe_literal(summary, empty_ok=True):
                    continue
            elif kind == "template":
                if _safe_literal(summary, empty_ok=False):
                    continue
                if _silence_expr(attr):
                    continue
            elif kind in {"identifier", "call", "property", "other"}:
                if _silence_expr(attr):
                    continue
            else:
                continue
            key = (line, name)
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(
                line=line,
                message=f"`{name}` is not a same-origin/https literal and has "
                        "no scheme allowlist (startsWith(\"http\") / "
                        "/^https?:/ test) in this function",
                rule_id=RULE_ID,
            ))
    return out
