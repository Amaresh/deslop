"""Detector: python.reliability.no-except-exception-pass-swallow

Do not write `except Exception: pass`, `except BaseException: pass`, or
bare `except: pass`. A body that is only pass / ... / Ellipsis counts.
Narrow handlers (KeyError, OSError, ...) and handlers that log or re-raise
are out of scope.
"""
from __future__ import annotations

from common import Finding, is_skipped
from pyast_client import load_facts

LANG = "python"
RULE_ID = "python.reliability.no-except-exception-pass-swallow"

_SWALLOWED = frozenset({"Exception", "BaseException"})
_BODY = frozenset({"pass", "ellipsis"})
# Destructors and context-exit hooks must not raise; pass-swallow is idiomatic.
_SKIP_FUNCS = frozenset({"__del__", "__exit__", "__aexit__"})


def _types(raw: str | None) -> list[str]:
    if raw is None:
        return []
    return [p.strip() for p in raw.split("|") if p.strip()]


def _is_broad_swallow(handler: dict) -> bool:
    if handler.get("body_kind") not in _BODY:
        return False
    typ = handler.get("type")
    if typ is None:
        return True  # bare except
    names = _types(typ)
    for n in names:
        leaf = n.rsplit(".", 1)[-1]
        if n in _SWALLOWED or leaf in _SWALLOWED:
            return True
    return False


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename, lang="python"):
        return []
    facts = load_facts(source, filename)
    if not facts:
        return []
    out: list[Finding] = []
    seen: set[int] = set()
    for handler in facts.get("except_handlers") or []:
        if handler.get("in_function") in _SKIP_FUNCS:
            continue
        if not _is_broad_swallow(handler):
            continue
        line = int(handler.get("line") or 1)
        if line in seen:
            continue
        seen.add(line)
        typ = handler.get("type")
        kind = "bare except" if typ is None else f"except {typ}"
        out.append(Finding(
            line=line,
            message=f"{kind} swallows with pass/ellipsis",
            rule_id=RULE_ID,
        ))
    return out
