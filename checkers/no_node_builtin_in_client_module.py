"""Detector: typescript.web.no-node-builtin-in-client-module

A file with a `'use client'` directive must not import Node builtins
(`node:fs`, `fs`, `path`, `child_process`, …). Those modules do not exist
in the browser bundle.

Same-file only (portable). Type-only imports are silent. Regex, not tsast.
"""
from __future__ import annotations

import re

from common import Finding
from tsast_client import is_out_of_scope

LANG = "ts"
RULE_ID = "typescript.web.no-node-builtin-in-client-module"

# Next/RSC: the directive is the first statement (comments already stripped).
_LEADING_USE_CLIENT = re.compile(r"""\A[ \t\n]*['"]use client['"]""")
_TYPE_IMPORT = re.compile(
    r"""(?:import|export)\s+type\b|import\s*\{[^}]*\btype\b"""
)
_NODE_SPEC = re.compile(
    r"""['"](?P<spec>node:(?:fs|path|child_process|os|crypto|url|stream|buffer|util|http|https)(?:/[^'"]*)?|fs(?:/promises)?|path|child_process)['"]"""
)


def _strip_js_comments(source: str) -> str:
    out: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        c = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if c in "\"'`":
            quote = c
            out.append(c)
            i += 1
            if quote == "`":
                while i < n:
                    ch = source[i]
                    out.append(ch)
                    if ch == "\\" and i + 1 < n:
                        out.append(source[i + 1])
                        i += 2
                        continue
                    i += 1
                    if ch == "`":
                        break
                continue
            while i < n:
                ch = source[i]
                out.append(ch)
                if ch == "\\" and i + 1 < n:
                    out.append(source[i + 1])
                    i += 2
                    continue
                i += 1
                if ch == quote:
                    break
            continue
        if c == "/" and nxt == "/":
            while i < n and source[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if c == "/" and nxt == "*":
            i += 2
            out.extend("  ")
            while i < n - 1 and not (source[i] == "*" and source[i + 1] == "/"):
                out.append("\n" if source[i] == "\n" else " ")
                i += 1
            if i < n - 1:
                out.extend("  ")
                i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _line_is_type_only(scannable: str, offset: int) -> bool:
    line_start = scannable.rfind("\n", 0, offset) + 1
    line_end = scannable.find("\n", offset)
    line = scannable[line_start: line_end if line_end != -1 else None]
    return _TYPE_IMPORT.search(line) is not None


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_out_of_scope(filename):
        return []
    scannable = _strip_js_comments(source)
    if _LEADING_USE_CLIENT.search(scannable) is None:
        return []
    out: list[Finding] = []
    seen: set[int] = set()
    for match in _NODE_SPEC.finditer(scannable):
        if _line_is_type_only(scannable, match.start()):
            continue
        line = scannable.count("\n", 0, match.start()) + 1
        if line in seen:
            continue
        seen.add(line)
        spec = match.group("spec")
        out.append(Finding(
            line=line,
            message=(
                f"Client module ('use client') imports `{spec}`, which cannot "
                "ship in the browser bundle; keep Node builtins on the server"
            ),
            rule_id=RULE_ID,
        ))
    return out
