"""Kotlin syntax facts for Android detectors.

Not PSI. Comment/string-blanked scan plus brace matching:

- classes: name, line_start, line_end, supers, annotations
- functions: name, line_start, line_end, annotations, owner, is_composable,
  is_preview
- calls: name (dotted), line, in_function, trailing_lambda
- string_lits: line, value (unescaped, truncated)

Parse is best-effort. Brace mismatch or empty scan still returns a dict
(possibly with no functions) rather than raising. FP-biased silence belongs
in detectors, not here.
"""
from __future__ import annotations

import re
from typing import Any

from common import is_skipped as _common_skipped

_MAX_LIT = 200
_CALL_SKIP = frozenset({
    "if", "for", "while", "when", "catch", "try", "return", "throw",
    "else", "do", "super", "this", "init",
})
_MODIFIERS = (
    r"(?:(?:public|private|protected|internal|open|override|abstract|"
    r"inline|suspend|actual|expect|operator|infix|tailrec|data|sealed|"
    r"enum|inner|value|companion|lateinit|const|vararg)\s+)*"
)
_FUN_RE = re.compile(
    rf"{_MODIFIERS}fun\s+(?:[A-Za-z_]\w*\.)?(`[^`]+`|[A-Za-z_]\w*)"
)
_CLASS_RE = re.compile(
    rf"{_MODIFIERS}\b(class|object|interface)\s+(`[^`]+`|[A-Za-z_]\w*)"
)
_ANN_RE = re.compile(r"@([A-Za-z_]\w*)")
_CALL_RE = re.compile(
    r"(?<![.\w])([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*(\(|\{)"
)
_SUPER_RE = re.compile(r":\s*([^/{]+)")


def is_skipped(filename: str, include_tests: bool = False) -> bool:
    return _common_skipped(filename, lang="android", include_tests=include_tests)


def load_facts(source: str, filename: str = "<inline>") -> dict[str, Any] | None:
    """Return Kotlin facts, or None when the path is out of scope."""
    if filename not in {"<inline>", "-"} and is_skipped(filename):
        return None
    if filename not in {"<inline>", "-"}:
        lower = filename.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if lower.endswith(".java") or lower.endswith(".gradle.kts"):
            return None
        if not (lower.endswith(".kt") or lower.endswith(".kts")
                or filename == "<inline>"):
            return None
    blanked = _blank_strings_and_comments(source)
    classes = _extract_classes(blanked)
    functions = _extract_functions(blanked, classes)
    calls = _extract_calls(blanked, functions)
    return {
        "file": filename,
        "classes": classes,
        "functions": functions,
        "calls": calls,
        "string_lits": _extract_string_lits(source),
    }


def _blank_strings_and_comments(src: str) -> str:
    out: list[str] = []
    i = 0
    n = len(src)
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            while i < n and src[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if ch == "/" and nxt == "*":
            out.append(" ")
            out.append(" ")
            i += 2
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append(" ")
                i += 1
            if i < n:
                out.append(" ")
                i += 1
            continue
        if ch == '"' and src.startswith('"""', i):
            out.extend("   ")
            i += 3
            while i < n and not src.startswith('"""', i):
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            out.extend("   " if i < n else "")
            i += 3 if i < n else 0
            continue
        if ch == '"':
            out.append(" ")
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\\" and i + 1 < n:
                    out.append(" ")
                    out.append(" ")
                    i += 2
                    continue
                out.append("\n" if src[i] == "\n" else " ")
                i += 1
            if i < n:
                out.append(" ")
                i += 1
            continue
        if ch == "'":
            out.append(" ")
            i += 1
            while i < n and src[i] != "'":
                if src[i] == "\\" and i + 1 < n:
                    out.append(" ")
                    out.append(" ")
                    i += 2
                    continue
                out.append(" ")
                i += 1
            if i < n:
                out.append(" ")
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _match_brace(text: str, open_idx: int) -> int | None:
    if open_idx >= len(text) or text[open_idx] != "{":
        return None
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _first_brace_after(text: str, start: int, limit: int) -> int | None:
    depth = 0
    i = start
    while i < limit and i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == "{" and depth == 0:
            return i
        elif ch == "=" and depth == 0:
            # Expression-body `fun f() = ...` — no block to attach.
            return None
        i += 1
    return None


def _annotations_before(text: str, index: int) -> list[str]:
    line_start = text.rfind("\n", 0, index) + 1
    prefix = text[line_start:index]
    found = _ANN_RE.findall(prefix)
    pos = line_start
    while pos > 0:
        prev_nl = text.rfind("\n", 0, pos - 1)
        prev_line = text[prev_nl + 1:pos].strip()
        if not prev_line:
            pos = prev_nl if prev_nl >= 0 else 0
            if prev_nl < 0:
                break
            continue
        anns = _ANN_RE.findall(prev_line)
        if not anns or not prev_line.startswith("@"):
            break
        found = anns + found
        pos = prev_nl if prev_nl >= 0 else 0
        if prev_nl < 0:
            break
    return found


def _owner_for(line: int, classes: list[dict[str, Any]]) -> str | None:
    for cls in reversed(classes):
        if cls["line_start"] <= line <= cls["line_end"]:
            return cls["name"]
    return None


def _extract_classes(blanked: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in _CLASS_RE.finditer(blanked):
        name = m.group(2).strip("`")
        brace = _first_brace_after(blanked, m.end(), len(blanked))
        if brace is None:
            continue
        end = _match_brace(blanked, brace)
        if end is None:
            continue
        supers: list[str] = []
        between = blanked[m.end():brace]
        sm = _SUPER_RE.search(between)
        if sm:
            for part in sm.group(1).split(","):
                token = part.strip().split("(")[0].strip()
                token = token.split("<")[0].strip()
                if token:
                    supers.append(token)
        out.append({
            "name": name,
            "line_start": _line_of(blanked, m.start()),
            "line_end": _line_of(blanked, end),
            "supers": supers,
            "annotations": _annotations_before(blanked, m.start()),
        })
    return out


def _extract_functions(blanked: str, classes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in _FUN_RE.finditer(blanked):
        name = m.group(1).strip("`")
        brace = _first_brace_after(blanked, m.end(), len(blanked))
        if brace is None:
            continue
        end = _match_brace(blanked, brace)
        if end is None:
            continue
        anns = _annotations_before(blanked, m.start())
        line_start = _line_of(blanked, m.start())
        out.append({
            "name": name,
            "line_start": line_start,
            "line_end": _line_of(blanked, end),
            "annotations": anns,
            "owner": _owner_for(line_start, classes),
            "is_composable": "Composable" in anns,
            "is_preview": "Preview" in anns or "PreviewParameter" in anns,
            "calls": [],
        })
    return out


def _function_at(line: int, functions: list[dict[str, Any]]) -> dict[str, Any] | None:
    for fn in functions:
        if fn["line_start"] <= line <= fn["line_end"]:
            return fn
    return None


def _extract_calls(blanked: str, functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for m in _CALL_RE.finditer(blanked):
        name = m.group(1)
        head = name.split(".", 1)[0]
        if head in _CALL_SKIP:
            continue
        line = _line_of(blanked, m.start())
        rec = {
            "name": name,
            "line": line,
            "trailing_lambda": m.group(2) == "{",
            "in_function": None,
        }
        fn = _function_at(line, functions)
        if fn is not None:
            rec["in_function"] = fn["name"]
            fn["calls"].append(rec)
        calls.append(rec)
    return calls


def _extract_string_lits(src: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    i = 0
    n = len(src)
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if ch == "/" and nxt == "*":
            i += 2
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                i += 1
            i += 2 if i < n else 0
            continue
        if ch == '"' and src.startswith('"""', i):
            start = i
            i += 3
            buf: list[str] = []
            while i < n and not src.startswith('"""', i):
                buf.append(src[i])
                i += 1
            i += 3 if i < n else 0
            val = "".join(buf)
            out.append({
                "line": _line_of(src, start),
                "value": val[:_MAX_LIT],
            })
            continue
        if ch == '"':
            start = i
            i += 1
            buf = []
            while i < n and src[i] != '"':
                if src[i] == "\\" and i + 1 < n:
                    buf.append(_unescape(src[i:i + 2]))
                    i += 2
                    continue
                buf.append(src[i])
                i += 1
            i += 1 if i < n else 0
            val = "".join(buf)
            out.append({
                "line": _line_of(src, start),
                "value": val[:_MAX_LIT],
            })
            continue
        i += 1
    return out


def _unescape(pair: str) -> str:
    table = {"\\n": "\n", "\\t": "\t", "\\r": "\r", '\\"': '"', "\\\\": "\\"}
    return table.get(pair, pair[-1] if pair else "")
