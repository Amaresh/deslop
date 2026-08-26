"""Detector: java.security.no-secret-fallback-literal

@Value("${secret.key:hardcoded}") and getenv/getProperty/orElse with a
secret-like key plus a non-placeholder literal default (length >= 8).
Timeout/port keys, empty defaults, CHANGE_ME/TODO/dummy/your-*, and
nested ${}/#{} placeholders are out of scope.

AST-facts implementation (JavaAstFacts annotations + call args_summary).
"""
from __future__ import annotations

import re

from common import Finding, is_skipped
from javaast_client import load_facts

LANG = "java"
RULE_ID = "java.security.no-secret-fallback-literal"

_SECRET_KEY = re.compile(
    r"(?i)(password|secret|token|apikey|api[-_.]?key|private)"
)
_PLACEHOLDER = re.compile(r"^\$\{(.+)\}$")
_STR_LIT = re.compile(r'^"((?:\\.|[^"\\])*)"$')
_SILENCE_EXACT = frozenset({
    "change_me", "changeme", "todo", "dummy", "null", "none", "",
})
_ENV_TWO_ARG = frozenset({"getproperty", "getenv", "getordefault"})
_OR_ELSE = frozenset({"orelse"})
_ENV_IN_SCOPE = re.compile(r"(?i)\b(getenv|getproperty|getordefault)\b")


def _unwrap(raw: str) -> str:
    s = (raw or "").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


def _looks_secret_key(key: str) -> bool:
    return bool(_SECRET_KEY.search(key or ""))


def _is_placeholder_default(default: str) -> bool:
    text = (default or "").strip()
    if not text:
        return True
    if text.startswith("${") or text.startswith("#{") or text.startswith("$"):
        return True
    low = text.lower()
    if low in _SILENCE_EXACT:
        return True
    if low.startswith("your-"):
        return True
    if low == "todo" or low.startswith("todo_") or low.startswith("todo-"):
        return True
    return False


def _bad_literal_default(default: str) -> bool:
    if _is_placeholder_default(default):
        return False
    return len(default.strip()) >= 8


def _split_placeholder(inner: str) -> tuple[str, str | None]:
    """Split Spring ${key:default} on the first colon."""
    depth = 0
    for i, ch in enumerate(inner):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
        elif ch == ":" and depth == 0:
            return inner[:i], inner[i + 1:]
    return inner, None


def _string_literal(arg: str) -> str | None:
    m = _STR_LIT.match((arg or "").strip())
    if not m:
        return None
    return m.group(1)


def _call_method(name: str) -> str:
    return (name or "").rsplit(".", 1)[-1]


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename, lang="java"):
        return []
    facts = load_facts(source, filename)
    if not facts:
        return []
    out: list[Finding] = []
    seen: set[int] = set()

    for ann in facts.get("annotations") or []:
        if (ann.get("name") or "") != "Value":
            continue
        members = ann.get("members") or {}
        raw = _unwrap(str(members.get("value") or ""))
        m = _PLACEHOLDER.match(raw.strip())
        if not m:
            continue
        key, default = _split_placeholder(m.group(1))
        if default is None:
            continue
        if not _looks_secret_key(key):
            continue
        if not _bad_literal_default(default):
            continue
        line = int(ann.get("line") or 1)
        if line in seen:
            continue
        seen.add(line)
        out.append(Finding(
            line=line,
            message=f"@Value placeholder '{key}' embeds a secret fallback "
                    "literal; use env/config with no checked-in default",
            rule_id=RULE_ID,
        ))

    for meth in facts.get("methods") or []:
        for call in meth.get("calls") or []:
            name = call.get("name") or ""
            simple = _call_method(name)
            args = list(call.get("args_summary") or [])
            key = None
            default = None
            low = simple.lower()
            if low in _ENV_TWO_ARG and len(args) >= 2:
                key = _string_literal(str(args[0]))
                default = _string_literal(str(args[1]))
            elif low in _OR_ELSE and args:
                if not _ENV_IN_SCOPE.search(name):
                    continue
                if not _looks_secret_key(name):
                    continue
                default = _string_literal(str(args[0]))
                key = name
            else:
                continue
            if default is None:
                continue
            if key is not None and not _looks_secret_key(str(key)):
                continue
            if not _bad_literal_default(default):
                continue
            line = int(call.get("line") or meth.get("line_start") or 1)
            if line in seen:
                continue
            seen.add(line)
            shown = key if isinstance(key, str) else "env"
            out.append(Finding(
                line=line,
                message=f"env lookup '{shown}' uses a secret fallback "
                        "literal; omit the default or use a placeholder",
                rule_id=RULE_ID,
            ))
    return out
