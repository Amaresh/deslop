"""Detector: android.reliability.no-runblocking-hotpath

`runBlocking` on a UI / hot path freezes the caller (often main). Flag the
call when it sits in a @Composable (except @Preview), a ViewModel, or a
class whose name or supers end in Activity / Fragment / View.

OkHttp Interceptor/Authenticator owners, tests, and expression-body
helpers with no enclosing function/class are silenced. Path-token
heuristics (geofence, FCM, deeplink) are out of scope.
"""
from __future__ import annotations

from common import Finding
from ktast_client import is_skipped, load_facts

LANG = "android"
RULE_ID = "android.reliability.no-runblocking-hotpath"

_ENGLISH_VIEW = ("Overview", "Preview", "Review")


def _tail(name: str) -> str:
    return (name or "").rsplit(".", 1)[-1]


def _is_runblocking(name: str) -> bool:
    return name == "runBlocking" or name.endswith(".runBlocking")


def _class_at(line: int, classes: list[dict]) -> dict | None:
    for cls in reversed(classes):
        if cls["line_start"] <= line <= cls["line_end"]:
            return cls
    return None


def _fns_at(line: int, functions: list[dict]) -> list[dict]:
    return [fn for fn in functions if fn["line_start"] <= line <= fn["line_end"]]


def _names_of(cls: dict | None) -> list[str]:
    if not cls:
        return []
    names = [_tail(cls.get("name") or "")]
    names.extend(_tail(s) for s in (cls.get("supers") or []))
    return [n for n in names if n]


def _is_okhttp_boundary(cls: dict | None) -> bool:
    return any(
        n.endswith("Interceptor") or n.endswith("Authenticator")
        for n in _names_of(cls)
    )


def _is_viewmodel(cls: dict | None) -> bool:
    return any(n.endswith("ViewModel") for n in _names_of(cls))


def _is_ui_owner(cls: dict | None) -> bool:
    for n in _names_of(cls):
        if n.endswith("ViewModel"):
            continue
        if n.endswith("Activity") or n.endswith("Fragment"):
            return True
        if n.endswith("View") and not n.endswith(_ENGLISH_VIEW):
            return True
    return False


def _is_self_def(call: dict, functions: list[dict]) -> bool:
    """`fun HomeScreen()` is also recorded as a call named HomeScreen."""
    name = call.get("name") or ""
    line = int(call.get("line") or 0)
    return any(
        fn.get("name") == name and int(fn.get("line_start") or 0) == line
        for fn in functions
    )


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename):
        return []
    facts = load_facts(source, filename)
    if not facts:
        return []
    functions = facts.get("functions") or []
    classes = facts.get("classes") or []
    out: list[Finding] = []
    seen: set[int] = set()
    for call in facts.get("calls") or []:
        name = call.get("name") or ""
        if not _is_runblocking(name):
            continue
        if _is_self_def(call, functions):
            continue
        line = int(call.get("line") or 1)
        if line in seen:
            continue
        cls = _class_at(line, classes)
        if _is_okhttp_boundary(cls):
            continue
        fns = _fns_at(line, functions)
        if any(fn.get("is_preview") for fn in fns):
            continue
        hot = any(
            fn.get("is_composable") and not fn.get("is_preview")
            for fn in fns
        )
        hot = hot or _is_viewmodel(cls) or _is_ui_owner(cls)
        if not hot:
            continue
        seen.add(line)
        shown = name if "." in name else "runBlocking"
        out.append(Finding(
            line=line,
            message=f"{shown} on a UI/hot path; use a scoped coroutine "
                    "(viewModelScope / lifecycleScope / rememberCoroutineScope)",
            rule_id=RULE_ID,
        ))
    return out
