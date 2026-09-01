"""TypeScript convention analyzer — regex/heuristic over .ts/.tsx."""
from __future__ import annotations

import re
from pathlib import Path

from stats import Candidate, Evidence, should_emit
from walk import discover, rel_to_repo

STACK = "ts"
_REPO_ROOT: Path | None = None

_FETCH_RE = re.compile(r"\bfetch\s*\(")
_ABORT_RE = re.compile(r"\b(AbortController|AbortSignal\.timeout)")
_ASYNC_CALL_RE = re.compile(r"\b(await\s+\w|\.then\s*\()")
_CATCH_OPEN_RE = re.compile(r"\bcatch\s*(?:\([^)]*\))?\s*\{")


def _evidence(path: Path, line: int, excerpt: str) -> Evidence:
    return Evidence(
        file=rel_to_repo(path, _REPO_ROOT),
        line=line,
        excerpt=excerpt[:120],
    )


def _catch_is_empty(body: str) -> bool:
    stripped = re.sub(r"//[^\n]*", "", body)
    stripped = re.sub(r"/\*.*?\*/", "", stripped, flags=re.DOTALL)
    return stripped.strip() == ""


def _floating_promises(files: list[Path]) -> Candidate:
    """Async calls should be awaited or handled.

    Regex-only; not emitted from analyze() until TS facts exist.
    """
    matched, total, ev = 0, 0, []
    for f in files:
        lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "*", "/*")):
                continue
            has_then = ".then(" in line
            has_await = "await " in line
            async_ish = re.search(r"\b(\w+\([^)]*\))\s*;?\s*$", stripped)
            if not has_then and not async_ish:
                continue
            total += 1
            handled = has_await or "void " in line or ".catch(" in line or \
                stripped.startswith("await") or ".then(" in line
            if has_then and ".catch(" not in line and ".then(" not in line.split(".then(")[1] if ".then(" in line else True:
                handled = False
            if has_then:
                handled = ".catch(" in line or "await " in line
            if not handled:
                matched += 1
                if len(ev) < 6:
                    ev.append(_evidence(f, i, stripped[:100]))
    return Candidate(
        rule_id="typescript.promises.no-floating",
        stack=STACK,
        invariant=("async calls are awaited, void-marked, or chained with "
                   ".catch — no floating promises"),
        evidence=ev, matched=matched, total=total,
        enforcement="checker-candidate",
        confidence="high" if total >= 20 else "medium",
    )


def _fetch_without_timeout(files: list[Path]) -> Candidate:
    """fetch should pair with an abort signal/timeout."""
    matched, total, ev = 0, 0, []
    for f in files:
        lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
        for i, line in enumerate(lines, 1):
            if not _FETCH_RE.search(line):
                continue
            total += 1
            window = "\n".join(lines[max(0, i - 12):i + 6])
            if _ABORT_RE.search(window) or "signal" in window.lower():
                matched += 1
            elif len(ev) < 6:
                ev.append(_evidence(f, i, line.strip()[:100]))
    return Candidate(
        rule_id="typescript.fetch.has-abort-timeout",
        stack=STACK,
        invariant=("fetch calls are paired with AbortController/AbortSignal "
                   "timeout"),
        evidence=ev, matched=matched, total=total,
        enforcement="checker-candidate",
        confidence="high" if total >= 15 else "medium",
    )


def _empty_catches(files: list[Path]) -> Candidate:
    """catch blocks should not be empty.

    total = catch blocks, matched = non-empty handlers (adoption).
    """
    matched, total, ev = 0, 0, []
    for f in files:
        text = f.read_text(encoding="utf-8", errors="ignore")
        for m in _CATCH_OPEN_RE.finditer(text):
            start = m.end()
            depth = 1
            idx = start
            while depth > 0 and idx < len(text):
                if text[idx] == "{":
                    depth += 1
                elif text[idx] == "}":
                    depth -= 1
                idx += 1
            body = text[start:idx - 1] if idx > start else ""
            total += 1
            if not _catch_is_empty(body):
                matched += 1
            elif len(ev) < 6:
                line = text[:m.start()].count("\n") + 1
                ev.append(_evidence(
                    f, line, m.group(0).replace("\n", " ")[:80]))
    return Candidate(
        rule_id="typescript.errors.no-empty-catch",
        stack=STACK,
        invariant=("catch blocks handle or rethrow the error — never empty"),
        evidence=ev, matched=matched, total=total,
        enforcement="checker-candidate",
        confidence="high" if total >= 10 else "medium",
    )


def _any_density(files: list[Path]) -> Candidate:
    """Explicit any should be rare."""
    matched, total, ev = 0, 0, []
    for f in files:
        text = f.read_text(encoding="utf-8", errors="ignore")
        any_count = len(re.findall(r":\s*any\b|\bas any\b", text))
        lines = len([l for l in text.splitlines() if l.strip()])
        k = lines / 1000.0
        if k <= 0:
            continue
        total += 1
        rate = any_count / k
        if rate >= 2.0:
            matched += 1
            if len(ev) < 6:
                ev.append(_evidence(f, 1, f"~{any_count} anys in {lines} lines"))
    return Candidate(
        rule_id="typescript.types.any-density",
        stack=STACK,
        invariant=("explicit `any` usage stays below ~2 per kLOC"),
        evidence=ev, matched=matched, total=total,
        enforcement="teach-only", confidence="medium",
    )


def _effect_cleanup(files: list[Path]) -> Candidate:
    """useEffect with subscriptions must return cleanup."""
    matched, total, ev = 0, 0, []
    for f in files:
        text = f.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(r"useEffect\s*\([^)]*\)\s*=>\s*\{", text):
            total += 1
            start = m.end()
            depth = 1
            idx = start
            while depth > 0 and idx < len(text):
                if text[idx] == "{":
                    depth += 1
                elif text[idx] == "}":
                    depth -= 1
                idx += 1
            body = text[start:idx]
            has_subs = any(k in body for k in
                           ("addEventListener", "setInterval",
                            "setTimeout", ".on("))
            if not has_subs:
                continue
            has_cleanup = "return () =>" in body or "clearInterval" in body \
                or "removeEventListener" in body or "clearTimeout" in body
            if not has_cleanup:
                matched += 1
                if len(ev) < 6:
                    ev.append(_evidence(f, text[:m.start()].count("\n") + 1,
                                        "useEffect without cleanup"))
    return Candidate(
        rule_id="typescript.react.effect-cleanup",
        stack=STACK,
        invariant=("useEffect subscriptions (listeners/timers) return a "
                   "cleanup function"),
        evidence=ev, matched=matched, total=total,
        enforcement="checker-candidate",
        confidence="high" if total >= 10 else "medium",
    )


def analyze(repo_root: str | Path) -> list[Candidate]:
    global _REPO_ROOT
    root = Path(repo_root)
    _REPO_ROOT = root
    try:
        files = discover(root, "ts")
        if not files:
            return []
        # _floating_promises is regex noise until TS facts exist — do not emit.
        checks = [
            _fetch_without_timeout,
            _empty_catches,
            _any_density,
            _effect_cleanup,
        ]
        out = []
        for check in checks:
            c = check(files)
            if should_emit(c):
                out.append(c)
        return out
    finally:
        _REPO_ROOT = None
