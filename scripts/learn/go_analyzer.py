"""Go convention analyzer — extracts implicit rules from a Go codebase.

Uses mine/detectors/goast/goast-facts for per-file AST facts, then counts
convention shapes repo-wide. Emits Candidate only when adoption is strong
(>=0.8) or consistently violated (<=0.5) — the two ends where a rule is
worth offering.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from stats import Candidate, Evidence
from walk import discover

_GOAST_BIN = (
    Path(__file__).resolve().parent / "goast" / "goast-facts"
)


def _ensure_goast_bin() -> Path:
    """Build goast-facts on demand from scripts/learn/goast/main.go."""
    if _GOAST_BIN.is_file():
        return _GOAST_BIN
    go = shutil.which("go")
    if not go:
        return _GOAST_BIN  # will fail loudly at facts-for
    import subprocess
    subprocess.run(
        [go, "build", "-o", str(_GOAST_BIN), str(_GOAST_BIN.parent / "main.go")],
        check=False, cwd=str(_GOAST_BIN.parent))
    return _GOAST_BIN

STACK = "go"


def _facts_for(path: Path) -> dict | None:
    try:
        proc = subprocess.run(
            [str(_ensure_goast_bin()), str(path)], capture_output=True, text=True,
            timeout=30)
        if proc.returncode != 0:
            return None
        return json.loads(proc.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None


def _evidence(path: Path, line: int, excerpt: str) -> Evidence:
    return Evidence(file=str(path), line=line, excerpt=excerpt[:120])


def _fmt_ratio(matched: int, total: int) -> float:
    return matched / total if total else 0.0


def _ctx_first_convention(files: list[Path]) -> Candidate:
    """Handlers and request funcs should take context.Context first."""
    matched, total, ev = 0, 0, []
    for f in files:
        facts = _facts_for(f)
        if not facts:
            continue
        for fn in facts.get("functions", []):
            params = fn.get("params") or []
            if not any("http.Request" in p for p in params):
                continue
            total += 1
            first = params[0] if params else ""
            if "context.Context" in first:
                matched += 1
            elif len(ev) < 6:
                ev.append(_evidence(f, fn.get("line_start", 0),
                                    f"{fn.get('name')}({', '.join(params)[:80]})"))
    c = Candidate(
        rule_id="go.api.handlers-take-context-first",
        stack=STACK,
        invariant=("Handlers and request-processing functions take "
                   "context.Context as their first parameter"),
        evidence=ev, matched=matched, total=total,
        enforcement="checker-candidate",
        confidence="high" if total >= 20 else "medium",
    )
    return c


def _error_wrap_convention(files: list[Path]) -> Candidate:
    """fmt.Errorf should use %w for wrapping errors, not %s/%v."""
    matched, total, ev = 0, 0, []
    for f in files:
        text = f.read_text(encoding="utf-8", errors="ignore")
        for i, line in enumerate(text.splitlines(), 1):
            if "fmt.Errorf(" not in line:
                continue
            total += 1
            if "%w" in line:
                matched += 1
            elif len(ev) < 6:
                ev.append(_evidence(f, i, line.strip()[:110]))
    return Candidate(
        rule_id="go.errors.wrap-with-percent-w",
        stack=STACK,
        invariant=("fmt.Errorf calls wrap errors with %w so callers can "
                   "errors.Is/As; %s/%v stringification is avoided"),
        evidence=ev, matched=matched, total=total,
        enforcement="checker-candidate",
        confidence="high" if total >= 20 else "medium",
    )


def _defer_close_convention(files: list[Path]) -> Candidate:
    """Resources opened should be closed with defer in the same function."""
    matched, total, ev = 0, 0, []
    for f in files:
        facts = _facts_for(f)
        if not facts:
            continue
        for fn in facts.get("functions", []):
            opens = [c for c in fn.get("calls", [])
                     if any(k in c.get("name", "") for k in
                            ("os.Open", "os.Create", "sql.Open",
                             "net.Dial", "net.Listen", "http.Get"))]
            if not opens:
                continue
            total += 1
            # defer isn't in calls facts; scan source lines of function range
            src_lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
            lo, hi = fn.get("line_start", 0), fn.get("line_end", 0)
            has_defer = any("defer" in (src_lines[i - 1] or "")
                            for i in range(lo, hi + 1) if i - 1 < len(src_lines))
            if has_defer:
                matched += 1
            elif len(ev) < 6:
                ev.append(_evidence(f, opens[0].get("line", 0),
                                    opens[0].get("name", "")[:80]))
    return Candidate(
        rule_id="go.resources.defer-close",
        stack=STACK,
        invariant=("Opened resources (files, connections, listeners) are "
                   "closed with defer in the same function"),
        evidence=ev, matched=matched, total=total,
        enforcement="teach-only", confidence="medium",
    )


def _http_timeout_convention(files: list[Path]) -> Candidate:
    """HTTP clients should shape timeouts; bare http.Get is discouraged."""
    bare, shaped, total, ev = 0, 0, 0, []
    for f in files:
        text = f.read_text(encoding="utf-8", errors="ignore")
        for i, line in enumerate(text.splitlines(), 1):
            if "http.Client{" in line:
                total += 1
                if "Timeout" in line:
                    shaped += 1
                elif len(ev) < 6:
                    ev.append(_evidence(f, i, line.strip()[:100]))
            elif "http.Get(" in line:
                total += 1
                bare += 1
                if len(ev) < 6:
                    ev.append(_evidence(f, i, line.strip()[:100]))
    matched = shaped
    return Candidate(
        rule_id="go.http.timeout-shaped-clients",
        stack=STACK,
        invariant=("http.Client literals declare a Timeout and bare http.Get "
                   "without timeout shaping is avoided"),
        evidence=ev, matched=matched, total=total,
        enforcement="checker-candidate",
        confidence="high" if total >= 15 else "medium",
    )


def _sentinel_error_convention(files: list[Path]) -> Candidate:
    """Packages should define sentinel errors with errors.New at package scope."""
    sentinels, total, ev = 0, 0, []
    for f in files:
        text = f.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        pkg_sentinels = 0
        for i, line in enumerate(lines, 1):
            if "errors.New(" in line and not line.lstrip().startswith(("return", "if", "var ")):
                continue
            if "errors.New(" in line:
                pkg_sentinels += 1
        if pkg_sentinels:
            sentinels += 1
        total += 1
        if not pkg_sentinels and len(ev) < 6:
            ev.append(_evidence(f, 1, f"{f.name}: no sentinel errors found"))
    return Candidate(
        rule_id="go.errors.package-sentinels",
        stack=STACK,
        invariant=("Packages define sentinel errors (errors.New at package "
                   "scope) rather than inline error creation"),
        evidence=ev, matched=sentinels, total=total,
        enforcement="teach-only", confidence="medium",
    )


def analyze(repo_root: str | Path) -> list[Candidate]:
    files = discover(repo_root, "go")
    if not files:
        return []
    checks = [
        _ctx_first_convention,
        _error_wrap_convention,
        _defer_close_convention,
        _http_timeout_convention,
        _sentinel_error_convention,
    ]
    out = []
    for check in checks:
        c = check(files)
        if c.total >= 3 and (c.ratio >= 0.8 or c.ratio <= 0.5):
            out.append(c)
    return out
