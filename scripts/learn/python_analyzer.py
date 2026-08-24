"""Python convention analyzer — extracts implicit rules via stdlib ast."""
from __future__ import annotations

import ast
from pathlib import Path

from stats import Candidate, Evidence
from walk import discover

STACK = "python"


def _evidence(path: Path, line: int, excerpt: str) -> Evidence:
    return Evidence(file=str(path), line=line, excerpt=excerpt[:120])


def _iter_funcs(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _async_route_purity(files: list[Path]) -> Candidate:
    """Async routes should not contain blocking calls."""
    matched, total, ev = 0, 0, []
    blocking = ("requests.", "time.sleep", "open(", ".execute(", "urllib.")
    for f in files:
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError:
            continue
        for fn in _iter_funcs(tree):
            if not isinstance(fn, ast.AsyncFunctionDef):
                continue
            is_route = False
            for dec in fn.decorator_list:
                src = ast.unparse(dec)
                if "router" in src or "app" in src or "route" in src:
                    is_route = True
            if not is_route:
                continue
            total += 1
            bad = any(
                isinstance(n, ast.Call) and any(
                    b in ast.unparse(n.func)[:40] for b in blocking)
                for n in ast.walk(fn) if isinstance(n, ast.Call))
            if bad:
                matched += 1
                if len(ev) < 6:
                    ev.append(_evidence(f, fn.lineno,
                                        f"async def {fn.name}"))
    return Candidate(
        rule_id="python.api.async-routes-blocking-free",
        stack=STACK,
        invariant=("async route handlers avoid blocking calls "
                   "(requests, time.sleep, sync IO)"),
        evidence=ev, matched=matched, total=total,
        enforcement="checker-candidate",
        confidence="high" if total >= 15 else "medium",
    )


def _response_model_convention(files: list[Path]) -> Candidate:
    """FastAPI routes should declare response_model."""
    matched, total, ev = 0, 0, []
    for f in files:
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError:
            continue
        for fn in _iter_funcs(tree):
            is_route = any(
                "route" in ast.unparse(d) or "router" in ast.unparse(d)
                or "app." in ast.unparse(d)
                for d in fn.decorator_list)
            if not is_route:
                continue
            total += 1
            has = any("response_model" in ast.unparse(d) or
                      "response_model" in ast.unparse(fn)
                      for d in fn.decorator_list)
            if has:
                matched += 1
            elif len(ev) < 6:
                ev.append(_evidence(f, fn.lineno, f"def {fn.name}"))
    return Candidate(
        rule_id="python.api.routes-declare-response-model",
        stack=STACK,
        invariant=("API routes declare response_model instead of leaking "
                   "internal models"),
        evidence=ev, matched=matched, total=total,
        enforcement="checker-candidate",
        confidence="high" if total >= 15 else "medium",
    )


def _exception_breadth(files: list[Path]) -> Candidate:
    """Bare/broad excepts without handling are slop."""
    matched, total, ev = 0, 0, []
    for f in files:
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            total += 1
            bare = node.type is None or (
                isinstance(node.type, ast.Name) and
                node.type.id in ("Exception", "BaseException"))
            handled = bool(node.body) and not all(
                isinstance(b, ast.Pass) for b in node.body)
            if bare and not handled:
                matched += 1
                if len(ev) < 6:
                    ev.append(_evidence(f, node.lineno, "except: ..."))
    return Candidate(
        rule_id="python.errors.no-bare-broad-except",
        stack=STACK,
        invariant=("except clauses are narrow or, if broad, actually handle "
                   "the error (no bare except/pass)"),
        evidence=ev, matched=matched, total=total,
        enforcement="checker-candidate",
        confidence="high" if total >= 20 else "medium",
    )


def _sql_interpolation(files: list[Path]) -> Candidate:
    """SQL should use parameterized queries, not f-strings."""
    matched, total, ev = 0, 0, []
    for f in files:
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = ast.unparse(node.func).lower()
            if not any(k in func for k in ("execute", "executemany",
                                           "query", "raw")):
                continue
            total += 1
            args = [ast.unparse(a) for a in node.args]
            bad = any(("f\"" in a or "f'" in a or ".format(" in a or "%s" in a)
                      and ("select" in a.lower() or "insert" in a.lower()
                           or "update" in a.lower()) for a in args)
            if bad:
                matched += 1
                if len(ev) < 6:
                    ev.append(_evidence(f, node.lineno, func[:60]))
    return Candidate(
        rule_id="python.sql.parameterized-queries",
        stack=STACK,
        invariant=("SQL strings are parameterized (bound params), not "
                   "f-string/.format/% interpolation"),
        evidence=ev, matched=matched, total=total,
        enforcement="checker-candidate",
        confidence="high" if total >= 15 else "medium",
    )


def _env_access_style(files: list[Path]) -> Candidate:
    """env access should be validated/centralized, not raw at import."""
    matched, total, ev = 0, 0, []
    for f in files:
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="ignore"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = ast.unparse(node.func)
            if not func.startswith("os.getenv") and "os.environ" not in func:
                continue
            total += 1
            if isinstance(node, ast.Call) and func == "os.getenv":
                default = None
                if len(node.args) >= 2:
                    default = ast.unparse(node.args[1])
                raw = default is None
            else:
                raw = True
            if raw:
                matched += 1
                if len(ev) < 6:
                    ev.append(_evidence(f, node.lineno, func[:50]))
    return Candidate(
        rule_id="python.config.no-raw-env-defaults",
        stack=STACK,
        invariant=("os.getenv calls provide a validated default (or go "
                   "through a settings object)"),
        evidence=ev, matched=matched, total=total,
        enforcement="teach-only", confidence="medium",
    )


def analyze(repo_root: str | Path) -> list[Candidate]:
    files = discover(repo_root, "python")
    if not files:
        return []
    checks = [
        _async_route_purity,
        _response_model_convention,
        _exception_breadth,
        _sql_interpolation,
        _env_access_style,
    ]
    out = []
    for check in checks:
        c = check(files)
        if c.total >= 3 and (c.ratio >= 0.8 or c.ratio <= 0.5):
            out.append(c)
    return out
