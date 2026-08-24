"""Java convention analyzer — regex/heuristic over .java files."""
from __future__ import annotations

import re
from pathlib import Path

from stats import Candidate, Evidence
from walk import discover

STACK = "java"

_HTTP_CLIENTS = ("RestTemplate", "WebClient", "FeignClient", "RestClient")


def _evidence(path: Path, line: int, excerpt: str) -> Evidence:
    return Evidence(file=str(path), line=line, excerpt=excerpt[:120])


def _lines_of(files: list[Path]):
    for f in files:
        try:
            lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        yield f, lines


def _jpql_param_styles(files: list[Path]) -> Candidate:
    """JPQL should use :named params, not string concat."""
    matched, total, ev = 0, 0, []
    for f, lines in _lines_of(files):
        in_query = False
        for i, line in enumerate(lines, 1):
            if "@Query" in line:
                in_query = True
                continue
            if in_query:
                if '"' in line or "+" in line:
                    total += 1
                    if ":" in line and "+" not in line:
                        matched += 1
                    elif len(ev) < 6:
                        ev.append(_evidence(f, i, line.strip()[:100]))
                    in_query = False
                elif not line.strip() or line.strip().startswith("@"):
                    continue
                else:
                    in_query = False
    return Candidate(
        rule_id="java.jpa.named-params-no-concat",
        stack=STACK,
        invariant=("JPQL @Query strings use :named parameters, never "
                   "string concatenation"),
        evidence=ev, matched=matched, total=total,
        enforcement="checker-candidate",
        confidence="high" if total >= 10 else "medium",
    )


def _transactional_scope(files: list[Path]) -> Candidate:
    """@Transactional methods should not do external IO."""
    matched, total, ev = 0, 0, []
    for f, lines in _lines_of(files):
        in_txn = False
        brace_depth = 0
        for i, line in enumerate(lines, 1):
            if "@Transactional" in line:
                in_txn = True
                brace_depth = 0
                continue
            if in_txn:
                brace_depth += line.count("{") - line.count("}")
                if any(h in line for h in _HTTP_CLIENTS) or \
                   re.search(r"\.(postForEntity|getForObject|exchange|put|delete)\(", line):
                    total += 1
                    matched += 1  # violation found
                    if len(ev) < 6:
                        ev.append(_evidence(f, i, line.strip()[:100]))
                    in_txn = False
                    continue
                if brace_depth <= 0:
                    in_txn = False
    return Candidate(
        rule_id="java.transactions.no-external-io",
        stack=STACK,
        invariant=("@Transactional methods persist only; external IO "
                   "(HTTP/S3/messaging) happens after commit"),
        evidence=ev, matched=matched, total=total,
        enforcement="teach-only", confidence="medium",
    )


def _timeout_shaping(files: list[Path]) -> Candidate:
    """HTTP clients should be timeout-shaped."""
    matched, total, ev = 0, 0, []
    for f, lines in _lines_of(files):
        for i, line in enumerate(lines, 1):
            if not any(h in line for h in _HTTP_CLIENTS):
                continue
            if "new " not in line:
                continue
            total += 1
            window = "\n".join(lines[i:i + 8])
            if any(k in window for k in
                   ("setConnectTimeout", "setReadTimeout", "setRequestFactory",
                    "timeout(", "Duration.")):
                matched += 1
            elif len(ev) < 6:
                ev.append(_evidence(f, i, line.strip()[:100]))
    return Candidate(
        rule_id="java.http.timeout-shaped-clients",
        stack=STACK,
        invariant=("HTTP clients (RestTemplate/WebClient/Feign) are "
                   "timeout-shaped at construction"),
        evidence=ev, matched=matched, total=total,
        enforcement="teach-only", confidence="medium",
    )


def _exception_hierarchy(files: list[Path]) -> Candidate:
    """Custom exceptions should extend RuntimeException, not checked Exception."""
    matched, total, ev = 0, 0, []
    for f, lines in _lines_of(files):
        for i, line in enumerate(lines, 1):
            m = re.search(r"class\s+(\w+Exception)\s+extends\s+(\w+)", line)
            if not m:
                continue
            total += 1
            if m.group(2) == "RuntimeException":
                matched += 1
            elif len(ev) < 6:
                ev.append(_evidence(f, i, line.strip()[:100]))
    return Candidate(
        rule_id="java.errors.runtime-exception-hierarchy",
        stack=STACK,
        invariant=("custom exceptions extend RuntimeException (unchecked)"),
        evidence=ev, matched=matched, total=total,
        enforcement="teach-only", confidence="medium",
    )


def _injection_style(files: list[Path]) -> Candidate:
    """Constructor injection beats field @Autowired."""
    matched, total, ev = 0, 0, []
    for f, lines in _lines_of(files):
        for i, line in enumerate(lines, 1):
            if "@Autowired" in line and "private" in line:
                total += 1
                matched += 1  # field injection = violation of constructor rule
                if len(ev) < 6:
                    ev.append(_evidence(f, i, line.strip()[:100]))
    return Candidate(
        rule_id="java.di.constructor-injection",
        stack=STACK,
        invariant=("dependency injection via constructors, not field "
                   "@Autowired"),
        evidence=ev, matched=matched, total=total,
        enforcement="teach-only", confidence="medium",
    )


def analyze(repo_root: str | Path) -> list[Candidate]:
    files = discover(repo_root, "java")
    if not files:
        return []
    checks = [
        _jpql_param_styles,
        _transactional_scope,
        _timeout_shaping,
        _exception_hierarchy,
        _injection_style,
    ]
    out = []
    for check in checks:
        c = check(files)
        if c.total >= 3 and (c.ratio >= 0.8 or c.ratio <= 0.5):
            out.append(c)
    return out
