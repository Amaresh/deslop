"""Java convention analyzer — regex/heuristic over .java files."""
from __future__ import annotations

import re
from pathlib import Path

from stats import Candidate, Evidence, should_emit
from walk import discover, rel_to_repo

STACK = "java"
_REPO_ROOT: Path | None = None

_HTTP_CLIENTS = ("RestTemplate", "WebClient", "FeignClient", "RestClient")
_EXTERNAL_IO_TYPES = _HTTP_CLIENTS + (
    "AmazonS3", "S3Client", "S3AsyncClient",
    "MessagingClient", "KafkaTemplate", "JmsTemplate",
)
_HTTP_CALL_RE = re.compile(
    r"\.(postForEntity|getForObject|getForEntity|exchange|putForEntity)\s*\("
)
_S3_CALL_RE = re.compile(
    r"(?i)(?:amazon)?s3.*\.(putObject|getObject|upload)"
)
_MSG_CALL_RE = re.compile(
    r"(?i)(messaging|kafka|jms).*\.(send|publish)\s*\("
)


def _evidence(path: Path, line: int, excerpt: str) -> Evidence:
    return Evidence(
        file=rel_to_repo(path, _REPO_ROOT),
        line=line,
        excerpt=excerpt[:120],
    )


def _line_has_external_io(line: str) -> bool:
    if any(t in line for t in _EXTERNAL_IO_TYPES):
        return True
    if _HTTP_CALL_RE.search(line):
        return True
    if _S3_CALL_RE.search(line):
        return True
    if _MSG_CALL_RE.search(line):
        return True
    return False


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
    """@Transactional methods should not do external IO.

    total = @Transactional methods, matched = those without HTTP/S3/messaging.
    """
    matched, total, ev = 0, 0, []
    for f, lines in _lines_of(files):
        i = 0
        n = len(lines)
        while i < n:
            line = lines[i]
            if "@TransactionalEventListener" in line:
                i += 1
                continue
            if "@Transactional" not in line:
                i += 1
                continue
            total += 1
            depth = line.count("{") - line.count("}")
            seen_body = "{" in line
            has_io = _line_has_external_io(line)
            ev_line, ev_ex = i + 1, line.strip()[:100]
            j = i + 1
            while j < n:
                body_line = lines[j]
                depth += body_line.count("{") - body_line.count("}")
                if "{" in body_line:
                    seen_body = True
                if _line_has_external_io(body_line):
                    has_io = True
                    ev_line, ev_ex = j + 1, body_line.strip()[:100]
                if seen_body and depth <= 0:
                    break
                if not seen_body and body_line.strip().endswith(";"):
                    break
                j += 1
            if not has_io:
                matched += 1
            elif len(ev) < 6:
                ev.append(_evidence(f, ev_line, ev_ex))
            i = j + 1 if j > i else i + 1
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
    global _REPO_ROOT
    root = Path(repo_root)
    _REPO_ROOT = root
    try:
        files = discover(root, "java")
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
            if should_emit(c):
                out.append(c)
        return out
    finally:
        _REPO_ROOT = None
