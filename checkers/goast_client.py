"""Shared bridge between Python detectors and the goast-facts extractor.

goast-facts (checkers/goast/) parses a Go file and emits structural JSON
facts. Detectors consume facts instead of regexing source text.

Binary resolution: $GOAST_BIN, else checkers/goast/goast-facts (built with
`go build` on first use).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

_GOAST_DIR = Path(__file__).resolve().parent / "goast"
_SRC = _GOAST_DIR / "main.go"
_DEFAULT_BIN = _GOAST_DIR / "goast-facts"


def _has_compile(root: Path) -> bool:
    return any((root / "pkg" / "tool").glob("*/compile"))


def _candidate_go_roots() -> list[Path]:
    roots: list[Path] = []
    if os.environ.get("GOROOT"):
        roots.append(Path(os.environ["GOROOT"]))
    if os.environ.get("GOAST_GO"):
        go = Path(os.environ["GOAST_GO"])
        roots.append(go.parent.parent if go.name == "go" else go)
    which = shutil.which("go")
    if which:
        roots.append(Path(which).resolve().parent.parent)
    roots.extend(
        [
            Path("/usr/local/go"),
            Path("/usr/lib/go"),
            Path("/tmp/opencode/go-root"),
        ]
    )
    seen: set[Path] = set()
    out: list[Path] = []
    for root in roots:
        resolved = root.resolve() if root.exists() else root
        if resolved in seen:
            continue
        seen.add(resolved)
        out.append(root)
    return out


def _go_build_cmd_env() -> tuple[list[str], dict[str, str]]:
    env = os.environ.copy()
    for root in _candidate_go_roots():
        go_bin = root / "bin" / "go"
        if not go_bin.is_file() or not _has_compile(root):
            continue
        env["GOROOT"] = str(root)
        env["PATH"] = str(root / "bin") + os.pathsep + env.get("PATH", "")
        return [str(go_bin)], env
    return ["go"], env


def _bin() -> Path:
    env_bin = os.environ.get("GOAST_BIN")
    if env_bin:
        path = Path(env_bin)
        if not path.is_file():
            raise FileNotFoundError(f"GOAST_BIN={path} is not a file")
        return path
    if (
        _DEFAULT_BIN.is_file()
        and _SRC.is_file()
        and _DEFAULT_BIN.stat().st_mtime >= _SRC.stat().st_mtime
    ):
        return _DEFAULT_BIN
    go_cmd, env = _go_build_cmd_env()
    proc = subprocess.run(
        [*go_cmd, "build", "-o", str(_DEFAULT_BIN), "main.go"],
        cwd=_GOAST_DIR,
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    if proc.returncode != 0 or not _DEFAULT_BIN.is_file():
        detail = (proc.stderr or proc.stdout or "").strip() or "go build failed"
        raise FileNotFoundError(
            "goast-facts build failed; install Go 1.21+ to run Go checkers. "
            + detail
        )
    return _DEFAULT_BIN


def is_skipped(filename: str, include_tests: bool = False) -> bool:
    """Test files, testdata and vendor trees are out of scope by default."""
    if include_tests:
        return False
    norm = filename.replace("\\", "/")
    name = norm.rsplit("/", 1)[-1]
    return (
        name.endswith("_test.go")
        or name.endswith("_tests.go")
        or name.startswith("test_")
        or "/testdata/" in norm or norm.startswith("testdata/")
        or "/vendor/" in norm or norm.startswith("vendor/")
        or "/e2e/" in norm or "/e2e/" in f"/{norm}/"
    )


def _has_package_clause(source: str) -> bool:
    """True if source already has a Go package clause after leading comments."""
    i, n = 0, len(source)
    while i < n:
        while i < n and source[i] in " \t\r\n":
            i += 1
        if i + 1 < n and source[i:i + 2] == "//":
            nl = source.find("\n", i)
            i = n if nl < 0 else nl + 1
            continue
        if i + 1 < n and source[i:i + 2] == "/*":
            end = source.find("*/", i + 2)
            if end < 0:
                return False
            i = end + 2
            continue
        return source.startswith("package", i)
    return False


def _shift_lines(obj, off: int):
    """Recursively subtract `off` from every line-number field."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, int) and k in ("line", "line_start", "line_end"):
                obj[k] = max(1, v - off)
            elif isinstance(v, list) and k == "lines" and all(
                    isinstance(i, int) for i in v):
                obj[k] = [max(1, i - off) for i in v]
            else:
                _shift_lines(v, off)
    elif isinstance(obj, list):
        for item in obj:
            _shift_lines(item, off)
    return obj


def load_facts(source: str, filename: str = "<inline>",
               include_tests: bool = False):
    """Run goast-facts over `source`, return parsed facts or None on skip/error."""
    if is_skipped(filename, include_tests):
        return None
    binary = _bin()
    # go/parser.ParseFile requires a package clause; inline snippets in
    # tests/prompts often omit it — wrap instead of silently skipping.
    # Do not wrap files that already have a package clause after a
    # leading comment block (Caddy copyright headers, chi examples).
    wrapped = False
    if not _has_package_clause(source):
        source = "package main\n\n" + source
        wrapped = True
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(suffix=".go", prefix="goast_facts_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(source)
        proc = subprocess.run(
            [str(binary), tmp], capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            return None  # parse error: FP-biased silence, stderr carries detail
        facts = json.loads(proc.stdout)
        if wrapped:
            # line numbers were reported against the wrapped file
            _shift_lines(facts, 2)
        return facts
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


# ---- shared fact helpers ----

_CRED_WORDS = {"secret", "token", "key", "password", "passwd",
               "credential", "apikey", "bearer"}
_SEG_RE = __import__("re").compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")


def ident_segments(name: str) -> list[str]:
    """Split an identifier into lowercase word segments.

    apiKey -> [api, key]; SECRETISH -> [secretish] (one upper run);
    mySecretiveNote -> [my, secretive, note]; X-Agent-Secret ->
    [x, agent, secret]. Whole-segment matching only: no bare substrings.
    """
    segs = []
    for part in name.replace("-", "_").split("_"):
        segs.extend(m.group(0).lower() for m in _SEG_RE.finditer(part))
    return segs


def is_credential_name(name: str) -> bool:
    """True iff one whole segment of the LAST dotted identifier is a credential word.

    Word-boundary match on the last identifier segment chain only, so
    r.Header.Get checks 'Get' (never a credential) rather than 'r'.
    """
    last = name.split(".")[-1]
    return bool(_CRED_WORDS.intersection(ident_segments(last)))


def quoted_strings(text: str) -> list[str]:
    """Contents of all double-quoted string literals in text."""
    out, i, n = [], 0, len(text)
    while i < n:
        if text[i] == '"':
            j = i + 1
            buf = []
            while j < n and text[j] != '"':
                if text[j] == "\\":
                    j += 1
                    if j >= n:
                        break
                buf.append(text[j])
                j += 1
            out.append("".join(buf))
            i = j + 1
        else:
            i += 1
    return out
