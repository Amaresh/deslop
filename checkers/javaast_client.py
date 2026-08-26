"""Shared bridge between Python detectors and the JavaAstFacts extractor.

JavaAstFacts (checkers/javaast/) parses a Java file with JavaParser
and emits structural JSON facts. Detectors consume facts instead of regexing
source text.

A long-lived ``--worker`` JVM is reused so OSS benches do not pay JVM
startup per file. Falls back to a one-shot process if the worker dies.
"""
from __future__ import annotations

import hashlib
import json
import os
import select
import subprocess
import tempfile
import threading
from collections import OrderedDict
from pathlib import Path

from common import is_skipped as _common_skipped

_DIR = Path(__file__).resolve().parent / "javaast"
_JAR = _DIR / "javaparser-core-3.26.4.jar"
_CLASS = _DIR / "JavaAstFacts.class"
_JAVA_SRC = _DIR / "JavaAstFacts.java"
_MAVEN_JAR = (
    "https://repo1.maven.org/maven2/com/github/javaparser/"
    "javaparser-core/3.26.4/javaparser-core-3.26.4.jar"
)
_JAR_SHA256 = (
    "3b2d6c4451b2c675d4f4be10784c5681049529d11f3c4e5936f08ba90dd45c27"
)

_CACHE_MAX = 32
_cache: OrderedDict[str, object] = OrderedDict()
_lock = threading.Lock()
_worker: subprocess.Popen | None = None


def is_skipped(filename: str, include_tests: bool = False) -> bool:
    return _common_skipped(filename, lang="java", include_tests=include_tests)


def _shift_lines(obj, off: int):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, int) and k in ("line", "line_start", "line_end"):
                obj[k] = max(1, v - off)
            else:
                _shift_lines(v, off)
    elif isinstance(obj, list):
        for item in obj:
            _shift_lines(item, off)
    return obj


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _ensure_jar() -> None:
    if _JAR.is_file() and _sha256(_JAR) == _JAR_SHA256:
        return
    if _JAR.is_file():
        _JAR.unlink()
    part = _JAR.with_suffix(".jar.part")
    subprocess.run(
        ["curl", "-fsSL", "-o", str(part), _MAVEN_JAR],
        check=True,
        timeout=120,
    )
    if _sha256(part) != _JAR_SHA256:
        part.unlink(missing_ok=True)
        raise RuntimeError(
            f"javaparser-core-3.26.4.jar sha256 mismatch (expected {_JAR_SHA256})"
        )
    part.replace(_JAR)


def _ensure_built() -> None:
    _ensure_jar()
    if _CLASS.is_file() and _CLASS.stat().st_mtime >= _JAVA_SRC.stat().st_mtime:
        return
    proc = subprocess.run(
        ["javac", "-cp", str(_JAR), "JavaAstFacts.java"],
        cwd=_DIR,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"javac JavaAstFacts failed: {proc.stderr}")


def _java_cmd(worker: bool) -> list[str]:
    cmd = ["java", "-Xmx192m", "-cp", f"{_JAR.name}:.", "JavaAstFacts"]
    if worker:
        cmd.append("--worker")
    return cmd


def _kill_worker() -> None:
    global _worker
    proc = _worker
    _worker = None
    if proc is None:
        return
    try:
        if proc.stdin:
            proc.stdin.write("QUIT\n")
            proc.stdin.flush()
    except OSError:
        pass
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _ensure_worker() -> subprocess.Popen:
    global _worker
    if _worker is not None and _worker.poll() is None:
        return _worker
    _kill_worker()
    _ensure_built()
    _worker = subprocess.Popen(
        _java_cmd(True),
        cwd=_DIR,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        bufsize=1,
    )
    return _worker


def _parse_file(path: str) -> dict | None:
    worker = _ensure_worker()
    try:
        assert worker.stdin is not None and worker.stdout is not None
        worker.stdin.write(path + "\n")
        worker.stdin.flush()
        ready, _, _ = select.select([worker.stdout], [], [], 30)
        if not ready:
            _kill_worker()
            return None
        line = worker.stdout.readline()
    except OSError:
        _kill_worker()
        return _parse_oneshot(path)
    if line == "" and worker.poll() is not None:
        _kill_worker()
        return _parse_oneshot(path)
    raw = line.strip()
    if not raw or raw == "null":
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _parse_oneshot(path: str) -> dict | None:
    _ensure_built()
    try:
        proc = subprocess.run(
            _java_cmd(False) + [path],
            cwd=_DIR,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


_TYPE_RE = __import__("re").compile(
    r"(?m)^\s*(?:(?:public|protected|private|abstract|final|sealed|"
    r"non-sealed|static)\s+)*(?:class|interface|enum|record|@interface)\b"
)


def _prepare(source: str) -> tuple[str, int]:
    stripped = source.lstrip()
    if stripped.startswith("package ") or stripped.startswith("import "):
        return source, 0
    if _TYPE_RE.search(source):
        return source, 0
    return "class __InlineSnippet {\n" + source + "\n}\n", 1


def load_facts(source: str, filename: str = "<inline>",
               include_tests: bool = False):
    """Run JavaAstFacts over `source`; return parsed facts or None on skip/error."""
    if is_skipped(filename, include_tests):
        return None
    key = filename + ":" + hashlib.sha256(
        source.encode("utf-8", "replace")).hexdigest()
    with _lock:
        if key in _cache:
            _cache.move_to_end(key)
            cached = _cache[key]
            return None if cached is _SENTINEL else cached

    prepared, shift = _prepare(source)
    tmp = None
    facts = None
    try:
        fd, tmp = tempfile.mkstemp(suffix=".java", prefix="javaast_facts_")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(prepared)
        with _lock:
            facts = _parse_file(tmp)
        if facts is not None and shift:
            _shift_lines(facts, shift)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        facts = None
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    with _lock:
        _cache[key] = _SENTINEL if facts is None else facts
        while len(_cache) > _CACHE_MAX:
            _cache.popitem(last=False)
    return facts


_SENTINEL = object()
