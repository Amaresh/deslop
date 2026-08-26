"""Shared bridge between Python detectors and the tsast-facts extractor.

tsast-facts (checkers/tsast/facts.mjs) parses a TS/JS file with the
TypeScript compiler API and emits structural JSON facts. Detectors
consume facts instead of regexing source text.

Binary resolution: $TSAST_NODE (default `node`) plus
$TSAST_FACTS or checkers/tsast/facts.mjs relative to this module.
`npm install` runs once if `node_modules/typescript` is missing.

A persistent `node facts.mjs --stdio` worker is reused across calls in this
process (bench runs three detectors per file). Falls back to a one-shot
subprocess if the worker is unavailable. Facts are cached by source hash so
sibling detectors do not reparse.
"""
from __future__ import annotations

import atexit
import hashlib
import json
import os
import subprocess
import tempfile
import threading
from pathlib import Path

from common import is_skipped as _common_skipped

# common.is_skipped does not drop /test/ or /__tests__/ trees (only *.test.ts).
# Production linters should not scan harnesses, benches, or playgrounds.
_EXTRA_SKIP_DIRS = {
    "test", "tests", "__tests__", "benchmarks", "e2e", "playground",
    "integration",
}

_FACTS = Path(os.environ.get("TSAST_FACTS")
              or Path(__file__).resolve().parent / "tsast" / "facts.mjs")
_NODE = os.environ.get("TSAST_NODE") or "node"

_KNOWN_EXT = (
    ".tsx", ".jsx", ".mts", ".cts", ".mjs", ".cjs", ".ts", ".js",
)

_CACHE: dict[tuple[str, str], dict | None] = {}
_CACHE_MAX = 16
_WORKER_LOCK = threading.Lock()
_WORKER: subprocess.Popen | None = None
_TSAST_DIR = Path(__file__).resolve().parent / "tsast"


def _ensure_typescript() -> None:
    if (_TSAST_DIR / "node_modules" / "typescript").is_dir():
        return
    proc = subprocess.run(
        ["npm", "install"],
        cwd=_TSAST_DIR,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise FileNotFoundError(
            "npm install in checkers/tsast failed; install Node + npm "
            "to run TypeScript checkers. " + detail
        )


def _suffix(filename: str) -> str:
    name = filename.replace("\\", "/").rsplit("/", 1)[-1]
    for ext in _KNOWN_EXT:
        if name.endswith(ext):
            return ext
    return ".ts"


def _kill_worker() -> None:
    global _WORKER
    proc = _WORKER
    _WORKER = None
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.stdin.close()
    except OSError:
        pass
    try:
        proc.kill()
    except OSError:
        pass


atexit.register(_kill_worker)


def _ensure_worker() -> subprocess.Popen:
    global _WORKER
    if _WORKER is not None and _WORKER.poll() is None:
        return _WORKER
    if not _FACTS.is_file():
        raise FileNotFoundError(
            f"tsast facts.mjs not found at {_FACTS} (set TSAST_FACTS)")
    _ensure_typescript()
    try:
        _WORKER = subprocess.Popen(
            [_NODE, str(_FACTS), "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        raise FileNotFoundError(
            f"node not found (set TSAST_NODE); install Node to run tsast") from None
    return _WORKER


def _extract_via_worker(tmp: str, timeout: float = 30) -> dict | None:
    with _WORKER_LOCK:
        proc = _ensure_worker()
        try:
            proc.stdin.write(tmp + "\n")
            proc.stdin.flush()
        except OSError:
            _kill_worker()
            return None
        holder: list[str | None] = [None]

        def _read() -> None:
            try:
                holder[0] = proc.stdout.readline()
            except OSError:
                holder[0] = None

        reader = threading.Thread(target=_read, daemon=True)
        reader.start()
        reader.join(timeout)
        if reader.is_alive():
            _kill_worker()
            return None
        line = holder[0]
        if not line:
            _kill_worker()
            return None
        line = line.strip()
        if not line or line == "null":
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None


def _extract_oneshot(tmp: str) -> dict | None:
    try:
        proc = subprocess.run(
            [_NODE, str(_FACTS), tmp],
            capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"node not found (set TSAST_NODE); install Node to run tsast") from None
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def is_out_of_scope(filename: str, include_tests: bool = False) -> bool:
    """common.is_skipped plus TS harness/playground directory names."""
    if _common_skipped(filename, lang="ts", include_tests=include_tests):
        return True
    if include_tests:
        return False
    parts = set(filename.replace("\\", "/").split("/"))
    return bool(parts & _EXTRA_SKIP_DIRS)


def load_facts(source: str, filename: str = "<inline>",
               include_tests: bool = False):
    """Run tsast-facts over `source`, return parsed facts or None on skip/error."""
    if is_out_of_scope(filename, include_tests=include_tests):
        return None
    if not _FACTS.is_file():
        raise FileNotFoundError(
            f"tsast facts.mjs not found at {_FACTS} (set TSAST_FACTS)")
    key = (hashlib.sha256(source.encode("utf-8", "replace")).hexdigest(),
           _suffix(filename))
    if key in _CACHE:
        return _CACHE[key]
    tmp = None
    facts = None
    try:
        fd, tmp = tempfile.mkstemp(suffix=_suffix(filename), prefix="tsast_facts_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(source)
        facts = _extract_via_worker(tmp)
        if facts is None and (_WORKER is None or _WORKER.poll() is not None):
            facts = _extract_oneshot(tmp)
    except OSError:
        facts = None
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    if len(_CACHE) >= _CACHE_MAX:
        _CACHE.clear()
    _CACHE[key] = facts
    return facts
