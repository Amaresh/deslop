"""Language-aware source discovery for deslop learn.

Respects the same skip discipline as the detectors: tests, vendored code,
generated output and build artifacts are never scanned.
"""
from __future__ import annotations

from pathlib import Path

_LANG_EXTS = {
    "go": ".go",
    "python": ".py",
    "ts": ".ts",
    "tsx": ".tsx",
    "java": ".java",
}

_SKIP_DIRS = {
    "vendor", "node_modules", "testdata", "dist", "build", "target",
    "__pycache__", ".venv", "venv", ".git", "migrations", "assets",
}

_SKIP_SUFFIXES = {
    "_test.go", "test_", "_test.py", ".test.ts", ".spec.ts",
    ".test.tsx", ".spec.tsx", "Test.java", "_test.ts",
}


def is_skipped(path: Path) -> bool:
    parts = set(path.parts)
    if parts & _SKIP_DIRS:
        return True
    name = path.name
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
    for suf in ("_test.go", "_test.py", ".test.ts", ".spec.ts",
                ".test.tsx", ".spec.tsx", "Test.java"):
        if name.endswith(suf):
            return True
    return False


def discover(repo_root: str | Path, lang: str,
             include_tests: bool = False) -> list[Path]:
    """All source files of `lang` in `repo_root`, sorted, skip-aware."""
    root = Path(repo_root)
    exts = {_LANG_EXTS[lang]}
    if lang == "ts":
        exts.add(".tsx")
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in exts:
            continue
        if not include_tests and is_skipped(path):
            continue
        files.append(path)
    return sorted(files)


def count_loc(files: list[Path]) -> int:
    total = 0
    for f in files:
        try:
            total += sum(
                1 for line in f.read_text(encoding="utf-8", errors="ignore")
                .splitlines() if line.strip())
        except OSError:
            continue
    return total
