"""Shared plumbing for portable AST checkers."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Finding:
    line: int          # 1-based
    message: str
    rule_id: str

    def __str__(self) -> str:
        return f"{self.rule_id}:{self.line}: {self.message}"


# Per-stack source globs for the benchmark harness.
LANG_GLOBS = {
    "go": ("*.go",),
    "python": ("*.py",),
    "ts": ("*.ts", "*.tsx", "*.js", "*.jsx"),
    "java": ("*.java",),
    "android": ("*.kt", "*.kts", "*.java"),
}

_SKIP_DIR_PARTS = {
    "vendor", "node_modules", "testdata", "dist", "build", "target",
    "__pycache__", ".venv", "venv", ".git", "migrations", "assets",
    ".next", "coverage", "generated", "androidTest", ".gradle", "e2e",
}

_TEST_SUFFIX = {
    "go": ("_test.go", "_tests.go"),
    "python": ("_test.py",),
    "ts": (".test.ts", ".spec.ts", ".test.tsx", ".spec.tsx",
           ".test.js", ".spec.js"),
    "java": ("Test.java", "Tests.java", "IT.java"),
    "android": ("Test.kt", "Tests.kt", "Test.java", "Tests.java",
                "ScreenshotTest.kt"),
}


def is_skipped(filename: str, lang: str = "go",
               include_tests: bool = False) -> bool:
    """Test files, testdata, vendor, and build trees are out of scope."""
    norm = filename.replace("\\", "/")
    parts = set(norm.split("/"))
    if parts & _SKIP_DIR_PARTS:
        return True
    for d in _SKIP_DIR_PARTS:
        if f"/{d}/" in f"/{norm}/":
            return True
    if include_tests:
        return False
    name = norm.rsplit("/", 1)[-1]
    if name.endswith(".gradle.kts") or name in {"build.gradle.kts", "settings.gradle.kts"}:
        return True
    if lang == "android":
        padded = f"/{norm}/"
        if "/src/test/" in padded or "/src/screenshotTest/" in padded:
            return True
    if lang == "java":
        padded = f"/{norm}/"
        if "/src/test/" in padded:
            return True
    if name.startswith("test_") and lang in ("python", "go"):
        return True
    for suf in _TEST_SUFFIX.get(lang, ()):
        if name.endswith(suf):
            return True
    return False
