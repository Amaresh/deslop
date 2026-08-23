"""Shared cross-language engineering rules adapter."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Iterable, Sequence
from pathlib import Path

from ..engine import AdapterContext, ExecutionMode, RulesAdapter
from ..models import FindingLocation, NormalizedFinding
from ..registry import RulesRegistry, create_default_registry

_SHARED_SECRET_RULE_ID = "shared.security.no-secrets-in-diff"
_SHARED_TEST_COVERAGE_RULE_ID = "shared.testing.changed-code-has-tests"
_SHARED_SKIP_RULE_ID = "shared.testing.no-unconditional-skip"
_SHARED_TEST_WITH_CHANGE_RATCHET_RULE_ID = "shared.testing.test-with-change-ratchet"
_APP_CHANGE_FILE_THRESHOLD = 3
_APP_CHANGE_LINE_THRESHOLD = 80
_SKIP_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".next",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "venv",
}
_PLACEHOLDER_TOKENS = {
    "changeme",
    "default",
    "development",
    "disabled",
    "enabled",
    "dev",
    "dummy",
    "example",
    "example-key",
    "example-token",
    "fake",
    "localhost",
    "local",
    "none",
    "null",
    "password",
    "placeholder",
    "prod",
    "production",
    "replace-me",
    "required",
    "sample",
    "secret",
    "staging",
    "test",
    "token",
    "undefined",
    "your-key-here",
    "your-secret-here",
    "your-token-here",
}
_PLACEHOLDER_PREFIXES = (
    "example-",
    "example_",
    "test-",
    "test_",
    "dummy-",
    "dummy_",
    "sample-",
    "sample_",
)
_PLACEHOLDER_WITH_NUMERIC_SUFFIX = re.compile(
    r"^(?:"
    + "|".join(re.escape(token) for token in sorted(_PLACEHOLDER_TOKENS, key=len, reverse=True))
    + r")(?:[-_.]?\d+)+$"
)
_INLINE_SECRET_PATTERNS = (
    (
        "github-token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),
    ),
    (
        "github-pat",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    ),
    (
        "openai-key",
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "google-api-key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ),
    (
        "private-key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ),
    (
        "basic-auth-url",
        re.compile(r"https?://[^/\s:@]+:[^/\s@]+@"),
    ),
)
_GENERIC_SECRET_ASSIGNMENT = re.compile(
    r"""
    (?P<name_quote>["'])?
    (?P<name>
        [A-Za-z0-9_.-]*
        (?:
            api[_-]?key|
            auth[_-]?token|
            access[_-]?token|
            refresh[_-]?token|
            client[_-]?secret|
            password|
            passwd|
            private[_-]?key|
            secret|
            token
        )
        [A-Za-z0-9_.-]*
    )
    (?P=name_quote)?
    \s*[:=]\s*
    (?:
        (?P<value_quote>["'])
        (?P<quoted_value>[^"'$\n][^"'\n]{7,})
        (?P=value_quote)
        |
        (?P<bare_value>[^\s"'`#;,]{8,})
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)
_GENERIC_SECRET_FILE_SUFFIXES = {
    ".conf",
    ".cfg",
    ".ini",
    ".json",
    ".properties",
    ".toml",
    ".yaml",
    ".yml",
}
_GENERIC_SECRET_FILENAMES = {
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".yarnrc",
}
_UI_SURFACE_ROOTS = ("src/components/", "src/screens/")
_UI_SURFACE_SUFFIXES = (".ts", ".tsx")
_TEST_FILE_SUFFIXES = (
    ".test.ts",
    ".test.tsx",
    ".test.js",
    ".test.jsx",
    ".spec.ts",
    ".spec.tsx",
    ".spec.js",
    ".spec.jsx",
)
_MIGRATION_PATH_MARKERS = (
    "/db/migration/",
    "/db/changelog/",
    "/migrations/",
    "/migration/",
    "/alembic/versions/",
    "/flyway/",
    "/liquibase/",
)
_MIGRATION_FILE_SUFFIXES = (".sql", ".xml")
_CONFIG_FILE_SUFFIXES = (
    ".conf",
    ".cfg",
    ".ini",
    ".json",
    ".properties",
    ".toml",
    ".yaml",
    ".yml",
)
_CONFIG_FILENAMES = {
    ".env",
    ".env.example",
    ".env.local",
    ".env.sample",
    ".engineering-rules.yaml",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "tsconfig.json",
    "jsconfig.json",
    "next.config.js",
    "next.config.mjs",
    "next.config.ts",
    "vite.config.ts",
    "vite.config.js",
    "vitest.config.ts",
    "jest.config.js",
    "jest.config.ts",
    "playwright.config.ts",
    "eslint.config.js",
    "eslint.config.mjs",
    "prettier.config.js",
    "tailwind.config.js",
    "tailwind.config.ts",
    "postcss.config.js",
    "postcss.config.mjs",
    "docker-compose.yml",
    "docker-compose.yaml",
}
_CONFIG_FILENAME_SUFFIXES = (
    ".config.js",
    ".config.mjs",
    ".config.ts",
    ".config.cjs",
)
_APP_SOURCE_SUFFIXES = (
    ".py",
    ".java",
    ".kt",
    ".go",
    ".rs",
    ".cs",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".vue",
    ".rb",
    ".php",
)
_SHARED_SKIP_TEST_FILE_SUFFIXES = (
    ".cy.ts",
    ".cy.tsx",
    ".cy.js",
    ".cy.jsx",
    ".e2e.ts",
    ".e2e.tsx",
    ".e2e.js",
    ".e2e.jsx",
)
_MAESTRO_FILE_SUFFIXES = (".yaml", ".yml")
_GENERIC_UI_TOKENS = {
    "component",
    "components",
    "flow",
    "maestro",
    "modal",
    "screen",
    "screens",
    "spec",
    "src",
    "test",
    "tests",
}
_COMMENT_LINE_PREFIXES = ("#", "//", "/*", "*", "*/")
_UNCONDITIONAL_SKIP_PATTERNS = (
    ("test.describe.skip", re.compile(r"\btest\.describe\.skip\s*\(")),
    ("describe.skip", re.compile(r"\b(?:describe|context|suite)\.skip\s*\(")),
    ("test.skip", re.compile(r"\btest\.skip\s*\(\s*(?:\)|true\b|['\"`])")),
    ("it.skip", re.compile(r"\bit\.skip\s*\(\s*(?:\)|true\b|['\"`])")),
    ("xdescribe", re.compile(r"\bxdescribe\s*\(")),
    ("xit", re.compile(r"\b(?:xit|xtest)(?:\.(?:only|skip))?\s*\(")),
    ("pytest.mark.skip", re.compile(r"@pytest\.mark\.skip(?:\s*\(|\b)")),
    ("pytest.skip", re.compile(r"\bpytest\.skip\s*\(")),
    ("@unittest.skip", re.compile(r"@(?:unittest\.)?skip\s*\(")),
    ("@Disabled", re.compile(r"@(?:org\.junit\.jupiter\.api\.)?Disabled\s*(?:\(|$)")),
    ("@Ignore", re.compile(r"@(?:org\.junit\.)?Ignore\s*(?:\(|$)")),
)
_DEPENDENCY_BOUNDARY_GENERAL_SUFFIXES = (
    "client",
    "gateway",
    "notifier",
    "publisher",
    "repository",
    "sender",
    "service",
    "store",
)
_DEPENDENCY_BOUNDARY_OUTBOUND_SUFFIXES = (
    "client",
    "connector",
    "gateway",
    "notifier",
    "publisher",
    "sender",
)
_DEPENDENCY_BOUNDARY_EXACT_NAMES = frozenset(
    {
        "AsyncClient",
        "AsyncGroq",
        "AsyncOpenAI",
        "ClientSession",
        "Groq",
        "HttpClient",
        "ObjectMapper",
        "OpenAI",
        "RestTemplate",
        "WebClient",
    }
)
_DEPENDENCY_BOUNDARY_EXCLUDED_NAMES = frozenset(
    {
        "ApiResponse",
        "FastAPI",
        "Form",
        "HTTPException",
        "JSONResponse",
        "PageRequest",
        "Path",
        "Query",
        "ResponseEntity",
    }
)


class SharedAdapter(RulesAdapter):
    adapter_key = "shared"

    def __init__(self, registry: RulesRegistry | None = None) -> None:
        self._registry = registry or create_default_registry()

    def run(
        self, *, context: AdapterContext, rule_ids: Sequence[str]
    ) -> tuple[NormalizedFinding, ...]:
        findings: list[NormalizedFinding] = []
        if _SHARED_SECRET_RULE_ID in rule_ids:
            findings.extend(self._run_secret_rule(context))
        if _SHARED_TEST_COVERAGE_RULE_ID in rule_ids:
            findings.extend(self._run_changed_code_has_tests_rule(context))
        if _SHARED_SKIP_RULE_ID in rule_ids:
            findings.extend(self._run_no_unconditional_skip_rule(context))
        if _SHARED_TEST_WITH_CHANGE_RATCHET_RULE_ID in rule_ids:
            findings.extend(self._run_test_with_change_ratchet_rule(context))
        return tuple(findings)

    def _run_secret_rule(self, context: AdapterContext) -> tuple[NormalizedFinding, ...]:
        rule = self._registry.get(_SHARED_SECRET_RULE_ID)
        if rule is None:
            return ()

        findings: list[NormalizedFinding] = []
        for relative_path in _candidate_files(context):
            absolute_path = context.repo_root / relative_path
            try:
                raw_bytes = absolute_path.read_bytes()
            except OSError:
                continue
            if b"\x00" in raw_bytes:
                continue
            text = raw_bytes.decode("utf-8", errors="ignore")
            if not text:
                continue
            allow_generic_assignment = _supports_generic_assignment_scan(relative_path)
            for line_number, line in enumerate(text.splitlines(), start=1):
                match_name = _match_secret_pattern(
                    line,
                    allow_generic_assignment=allow_generic_assignment,
                )
                if match_name is None:
                    continue
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            "Potential secret material appears in changed code; move the value "
                            "to environment/configuration before committing."
                        ),
                        location=FindingLocation(path=relative_path, line=line_number),
                        adapter_id=self.adapter_key,
                        metadata={"matched_pattern": match_name},
                    )
                )
        return tuple(findings)

    def _run_changed_code_has_tests_rule(
        self, context: AdapterContext
    ) -> tuple[NormalizedFinding, ...]:
        if context.mode is not ExecutionMode.DIFF:
            return ()
        if "react-native" not in context.repo_profile.frameworks:
            return ()
        if not _repo_supports_ui_coverage(context.repo_root):
            return ()

        rule = self._registry.get(_SHARED_TEST_COVERAGE_RULE_ID)
        if rule is None:
            return ()

        changed_paths = tuple(_normalize_context_paths(context))
        coverage_paths = tuple(path for path in changed_paths if _is_ui_coverage_path(path))

        findings: list[NormalizedFinding] = []
        for relative_path in changed_paths:
            if not _is_ui_surface_source_path(relative_path):
                continue
            absolute_path = context.repo_root / relative_path
            if not absolute_path.is_file():
                continue
            if _has_matching_ui_coverage(relative_path, coverage_paths):
                continue
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    message=(
                        "Changed React Native UI surface should include a matching "
                        "Maestro or test coverage update in the same diff."
                    ),
                    location=FindingLocation(
                        path=relative_path,
                        line=_first_nonempty_line_number(absolute_path),
                    ),
                    adapter_id=self.adapter_key,
                    metadata={"surface_kind": _ui_surface_kind(relative_path)},
                )
            )
        return tuple(findings)

    def _run_no_unconditional_skip_rule(
        self, context: AdapterContext
    ) -> tuple[NormalizedFinding, ...]:
        if context.mode is not ExecutionMode.DIFF:
            return ()

        rule = self._registry.get(_SHARED_SKIP_RULE_ID)
        if rule is None:
            return ()

        findings: list[NormalizedFinding] = []
        for relative_path in _normalize_context_paths(context):
            if not _is_skip_hygiene_test_path(relative_path):
                continue
            absolute_path = context.repo_root / relative_path
            if not absolute_path.is_file():
                continue
            try:
                raw_bytes = absolute_path.read_bytes()
            except OSError:
                continue
            if b"\x00" in raw_bytes:
                continue
            text = raw_bytes.decode("utf-8", errors="ignore")
            if not text:
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                matched_pattern = _match_unconditional_skip_marker(line)
                if matched_pattern is None:
                    continue
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        message=(
                            "Changed test files should not add unconditional skip or disable "
                            "markers; restore the coverage path before merging."
                        ),
                        location=FindingLocation(path=relative_path, line=line_number),
                        adapter_id=self.adapter_key,
                        metadata={"matched_pattern": matched_pattern},
                    )
                )
        return tuple(findings)

    def _run_test_with_change_ratchet_rule(
        self, context: AdapterContext
    ) -> tuple[NormalizedFinding, ...]:
        if context.mode is not ExecutionMode.DIFF:
            return ()

        rule = self._registry.get(_SHARED_TEST_WITH_CHANGE_RATCHET_RULE_ID)
        if rule is None:
            return ()

        changed_paths = tuple(_normalize_context_paths(context))
        app_paths = tuple(path for path in changed_paths if _is_app_change_path(path))
        test_paths = tuple(path for path in changed_paths if _is_test_path(path))
        if not app_paths or test_paths:
            return ()

        app_line_count = _count_changed_app_lines(context.repo_root, app_paths)
        if (
            len(app_paths) <= _APP_CHANGE_FILE_THRESHOLD
            and app_line_count <= _APP_CHANGE_LINE_THRESHOLD
        ):
            return ()

        anchor_path = app_paths[0]
        anchor_file = context.repo_root / anchor_path
        return (
            NormalizedFinding.from_rule(
                rule,
                message=(
                    "Substantial application changes should include test updates in the same diff; "
                    f"this diff changes {len(app_paths)} app file(s) (~{app_line_count} lines) "
                    "without any test file updates."
                ),
                location=FindingLocation(
                    path=anchor_path,
                    line=_first_nonempty_line_number(anchor_file),
                ),
                adapter_id=self.adapter_key,
                metadata={
                    "app_file_count": str(len(app_paths)),
                    "app_line_count": str(app_line_count),
                    "test_file_count": "0",
                },
            ),
        )


def _candidate_files(context: AdapterContext) -> Iterable[str]:
    if context.mode is ExecutionMode.DIFF:
        seen: set[str] = set()
        for path in context.target_files:
            normalized = Path(path).as_posix()
            if normalized in seen or _should_skip_path(normalized):
                continue
            absolute_path = context.repo_root / normalized
            if not absolute_path.is_file():
                continue
            seen.add(normalized)
            yield normalized
        return

    for path in sorted(context.repo_root.rglob("*")):
        if not path.is_file():
            continue
        relative_path = path.relative_to(context.repo_root).as_posix()
        if _should_skip_path(relative_path):
            continue
        yield relative_path


def _should_skip_path(relative_path: str) -> bool:
    path = Path(relative_path)
    return any(part in _SKIP_DIRS for part in path.parts)


def _supports_generic_assignment_scan(relative_path: str) -> bool:
    path = Path(relative_path)
    name = path.name.lower()
    if name == ".env" or name.startswith(".env."):
        return True
    if name in _GENERIC_SECRET_FILENAMES:
        return True
    return any(suffix.lower() in _GENERIC_SECRET_FILE_SUFFIXES for suffix in path.suffixes)


def _match_secret_pattern(line: str, *, allow_generic_assignment: bool) -> str | None:
    for match_name, pattern in _INLINE_SECRET_PATTERNS:
        if pattern.search(line):
            return match_name

    if not allow_generic_assignment:
        return None
    assignment_match = _GENERIC_SECRET_ASSIGNMENT.search(line)
    if assignment_match is None:
        return None
    value = assignment_match.group("quoted_value") or assignment_match.group("bare_value") or ""
    name = assignment_match.group("name")
    if _looks_like_placeholder(value):
        return None
    if not _looks_like_secret_assignment(name, value):
        return None
    return f"assignment:{name.lower()}"


def _looks_like_placeholder(value: str) -> bool:
    normalized = value.strip().strip("\"'").lower()
    if not normalized:
        return True
    if normalized in _PLACEHOLDER_TOKENS:
        return True
    if normalized.startswith(_PLACEHOLDER_PREFIXES):
        return True
    if _PLACEHOLDER_WITH_NUMERIC_SUFFIX.fullmatch(normalized):
        return True
    if normalized.startswith(("${", "process.env.", "env.")):
        return True
    if normalized.endswith(("_example", "_sample", "_test")):
        return True
    return bool(normalized.endswith(("_here", "-here")))


def _looks_like_secret_assignment(name: str, value: str) -> bool:
    normalized_name = name.lower().replace("-", "_").replace(".", "_")
    normalized_value = value.strip().strip("\"'")
    lowered_value = normalized_value.lower()
    if not normalized_value:
        return False
    if " " in normalized_value:
        return False
    if normalized_value.startswith(("/", "./", "../")):
        return False
    if "://" in normalized_value:
        return False
    if any(symbol in normalized_value for symbol in ("(", ")", "{", "}", "[", "]")):
        return False
    if any(token in lowered_value for token in ("process.env.", "import.meta.env.", "os.environ[")):
        return False
    if any(token in normalized_value for token in (" + ", " && ", " || ", " ? ")):
        return False
    if _is_strong_secret_name(normalized_name):
        return True
    return _looks_like_tokenish_value(normalized_value)


def _is_strong_secret_name(name: str) -> bool:
    tokens = tuple(token for token in re.split(r"[_\-.]+", name) if token)
    if not tokens:
        return False
    if tokens[-1] in {"password", "passwd"}:
        return True
    if tokens[-2:] in {
        ("api", "key"),
        ("auth", "token"),
        ("access", "token"),
        ("refresh", "token"),
        ("client", "secret"),
        ("private", "key"),
        ("secret", "key"),
    }:
        return True
    return tokens[-1] == "key" and "secret" in tokens


def _looks_like_tokenish_value(value: str) -> bool:
    if len(value) < 12:
        return False
    if value.count(".") >= 2 and all(len(part) >= 8 for part in value.split(".")[:3]):
        return True
    if re.fullmatch(r"[A-Fa-f0-9]{16,}", value):
        return True
    has_letter = any(character.isalpha() for character in value)
    has_digit = any(character.isdigit() for character in value)
    if has_letter and has_digit:
        return True
    if any(separator in value for separator in ("+", "=")) and len(value) >= 20:
        return True
    return (
        not value.istitle()
        and any(character.isupper() for character in value)
        and any(character.islower() for character in value)
    )


_SENSITIVE_TOKEN_NORMALIZATIONS = {
    "cookies": "cookie",
    "emails": "email",
    "keys": "key",
    "passwords": "password",
    "phones": "phone",
    "registrations": "registration",
    "secrets": "secret",
    "tokens": "token",
}
_MASKING_NAME_TOKENS = frozenset(
    {
        "hash",
        "hashed",
        "mask",
        "masked",
        "partial",
        "prefix",
        "preview",
        "redact",
        "redacted",
        "suffix",
        "truncate",
        "truncated",
    }
)
_CREDENTIAL_TRAILING_TOKENS = frozenset({"cookie", "jwt", "secret", "token"})
_PII_TRAILING_TOKENS = frozenset({"email", "phone", "plate", "registration"})
_PII_TOKEN_PAIRS = frozenset(
    {
        ("email", "address"),
        ("license", "plate"),
        ("phone", "number"),
        ("registration", "number"),
    }
)


def _is_masked_sensitive_logging_name(name: str) -> bool:
    tokens = tuple(
        _normalized_sensitive_logging_token(token) for token in _split_identifier_tokens(name)
    )
    return any(token in _MASKING_NAME_TOKENS for token in tokens)


def _sensitive_logging_name_kind(name: str) -> str | None:
    tokens = tuple(
        _normalized_sensitive_logging_token(token) for token in _split_identifier_tokens(name)
    )
    if not tokens or any(token in _MASKING_NAME_TOKENS for token in tokens):
        return None
    normalized_name = "_".join(tokens)
    if _is_strong_secret_name(normalized_name):
        return "credential"
    if tokens[-1] in _CREDENTIAL_TRAILING_TOKENS or "authorization" in tokens:
        return "credential"
    if tokens[-1] in _PII_TRAILING_TOKENS:
        return "pii"
    if len(tokens) >= 2 and tokens[-2:] in _PII_TOKEN_PAIRS:
        return "pii"
    return None


def _normalized_sensitive_logging_token(token: str) -> str:
    return _SENSITIVE_TOKEN_NORMALIZATIONS.get(token, token)


def _normalize_context_paths(context: AdapterContext) -> Iterable[str]:
    seen: set[str] = set()
    for path in context.target_files or context.changed_files:
        normalized = Path(path).as_posix()
        if normalized in seen or _should_skip_path(normalized):
            continue
        seen.add(normalized)
        yield normalized


def _iter_repo_files(repo_root: Path) -> Iterable[str]:
    for current_root, dirs, files in os.walk(repo_root):
        dirs[:] = [directory for directory in dirs if directory not in _SKIP_DIRS]
        root_path = Path(current_root)
        for filename in files:
            relative_path = (root_path / filename).relative_to(repo_root).as_posix()
            if _should_skip_path(relative_path):
                continue
            yield relative_path


def _repo_supports_ui_coverage(repo_root: Path) -> bool:
    return any(_is_ui_coverage_path(relative_path) for relative_path in _iter_repo_files(repo_root))


def _has_matching_ui_coverage(surface_path: str, coverage_paths: Sequence[str]) -> bool:
    surface_tokens = _coverage_tokens(surface_path)
    if surface_tokens:
        return any(surface_tokens.intersection(_coverage_tokens(path)) for path in coverage_paths)

    surface_parent = Path(surface_path).parent.as_posix()
    surface_stem_tokens = frozenset(_split_identifier_tokens(Path(surface_path).stem))
    return any(
        surface_stem_tokens.intersection(_split_identifier_tokens(Path(path).stem))
        and _paths_share_subtree(surface_parent, Path(path).parent.as_posix())
        for path in coverage_paths
    )


def _coverage_tokens(relative_path: str) -> frozenset[str]:
    tokens: set[str] = set()
    for part in Path(relative_path).parts:
        tokens.update(_split_identifier_tokens(Path(part).stem))
    return frozenset(token for token in tokens if token not in _GENERIC_UI_TOKENS)


def _split_identifier_tokens(value: str) -> tuple[str, ...]:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    normalized = re.sub(r"[^A-Za-z0-9]+", " ", normalized)
    return tuple(token.lower() for token in normalized.split() if token)


def _is_skip_hygiene_test_path(relative_path: str) -> bool:
    normalized = Path(relative_path).as_posix()
    if _is_test_path(normalized) or normalized.endswith(_SHARED_SKIP_TEST_FILE_SUFFIXES):
        return True

    path = Path(normalized)
    name = path.name.lower()
    suffix = path.suffix.lower()
    parts = {part.lower() for part in path.parts}

    if suffix == ".py":
        return "tests" in parts or name.startswith("test_") or name.endswith("_test.py")
    if suffix in {".java", ".kt"}:
        lowered = normalized.lower()
        return (
            "/src/test/" in f"/{lowered}"
            or "/src/androidtest/" in f"/{lowered}"
            or name.endswith(
                ("test.java", "tests.java", "it.java", "test.kt", "tests.kt", "it.kt")
            )
        )
    return False


def _match_unconditional_skip_marker(line: str) -> str | None:
    if _looks_like_comment_line(line):
        return None
    for matched_pattern, pattern in _UNCONDITIONAL_SKIP_PATTERNS:
        if pattern.search(line):
            return matched_pattern
    return None


def _looks_like_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return not stripped or stripped.startswith(_COMMENT_LINE_PREFIXES)


def _looks_like_dependency_boundary_name(name: str, *, outbound_only: bool = False) -> bool:
    tail = name.rsplit(".", 1)[-1].strip()
    tail = tail.lstrip("&*").strip()
    if tail.lower().startswith("new "):
        tail = tail[4:].strip()
    if not tail or tail in _DEPENDENCY_BOUNDARY_EXCLUDED_NAMES:
        return False
    if tail in _DEPENDENCY_BOUNDARY_EXACT_NAMES:
        return True
    normalized_tail = tail.lower()
    suffixes = (
        _DEPENDENCY_BOUNDARY_OUTBOUND_SUFFIXES
        if outbound_only
        else _DEPENDENCY_BOUNDARY_GENERAL_SUFFIXES
    )
    return any(normalized_tail.endswith(suffix) for suffix in suffixes)


def _paths_share_subtree(first: str, second: str) -> bool:
    return first == second or first.startswith(f"{second}/") or second.startswith(f"{first}/")


def _is_ui_surface_source_path(relative_path: str) -> bool:
    normalized = Path(relative_path).as_posix()
    if _is_test_path(normalized):
        return False
    if not normalized.endswith(_UI_SURFACE_SUFFIXES):
        return False
    return normalized.startswith(_UI_SURFACE_ROOTS)


def _is_ui_coverage_path(relative_path: str) -> bool:
    normalized = Path(relative_path).as_posix()
    return (
        normalized.startswith("maestro/") and normalized.endswith(_MAESTRO_FILE_SUFFIXES)
    ) or _is_test_path(normalized)


def _is_test_path(relative_path: str) -> bool:
    normalized = Path(relative_path).as_posix()
    if normalized.endswith(_TEST_FILE_SUFFIXES) or "__tests__" in Path(normalized).parts:
        return True
    path_parts = Path(normalized).parts
    if "test" in path_parts or "tests" in path_parts:
        if normalized.endswith((".java", ".kt", ".scala", ".groovy")):
            return True
    return False


def _is_migration_path(relative_path: str) -> bool:
    normalized = Path(relative_path).as_posix().lower()
    if not normalized.endswith(_MIGRATION_FILE_SUFFIXES):
        return False
    return any(marker in normalized for marker in _MIGRATION_PATH_MARKERS) or re.search(
        r"/v\d+__[^/]+\.(sql|xml)$",
        normalized,
    )


def _is_config_path(relative_path: str) -> bool:
    path = Path(relative_path)
    normalized = path.as_posix()
    name = path.name.lower()
    if name in _CONFIG_FILENAMES or name.startswith(".env."):
        return True
    if name.endswith(_CONFIG_FILENAME_SUFFIXES):
        return True
    if any(suffix.lower() in _CONFIG_FILE_SUFFIXES for suffix in path.suffixes):
        if any(
            part.lower() in {"config", "configs", "settings", ".github", ".vscode", "deploy"}
            for part in path.parts
        ):
            return True
        if name in {
            "settings.json",
            "launch.json",
            "tasks.json",
            "components.json",
            "biome.json",
            "renovate.json",
        }:
            return True
    return normalized.endswith(
        (
            "/docker-compose.yml",
            "/docker-compose.yaml",
            "/.engineering-rules.yaml",
        )
    )


def _is_app_change_path(relative_path: str) -> bool:
    normalized = Path(relative_path).as_posix()
    if _should_skip_path(normalized):
        return False
    if _is_test_path(normalized) or _is_migration_path(normalized) or _is_config_path(normalized):
        return False
    return normalized.endswith(_APP_SOURCE_SUFFIXES)


def _count_changed_app_lines(repo_root: Path, app_paths: Sequence[str]) -> int:
    git_line_count = _git_numstat_line_count(repo_root, app_paths)
    if git_line_count is not None:
        return git_line_count

    total_lines = 0
    for relative_path in app_paths:
        absolute_path = repo_root / relative_path
        if not absolute_path.is_file():
            continue
        try:
            text = absolute_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        total_lines += sum(1 for line in text.splitlines() if line.strip())
    return total_lines


def _git_numstat_line_count(repo_root: Path, relative_paths: Sequence[str]) -> int | None:
    if not relative_paths:
        return 0
    command = [
        "git",
        "-C",
        str(repo_root),
        "--no-pager",
        "diff",
        "--numstat",
        "HEAD",
        "--",
        *relative_paths,
    ]
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None

    total = 0
    saw_numstat = False
    for line in completed.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t", 2)
        if len(parts) < 2:
            continue
        added, deleted = parts[0], parts[1]
        if added == "-" or deleted == "-":
            continue
        saw_numstat = True
        total += int(added) + int(deleted)

    if saw_numstat:
        return total

    untracked_total = 0
    for relative_path in relative_paths:
        try:
            untracked = subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo_root),
                    "--no-pager",
                    "ls-files",
                    "--others",
                    "--exclude-standard",
                    "--",
                    relative_path,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError):
            return None
        if not untracked.stdout.strip():
            continue
        absolute_path = repo_root / relative_path
        if not absolute_path.is_file():
            continue
        try:
            text = absolute_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        untracked_total += sum(1 for line in text.splitlines() if line.strip())

    return untracked_total if untracked_total else None


def _ui_surface_kind(relative_path: str) -> str:
    normalized = Path(relative_path).as_posix()
    if normalized.startswith("src/screens/"):
        return "screen"
    if normalized.startswith("src/components/"):
        return "component"
    return "ui-surface"


def _first_nonempty_line_number(path: Path) -> int:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 1
    for line_number, line in enumerate(text.splitlines(), start=1):
        if line.strip():
            return line_number
    return 1


DEFAULT_ADAPTERS = (SharedAdapter(),)
