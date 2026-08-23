"""Repo detection primitives for the engineering rules framework."""

from __future__ import annotations

import json
import tomllib
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .models import DetectionSource, RepoDetectionOverride, RepoLanguage, RepoProfile

_OVERRIDE_FILENAMES = (".engineering-rules.yaml", ".engineering-rules.yml")
_LANGUAGE_PRIORITY = (
    RepoLanguage.PYTHON,
    RepoLanguage.JAVA,
    RepoLanguage.GO,
    RepoLanguage.TYPESCRIPT,
    RepoLanguage.JAVASCRIPT,
    RepoLanguage.UNITY,
    RepoLanguage.ANDROID,
)
_ESLINT_CONFIG_CANDIDATES = (
    "eslint.config.js",
    "eslint.config.cjs",
    "eslint.config.mjs",
    ".eslintrc",
    ".eslintrc.js",
    ".eslintrc.cjs",
    ".eslintrc.json",
    ".eslintrc.yml",
    ".eslintrc.yaml",
)
_ANDROID_GRADLE_CANDIDATES = (
    "android/build.gradle",
    "android/build.gradle.kts",
    "android/settings.gradle",
    "android/settings.gradle.kts",
    "app/build.gradle",
    "app/build.gradle.kts",
)
_GRADLE_SCAN_CANDIDATES = (
    *_ANDROID_GRADLE_CANDIDATES,
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
)
_DETEKT_CONFIG_CANDIDATES = ("detekt.yml", ".detekt.yml", "config/detekt/detekt.yml")
_JAVA_GRADLE_CANDIDATES = (
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
)
_GO_MARKER_CANDIDATES = ("go.mod",)
_GOLANGCI_CONFIG_CANDIDATES = (
    ".golangci.yml",
    ".golangci.yaml",
    ".golangci.toml",
    ".golangci.json",
)
_UNITY_VERSION_MARKER = "ProjectSettings/ProjectVersion.txt"
_UNITY_MANIFEST_MARKER = "Packages/manifest.json"


class RepoDetectionOverrideError(ValueError):
    """Raised when a repo override file cannot be parsed or validated."""

    def __init__(
        self, override_path: Path, reason: str, details: Sequence[str] | None = None
    ) -> None:
        self.override_path = override_path
        self.reason = reason
        self.details = tuple(details or ())
        super().__init__(self._render_message())

    def _render_message(self) -> str:
        message = f"Invalid engineering rules override file at {self.override_path}: {self.reason}."
        if self.details:
            rendered_details = "; ".join(self.details)
            message = f"{message} Details: {rendered_details}"
        return message


def _unique_strings(*groups: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    values: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for raw in group:
            candidate = raw.strip()
            if not candidate or candidate in seen:
                continue
            values.append(candidate)
            seen.add(candidate)
    return tuple(values)


def _ordered_languages(languages: set[RepoLanguage]) -> tuple[RepoLanguage, ...]:
    return tuple(language for language in _LANGUAGE_PRIORITY if language in languages)


def _load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    return data if isinstance(data, dict) else {}


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    return data if isinstance(data, dict) else {}


def _load_unity_dependencies(path: Path) -> dict[str, str]:
    manifest = _load_json(path)
    dependencies = manifest.get("dependencies", {})
    if not isinstance(dependencies, dict):
        return {}
    return {str(name): str(version) for name, version in dependencies.items()}


def _file_contains_token(path: Path, token: str) -> bool:
    try:
        return token in path.read_text(encoding="utf-8")
    except OSError:
        return False


def load_repo_override(
    repo_root: Path, override_path: Path | None = None
) -> tuple[RepoDetectionOverride | None, Path | None]:
    candidate_paths = (
        [override_path]
        if override_path is not None
        else [repo_root / filename for filename in _OVERRIDE_FILENAMES]
    )
    for candidate in candidate_paths:
        if candidate is None:
            continue
        if not candidate.exists():
            if override_path is not None:
                raise RepoDetectionOverrideError(candidate, "file does not exist")
            continue
        try:
            with candidate.open(encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
        except OSError as exc:
            raise RepoDetectionOverrideError(candidate, "unable to read file", [str(exc)]) from exc
        except yaml.YAMLError as exc:
            raise RepoDetectionOverrideError(candidate, "invalid YAML", [str(exc)]) from exc
        try:
            return RepoDetectionOverride.model_validate(data), candidate
        except ValidationError as exc:
            raise RepoDetectionOverrideError(
                candidate,
                "schema validation failed",
                [_format_validation_error(error) for error in exc.errors(include_url=False)],
            ) from exc
    return None, None


def _format_validation_error(error: dict[str, Any]) -> str:
    location = ".".join(str(part) for part in error.get("loc", ())) or "<root>"
    message = str(error.get("msg", "invalid value"))
    return f"{location}: {message}"


def detect_repo_profile(
    repo_root: Path,
    override_path: Path | None = None,
    *,
    override_data: RepoDetectionOverride | None = None,
    resolved_override_path: Path | None = None,
) -> RepoProfile:
    """Detect repo languages and tooling from marker files."""

    root = repo_root.resolve()
    languages: set[RepoLanguage] = set()
    tooling: list[str] = []
    frameworks: list[str] = []
    markers: list[str] = []

    pyproject_path = root / "pyproject.toml"
    if pyproject_path.exists():
        markers.append("pyproject.toml")
        languages.add(RepoLanguage.PYTHON)
        tooling.extend(["python", "pyproject"])
        pyproject = _load_toml(pyproject_path)
        tool_section = pyproject.get("tool", {})
        if isinstance(tool_section, dict):
            if "pytest" in tool_section or "pytest.ini_options" in tool_section.get("pytest", {}):
                tooling.append("pytest")
            if "ruff" in tool_section:
                tooling.append("ruff")
            if "mypy" in tool_section:
                tooling.append("mypy")

    if any(
        (root / candidate).exists() for candidate in ("requirements.txt", "setup.py", "tox.ini")
    ):
        languages.add(RepoLanguage.PYTHON)
        tooling.append("python")
    if (root / "pytest.ini").exists():
        tooling.append("pytest")
        markers.append("pytest.ini")
    if any((root / candidate).exists() for candidate in ("ruff.toml", ".ruff.toml")):
        tooling.append("ruff")
    if any((root / candidate).exists() for candidate in ("mypy.ini", ".mypy.ini")):
        tooling.append("mypy")

    unity_version_path = root / _UNITY_VERSION_MARKER
    unity_manifest_path = root / _UNITY_MANIFEST_MARKER
    has_unity_surface = unity_version_path.exists() and (root / "Assets").is_dir()
    if has_unity_surface:
        languages.add(RepoLanguage.UNITY)
        tooling.extend(["unity", "csharp"])
        frameworks.append("unity")
        markers.append(_UNITY_VERSION_MARKER)
        if unity_manifest_path.exists():
            markers.append(_UNITY_MANIFEST_MARKER)
            tooling.append("upm")
            unity_dependencies = _load_unity_dependencies(unity_manifest_path)
            if "com.unity.test-framework" in unity_dependencies:
                tooling.append("unity-test-framework")
        if any(root.glob("Assets/**/*.asmdef")) or any(root.glob("Packages/**/*.asmdef")):
            tooling.append("asmdef")

    package_json_path = root / "package.json"
    package_json: dict[str, Any] = {}
    raw_scripts: dict[str, Any] = {}
    if package_json_path.exists():
        markers.append("package.json")
        languages.add(RepoLanguage.JAVASCRIPT)
        tooling.extend(["node", "package-json"])
        package_json = _load_json(package_json_path)
        package_json_scripts = package_json.get("scripts", {})
        if isinstance(package_json_scripts, dict):
            raw_scripts = package_json_scripts
        dependencies: dict[str, str] = {}
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            values = package_json.get(key, {})
            if isinstance(values, dict):
                dependencies.update({str(name): str(version) for name, version in values.items()})
        if "typescript" in dependencies:
            languages.add(RepoLanguage.TYPESCRIPT)
            tooling.append("typescript")
        if "react-native" in dependencies:
            frameworks.append("react-native")
        if "react" in dependencies:
            frameworks.append("react")

    if any((root / candidate).exists() for candidate in ("tsconfig.json", "tsconfig.base.json")):
        markers.append("tsconfig.json")
        languages.add(RepoLanguage.TYPESCRIPT)
        tooling.append("typescript")

    if (root / "pnpm-lock.yaml").exists():
        tooling.append("pnpm")
    elif (root / "yarn.lock").exists():
        tooling.append("yarn")
    elif (root / "package-lock.json").exists():
        tooling.append("npm")
    elif any((root / candidate).exists() for candidate in ("bun.lockb", "bun.lock")):
        tooling.append("bun")
    elif package_json_path.exists():
        tooling.append("npm")

    package_dependency_names = {
        str(name)
        for section in ("dependencies", "devDependencies", "peerDependencies")
        for name in (
            package_json.get(section, {}).keys()
            if isinstance(package_json.get(section, {}), dict)
            else ()
        )
    }
    if any(
        (root / candidate).exists() for candidate in _ESLINT_CONFIG_CANDIDATES
    ) or (
        isinstance(package_json.get("eslintConfig"), dict)
        or "eslint" in package_dependency_names
        or "eslint" in str(raw_scripts.get("lint", ""))
    ):
        tooling.append("eslint")
    if any(
        (root / candidate).exists()
        for candidate in ("jest.config.js", "jest.config.cjs", "jest.config.ts", "jest.setup.ts")
    ) or (
        package_json
        and (
            "jest" in package_json
            or bool(
                package_dependency_names.intersection(
                    {
                        "jest",
                        "ts-jest",
                        "@testing-library/react-native",
                        "@testing-library/jest-native",
                    }
                )
            )
        )
    ):
        tooling.append("jest")

    android_markers = tuple(root / candidate for candidate in _ANDROID_GRADLE_CANDIDATES)
    has_android_gradle_surface = any(candidate.exists() for candidate in android_markers)
    if has_android_gradle_surface:
        languages.add(RepoLanguage.ANDROID)
        tooling.extend(["gradle", "android-gradle", "android-lint"])
        if (root / "android" / "build.gradle").exists() or (
            root / "android" / "build.gradle.kts"
        ).exists():
            markers.append("android/build.gradle")
    if has_android_gradle_surface and (
        any((root / candidate).exists() for candidate in _DETEKT_CONFIG_CANDIDATES)
        or any(
            _file_contains_token(root / candidate, "detekt")
            for candidate in _GRADLE_SCAN_CANDIDATES
            if (root / candidate).is_file()
        )
    ):
        tooling.append("detekt")
    if (root / "react-native.config.js").exists():
        frameworks.append("react-native")
    if (root / "maestro").is_dir():
        tooling.append("maestro")

    pom_path = root / "pom.xml"
    if pom_path.exists():
        markers.append("pom.xml")
        languages.add(RepoLanguage.JAVA)
        tooling.extend(["java", "maven"])
        if _file_contains_token(pom_path, "checkstyle"):
            tooling.append("checkstyle")
        if _file_contains_token(pom_path, "spotbugs"):
            tooling.append("spotbugs")
        if _file_contains_token(pom_path, "<pmd"):
            tooling.append("pmd")
        if any(
            _file_contains_token(pom_path, token)
            for token in ("springframework", "spring-boot")
        ):
            frameworks.append("spring")
        if any(
            _file_contains_token(pom_path, token)
            for token in ("data-jpa", "hibernate", "jakarta.persistence")
        ):
            frameworks.append("jpa")

    java_gradle_markers = tuple(root / candidate for candidate in _JAVA_GRADLE_CANDIDATES)
    has_java_gradle_surface = (
        not has_android_gradle_surface
        and any(candidate.exists() for candidate in java_gradle_markers)
    )
    if has_java_gradle_surface:
        languages.add(RepoLanguage.JAVA)
        tooling.extend(["java", "gradle"])
        if (root / "build.gradle").exists() or (root / "build.gradle.kts").exists():
            markers.append("build.gradle")
        for gradle_name in ("build.gradle", "build.gradle.kts"):
            gradle_path = root / gradle_name
            if not gradle_path.is_file():
                continue
            if any(
                _file_contains_token(gradle_path, token)
                for token in ("org.springframework", "spring-boot")
            ):
                frameworks.append("spring")
            if any(
                _file_contains_token(gradle_path, token)
                for token in ("data-jpa", "hibernate")
            ):
                frameworks.append("jpa")

    go_mod_path = root / "go.mod"
    if go_mod_path.exists():
        markers.append("go.mod")
        languages.add(RepoLanguage.GO)
        tooling.extend(["go", "go-mod"])
        if any((root / candidate).exists() for candidate in _GOLANGCI_CONFIG_CANDIDATES):
            tooling.append("golangci-lint")
        if (root / "go.sum").exists():
            markers.append("go.sum")

    ci_provider = "github-actions" if (root / ".github" / "workflows").exists() else None
    if ci_provider is not None:
        tooling.append("github-actions")

    override = override_data
    if override is None and resolved_override_path is None:
        override, resolved_override_path = load_repo_override(root, override_path)
    detected_languages = _ordered_languages(languages)
    primary_language = detected_languages[0] if detected_languages else None
    detection_source = DetectionSource.AUTO

    if override is not None:
        if override.languages is not None:
            detected_languages = tuple(override.languages)
        if override.primary_language is not None:
            primary_language = override.primary_language
        elif primary_language is None and detected_languages:
            primary_language = detected_languages[0]
        if override.tooling is not None:
            tooling = list(override.tooling)
        if override.frameworks is not None:
            frameworks = list(override.frameworks)
        detection_source = DetectionSource.OVERRIDE

    return RepoProfile(
        repo_root=str(root),
        repo_name=root.name,
        detected_languages=detected_languages,
        primary_language=primary_language,
        tooling=_unique_strings(tooling),
        frameworks=_unique_strings(frameworks),
        marker_files=_unique_strings(markers),
        ci_provider=ci_provider,
        detection_source=detection_source,
        override_path=str(resolved_override_path) if resolved_override_path is not None else None,
    )
