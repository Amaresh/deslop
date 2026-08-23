"""Tool-backed Android adapters that wrap repo-native Android tooling."""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ..engine import AdapterContext, AdapterUnavailableError, RulesAdapter
from ..models import FindingLocation, FindingSeverity, NormalizedFinding, RepoLanguage
from ..registry import create_default_registry

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ..registry import RuleDefinition

_ANDROID_LINT_RULE_ID = "android.foundation.android-lint-clean"
_DETEKT_RULE_ID = "android.foundation.detekt-clean"
_ANDROID_LINT_REPORT_PATTERNS = ("**/build/reports/lint-results*.xml",)
_DETEKT_REPORT_PATTERNS = ("**/build/reports/detekt/*.xml",)
_TOOL_UNAVAILABLE_SNIPPETS = (
    "task 'detekt' not found",
    "task 'lint' not found",
    "task 'lintdebug' not found",
    "plugin [id: 'io.gitlab.arturbosch.detekt'] was not found",
    "no gradle wrapper found",
)


@dataclass(frozen=True)
class _GradleWrapper:
    command_prefix: tuple[str, ...]


class AndroidLintAdapter(RulesAdapter):
    adapter_key = "android-lint"

    def __init__(self) -> None:
        self._rule = create_default_registry().get(_ANDROID_LINT_RULE_ID)
        if self._rule is None:
            raise ValueError(f"Missing rule definition for {_ANDROID_LINT_RULE_ID}")

    def run(
        self, *, context: AdapterContext, rule_ids: Sequence[str]
    ) -> Sequence[NormalizedFinding]:
        if _ANDROID_LINT_RULE_ID not in rule_ids:
            return ()

        wrapper = _resolve_gradle_wrapper(context.repo_root, context.repo_profile.tooling)
        if "android-lint" not in context.repo_profile.tooling and (
            "android-gradle" not in context.repo_profile.tooling
        ):
            raise AdapterUnavailableError("No Android Lint surface detected for this repo.")

        _clear_report_files(context.repo_root, _ANDROID_LINT_REPORT_PATTERNS)
        completed = _run_tool_command(context.repo_root, (*wrapper.command_prefix, "lint"))
        findings = _parse_android_lint_findings(
            rule=self._rule,
            repo_root=context.repo_root,
            target_files=context.target_files,
            mode=context.mode,
            report_paths=_find_report_paths(context.repo_root, _ANDROID_LINT_REPORT_PATTERNS),
        )
        if completed.returncode != 0 and not findings:
            _raise_tool_command_error("Android Lint", completed)
        return findings


class AndroidDetektAdapter(RulesAdapter):
    adapter_key = "android-detekt"

    def __init__(self) -> None:
        self._rule = create_default_registry().get(_DETEKT_RULE_ID)
        if self._rule is None:
            raise ValueError(f"Missing rule definition for {_DETEKT_RULE_ID}")

    def run(
        self, *, context: AdapterContext, rule_ids: Sequence[str]
    ) -> Sequence[NormalizedFinding]:
        if _DETEKT_RULE_ID not in rule_ids:
            return ()

        wrapper = _resolve_gradle_wrapper(context.repo_root, context.repo_profile.tooling)
        if "detekt" not in context.repo_profile.tooling:
            raise AdapterUnavailableError("No Detekt surface detected for this repo.")

        _clear_report_files(context.repo_root, _DETEKT_REPORT_PATTERNS)
        completed = _run_tool_command(context.repo_root, (*wrapper.command_prefix, "detekt"))
        findings = _parse_detekt_findings(
            rule=self._rule,
            repo_root=context.repo_root,
            target_files=context.target_files,
            mode=context.mode,
            report_paths=_find_report_paths(context.repo_root, _DETEKT_REPORT_PATTERNS),
        )
        if completed.returncode != 0 and not findings:
            _raise_tool_command_error("Detekt", completed)
        return findings


def _resolve_gradle_wrapper(repo_root: Path, tooling: Sequence[str]) -> _GradleWrapper:
    if "gradle" not in tooling and "android-gradle" not in tooling:
        raise AdapterUnavailableError("No Gradle surface detected for Android tooling rules.")

    gradlew = repo_root / "gradlew"
    if gradlew.is_file():
        return _GradleWrapper(command_prefix=("bash", str(gradlew), "--console=plain"))

    gradlew_bat = repo_root / "gradlew.bat"
    if gradlew_bat.is_file():
        return _GradleWrapper(command_prefix=(str(gradlew_bat), "--console=plain"))

    raise AdapterUnavailableError("No Gradle wrapper found for Android tooling rules.")


def _run_tool_command(repo_root: Path, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )


def _clear_report_files(repo_root: Path, patterns: Sequence[str]) -> None:
    for report_path in _find_report_paths(repo_root, patterns):
        report_path.unlink(missing_ok=True)


def _find_report_paths(repo_root: Path, patterns: Sequence[str]) -> tuple[Path, ...]:
    paths: list[Path] = []
    seen: set[Path] = set()
    for pattern in patterns:
        for candidate in sorted(repo_root.glob(pattern)):
            if not candidate.is_file():
                continue
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            paths.append(candidate)
    return tuple(paths)


def _parse_android_lint_findings(
    *,
    rule: RuleDefinition,
    repo_root: Path,
    target_files: Sequence[str],
    mode: object,
    report_paths: Sequence[Path],
) -> tuple[NormalizedFinding, ...]:
    findings: list[NormalizedFinding] = []
    seen: set[tuple[str, int, int, str]] = set()

    for report_path in report_paths:
        try:
            root = ET.parse(report_path).getroot()
        except ET.ParseError:
            continue

        for issue in root.findall(".//issue"):
            issue_id = issue.get("id", "<unknown>")
            severity_name = issue.get("severity", "warning")
            rendered_message = issue.get("message") or issue.get("summary") or issue_id
            location = issue.find("location")
            if location is None:
                continue
            raw_path = location.get("file")
            if not raw_path:
                continue
            normalized_path = _normalize_tool_path(repo_root, raw_path)
            if normalized_path is None or not _should_include_path(
                mode, target_files, normalized_path
            ):
                continue
            line = _parse_report_position(location.get("line"))
            column = _parse_report_position(location.get("column"))
            if line is None or column is None:
                continue
            key = (normalized_path, line, column, issue_id)
            if key in seen:
                continue
            seen.add(key)
            severity = _android_lint_severity(severity_name)
            is_blocking = severity is FindingSeverity.ERROR
            findings.append(
                NormalizedFinding.from_rule(
                    rule,
                    adapter_id="android-lint",
                    language=RepoLanguage.ANDROID,
                    location=FindingLocation(path=normalized_path, line=line, column=column),
                    message=f"[{issue_id}] {rendered_message}",
                    severity=severity,
                    blocking=is_blocking,
                    advisory=not is_blocking,
                    metadata={
                        "tool": "android-lint",
                        "lint_issue_id": issue_id,
                        "source_severity": severity_name.lower(),
                    },
                )
            )

    return tuple(findings)


def _parse_detekt_findings(
    *,
    rule: RuleDefinition,
    repo_root: Path,
    target_files: Sequence[str],
    mode: object,
    report_paths: Sequence[Path],
) -> tuple[NormalizedFinding, ...]:
    findings: list[NormalizedFinding] = []
    seen: set[tuple[str, int, int, str]] = set()

    for report_path in report_paths:
        try:
            root = ET.parse(report_path).getroot()
        except ET.ParseError:
            continue

        for file_node in root.findall(".//file"):
            file_name = file_node.get("name")
            if not file_name:
                continue
            normalized_path = _normalize_tool_path(repo_root, file_name)
            if normalized_path is None or not _should_include_path(
                mode, target_files, normalized_path
            ):
                continue
            for error in file_node.findall("error"):
                source = str(error.get("source", "")).strip()
                rendered_source = _render_detekt_source(source) if source else "<unknown>"
                rendered_message = error.get("message", "").strip() or source
                if not rendered_message:
                    continue
                line = _parse_report_position(error.get("line"))
                column = _parse_report_position(error.get("column"))
                if line is None or column is None:
                    continue
                key = (normalized_path, line, column, source)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    NormalizedFinding.from_rule(
                        rule,
                        adapter_id="android-detekt",
                        language=RepoLanguage.ANDROID,
                        location=FindingLocation(path=normalized_path, line=line, column=column),
                        message=f"[{rendered_source}] {rendered_message}",
                        severity=_detekt_severity(error.get("severity", "warning")),
                        blocking=False,
                        advisory=True,
                        metadata={
                            "tool": "detekt",
                            "detekt_rule_id": rendered_source,
                            "source_severity": str(error.get("severity", "warning")).lower(),
                        },
                    )
                )

    return tuple(findings)


def _android_lint_severity(raw_severity: str) -> FindingSeverity:
    normalized = raw_severity.strip().lower()
    if normalized in {"error", "fatal"}:
        return FindingSeverity.ERROR
    if normalized in {"informational", "information", "info"}:
        return FindingSeverity.INFO
    return FindingSeverity.WARNING


def _detekt_severity(raw_severity: str) -> FindingSeverity:
    normalized = raw_severity.strip().lower()
    if normalized == "error":
        return FindingSeverity.ERROR
    if normalized in {"info", "informational", "information"}:
        return FindingSeverity.INFO
    return FindingSeverity.WARNING


def _render_detekt_source(source: str) -> str:
    return source.rsplit(".", maxsplit=1)[-1] if "." in source else source


def _parse_report_position(raw_value: str | None) -> int | None:
    try:
        return int(raw_value or 1)
    except (TypeError, ValueError):
        return None


def _normalize_tool_path(repo_root: Path, raw_path: str) -> str | None:
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = repo_root / candidate

    try:
        return candidate.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        normalized_root = repo_root.resolve().as_posix()
        normalized_raw = raw_path.replace("\\", "/")
        if normalized_raw.startswith(normalized_root.rstrip("/") + "/"):
            return normalized_raw[len(normalized_root.rstrip("/")) + 1 :]
    return None


def _should_include_path(mode: object, target_files: Sequence[str], path: str) -> bool:
    if getattr(mode, "value", mode) == "inventory":
        return True
    normalized_targets = {target.replace("\\", "/") for target in target_files}
    return path.replace("\\", "/") in normalized_targets


def _combine_tool_output(completed: subprocess.CompletedProcess[str]) -> str:
    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    if stdout and stderr:
        return f"{stdout}\n{stderr}"
    return stdout or stderr


def _raise_tool_command_error(
    tool_name: str, completed: subprocess.CompletedProcess[str]
) -> None:
    rendered_output = _combine_tool_output(completed).strip()
    message = rendered_output.splitlines()[0] if rendered_output else f"{tool_name} command failed."
    lowered = rendered_output.lower()
    if any(snippet in lowered for snippet in _TOOL_UNAVAILABLE_SNIPPETS):
        raise AdapterUnavailableError(f"{tool_name} unavailable: {message}")
    raise RuntimeError(f"{tool_name} command failed: {message}")


DEFAULT_ADAPTERS = (AndroidLintAdapter(), AndroidDetektAdapter())
