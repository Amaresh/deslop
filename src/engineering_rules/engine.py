"""Diff-first rules engine core and adapter wiring."""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date
from fnmatch import fnmatchcase
from functools import cache
from pathlib import Path

from .adapters import load_default_adapters
from .detection import detect_repo_profile, load_repo_override
from .framework_compat import (
    compute_coverage_summary,
    enrich_rule_frameworks,
    filter_rules_for_repo,
)
from .models import (
    AdapterExecutionResult,
    AdapterStatus,
    DebtSummary,
    ExecutionMode,
    FindingDebtStatus,
    NormalizedFinding,
    RepoLanguage,
    RepoProfile,
    RulesBaseline,
    RulesRunResult,
    RuleWaiver,
    RunSource,
)
from .registry import RulesRegistry, create_default_registry

logger = logging.getLogger(__name__)

_EXTENSION_LANGUAGE_MAP = {
    ".py": RepoLanguage.PYTHON,
    ".go": RepoLanguage.GO,
    ".java": RepoLanguage.JAVA,
    ".js": RepoLanguage.JAVASCRIPT,
    ".jsx": RepoLanguage.JAVASCRIPT,
    ".mjs": RepoLanguage.JAVASCRIPT,
    ".cjs": RepoLanguage.JAVASCRIPT,
    ".ts": RepoLanguage.TYPESCRIPT,
    ".tsx": RepoLanguage.TYPESCRIPT,
    ".kt": RepoLanguage.ANDROID,
    ".kts": RepoLanguage.ANDROID,
    ".gradle": RepoLanguage.ANDROID,
}
_UNITY_PATH_SUFFIXES = {
    ".asset",
    ".asmdef",
    ".controller",
    ".cs",
    ".mat",
    ".prefab",
    ".shader",
    ".unity",
}


@dataclass(frozen=True)
class AdapterContext:
    repo_root: Path
    repo_profile: RepoProfile
    changed_files: tuple[str, ...]
    target_files: tuple[str, ...]
    mode: ExecutionMode
    source: RunSource


@dataclass(frozen=True)
class ExecutionPlan:
    mode: ExecutionMode
    changed_files: tuple[str, ...]
    target_files: tuple[str, ...]
    warnings: tuple[str, ...]


class RulesAdapter:
    """Protocol-like base class for future language adapters."""

    adapter_key: str

    def run(
        self, *, context: AdapterContext, rule_ids: Sequence[str]
    ) -> Sequence[NormalizedFinding]:
        raise NotImplementedError


class AdapterUnavailableError(RuntimeError):
    """Raised when an adapter cannot run because the repo lacks the required tool surface."""


def classify_path_language(
    path: str, *, repo_profile: RepoProfile | None = None
) -> RepoLanguage | None:
    """Infer the repo language for a changed path."""

    normalized = path.replace("\\", "/").lower()
    suffix = Path(normalized).suffix
    if repo_profile is not None and RepoLanguage.UNITY in repo_profile.detected_languages:
        if normalized in {"packages/manifest.json", "projectsettings/projectversion.txt"}:
            return RepoLanguage.UNITY
        if normalized.startswith(("assets/", "packages/", "projectsettings/")) and (
            suffix in _UNITY_PATH_SUFFIXES
        ):
            return RepoLanguage.UNITY
    if normalized.endswith("androidmanifest.xml"):
        return RepoLanguage.ANDROID
    if normalized.startswith("android/") and suffix in {".xml", ".gradle", ".kts", ".kt", ".java"}:
        return RepoLanguage.ANDROID
    if (normalized.startswith("app/src/") or "/app/src/" in normalized) and suffix in {
        ".kt",
        ".kts",
        ".java",
    }:
        return RepoLanguage.ANDROID
    if (
        suffix == ".java"
        and repo_profile is not None
        and RepoLanguage.ANDROID in repo_profile.detected_languages
        and RepoLanguage.JAVA not in repo_profile.detected_languages
        and "/src/" in normalized
    ):
        return RepoLanguage.ANDROID
    return _EXTENSION_LANGUAGE_MAP.get(suffix)


def _normalize_changed_path(repo_root: Path, path: str) -> str:
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve().relative_to(repo_root.resolve())
        except ValueError:
            candidate = Path(candidate.name)
    return candidate.as_posix()


def _run_git_command(repo_root: Path, args: Sequence[str]) -> tuple[str, ...]:
    completed = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    return tuple(lines)


def _unique_ordered(values: Iterable[str]) -> tuple[str, ...]:
    ordered: list[str] = []
    seen: set[str] = set()
    for value in values:
        candidate = value.strip()
        if not candidate or candidate in seen:
            continue
        ordered.append(candidate)
        seen.add(candidate)
    return tuple(ordered)


def _target_languages_for_mode(
    *, mode: ExecutionMode, changed_files: Sequence[str], repo_profile: RepoProfile
) -> set[RepoLanguage]:
    if mode is ExecutionMode.INVENTORY:
        if repo_profile.detected_languages:
            return set(repo_profile.detected_languages)
        if repo_profile.primary_language is not None:
            return {repo_profile.primary_language}
        return set()

    target_languages = {
        language
        for path in changed_files
        if (language := classify_path_language(path, repo_profile=repo_profile)) is not None
    }
    if not target_languages and repo_profile.primary_language is not None:
        target_languages.add(repo_profile.primary_language)
    return target_languages


def _finding_fingerprint(finding: NormalizedFinding) -> str:
    location_payload = None
    if finding.location is not None:
        location_payload = {
            "path": finding.location.path,
            "line": finding.location.line,
            "end_line": finding.location.end_line,
            "column": finding.location.column,
            "end_column": finding.location.end_column,
        }

    payload = {
        "adapter_id": finding.adapter_id,
        "category": finding.category.value,
        "language": finding.language.value if finding.language else None,
        "location": location_payload,
        "message": finding.message,
        "metadata": finding.metadata,
        "rule_id": finding.rule_id,
        "title": finding.title,
    }
    rendered = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _normalize_finding_location(repo_root: Path, finding: NormalizedFinding) -> NormalizedFinding:
    if finding.location is None:
        return finding

    normalized_path = _normalize_changed_path(repo_root, finding.location.path)
    if normalized_path == finding.location.path:
        return finding

    normalized_finding = finding.model_copy(
        update={
            "location": finding.location.model_copy(
                update={
                    "path": normalized_path,
                }
            )
        }
    )
    return normalized_finding.model_copy(update={"fingerprint": None})


def _apply_baseline(
    findings: Sequence[NormalizedFinding], baseline: RulesBaseline | None
) -> tuple[tuple[NormalizedFinding, ...], DebtSummary]:
    baseline_fingerprints = (
        {record.fingerprint for record in baseline.records} if baseline else set()
    )

    annotated: list[NormalizedFinding] = []
    new_count = 0
    existing_count = 0
    unknown_count = 0

    for finding in findings:
        fingerprint = finding.fingerprint or _finding_fingerprint(finding)
        if baseline is None:
            debt_status = FindingDebtStatus.UNKNOWN
            unknown_count += 1
        elif fingerprint in baseline_fingerprints:
            debt_status = FindingDebtStatus.EXISTING
            existing_count += 1
        else:
            debt_status = FindingDebtStatus.NEW
            new_count += 1
        annotated.append(
            finding.model_copy(update={"fingerprint": fingerprint, "debt_status": debt_status})
        )

    return (
        tuple(annotated),
        DebtSummary(
            compared_findings=len(annotated),
            new_count=new_count,
            existing_count=existing_count,
            unknown_count=unknown_count,
        ),
    )


def _split_glob_parts(value: str) -> tuple[str, ...]:
    return tuple(
        part for part in value.replace("\\", "/").split("/") if part and part != "."
    )


def _path_matches_glob(path: str, pattern: str) -> bool:
    path_parts = _split_glob_parts(path)
    pattern_parts = _split_glob_parts(pattern)

    @cache
    def _match(path_index: int, pattern_index: int) -> bool:
        if pattern_index == len(pattern_parts):
            return path_index == len(path_parts)

        part = pattern_parts[pattern_index]
        if part == "**":
            while (
                pattern_index + 1 < len(pattern_parts)
                and pattern_parts[pattern_index + 1] == "**"
            ):
                pattern_index += 1
            if pattern_index == len(pattern_parts) - 1:
                return True
            return _match(path_index, pattern_index + 1) or (
                path_index < len(path_parts) and _match(path_index + 1, pattern_index)
            )

        return (
            path_index < len(path_parts)
            and fnmatchcase(path_parts[path_index], part)
            and _match(path_index + 1, pattern_index + 1)
        )

    return _match(0, 0)


def _waiver_matches_finding(waiver: RuleWaiver, finding: NormalizedFinding) -> bool:
    if waiver.rule_id != finding.rule_id:
        return False
    if waiver.paths:
        if finding.location is None:
            return False
        normalized_path = finding.location.path.replace("\\", "/")
        if not any(_path_matches_glob(normalized_path, pattern) for pattern in waiver.paths):
            return False
    return not waiver.fingerprints or (
        finding.fingerprint is not None and finding.fingerprint in waiver.fingerprints
    )


def _apply_waivers(
    findings: Sequence[NormalizedFinding], waivers: Sequence[RuleWaiver]
) -> tuple[tuple[NormalizedFinding, ...], tuple[str, ...]]:
    if not waivers:
        return tuple(findings), ()

    today = date.today()
    warnings: list[str] = []
    warned_keys: set[tuple[str, tuple[str, ...], tuple[str, ...], str | None]] = set()
    annotated: list[NormalizedFinding] = []

    for finding in findings:
        matched_waiver: RuleWaiver | None = None
        for waiver in waivers:
            if waiver.expires_on is not None and waiver.expires_on < today:
                warning_key = (
                    waiver.rule_id,
                    waiver.paths,
                    waiver.fingerprints,
                    waiver.expires_on.isoformat(),
                )
                if warning_key not in warned_keys:
                    warned_keys.add(warning_key)
                    warnings.append(
                        "Expired waiver ignored for "
                        f"{waiver.rule_id} (expires_on={waiver.expires_on.isoformat()})."
                    )
                continue
            if _waiver_matches_finding(waiver, finding):
                matched_waiver = waiver
                break

        if matched_waiver is None:
            annotated.append(finding)
            continue

        annotated.append(
            finding.model_copy(
                update={
                    "waived": True,
                    "waiver_reason": matched_waiver.reason,
                    "waiver_expires_on": matched_waiver.expires_on,
                }
            )
        )

    return tuple(annotated), tuple(warnings)


class RulesEngine:
    """Diff-first orchestration layer for normalized rule execution."""

    def __init__(
        self,
        registry: RulesRegistry | None = None,
        adapters: Iterable[RulesAdapter] | None = None,
    ):
        self._registry = registry or create_default_registry()
        resolved_adapters = load_default_adapters() if adapters is None else tuple(adapters)
        self._adapters = {adapter.adapter_key: adapter for adapter in resolved_adapters}

    def resolve_execution_plan(
        self,
        *,
        repo_root: Path,
        mode: ExecutionMode,
        source: RunSource,
        changed_files: Sequence[str] | None = None,
        base_ref: str | None = None,
    ) -> ExecutionPlan:
        """Resolve execution scope from explicit input or git metadata."""

        if mode is ExecutionMode.INVENTORY:
            return ExecutionPlan(
                mode=mode,
                changed_files=(),
                target_files=(),
                warnings=(),
            )

        if changed_files:
            normalized = (_normalize_changed_path(repo_root, path) for path in changed_files)
            resolved = _unique_ordered(normalized)
            return ExecutionPlan(
                mode=mode,
                changed_files=resolved,
                target_files=resolved,
                warnings=(),
            )

        try:
            if source is RunSource.CI and base_ref:
                diff_files = _run_git_command(
                    repo_root,
                    ["diff", "--name-only", "--diff-filter=ACMR", f"{base_ref}...HEAD"],
                )
                resolved = _unique_ordered(diff_files)
                return ExecutionPlan(
                    mode=mode,
                    changed_files=resolved,
                    target_files=resolved,
                    warnings=(),
                )

            if source is RunSource.CI and not base_ref:
                tracked = _run_git_command(
                    repo_root,
                    ["diff", "--name-only", "--diff-filter=ACMR", "HEAD~1", "HEAD"],
                )
                resolved = _unique_ordered(tracked)
                return ExecutionPlan(
                    mode=mode,
                    changed_files=resolved,
                    target_files=resolved,
                    warnings=(
                        "No base ref supplied; CI mode fell back to the last commit diff "
                        "(HEAD~1..HEAD).",
                    ),
                )

            tracked = _run_git_command(
                repo_root, ["diff", "--name-only", "--diff-filter=ACMR", "HEAD"]
            )
            untracked = _run_git_command(repo_root, ["ls-files", "--others", "--exclude-standard"])
            resolved = _unique_ordered((*tracked, *untracked))
            return ExecutionPlan(
                mode=mode,
                changed_files=resolved,
                target_files=resolved,
                warnings=(),
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            return ExecutionPlan(
                mode=mode,
                changed_files=(),
                target_files=(),
                warnings=(f"Unable to resolve changed files from git: {exc}",),
            )

    def run(
        self,
        *,
        repo_root: Path,
        mode: ExecutionMode = ExecutionMode.DIFF,
        source: RunSource,
        changed_files: Sequence[str] | None = None,
        override_path: Path | None = None,
        base_ref: str | None = None,
        selected_rule_ids: Sequence[str] | None = None,
        baseline: RulesBaseline | None = None,
    ) -> RulesRunResult:
        """Run the rules engine with diff or inventory execution."""

        resolved_root = repo_root.resolve()
        override, resolved_override_path = load_repo_override(resolved_root, override_path)
        repo_profile = detect_repo_profile(
            resolved_root,
            override_path=override_path,
            override_data=override,
            resolved_override_path=resolved_override_path,
        )
        execution_plan = self.resolve_execution_plan(
            repo_root=resolved_root,
            mode=mode,
            source=source,
            changed_files=changed_files,
            base_ref=base_ref,
        )

        target_languages = _target_languages_for_mode(
            mode=mode,
            changed_files=execution_plan.changed_files,
            repo_profile=repo_profile,
        )

        selected_rules = self._registry.list_rules(languages=target_languages)
        if selected_rule_ids:
            requested_ids = set(selected_rule_ids)
            selected_rules = [rule for rule in selected_rules if rule.rule_id in requested_ids]

        enriched_rules = tuple(enrich_rule_frameworks(rule) for rule in selected_rules)
        coverage = compute_coverage_summary(
            selected_rules=enriched_rules,
            repo_profile=repo_profile,
            findings=(),
        )
        applicable_rules = filter_rules_for_repo(enriched_rules, repo_profile)

        rules_by_adapter: dict[str, list[str]] = defaultdict(list)
        for rule in applicable_rules:
            rules_by_adapter[rule.adapter_key].append(rule.rule_id)

        context = AdapterContext(
            repo_root=resolved_root,
            repo_profile=repo_profile,
            changed_files=execution_plan.changed_files,
            target_files=execution_plan.target_files,
            mode=mode,
            source=source,
        )

        findings: list[NormalizedFinding] = []
        adapter_results: list[AdapterExecutionResult] = []
        warnings = execution_plan.warnings

        for adapter_key, rule_ids in sorted(rules_by_adapter.items()):
            adapter = self._adapters.get(adapter_key)
            if adapter is None:
                adapter_results.append(
                    AdapterExecutionResult(
                        adapter_key=adapter_key,
                        status=AdapterStatus.UNAVAILABLE,
                        rule_ids=tuple(rule_ids),
                        message="No adapter registered yet.",
                    )
                )
                continue

            try:
                adapter_findings = tuple(
                    _normalize_finding_location(resolved_root, finding)
                    for finding in adapter.run(context=context, rule_ids=tuple(rule_ids))
                )
            except AdapterUnavailableError as exc:
                adapter_results.append(
                    AdapterExecutionResult(
                        adapter_key=adapter_key,
                        status=AdapterStatus.UNAVAILABLE,
                        rule_ids=tuple(rule_ids),
                        message=str(exc),
                    )
                )
                warnings = (*warnings, f"Adapter {adapter_key} unavailable: {exc}")
                continue
            except Exception as exc:
                logger.warning("Rules adapter %s failed: %s", adapter_key, exc)
                warnings = (*warnings, f"Adapter {adapter_key} failed: {exc}")
                adapter_results.append(
                    AdapterExecutionResult(
                        adapter_key=adapter_key,
                        status=AdapterStatus.FAILED,
                        rule_ids=tuple(rule_ids),
                        message=str(exc),
                    )
                )
                continue

            findings.extend(adapter_findings)
            adapter_results.append(
                AdapterExecutionResult(
                    adapter_key=adapter_key,
                    status=AdapterStatus.SUCCESS,
                    rule_ids=tuple(rule_ids),
                    finding_count=len(adapter_findings),
                )
            )

        resolved_findings, debt_summary = _apply_baseline(findings, baseline)
        resolved_findings, waiver_warnings = _apply_waivers(
            resolved_findings,
            override.waivers if override is not None else (),
        )
        warnings = (*warnings, *waiver_warnings)
        coverage = compute_coverage_summary(
            selected_rules=enriched_rules,
            repo_profile=repo_profile,
            findings=resolved_findings,
        )
        blocking_count = sum(
            1 for finding in resolved_findings if finding.blocking and not finding.waived
        )
        advisory_count = sum(
            1 for finding in resolved_findings if finding.advisory and not finding.waived
        )
        waived_count = sum(1 for finding in resolved_findings if finding.waived)
        fail_on_advisories = override.fail_on_advisories if override is not None else False

        return RulesRunResult(
            repo_profile=repo_profile,
            mode=mode,
            source=source,
            changed_files=execution_plan.changed_files,
            selected_rule_ids=tuple(rule.rule_id for rule in applicable_rules),
            findings=resolved_findings,
            adapter_results=tuple(adapter_results),
            warnings=warnings,
            blocking_count=blocking_count,
            advisory_count=advisory_count,
            waived_count=waived_count,
            debt_summary=debt_summary,
            coverage=coverage,
            passed=blocking_count == 0 and (not fail_on_advisories or advisory_count == 0),
        )
