"""Normalized models for the engineering rules core."""

from __future__ import annotations

import re
from datetime import date, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_RULE_ID_PATTERN = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)+$")


def _normalize_optional_string(value: Any) -> str | None:
    if value is None:
        return None
    rendered = str(value).strip()
    return rendered or None


def _normalize_string_sequence(value: Any) -> tuple[str, ...] | None:
    if value is None:
        return None
    raw_values = [value] if isinstance(value, str) else list(value)
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        rendered = str(raw).strip()
        if not rendered or rendered in seen:
            continue
        normalized.append(rendered)
        seen.add(rendered)
    return tuple(normalized)


def _normalize_enum_sequence(value: Any) -> tuple[Any, ...] | None:
    if value is None:
        return None
    raw_values = [value] if isinstance(value, str) else list(value)
    normalized: list[Any] = []
    seen: set[Any] = set()
    for raw in raw_values:
        if raw in seen:
            continue
        normalized.append(raw)
        seen.add(raw)
    return tuple(normalized)


class RepoLanguage(StrEnum):
    PYTHON = "python"
    JAVA = "java"
    GO = "go"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    UNITY = "unity"
    ANDROID = "android"


class DetectionSource(StrEnum):
    AUTO = "auto"
    OVERRIDE = "override"


class RuleCategory(StrEnum):
    ARCHITECTURE = "architecture"
    CORRECTNESS = "correctness"
    MAINTAINABILITY = "maintainability"
    PERFORMANCE = "performance"
    RELIABILITY = "reliability"
    SECURITY = "security"
    TESTING = "testing"
    TYPING = "typing"


class FindingSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class FindingConfidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ExecutionMode(StrEnum):
    DIFF = "diff"
    INVENTORY = "inventory"


class RunSource(StrEnum):
    LOCAL = "local"
    CI = "ci"


class RemoteExecutionProofStatus(StrEnum):
    OK = "ok"
    REMOTE_FAILURE = "remote_failure"
    LOCAL_ERROR = "local_error"


class AdapterStatus(StrEnum):
    SKIPPED = "skipped"
    SUCCESS = "success"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"


class FindingDebtStatus(StrEnum):
    NEW = "new"
    EXISTING = "existing"
    UNKNOWN = "unknown"


class RuleWaiver(BaseModel):
    """Repo-local waiver for a known false positive or temporary exception."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    reason: str
    paths: tuple[str, ...] = Field(default_factory=tuple)
    fingerprints: tuple[str, ...] = Field(default_factory=tuple)
    expires_on: date | None = None

    @field_validator("rule_id")
    @classmethod
    def _validate_rule_id(cls, value: str) -> str:
        if not _RULE_ID_PATTERN.fullmatch(value):
            raise ValueError(f"rule ids must match {_RULE_ID_PATTERN.pattern!r}: {value!r}")
        return value

    @field_validator("reason", mode="before")
    @classmethod
    def _normalize_reason(cls, value: Any) -> str:
        normalized = _normalize_optional_string(value)
        if normalized is None:
            raise ValueError("reason is required")
        return normalized

    @field_validator("paths", mode="before")
    @classmethod
    def _normalize_paths(cls, value: Any) -> tuple[str, ...]:
        normalized = _normalize_string_sequence(value) or ()
        return tuple(path.replace("\\", "/") for path in normalized)

    @field_validator("fingerprints", mode="before")
    @classmethod
    def _normalize_fingerprints(cls, value: Any) -> tuple[str, ...]:
        return _normalize_string_sequence(value) or ()

    @model_validator(mode="after")
    def _validate_scope(self) -> RuleWaiver:
        if not self.paths and not self.fingerprints:
            raise ValueError("waivers must include at least one path or fingerprint")
        return self


class RepoDetectionOverride(BaseModel):
    """Optional repo-level engineering-rules configuration."""

    model_config = ConfigDict(extra="forbid")

    primary_language: RepoLanguage | None = None
    languages: tuple[RepoLanguage, ...] | None = None
    tooling: tuple[str, ...] | None = None
    frameworks: tuple[str, ...] | None = None
    fail_on_advisories: bool = False
    waivers: tuple[RuleWaiver, ...] = Field(default_factory=tuple)

    @field_validator("languages", mode="before")
    @classmethod
    def _normalize_languages(cls, value: Any) -> tuple[RepoLanguage, ...] | None:
        return _normalize_enum_sequence(value)

    @field_validator("tooling", "frameworks", mode="before")
    @classmethod
    def _normalize_string_fields(cls, value: Any) -> tuple[str, ...] | None:
        return _normalize_string_sequence(value)


class RepoProfile(BaseModel):
    """Detected repo/tooling profile used to route rules."""

    model_config = ConfigDict(extra="forbid")

    repo_root: str
    repo_name: str
    detected_languages: tuple[RepoLanguage, ...] = Field(default_factory=tuple)
    primary_language: RepoLanguage | None = None
    tooling: tuple[str, ...] = Field(default_factory=tuple)
    frameworks: tuple[str, ...] = Field(default_factory=tuple)
    marker_files: tuple[str, ...] = Field(default_factory=tuple)
    ci_provider: str | None = None
    detection_source: DetectionSource = DetectionSource.AUTO
    override_path: str | None = None

    @field_validator("tooling", "frameworks", "marker_files", mode="before")
    @classmethod
    def _normalize_string_sequences(cls, value: Any) -> tuple[str, ...] | None:
        return _normalize_string_sequence(value)

    @field_validator("detected_languages", mode="before")
    @classmethod
    def _normalize_detected_languages(cls, value: Any) -> tuple[RepoLanguage, ...] | None:
        return _normalize_enum_sequence(value)


class RemoteExecutionProof(BaseModel):
    """Proof that a remote-first tool was attempted for the current repo."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["ai-platform.remote-proof.v1"] = "ai-platform.remote-proof.v1"
    recorded_at: datetime
    repo_root: str
    git_head: str
    tool: str
    wrapper: str
    status: RemoteExecutionProofStatus
    error: str | None = None

    @field_validator("repo_root", "git_head", "tool", "wrapper", mode="before")
    @classmethod
    def _normalize_required_string(cls, value: Any) -> str:
        normalized = _normalize_optional_string(value)
        if normalized is None:
            raise ValueError("value is required")
        return normalized

    @field_validator("error", mode="before")
    @classmethod
    def _normalize_optional_error(cls, value: Any) -> str | None:
        return _normalize_optional_string(value)


class RuleDefinition(BaseModel):
    """Cross-language rule metadata and taxonomy entry."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    name: str
    summary: str
    category: RuleCategory
    languages: tuple[RepoLanguage, ...]
    adapter_key: str
    default_severity: FindingSeverity
    default_confidence: FindingConfidence
    default_blocking: bool = False
    enabled_by_default: bool = True
    implementation_state: Literal["planned", "active"] = "planned"
    tags: tuple[str, ...] = Field(default_factory=tuple)
    frameworks: tuple[str, ...] = Field(
        default_factory=tuple,
        description=(
            "Optional framework coupling. Empty means stack-agnostic for the rule language."
        ),
    )

    @field_validator("rule_id")
    @classmethod
    def _validate_rule_id(cls, value: str) -> str:
        if not _RULE_ID_PATTERN.fullmatch(value):
            raise ValueError(f"rule ids must match {_RULE_ID_PATTERN.pattern!r}: {value!r}")
        return value

    @field_validator("tags", mode="before")
    @classmethod
    def _normalize_tags(cls, value: Any) -> tuple[str, ...] | None:
        return _normalize_string_sequence(value)

    @field_validator("frameworks", mode="before")
    @classmethod
    def _normalize_frameworks(cls, value: Any) -> tuple[str, ...] | None:
        normalized = _normalize_string_sequence(value)
        if normalized is None:
            return ()
        return tuple(token.lower() for token in normalized)

    @field_validator("languages", mode="before")
    @classmethod
    def _normalize_languages(cls, value: Any) -> tuple[RepoLanguage, ...]:
        normalized = _normalize_enum_sequence(value)
        if not normalized:
            raise ValueError("languages must include at least one language")
        return normalized


class CoverageSummary(BaseModel):
    """Framework-aware applicability summary for a rules run."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rules.coverage.v1"] = "rules.coverage.v1"
    repo_frameworks: tuple[str, ...] = Field(default_factory=tuple)
    applicable_rule_ids: tuple[str, ...] = Field(default_factory=tuple)
    suppressed_rule_ids: tuple[str, ...] = Field(default_factory=tuple)
    applicable_count: int = Field(default=0, ge=0)
    suppressed_count: int = Field(default=0, ge=0)
    stack_agnostic_applicable_count: int = Field(default=0, ge=0)
    framework_coupled_applicable_count: int = Field(default=0, ge=0)
    uncovered_frameworks: tuple[str, ...] = Field(default_factory=tuple)
    fired_rule_ids: tuple[str, ...] = Field(default_factory=tuple)
    stack_agnostic_fired_count: int = Field(default=0, ge=0)


class RulePack(BaseModel):
    """Curated set of rule ids for a specific workflow or enforcement tier."""

    model_config = ConfigDict(extra="forbid")

    pack_id: str
    name: str
    summary: str
    rule_ids: tuple[str, ...]

    @field_validator("pack_id")
    @classmethod
    def _validate_pack_id(cls, value: str) -> str:
        if not _RULE_ID_PATTERN.fullmatch(value):
            raise ValueError(f"pack ids must match {_RULE_ID_PATTERN.pattern!r}: {value!r}")
        return value

    @field_validator("rule_ids", mode="before")
    @classmethod
    def _normalize_rule_ids(cls, value: Any) -> tuple[str, ...]:
        normalized = _normalize_string_sequence(value)
        if not normalized:
            raise ValueError("rule_ids must include at least one rule id")
        return normalized


class FindingLocation(BaseModel):
    """Normalized source location for a finding."""

    model_config = ConfigDict(extra="forbid")

    path: str
    line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)
    end_column: int | None = Field(default=None, ge=1)

    @field_validator("path", mode="before")
    @classmethod
    def _normalize_path(cls, value: Any) -> str:
        candidate = _normalize_optional_string(value)
        if candidate is None:
            raise ValueError("path is required")
        return candidate.replace("\\", "/")


class NormalizedFinding(BaseModel):
    """Stable finding contract across adapters."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rules.finding.v1"] = "rules.finding.v1"
    rule_id: str
    title: str
    category: RuleCategory
    severity: FindingSeverity
    confidence: FindingConfidence
    blocking: bool = False
    advisory: bool = True
    message: str
    language: RepoLanguage | None = None
    location: FindingLocation | None = None
    adapter_id: str | None = None
    suggestion: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)
    fingerprint: str | None = None
    debt_status: FindingDebtStatus = FindingDebtStatus.UNKNOWN
    waived: bool = False
    waiver_reason: str | None = None
    waiver_expires_on: date | None = None

    @model_validator(mode="before")
    @classmethod
    def _default_advisory_flag(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        if "advisory" not in data:
            values = dict(data)
            values["advisory"] = not bool(values.get("blocking", False))
            return values
        return data

    @field_validator("rule_id")
    @classmethod
    def _validate_rule_id(cls, value: str) -> str:
        if not _RULE_ID_PATTERN.fullmatch(value):
            raise ValueError(f"rule ids must match {_RULE_ID_PATTERN.pattern!r}: {value!r}")
        return value

    @model_validator(mode="after")
    def _validate_flags(self) -> NormalizedFinding:
        if self.blocking and self.advisory:
            raise ValueError("finding cannot be both blocking and advisory")
        if self.waived and not self.waiver_reason:
            raise ValueError("waived findings must include a waiver_reason")
        return self

    @classmethod
    def from_rule(
        cls,
        rule: RuleDefinition,
        *,
        message: str,
        location: FindingLocation | None = None,
        adapter_id: str | None = None,
        language: RepoLanguage | None = None,
        severity: FindingSeverity | None = None,
        confidence: FindingConfidence | None = None,
        blocking: bool | None = None,
        advisory: bool | None = None,
        suggestion: str | None = None,
        metadata: dict[str, str] | None = None,
    ) -> NormalizedFinding:
        resolved_blocking = rule.default_blocking if blocking is None else blocking
        resolved_advisory = (not resolved_blocking) if advisory is None else advisory
        return cls(
            rule_id=rule.rule_id,
            title=rule.name,
            category=rule.category,
            severity=severity or rule.default_severity,
            confidence=confidence or rule.default_confidence,
            blocking=resolved_blocking,
            advisory=resolved_advisory,
            message=message,
            language=language,
            location=location,
            adapter_id=adapter_id,
            suggestion=suggestion,
            metadata=metadata or {},
        )


class AdapterExecutionResult(BaseModel):
    """Per-adapter execution summary for a run."""

    model_config = ConfigDict(extra="forbid")

    adapter_key: str
    status: AdapterStatus
    rule_ids: tuple[str, ...] = Field(default_factory=tuple)
    finding_count: int = Field(default=0, ge=0)
    message: str | None = None

    @field_validator("rule_ids", mode="before")
    @classmethod
    def _normalize_rule_ids(cls, value: Any) -> tuple[str, ...] | None:
        return _normalize_string_sequence(value)


class BaselineFindingRecord(BaseModel):
    """Lightweight, stable debt snapshot entry."""

    model_config = ConfigDict(extra="forbid")

    fingerprint: str
    rule_id: str
    title: str
    adapter_id: str | None = None
    language: RepoLanguage | None = None
    location: FindingLocation | None = None


class RulesBaseline(BaseModel):
    """Serializable baseline snapshot for later debt comparisons."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rules.baseline.v1"] = "rules.baseline.v1"
    repo_name: str
    mode: ExecutionMode
    generated_from_source: RunSource
    records: tuple[BaselineFindingRecord, ...] = Field(default_factory=tuple)


class DebtSummary(BaseModel):
    """Counts describing how current findings compare to an optional baseline."""

    model_config = ConfigDict(extra="forbid")

    compared_findings: int = Field(default=0, ge=0)
    new_count: int = Field(default=0, ge=0)
    existing_count: int = Field(default=0, ge=0)
    unknown_count: int = Field(default=0, ge=0)


class RulesRunResult(BaseModel):
    """Normalized run result for local and CI entrypoints."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rules.result.v1"] = "rules.result.v1"
    repo_profile: RepoProfile
    mode: ExecutionMode
    source: RunSource
    changed_files: tuple[str, ...] = Field(default_factory=tuple)
    selected_rule_ids: tuple[str, ...] = Field(default_factory=tuple)
    findings: tuple[NormalizedFinding, ...] = Field(default_factory=tuple)
    adapter_results: tuple[AdapterExecutionResult, ...] = Field(default_factory=tuple)
    warnings: tuple[str, ...] = Field(default_factory=tuple)
    blocking_count: int = Field(default=0, ge=0)
    advisory_count: int = Field(default=0, ge=0)
    waived_count: int = Field(default=0, ge=0)
    debt_summary: DebtSummary = Field(default_factory=DebtSummary)
    coverage: CoverageSummary | None = None
    passed: bool = True

    @field_validator("changed_files", "selected_rule_ids", "warnings", mode="before")
    @classmethod
    def _normalize_sequences(cls, value: Any) -> tuple[str, ...] | None:
        return _normalize_string_sequence(value)

    def to_baseline(self) -> RulesBaseline:
        """Convert current findings into a lightweight reusable debt snapshot."""

        records = tuple(
            BaselineFindingRecord(
                fingerprint=finding.fingerprint or "",
                rule_id=finding.rule_id,
                title=finding.title,
                adapter_id=finding.adapter_id,
                language=finding.language,
                location=finding.location,
            )
            for finding in self.findings
            if finding.fingerprint
        )
        return RulesBaseline(
            repo_name=self.repo_profile.repo_name,
            mode=self.mode,
            generated_from_source=self.source,
            records=records,
        )
