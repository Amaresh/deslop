"""Shared engineering rules CLI core."""

from .adapters import load_default_adapters
from .detection import detect_repo_profile
from .engine import RulesEngine
from .models import (
    AdapterExecutionResult,
    BaselineFindingRecord,
    DebtSummary,
    DetectionSource,
    ExecutionMode,
    FindingConfidence,
    FindingDebtStatus,
    FindingLocation,
    FindingSeverity,
    NormalizedFinding,
    RepoDetectionOverride,
    RepoLanguage,
    RepoProfile,
    RuleCategory,
    RuleDefinition,
    RulePack,
    RulesBaseline,
    RulesRunResult,
    RunSource,
)
from .packs import RulePackRegistry, create_default_pack_registry
from .registry import RulesRegistry, create_default_registry

__all__ = [
    "AdapterExecutionResult",
    "BaselineFindingRecord",
    "DebtSummary",
    "DetectionSource",
    "ExecutionMode",
    "FindingDebtStatus",
    "FindingConfidence",
    "FindingLocation",
    "FindingSeverity",
    "load_default_adapters",
    "NormalizedFinding",
    "RepoDetectionOverride",
    "RepoLanguage",
    "RepoProfile",
    "RuleCategory",
    "RulePack",
    "RulesBaseline",
    "RuleDefinition",
    "RulePackRegistry",
    "RulesEngine",
    "RulesRegistry",
    "RulesRunResult",
    "RunSource",
    "create_default_pack_registry",
    "create_default_registry",
    "detect_repo_profile",
]
