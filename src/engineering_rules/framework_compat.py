"""Framework compatibility and coverage reporting for rule selection."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from .models import CoverageSummary, NormalizedFinding, RepoLanguage, RepoProfile, RuleDefinition

# Tags and rule-id tokens that imply a rule only applies when the repo uses that
# framework. Empty inferred frameworks means stack-agnostic for the rule language.
_FRAMEWORK_TAG_SIGNALS: frozenset[str] = frozenset(
    {
        "fastapi",
        "spring",
        "flyway",
        "jpa",
        "hibernate",
        "react",
        "react-native",
        "react-query",
        "tanstack",
        "next",
        "nextjs",
        "compose",
        "unity",
        "android",
        "gradle",
        "django",
        "flask",
        "quarkus",
        "micronaut",
    }
)

_RULE_ID_FRAMEWORK_HINTS: tuple[tuple[str, str], ...] = (
    ("fastapi", "fastapi"),
    ("flyway", "spring"),
    ("jpql", "spring"),
    ("spring", "spring"),
    ("compose", "compose"),
    ("react-query", "tanstack"),
    ("usequery", "tanstack"),
    ("unityeditor", "unity"),
    ("unity.", "unity"),
)

_TOOLING_FRAMEWORK_SIGNALS: frozenset[str] = frozenset(
    {
        "spring",
        "fastapi",
        "django",
        "flask",
        "react",
        "react-native",
        "unity",
        "gradle",
        "android-gradle",
        "android-lint",
        "detekt",
        "eslint",
        "typescript",
    }
)


def infer_rule_frameworks(rule: RuleDefinition) -> tuple[str, ...]:
    """Infer framework coupling from explicit metadata, tags, and rule id."""

    if rule.frameworks:
        return rule.frameworks

    inferred: list[str] = []
    seen: set[str] = set()
    haystack = f"{rule.rule_id} {' '.join(rule.tags)}".lower()

    for tag in rule.tags:
        token = tag.strip().lower()
        if token in _FRAMEWORK_TAG_SIGNALS and token not in seen:
            inferred.append(token)
            seen.add(token)

    for needle, framework in _RULE_ID_FRAMEWORK_HINTS:
        if needle in haystack and framework not in seen:
            inferred.append(framework)
            seen.add(framework)

    if (
        RepoLanguage.JAVA in rule.languages
        and "backend" in rule.tags
        and any(
            token in haystack
            for token in ("transactional", "jpql", "web-layer", "service-layer")
        )
        and "spring" not in seen
    ):
        inferred.append("spring")
        seen.add("spring")

    return tuple(inferred)


def enrich_rule_frameworks(rule: RuleDefinition) -> RuleDefinition:
    """Attach inferred frameworks when the registry entry has none."""

    inferred = infer_rule_frameworks(rule)
    if rule.frameworks == inferred:
        return rule
    return rule.model_copy(update={"frameworks": inferred})


def repo_framework_signals(profile: RepoProfile) -> frozenset[str]:
    """Normalize detected repo frameworks and tooling into comparable tokens."""

    signals: set[str] = set()
    for value in (*profile.frameworks, *profile.tooling):
        token = value.strip().lower()
        if not token:
            continue
        signals.add(token)
        if token == "react-native":
            signals.add("react")
        if token in {"android-gradle", "android-lint", "detekt"}:
            signals.add("android")
            signals.add("compose")
        if token == "typescript" and "react" in signals:
            signals.add("react")
    return frozenset(signals)


def rule_applies_to_repo(rule: RuleDefinition, repo_signals: frozenset[str]) -> bool:
    """Return whether a rule should run for the repo's detected framework surface."""

    frameworks = rule.frameworks or infer_rule_frameworks(rule)
    if not frameworks:
        return True

    required = {framework.lower() for framework in frameworks}
    if required.intersection(repo_signals):
        return True

    # TanStack Query rules also match generic React repos until we detect query libs.
    if "tanstack" in required and "react" in repo_signals:
        return True
    return "compose" in required and "android" in repo_signals


def compute_coverage_summary(
    *,
    selected_rules: Sequence[RuleDefinition],
    repo_profile: RepoProfile,
    findings: Sequence[NormalizedFinding],
) -> CoverageSummary:
    """Summarize applicable vs framework-suppressed rules for a run."""

    repo_signals = repo_framework_signals(repo_profile)
    applicable: list[str] = []
    suppressed: list[str] = []
    stack_agnostic_applicable = 0
    framework_coupled_applicable = 0
    missing_frameworks: set[str] = set()

    for rule in selected_rules:
        frameworks = rule.frameworks or infer_rule_frameworks(rule)
        if rule_applies_to_repo(rule, repo_signals):
            applicable.append(rule.rule_id)
            if frameworks:
                framework_coupled_applicable += 1
            else:
                stack_agnostic_applicable += 1
            continue
        suppressed.append(rule.rule_id)
        missing_frameworks.update(framework.lower() for framework in frameworks)

    fired_rule_ids = tuple(
        sorted({finding.rule_id for finding in findings if not finding.waived})
    )
    stack_agnostic_fired = sum(
        1
        for rule_id in fired_rule_ids
        for rule in selected_rules
        if rule.rule_id == rule_id and not (rule.frameworks or infer_rule_frameworks(rule))
    )

    uncovered = tuple(
        sorted(framework for framework in missing_frameworks if framework not in repo_signals)
    )

    return CoverageSummary(
        repo_frameworks=tuple(sorted(repo_signals)),
        applicable_rule_ids=tuple(applicable),
        suppressed_rule_ids=tuple(suppressed),
        applicable_count=len(applicable),
        suppressed_count=len(suppressed),
        stack_agnostic_applicable_count=stack_agnostic_applicable,
        framework_coupled_applicable_count=framework_coupled_applicable,
        uncovered_frameworks=uncovered,
        fired_rule_ids=fired_rule_ids,
        stack_agnostic_fired_count=stack_agnostic_fired,
    )


def filter_rules_for_repo(
    rules: Iterable[RuleDefinition], repo_profile: RepoProfile
) -> tuple[RuleDefinition, ...]:
    """Drop framework-mismatched rules before adapter execution."""

    repo_signals = repo_framework_signals(repo_profile)
    return tuple(rule for rule in rules if rule_applies_to_repo(rule, repo_signals))
