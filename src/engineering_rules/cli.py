"""CLI entrypoint for the shared engineering rules core."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from .attestation import build_attestation_bundle
from .detection import RepoDetectionOverrideError, detect_repo_profile
from .engine import RulesEngine
from .models import (
    ExecutionMode,
    RepoLanguage,
    RuleCategory,
    RulesBaseline,
    RulesRunResult,
    RunSource,
)
from .packs import create_default_pack_registry
from .registry import create_default_registry
from .remote_proof import RemoteExecutionProofError, require_remote_execution_proof


class RulesBaselineLoadError(ValueError):
    """Raised when a baseline snapshot cannot be loaded."""


def _build_parser() -> argparse.ArgumentParser:
    rule_pack_ids = tuple(pack.pack_id for pack in create_default_pack_registry().list_packs())
    parser = argparse.ArgumentParser(
        prog="engineering-rules",
        description="Shared diff-first engineering rules CLI core.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    detect_parser = subparsers.add_parser("detect", help="Detect repo languages and tooling.")
    _add_repo_options(detect_parser)
    detect_parser.add_argument("--format", choices=("text", "json"), default="text")

    list_parser = subparsers.add_parser("list-rules", help="List registered rules.")
    list_parser.add_argument(
        "--language",
        action="append",
        choices=tuple(language.value for language in RepoLanguage),
        default=[],
    )
    list_parser.add_argument(
        "--category",
        choices=tuple(category.value for category in RuleCategory),
        default=None,
    )
    list_parser.add_argument(
        "--rule-pack",
        action="append",
        choices=rule_pack_ids,
        default=[],
        help="Optional curated rule pack filter (repeatable).",
    )
    list_parser.add_argument("--format", choices=("text", "json"), default="text")

    run_parser = subparsers.add_parser("run", help="Run the local diff-first engine.")
    _add_run_options(run_parser)

    ci_parser = subparsers.add_parser("ci", help="Run the CI entrypoint for changed code.")
    _add_run_options(ci_parser)
    ci_parser.add_argument(
        "--base-ref",
        default=None,
        help="Merge-base reference for CI diff (defaults to GITHUB_BASE_REF when set).",
    )

    inventory_parser = subparsers.add_parser(
        "inventory", help="Run a full-repo inventory for debt snapshots."
    )
    _add_run_options(inventory_parser)

    return parser


def _add_repo_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--override-file",
        type=Path,
        default=None,
        help="Optional repo override file (.engineering-rules.yaml).",
    )


def _add_run_options(parser: argparse.ArgumentParser) -> None:
    rule_pack_ids = tuple(pack.pack_id for pack in create_default_pack_registry().list_packs())
    _add_repo_options(parser)
    parser.add_argument(
        "--changed-file",
        action="append",
        default=[],
        help="Explicit changed file path (repeatable).",
    )
    parser.add_argument(
        "--baseline-file",
        type=Path,
        default=None,
        help="Optional prior inventory/run JSON used to mark findings as new vs existing debt.",
    )
    parser.add_argument(
        "--rule-pack",
        action="append",
        choices=rule_pack_ids,
        default=[],
        help="Optional curated rule pack to restrict rule selection (repeatable).",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--attestation",
        action="store_true",
        help="When using --format json, also emit a CC8.1-oriented attestation bundle.",
    )
    parser.add_argument(
        "--attestation-key",
        default=None,
        help="Optional HMAC signing key for attestation bundles (or DESLOP_ATTESTATION_KEY env).",
    )
    parser.add_argument(
        "--git-head",
        default=None,
        help="Optional git HEAD SHA to bind into attestation subject metadata.",
    )
    parser.add_argument(
        "--pull-request-url",
        default=None,
        help="Optional pull request URL for attestation traceability.",
    )
    parser.add_argument(
        "--reviewer-identity",
        default=None,
        help="Optional reviewer identity for attestation human-oversight metadata.",
    )


def _emit_json(value: BaseModel | list[dict[str, Any]]) -> None:
    if isinstance(value, BaseModel):
        print(value.model_dump_json(indent=2))
        return
    print(json.dumps(value, indent=2))


def _emit_profile_text(profile: BaseModel) -> None:
    payload = profile.model_dump()
    print(f"Repo: {payload['repo_name']}")
    print(f"Primary language: {payload['primary_language'] or '-'}")
    print(f"Detected languages: {', '.join(payload['detected_languages']) or '-'}")
    print(f"Tooling: {', '.join(payload['tooling']) or '-'}")
    print(f"Frameworks: {', '.join(payload['frameworks']) or '-'}")
    print(f"CI provider: {payload['ci_provider'] or '-'}")
    print(f"Markers: {', '.join(payload['marker_files']) or '-'}")
    print(f"Detection source: {payload['detection_source']}")
    if payload["override_path"]:
        print(f"Override file: {payload['override_path']}")


def _emit_rules_text(rules: list[dict[str, Any]]) -> None:
    for rule in rules:
        languages = ",".join(rule["languages"])
        print(
            f"{rule['rule_id']} [{rule['category']}] "
            f"languages={languages} adapter={rule['adapter_key']} "
            f"state={rule['implementation_state']}"
        )


def _emit_run_text(result: RulesRunResult) -> None:
    print(f"Status: {'PASS' if result.passed else 'FAIL'}")
    print(f"Mode: {result.mode.value}")
    print(f"Source: {result.source.value}")
    print(f"Changed files: {len(result.changed_files)}")
    print(f"Selected rules: {len(result.selected_rule_ids)}")
    print(f"Blocking findings: {result.blocking_count}")
    print(f"Advisory findings: {result.advisory_count}")
    print(f"Waived findings: {result.waived_count}")
    print(
        "Debt summary: "
        f"new={result.debt_summary.new_count} "
        f"existing={result.debt_summary.existing_count} "
        f"unknown={result.debt_summary.unknown_count}"
    )
    if result.coverage is not None:
        print(
            "Coverage: "
            f"applicable={result.coverage.applicable_count} "
            f"suppressed={result.coverage.suppressed_count} "
            f"stack_agnostic_applicable={result.coverage.stack_agnostic_applicable_count} "
            f"framework_coupled_applicable={result.coverage.framework_coupled_applicable_count}"
        )
        if result.coverage.uncovered_frameworks:
            print(
                "Uncovered frameworks: "
                f"{', '.join(result.coverage.uncovered_frameworks)}"
            )
    if result.changed_files:
        print("Files:")
        for path in result.changed_files:
            print(f"  - {path}")
    if result.adapter_results:
        print("Adapters:")
        for adapter in result.adapter_results:
            print(
                f"  - {adapter.adapter_key}: {adapter.status.value} "
                f"(rules={len(adapter.rule_ids)}, findings={adapter.finding_count})"
            )
    if result.warnings:
        print("Warnings:")
        for warning in result.warnings:
            print(f"  - {warning}")


def _load_baseline(path: Path | None) -> RulesBaseline | None:
    if path is None:
        return None
    try:
        raw_payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RulesBaselineLoadError(f"{path}: baseline file does not exist") from exc
    except OSError as exc:
        raise RulesBaselineLoadError(f"{path}: unable to read baseline file: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RulesBaselineLoadError(f"{path}: invalid JSON baseline file: {exc}") from exc

    if not isinstance(raw_payload, dict):
        raise RulesBaselineLoadError(
            f"{path}: unsupported baseline payload; expected a JSON object"
        )

    try:
        schema_version = raw_payload.get("schema_version")
        if schema_version == "rules.baseline.v1":
            return RulesBaseline.model_validate(raw_payload)
        if schema_version == "rules.result.v1":
            return RulesRunResult.model_validate(raw_payload).to_baseline()
    except ValidationError as exc:
        raise RulesBaselineLoadError(f"{path}: baseline validation failed: {exc}") from exc

    raise RulesBaselineLoadError(
        f"{path}: unsupported baseline payload; expected rules.baseline.v1 or rules.result.v1"
    )


def _normalize_ci_base_ref(base_ref: str | None) -> str | None:
    if base_ref is None:
        return None

    normalized = base_ref.strip()
    if not normalized:
        return None
    if normalized.startswith("refs/heads/"):
        return f"origin/{normalized.removeprefix('refs/heads/')}"
    if normalized.startswith("refs/"):
        return normalized
    if normalized.startswith("origin/"):
        return normalized
    return f"origin/{normalized}"


def _handle_detect(args: argparse.Namespace) -> int:
    profile = detect_repo_profile(args.repo_root, override_path=args.override_file)
    if args.format == "json":
        _emit_json(profile)
    else:
        _emit_profile_text(profile)
    return 0


def _handle_list_rules(args: argparse.Namespace) -> int:
    registry = create_default_registry()
    pack_registry = create_default_pack_registry(rules_registry=registry)
    languages = [RepoLanguage(value) for value in args.language] if args.language else None
    category = RuleCategory(args.category) if args.category else None
    selected_rules = registry.list_rules(languages=languages, category=category)
    if args.rule_pack:
        pack_rule_ids = set(pack_registry.resolve_rule_ids(args.rule_pack))
        selected_rules = [rule for rule in selected_rules if rule.rule_id in pack_rule_ids]
    rules = [rule.model_dump(mode="json") for rule in selected_rules]
    if args.format == "json":
        _emit_json(rules)
    else:
        _emit_rules_text(rules)
    return 0


def _handle_run(args: argparse.Namespace, *, source: RunSource, mode: ExecutionMode) -> int:
    engine = RulesEngine()
    selected_rule_ids = None
    if args.rule_pack:
        selected_rule_ids = create_default_pack_registry().resolve_rule_ids(args.rule_pack)
    base_ref = args.base_ref if hasattr(args, "base_ref") else None
    if source is RunSource.CI and base_ref is None:
        env_base_ref = os.getenv("GITHUB_BASE_REF", "").strip()
        base_ref = env_base_ref or None
    if source is RunSource.CI:
        base_ref = _normalize_ci_base_ref(base_ref)
    baseline = _load_baseline(args.baseline_file)
    require_remote_execution_proof(
        repo_root=args.repo_root,
        source=source,
        changed_files=args.changed_file or None,
    )
    result = engine.run(
        repo_root=args.repo_root,
        mode=mode,
        override_path=args.override_file,
        changed_files=args.changed_file or None,
        base_ref=base_ref,
        source=source,
        selected_rule_ids=selected_rule_ids,
        baseline=baseline,
    )
    if args.format == "json":
        if args.attestation:
            signing_key = args.attestation_key or os.getenv("DESLOP_ATTESTATION_KEY")
            attestation = build_attestation_bundle(
                result,
                git_head=args.git_head,
                base_ref=base_ref,
                pull_request_url=args.pull_request_url,
                reviewer_identity=args.reviewer_identity,
                signing_key=signing_key,
            )
            payload = {
                "run": result.model_dump(mode="json"),
                "attestation": attestation.model_dump(mode="json"),
            }
            _emit_json(payload)
        else:
            _emit_json(result)
    else:
        _emit_run_text(result)
    if any(adapter.status.value == "failed" for adapter in result.adapter_results):
        return 2
    return 0 if result.passed else 1


def main(argv: Sequence[str] | None = None) -> int:
    """Run the engineering rules CLI."""

    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        if args.command == "detect":
            return _handle_detect(args)
        if args.command == "list-rules":
            return _handle_list_rules(args)
        if args.command == "run":
            return _handle_run(args, source=RunSource.LOCAL, mode=ExecutionMode.DIFF)
        if args.command == "ci":
            return _handle_run(args, source=RunSource.CI, mode=ExecutionMode.DIFF)
        if args.command == "inventory":
            return _handle_run(args, source=RunSource.LOCAL, mode=ExecutionMode.INVENTORY)
    except (RepoDetectionOverrideError, RemoteExecutionProofError, RulesBaselineLoadError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
