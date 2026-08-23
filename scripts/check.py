#!/usr/bin/env python3
"""Enforce the pack: run the existing Java engine, not the SKILL.md files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from pack_lib import (
    checker_rule_ids,
    collision_hits,
    engine_rule_ids,
    format_collision_report,
    load_pack,
    pack_frameworks,
    prefer_engine_src,
    skill_enforcement_map,
    teach_only_rule_ids,
)

prefer_engine_src()

from engineering_rules.engine import RulesEngine  # noqa: E402
from engineering_rules.models import ExecutionMode, RunSource  # noqa: E402


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run deterministic checks for deslop-java-spring-v1."
    )
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument(
        "--rule",
        action="append",
        default=[],
        help="Limit to one engine rule id (repeatable). Default: all pack rules.",
    )
    parser.add_argument(
        "--changed-file",
        action="append",
        default=[],
        help="Diff-mode file path (repeatable). Default: inventory of the repo.",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--report-collisions",
        action="store_true",
        help="Include agent-instruction collision markers under --repo-root.",
    )
    parser.add_argument(
        "--fail-on-teach-only",
        action="store_true",
        help="Also exit 1 on teach-only findings. Default: gate checker rules only.",
    )
    parser.add_argument(
        "--override-file",
        type=Path,
        help="Optional .engineering-rules.yaml (does not write into the repo).",
    )
    return parser.parse_args()


def run_check(
    *,
    repo_root: Path,
    rule_ids: list[str] | None = None,
    changed_files: list[str] | None = None,
    override_path: Path | None = None,
):
    selected = tuple(rule_ids) if rule_ids else engine_rule_ids()
    mode = ExecutionMode.DIFF if changed_files else ExecutionMode.INVENTORY
    return RulesEngine().run(
        repo_root=repo_root,
        mode=mode,
        source=RunSource.LOCAL,
        changed_files=changed_files or None,
        selected_rule_ids=selected,
        override_path=override_path,
    )


def _coverage_payload(result: Any) -> dict[str, Any] | None:
    coverage = getattr(result, "coverage", None)
    if coverage is None:
        return None
    return coverage.model_dump(mode="json")


def _repo_frameworks(result: Any) -> list[str]:
    coverage = getattr(result, "coverage", None)
    if coverage is not None:
        return [str(item) for item in (coverage.repo_frameworks or ())]
    profile = getattr(result, "repo_profile", None)
    if profile is None:
        return []
    return [str(item) for item in (getattr(profile, "frameworks", ()) or ())]


def _finding_payload(finding: Any, enforcement: str) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "enforcement": enforcement,
        "path": None if finding.location is None else finding.location.path,
        "message": finding.message,
    }


def build_report(
    *,
    pack: dict[str, Any],
    repo_root: Path,
    selected: list[str],
    result: Any,
    report_collisions: bool,
    fail_on_teach_only: bool,
) -> dict[str, Any]:
    enforcement = skill_enforcement_map(pack)
    findings = [finding for finding in result.findings if not finding.waived]
    gate_ids = set(checker_rule_ids(pack))
    teach_ids = set(teach_only_rule_ids(pack))
    gate_findings = [
        finding for finding in findings if enforcement.get(finding.rule_id) == "checker"
    ]
    teach_findings = [
        finding
        for finding in findings
        if enforcement.get(finding.rule_id) == "teach-only"
    ]
    not_covered = [rule_id for rule_id in selected if rule_id in teach_ids]
    collisions = collision_hits(repo_root) if report_collisions else ()
    blocking = findings if fail_on_teach_only else gate_findings
    required = pack_frameworks(pack)
    detected = {item.lower() for item in _repo_frameworks(result)}
    uncovered_pack_frameworks = [
        name for name in required if name.lower() not in detected
    ]
    return {
        "pack_id": pack["pack_id"],
        "passed": not blocking,
        "finding_count": len(blocking),
        "gate_finding_count": len(gate_findings),
        "teach_only_finding_count": len(teach_findings),
        "rule_ids": selected,
        "enforcement": {rule_id: enforcement[rule_id] for rule_id in selected},
        "not_covered": not_covered,
        "pack_frameworks": list(required),
        "uncovered_pack_frameworks": uncovered_pack_frameworks,
        "coverage": _coverage_payload(result),
        "collisions": list(collisions),
        "findings": [
            _finding_payload(finding, enforcement.get(finding.rule_id, "unknown"))
            for finding in findings
        ],
        "gate_rule_ids": [rule_id for rule_id in selected if rule_id in gate_ids],
    }


def _print_text(report: dict[str, Any], repo_root: Path, report_collisions: bool) -> None:
    print(f"Pack: {report['pack_id']}")
    print(f"Repo: {repo_root}")
    print(
        "Enforcement: "
        + ", ".join(f"{rule_id}={kind}" for rule_id, kind in report["enforcement"].items())
    )
    coverage = report["coverage"] or {}
    uncovered = ", ".join(coverage.get("uncovered_frameworks") or []) or "-"
    print(
        "Coverage: "
        f"applicable={coverage.get('applicable_count', '-')} "
        f"suppressed={coverage.get('suppressed_count', '-')} "
        f"uncovered_frameworks={uncovered}"
    )
    print(f"not_covered (teach-only): {', '.join(report['not_covered']) or '-'}")
    print(
        "Pack frameworks: "
        + (", ".join(report.get("pack_frameworks") or []) or "-")
        + "  uncovered="
        + (", ".join(report.get("uncovered_pack_frameworks") or []) or "-")
    )
    if report_collisions:
        print(format_collision_report(repo_root, tuple(report["collisions"])))
    print(
        f"Gate findings: {report['gate_finding_count']}  "
        f"Teach-only findings: {report['teach_only_finding_count']}"
    )
    for finding in report["findings"]:
        path = finding["path"] or "-"
        print(f"- [{finding['enforcement']}] {finding['rule_id']}  {path}")
        print(f"    {finding['message']}")


def main() -> int:
    args = _parse_args()
    pack = load_pack()
    allowed = set(engine_rule_ids(pack))
    selected = args.rule or list(allowed)
    unknown = [rule_id for rule_id in selected if rule_id not in allowed]
    if unknown:
        print(f"Unknown pack rule ids: {', '.join(unknown)}", file=sys.stderr)
        return 2

    result = run_check(
        repo_root=args.repo_root,
        rule_ids=selected,
        changed_files=args.changed_file or None,
        override_path=args.override_file,
    )
    report = build_report(
        pack=pack,
        repo_root=args.repo_root,
        selected=selected,
        result=result,
        report_collisions=args.report_collisions,
        fail_on_teach_only=args.fail_on_teach_only,
    )

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        _print_text(report, args.repo_root, args.report_collisions)

    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
