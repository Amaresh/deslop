#!/usr/bin/env python3
"""Enforce packs: portable AST checkers."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from pack_lib import (
    PACK_ROOT,
    checker_rule_ids,
    check_rule_ids,
    collision_hits,
    detect_java_frameworks,
    format_collision_report,
    load_all_packs,
    load_pack,
    load_pack_by_id,
    mine_rule_ids,
    pack_frameworks,
    skill_enforcement_map,
    teach_only_rule_ids,
)

sys.path.insert(0, str(PACK_ROOT / "checkers"))

from run import CheckFinding, run_mine  # noqa: E402


@dataclass
class CombinedResult:
    findings: tuple[Any, ...]
    coverage: Any = None
    repo_profile: Any = None


@dataclass
class CoverageInfo:
    repo_frameworks: tuple[str, ...] = ()
    applicable_count: int = 0
    suppressed_count: int = 0
    uncovered_frameworks: tuple[str, ...] = ()

    def model_dump(self, mode: str = "json") -> dict[str, Any]:
        return {
            "repo_frameworks": list(self.repo_frameworks),
            "applicable_count": self.applicable_count,
            "suppressed_count": self.suppressed_count,
            "uncovered_frameworks": list(self.uncovered_frameworks),
        }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run deterministic checks for selected stopthatslop packs."
    )
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument(
        "--pack",
        action="append",
        default=[],
        help="Pack id or alias (java, python, ts, go, android). Repeatable. "
        "Default: packs whose languages are present in the repo.",
    )
    parser.add_argument(
        "--rule",
        action="append",
        default=[],
        help="Limit to one rule id (repeatable). Default: all selected pack rules.",
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
        "--override-file",
        type=Path,
        help="Optional .engineering-rules.yaml (does not write into the repo).",
    )
    return parser.parse_args()


def _looks_java_project(repo: Path) -> bool:
    return (
        (repo / "pom.xml").exists()
        or (repo / "build.gradle").exists()
        or (repo / "build.gradle.kts").exists()
    )


def _has_glob(repo: Path, pattern: str) -> bool:
    return next(repo.rglob(pattern), None) is not None


def _repo_matches_lang(repo: Path, lang: str) -> bool:
    if lang == "java":
        return _has_glob(repo, "*.java") or _looks_java_project(repo)
    if lang == "python":
        return (
            _has_glob(repo, "*.py")
            or (repo / "pyproject.toml").exists()
            or (repo / "requirements.txt").exists()
        )
    if lang == "ts":
        return (
            _has_glob(repo, "*.ts")
            or _has_glob(repo, "*.tsx")
            or ((repo / "package.json").exists() and not _looks_java_project(repo))
        )
    if lang == "go":
        return _has_glob(repo, "*.go") or (repo / "go.mod").exists()
    if lang == "android":
        return _has_glob(repo, "*.kt") or _has_glob(repo, "*.kts")
    return False


def select_packs(repo: Path, pack_args: Sequence[str]) -> list[dict[str, Any]]:
    if pack_args:
        if any(arg == "all" for arg in pack_args):
            return load_all_packs()
        return [load_pack_by_id(arg) for arg in pack_args]
    matched = [
        pack
        for pack in load_all_packs()
        if _repo_matches_lang(repo, str(pack.get("lang") or ""))
    ]
    return matched or [load_pack()]


def _merge_enforcement(packs: Sequence[dict[str, Any]]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for pack in packs:
        merged.update(skill_enforcement_map(pack))
    return merged


def run_check(
    *,
    repo_root: Path,
    rule_ids: list[str] | None = None,
    changed_files: list[str] | None = None,
    override_path: Path | None = None,
    packs: list[dict[str, Any]] | None = None,
):
    selected_packs = packs if packs is not None else select_packs(repo_root, ())
    allowed: list[str] = []
    for pack in selected_packs:
        allowed.extend(check_rule_ids(pack))
    allowed_unique = tuple(dict.fromkeys(allowed))
    selected = tuple(rule_ids) if rule_ids else allowed_unique

    mine_ids = [
        rid
        for rid in selected
        if any(rid in mine_rule_ids(pack) for pack in selected_packs)
    ]

    findings: list[Any] = []
    coverage = None
    repo_profile = None
    if any(str(pack.get("lang") or "") == "java" for pack in selected_packs):
        detected = detect_java_frameworks(repo_root, override_path)
        required: list[str] = []
        for pack in selected_packs:
            if str(pack.get("lang") or "") == "java":
                required.extend(pack_frameworks(pack))
        detected_l = {item.lower() for item in detected}
        uncovered = tuple(
            name for name in dict.fromkeys(required) if name.lower() not in detected_l
        )
        coverage = CoverageInfo(
            repo_frameworks=tuple(sorted(detected, key=str.lower)),
            applicable_count=len(selected),
            suppressed_count=0,
            uncovered_frameworks=uncovered,
        )
    if mine_ids:
        findings.extend(
            run_mine(
                repo_root=repo_root,
                rule_ids=mine_ids,
                changed_files=changed_files,
            )
        )
    return CombinedResult(
        findings=tuple(findings),
        coverage=coverage,
        repo_profile=repo_profile,
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
    location = finding.location
    path = None if location is None else location.path
    return {
        "rule_id": finding.rule_id,
        "enforcement": enforcement,
        "path": path,
        "message": finding.message,
    }


def build_report(
    *,
    packs: Sequence[dict[str, Any]],
    repo_root: Path,
    selected: list[str],
    result: Any,
    report_collisions: bool,
) -> dict[str, Any]:
    enforcement = _merge_enforcement(packs)
    findings = [finding for finding in result.findings if not finding.waived]
    gate_ids: set[str] = set()
    teach_ids: set[str] = set()
    for pack in packs:
        gate_ids.update(checker_rule_ids(pack))
        teach_ids.update(teach_only_rule_ids(pack))
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
    blocking = gate_findings
    required: list[str] = []
    for pack in packs:
        required.extend(pack_frameworks(pack))
    required_unique = list(dict.fromkeys(required))
    coverage_payload = _coverage_payload(result)
    if coverage_payload is None:
        uncovered_pack_frameworks: list[str] = []
    else:
        detected = {item.lower() for item in _repo_frameworks(result)}
        uncovered_pack_frameworks = [
            name for name in required_unique if name.lower() not in detected
        ]
    pack_ids = [pack["pack_id"] for pack in packs]
    return {
        "pack_id": pack_ids[0] if len(pack_ids) == 1 else "+".join(pack_ids),
        "pack_ids": pack_ids,
        "passed": not blocking,
        "finding_count": len(blocking),
        "gate_finding_count": len(gate_findings),
        "teach_only_finding_count": len(teach_findings),
        "rule_ids": selected,
        "enforcement": {rule_id: enforcement[rule_id] for rule_id in selected},
        "not_covered": not_covered,
        "pack_frameworks": required_unique,
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
    packs = select_packs(args.repo_root, args.pack)
    allowed = set()
    for pack in packs:
        allowed.update(check_rule_ids(pack))
    selected = args.rule or list(allowed)
    unknown = [rule_id for rule_id in selected if rule_id not in allowed]
    if unknown:
        print(f"Unknown pack rule ids: {', '.join(unknown)}", file=sys.stderr)
        return 2

    try:
        result = run_check(
            repo_root=args.repo_root,
            rule_ids=selected,
            changed_files=args.changed_file or None,
            override_path=args.override_file,
            packs=packs,
        )
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    report = build_report(
        packs=packs,
        repo_root=args.repo_root,
        selected=selected,
        result=result,
        report_collisions=args.report_collisions,
    )

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        _print_text(report, args.repo_root, args.report_collisions)

    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
