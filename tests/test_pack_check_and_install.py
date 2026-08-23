from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from check import run_check
from export import export_pack
from install import install, rollback
from pack_lib import (
    PACK_INDEX_NAME,
    PACK_ROOT,
    checker_rule_ids,
    engine_rule_ids,
    invariant_skill_dirs,
    load_all_packs,
    load_pack,
    teach_only_rule_ids,
)

DIRTY = PACK_ROOT / "fixtures" / "dirty"
CLEAN = PACK_ROOT / "fixtures" / "clean"
CONTROL = PACK_ROOT / "agent-runs" / "control"
TREATMENT = PACK_ROOT / "agent-runs" / "treatment"
JPQL = "java.reliability.no-jpql-null-or-lower-on-optional-filter"
REST_TEMPLATE = (
    "java.architecture.no-service-layer-rest-template-without-timeout-shaping"
)


def test_invariant_skills_are_explicit_invoke() -> None:
    names: list[str] = []
    for pack in load_all_packs():
        for skill_dir in invariant_skill_dirs(pack_id=pack["pack_id"]):
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            frontmatter = yaml.safe_load(text.split("---", 2)[1])
            assert frontmatter["disable-model-invocation"] is True
            assert frontmatter["name"] == skill_dir.name
            names.append(frontmatter["name"])
            assert "do not use for" in frontmatter["description"].lower()
    assert len(names) == len(set(names)) == 19


def test_service_globs_overlap_so_those_skills_stay_explicit() -> None:
    pack = load_pack()
    service_skills = [
        skill["name"] for skill in pack["skills"] if skill["globs"] == "**/*Service.java"
    ]
    assert service_skills == [
        "no-transactional-external-io",
        "no-rest-template-without-timeout",
    ]


def test_dirty_fixture_fails_on_all_engine_rules() -> None:
    result = run_check(repo_root=DIRTY)
    fired = {finding.rule_id for finding in result.findings}
    assert fired == set(engine_rule_ids())


def test_clean_fixture_has_no_findings() -> None:
    result = run_check(repo_root=CLEAN)
    assert result.findings == ()


def test_only_jpql_is_checker() -> None:
    assert checker_rule_ids() == (JPQL,)
    assert set(teach_only_rule_ids()) == set(engine_rule_ids()) - {JPQL}


def test_check_cli_exit_codes() -> None:
    check = PACK_ROOT / "scripts" / "check.py"
    dirty = subprocess.run(
        [sys.executable, str(check), "--repo-root", str(DIRTY)],
        check=False,
        capture_output=True,
        text=True,
    )
    clean = subprocess.run(
        [sys.executable, str(check), "--repo-root", str(CLEAN)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert dirty.returncode == 1
    assert clean.returncode == 0


def test_json_includes_enforcement_coverage_and_not_covered() -> None:
    check = PACK_ROOT / "scripts" / "check.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(check),
            "--repo-root",
            str(DIRTY),
            "--format",
            "json",
            "--report-collisions",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 1
    payload = json.loads(completed.stdout)
    assert payload["passed"] is False
    assert payload["enforcement"][JPQL] == "checker"
    assert JPQL not in payload["not_covered"]
    assert set(payload["not_covered"]) == set(teach_only_rule_ids())
    assert payload["coverage"] is not None
    assert payload["pack_frameworks"] == ["spring", "jpa"]
    assert payload["uncovered_pack_frameworks"] == []
    assert payload["gate_finding_count"] >= 1
    assert payload["teach_only_finding_count"] >= 1
    assert payload["collisions"] == []


def test_spring_boot_pom_covers_pack_frameworks_without_override(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text(
        """
<project>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.4.0</version>
  </parent>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
  </dependencies>
</project>
""".strip(),
        encoding="utf-8",
    )
    check = PACK_ROOT / "scripts" / "check.py"
    completed = subprocess.run(
        [sys.executable, str(check), "--repo-root", str(tmp_path), "--format", "json"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    payload = json.loads(completed.stdout)
    assert payload["uncovered_pack_frameworks"] == []
    assert "spring" in (payload.get("coverage") or {}).get("repo_frameworks", [])
    assert "jpa" in (payload.get("coverage") or {}).get("repo_frameworks", [])


def test_teach_only_finding_does_not_fail_ci() -> None:
    check = PACK_ROOT / "scripts" / "check.py"
    default = subprocess.run(
        [sys.executable, str(check), "--repo-root", str(DIRTY), "--rule", REST_TEMPLATE],
        check=False,
        capture_output=True,
        text=True,
    )
    forced = subprocess.run(
        [
            sys.executable,
            str(check),
            "--repo-root",
            str(DIRTY),
            "--rule",
            REST_TEMPLATE,
            "--fail-on-teach-only",
            "--format",
            "json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert default.returncode == 0
    assert forced.returncode == 1
    payload = json.loads(forced.stdout)
    assert payload["not_covered"] == [REST_TEMPLATE]
    assert payload["teach_only_finding_count"] == 1


def test_ci_script_exit_codes() -> None:
    script = PACK_ROOT / "scripts" / "ci.sh"
    env = os.environ.copy()
    env["ENGINE_PYTHON"] = sys.executable
    dirty = subprocess.run(
        ["bash", str(script), str(DIRTY)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    clean = subprocess.run(
        ["bash", str(script), str(CLEAN)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert dirty.returncode == 1, dirty.stderr + dirty.stdout
    assert clean.returncode == 0, clean.stderr + clean.stdout
    assert "not_covered (teach-only)" in dirty.stdout


def test_deslop_review_and_check() -> None:
    deslop = PACK_ROOT / "scripts" / "deslop.py"
    review = subprocess.run(
        [sys.executable, str(deslop), "review"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert review.returncode == 0, review.stderr
    assert "no-jpql-null-or-lower  checker" in review.stdout
    check = subprocess.run(
        [
            sys.executable,
            str(deslop),
            "check",
            "--repo-root",
            str(CLEAN),
            "--format",
            "json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stderr
    payload = json.loads(check.stdout)
    assert payload["passed"] is True
    assert payload["pack_frameworks"] == ["spring", "jpa"]


def test_install_refuses_existing_rules_marker_repo(tmp_path: Path) -> None:
    marker = tmp_path / ".cursor" / "skills" / "engineering-rules" / "SKILL.md"
    marker.parent.mkdir(parents=True)
    marker.write_text("---\nname: engineering-rules\n---\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="Refusing to install"):
        install(target=tmp_path)


def test_install_writes_pack_index_not_sibling_skills(tmp_path: Path) -> None:
    written, hits = install(target=tmp_path)
    assert hits == ()
    skill_md = (
        tmp_path / ".agents" / "skills" / "deslop" / PACK_INDEX_NAME / "SKILL.md"
    )
    assert skill_md in written
    text = skill_md.read_text(encoding="utf-8")
    assert "name: deslop-java-spring" in text
    references = tmp_path / ".agents" / "skills" / "deslop" / PACK_INDEX_NAME / "references"
    assert (references / "no-jpql-null-or-lower.md").exists()
    assert not (
        tmp_path / ".agents" / "skills" / "deslop" / "no-jpql-null-or-lower"
    ).exists()
    manifest = yaml.safe_load(
        (
            tmp_path / ".agents" / "skills" / "deslop" / PACK_INDEX_NAME / "installed.yaml"
        ).read_text(encoding="utf-8")
    )
    assert manifest["version"] == load_pack()["version"]
    assert not (tmp_path / "AGENTS.md").exists()


def test_install_force_reports_collision_and_snapshots(tmp_path: Path) -> None:
    marker = tmp_path / ".cursor" / "skills" / "engineering-rules" / "SKILL.md"
    marker.parent.mkdir(parents=True)
    marker.write_text("---\nname: engineering-rules\n---\n", encoding="utf-8")
    first, hits = install(target=tmp_path, force=True)
    assert any("engineering-rules" in hit for hit in hits)
    assert first
    install(target=tmp_path, force=True)
    snapshot = tmp_path / ".deslop" / "versions" / "deslop" / PACK_INDEX_NAME
    assert snapshot.exists()
    restored = rollback(target=tmp_path)
    assert restored


def test_export_writes_index_and_invariant_references(tmp_path: Path) -> None:
    out = tmp_path / "exported"
    written = export_pack(out=out)
    assert (out / "SKILL.md") in written
    assert (out / "pack.yaml") in written
    assert len(list((out / "references").glob("*.md"))) == 3


def test_composer_control_wrote_jpql_antipattern() -> None:
    source = (
        CONTROL / "src" / "main" / "java" / "example" / "repo" / "CustomerRepository.java"
    ).read_text(encoding="utf-8")
    assert "IS NULL OR" in source
    assert "LOWER(" in source


def test_composer_treatment_followed_jpql_skill() -> None:
    source = (
        TREATMENT / "src" / "main" / "java" / "example" / "repo" / "CustomerRepository.java"
    ).read_text(encoding="utf-8")
    assert "IS NULL OR" not in source
    assert ":status = ''" in source or ':status = ""' in source


def test_pack_checker_flags_concatenated_control_query() -> None:
    result = run_check(
        repo_root=CONTROL,
        rule_ids=["java.reliability.no-jpql-null-or-lower-on-optional-filter"],
    )
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == (
        "java.reliability.no-jpql-null-or-lower-on-optional-filter"
    )
