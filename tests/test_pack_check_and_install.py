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
    check_rule_ids,
    engine_rule_ids,
    invariant_skill_dirs,
    load_all_packs,
    load_pack,
    load_pack_by_id,
    pack_skill_globs,
    teach_only_rule_ids,
)

DIRTY = PACK_ROOT / "fixtures" / "dirty"
CLEAN = PACK_ROOT / "fixtures" / "clean"
CONTROL = PACK_ROOT / "agent-runs" / "control"
TREATMENT = PACK_ROOT / "agent-runs" / "treatment"
JPQL = "java.reliability.no-jpql-null-or-lower-on-optional-filter"
TX_IO = "java.architecture.no-service-layer-transactional-external-io"
REST_TEMPLATE = (
    "java.architecture.no-service-layer-rest-template-without-timeout-shaping"
)
PORTABLE_JAVA_GATES = (JPQL, TX_IO, REST_TEMPLATE)


def test_invariant_skills_are_model_invocable() -> None:
    names: list[str] = []
    for pack in load_all_packs():
        globs_by_name = {skill["name"]: skill["globs"] for skill in pack["skills"]}
        for skill_dir in invariant_skill_dirs(pack_id=pack["pack_id"]):
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            frontmatter = yaml.safe_load(text.split("---", 2)[1])
            assert frontmatter.get("disable-model-invocation") is not True
            assert frontmatter["name"] == skill_dir.name
            assert frontmatter["paths"] == globs_by_name[skill_dir.name]
            names.append(frontmatter["name"])
            assert "do not use for" in frontmatter["description"].lower()
    assert len(names) == len(set(names))


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
    result = run_check(repo_root=DIRTY, rule_ids=list(PORTABLE_JAVA_GATES))
    fired = {finding.rule_id for finding in result.findings}
    assert fired == set(PORTABLE_JAVA_GATES)


def test_clean_fixture_has_no_findings() -> None:
    result = run_check(repo_root=CLEAN)
    assert result.findings == ()


def test_all_java_pack_check_rules_are_checkers() -> None:
    assert set(checker_rule_ids()) == set(check_rule_ids())
    assert teach_only_rule_ids() == ()
    assert engine_rule_ids() == ()
    assert set(PORTABLE_JAVA_GATES) <= set(check_rule_ids())


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
    assert payload["not_covered"] == []
    assert payload["coverage"] is not None
    assert payload["pack_frameworks"] == ["spring", "jpa"]
    assert payload["uncovered_pack_frameworks"] == []
    assert payload["gate_finding_count"] >= 1
    assert payload["teach_only_finding_count"] == 0
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


def test_rest_template_finding_fails_ci() -> None:
    check = PACK_ROOT / "scripts" / "check.py"
    default = subprocess.run(
        [sys.executable, str(check), "--repo-root", str(DIRTY), "--rule", REST_TEMPLATE],
        check=False,
        capture_output=True,
        text=True,
    )
    assert default.returncode == 1


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


def test_stopthatslop_review_and_check() -> None:
    stopthatslop = PACK_ROOT / "scripts" / "stopthatslop.py"
    review = subprocess.run(
        [sys.executable, str(stopthatslop), "review"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert review.returncode == 0, review.stderr
    assert "no-jpql-null-or-lower  checker" in review.stdout
    assert "no-transactional-external-io  checker" in review.stdout
    assert "no-rest-template-without-timeout  checker" in review.stdout
    check = subprocess.run(
        [
            sys.executable,
            str(stopthatslop),
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
        install(target=tmp_path, pack="java")


def test_install_writes_pack_index_not_sibling_skills(tmp_path: Path) -> None:
    written, hits = install(target=tmp_path, pack="java")
    assert hits == ()
    skill_md = (
        tmp_path / ".agents" / "skills" / "stopthatslop" / PACK_INDEX_NAME / "SKILL.md"
    )
    assert skill_md in written
    text = skill_md.read_text(encoding="utf-8")
    assert "name: stopthatslop-java-spring" in text
    references = tmp_path / ".agents" / "skills" / "stopthatslop" / PACK_INDEX_NAME / "references"
    assert (references / "no-jpql-null-or-lower.md").exists()
    assert not (
        tmp_path / ".agents" / "skills" / "stopthatslop" / "no-jpql-null-or-lower"
    ).exists()
    manifest = yaml.safe_load(
        (
            tmp_path / ".agents" / "skills" / "stopthatslop" / PACK_INDEX_NAME / "installed.yaml"
        ).read_text(encoding="utf-8")
    )
    assert manifest["version"] == load_pack()["version"]
    assert not (tmp_path / "AGENTS.md").exists()
    mdc = tmp_path / ".cursor" / "rules" / "stopthatslop-no-jpql-null-or-lower.mdc"
    assert mdc.exists()
    mdc_text = mdc.read_text(encoding="utf-8")
    mdc_fm = yaml.safe_load(mdc_text.split("---", 2)[1])
    assert mdc_fm["alwaysApply"] is False
    assert mdc_fm["globs"] == "**/*Repository.java"
    assert "alwaysApply: true" not in mdc_text


def test_install_force_reports_collision_and_snapshots(tmp_path: Path) -> None:
    marker = tmp_path / ".cursor" / "skills" / "engineering-rules" / "SKILL.md"
    marker.parent.mkdir(parents=True)
    marker.write_text("---\nname: engineering-rules\n---\n", encoding="utf-8")
    first, hits = install(target=tmp_path, pack="java", force=True)
    assert any("engineering-rules" in hit for hit in hits)
    assert first
    install(target=tmp_path, pack="java", force=True)
    snapshot = tmp_path / ".stopthatslop" / "versions" / "stopthatslop" / PACK_INDEX_NAME
    assert snapshot.exists()
    restored = rollback(target=tmp_path, pack="java")
    assert restored


def test_export_writes_index_and_invariant_references(tmp_path: Path) -> None:
    out = tmp_path / "exported"
    written = export_pack(out=out)
    assert (out / "SKILL.md") in written
    assert (out / "pack.yaml") in written
    assert len(list((out / "references").glob("*.md"))) == len(invariant_skill_dirs())


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


def test_pack_checker_is_quiet_on_treatment_query() -> None:
    result = run_check(
        repo_root=TREATMENT,
        rule_ids=["java.reliability.no-jpql-null-or-lower-on-optional-filter"],
    )
    assert result.findings == ()


def test_install_python_pack_writes_glob_mdc(tmp_path: Path) -> None:
    python = load_pack_by_id("python")
    globs = pack_skill_globs(python)
    written, hits = install(target=tmp_path, pack="python")
    assert hits == ()
    skill_md = (
        tmp_path
        / ".agents"
        / "skills"
        / "stopthatslop"
        / "stopthatslop-python-fastapi"
        / "SKILL.md"
    )
    assert skill_md.exists()
    assert skill_md in written
    mdc = tmp_path / ".cursor" / "rules" / "stopthatslop-no-except-exception-pass.mdc"
    assert mdc.exists()
    text = mdc.read_text(encoding="utf-8")
    frontmatter = yaml.safe_load(text.split("---", 2)[1])
    assert frontmatter["alwaysApply"] is False
    assert frontmatter["globs"] == globs["no-except-exception-pass"]
    assert "alwaysApply: true" not in text
    for path in (tmp_path / ".cursor" / "rules").glob("stopthatslop-*.mdc"):
        body = path.read_text(encoding="utf-8")
        assert "alwaysApply: true" not in body
        fm = yaml.safe_load(body.split("---", 2)[1])
        assert fm["alwaysApply"] is False
        assert fm["globs"] == globs[path.stem.removeprefix("stopthatslop-")]


def test_install_does_not_refuse_agents_md(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_text("# existing house notes\n", encoding="utf-8")
    written, hits = install(target=tmp_path, pack="java")
    assert hits == ()
    assert written
    assert (tmp_path / "AGENTS.md").read_text(encoding="utf-8") == "# existing house notes\n"


def test_install_copies_claude_and_github_when_present(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".github").mkdir()
    install(target=tmp_path, pack="python")
    assert (
        tmp_path
        / ".claude"
        / "skills"
        / "stopthatslop"
        / "stopthatslop-python-fastapi"
        / "SKILL.md"
    ).exists()
    instructions = (
        tmp_path
        / ".github"
        / "instructions"
        / "stopthatslop-python-fastapi.instructions.md"
    )
    assert instructions.exists()
    frontmatter = yaml.safe_load(instructions.read_text(encoding="utf-8").split("---", 2)[1])
    assert "**/*.py" in str(frontmatter["applyTo"])


def test_broken_detector_fails_the_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import run as run_mod

    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    def boom(_source: str, filename: str = "") -> list:
        raise RuntimeError("boom")

    catalog = run_mod.load_all_detectors()
    python_id = next(rid for rid, det in catalog.items() if det.lang == "python")

    def fake_load() -> dict:
        return {
            python_id: run_mod.Detector(
                rule_id=python_id, lang="python", detect=boom
            )
        }

    monkeypatch.setattr(run_mod, "load_all_detectors", fake_load)
    with pytest.raises(RuntimeError, match="boom"):
        run_mod.run_mine(repo_root=tmp_path, rule_ids=[python_id])


def test_install_cli_requires_pack(tmp_path: Path) -> None:
    stopthatslop = PACK_ROOT / "scripts" / "stopthatslop.py"
    completed = subprocess.run(
        [sys.executable, str(stopthatslop), "install", "--target", str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "--pack" in completed.stderr


def test_console_entry_review() -> None:
    from stopthatslop_cli import main as cli_main

    assert cli_main(["review"]) == 0
