from __future__ import annotations

import json
import subprocess
import sys

import yaml
from pack_lib import (
    SKILLS_ROOT,
    all_pack_yamls,
    check_rule_ids,
    invariant_skill_dirs,
    load_all_packs,
    load_pack,
    load_pack_by_id,
    mine_rule_ids,
    pack_folder_name,
    pack_glob_union,
    parse_skill_frontmatter,
)

ECOSYSTEM_PACK_IDS = {
    "stopthatslop-python-fastapi": "stopthatslop-python-fastapi-v1",
    "stopthatslop-ts-node": "stopthatslop-ts-node-v1",
    "stopthatslop-go": "stopthatslop-go-v1",
    "stopthatslop-android": "stopthatslop-android-v1",
}


def test_ecosystem_packs_declare_pack_yaml() -> None:
    for pack_dir, expected_id in ECOSYSTEM_PACK_IDS.items():
        path = SKILLS_ROOT / pack_dir / "pack.yaml"
        assert path in all_pack_yamls()
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert data["pack_id"] == expected_id
        assert data["invocation"] == "model"
        assert data["install_namespace"] == "stopthatslop"
        assert "collisions" not in data
        assert data["engine"]["rule_ids"] == []
        assert mine_rule_ids(data)


def test_python_and_ts_keep_some_teach_only() -> None:
    python = load_pack_by_id("python")
    ts_pack = load_pack_by_id("ts")
    assert {s["enforcement"] for s in python["skills"]} == {"checker", "teach-only"}
    assert {s["enforcement"] for s in ts_pack["skills"]} == {"checker", "teach-only"}
    assert len(mine_rule_ids(python)) == 8
    assert len(mine_rule_ids(ts_pack)) == 9


def test_go_and_android_are_all_checkers() -> None:
    for alias, count in (("go", 8), ("android", 3)):
        pack = load_pack_by_id(alias)
        assert all(skill["enforcement"] == "checker" for skill in pack["skills"])
        assert len(mine_rule_ids(pack)) == count
        assert set(check_rule_ids(pack)) == set(mine_rule_ids(pack))


def test_ecosystem_skill_dirs_belong_to_their_pack() -> None:
    for pack_dir, pack_id in ECOSYSTEM_PACK_IDS.items():
        skills = invariant_skill_dirs(pack_id=pack_id)
        assert skills
        for skill_dir in skills:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            frontmatter = yaml.safe_load(text.split("---", 2)[1])
            metadata = frontmatter["metadata"]
            assert metadata["pack"] == pack_id
            assert metadata.get("kind") != "pack-index"
            assert "do not use for" in frontmatter["description"].lower()
            assert frontmatter.get("disable-model-invocation") is not True


def test_pack_index_skills_use_union_paths() -> None:
    assert load_pack()["invocation"] == "model"
    for pack in load_all_packs():
        skill_dir = SKILLS_ROOT / pack_folder_name(pack)
        frontmatter = parse_skill_frontmatter(skill_dir)
        assert frontmatter.get("disable-model-invocation") is not True
        union = pack_glob_union(pack)
        paths = frontmatter.get("paths")
        if len(union) == 1:
            assert paths == union[0]
        else:
            assert list(paths) == list(union)


def test_java_tooling_stays_scoped_to_java_pack() -> None:
    java_ids = {skill["name"] for skill in load_pack()["skills"]}
    java_skill_names = {skill_dir.name for skill_dir in invariant_skill_dirs()}
    assert java_skill_names == java_ids


def test_every_rule_has_a_bad_and_good_code_pair() -> None:
    for pack_dir in ECOSYSTEM_PACK_IDS:
        pack = yaml.safe_load(
            (SKILLS_ROOT / pack_dir / "pack.yaml").read_text(encoding="utf-8")
        )
        for skill in pack["skills"]:
            skill_dir = SKILLS_ROOT / skill["name"]
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            assert "## Do" in text, skill["name"]
            assert "## Do not" in text, skill["name"]


def test_missing_pack_metadata_is_fatal(tmp_path) -> None:
    skill = tmp_path / "orphan-skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: orphan-skill\nmetadata: {}\n---\n\n# orphan\n",
        encoding="utf-8",
    )
    try:
        invariant_skill_dirs(pack_id="stopthatslop-java-spring-v1", skills_root=tmp_path)
    except SystemExit as exc:
        assert "orphan-skill" in str(exc)
        return
    raise AssertionError("expected SystemExit for missing metadata.pack")


def test_load_pack_aliases() -> None:
    assert load_pack_by_id("java")["pack_id"] == "stopthatslop-java-spring-v1"
    assert load_pack_by_id("python")["pack_id"] == "stopthatslop-python-fastapi-v1"
    packs = {data["pack_id"] for data in load_all_packs()}
    assert packs >= set(ECOSYSTEM_PACK_IDS.values()) | {"stopthatslop-java-spring-v1"}
