from __future__ import annotations

import yaml
from pack_lib import (
    SKILLS_ROOT,
    all_pack_yamls,
    invariant_skill_dirs,
    load_all_packs,
    load_pack,
)

ECOSYSTEM_PACK_IDS = {
    "deslop-python-fastapi": "deslop-python-fastapi-v1",
    "deslop-ts-node": "deslop-ts-node-v1",
}


def test_ecosystem_packs_declare_pack_yaml() -> None:
    for pack_dir, expected_id in ECOSYSTEM_PACK_IDS.items():
        path = SKILLS_ROOT / pack_dir / "pack.yaml"
        assert path in all_pack_yamls()
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert data["pack_id"] == expected_id
        assert data["invocation"] == "explicit"
        assert data["install_namespace"] == "deslop"
        assert data["engine"]["rule_ids"] == []
        assert len(data["skills"]) == 8


def test_ecosystem_skills_are_all_teach_only() -> None:
    packs = {data["pack_id"]: data for data in load_all_packs()}
    root_engine_rules = set(load_pack()["engine"]["rule_ids"])
    for pack_id in ECOSYSTEM_PACK_IDS.values():
        for skill in packs[pack_id]["skills"]:
            assert skill["enforcement"] == "teach-only"
            rule_id = skill["rule_id"]
            assert rule_id not in root_engine_rules
        names = [skill["name"] for skill in packs[pack_id]["skills"]]
        assert len(names) == len(set(names)) == 8


def test_ecosystem_skill_dirs_belong_to_their_pack() -> None:
    for pack_dir, pack_id in ECOSYSTEM_PACK_IDS.items():
        skills = invariant_skill_dirs(pack_id=pack_id)
        assert len(skills) == 8
        for skill_dir in skills:
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            frontmatter = yaml.safe_load(text.split("---", 2)[1])
            metadata = frontmatter["metadata"]
            assert metadata["pack"] == pack_id
            assert metadata.get("kind") != "pack-index"
            assert "do not use for" in frontmatter["description"].lower()
            assert frontmatter["disable-model-invocation"] is True


def test_java_tooling_stays_scoped_to_java_pack() -> None:
    java_ids = {skill["name"] for skill in load_pack()["skills"]}
    java_skill_names = {skill_dir.name for skill_dir in invariant_skill_dirs()}
    assert java_skill_names == java_ids


def test_every_rule_has_a_bad_and_good_code_pair() -> None:
    for pack_dir in ECOSYSTEM_PACK_IDS:
        for skill_dir in sorted((SKILLS_ROOT / pack_dir).iterdir()):
            if not skill_dir.is_dir():
                continue
            text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
            assert "## Do" in text, skill_dir.name
            assert "## Do not" in text, skill_dir.name
