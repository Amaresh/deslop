"""Shared paths and pack metadata for deslop packs."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

PACK_ROOT = Path(__file__).resolve().parents[1]
SKILLS_ROOT = PACK_ROOT / "skills"
ENGINE_SRC = PACK_ROOT / "src"
PACK_YAML = PACK_ROOT / "pack.yaml"
PACK_INDEX_NAME = "deslop-java-spring"
ENFORCEMENT_CHECKER = "checker"
ENFORCEMENT_TEACH_ONLY = "teach-only"
VALID_ENFORCEMENT = frozenset({ENFORCEMENT_CHECKER, ENFORCEMENT_TEACH_ONLY})


def prefer_engine_src() -> None:
    """Put this pack's engine first even if PYTHONPATH already has another copy."""

    rendered = str(ENGINE_SRC)
    try:
        sys.path.remove(rendered)
    except ValueError:
        pass
    sys.path.insert(0, rendered)

DEFAULT_COLLISION_MARKERS = (
    ".cursor/skills/engineering-rules/SKILL.md",
    ".cursor/rules/engineering-rules.mdc",
    "AGENTS.md",
)


def collision_markers(pack: dict[str, Any] | None = None) -> tuple[str, ...]:
    data = pack if pack is not None else load_pack()
    extra = data.get("collisions") or []
    return tuple([*DEFAULT_COLLISION_MARKERS, *extra])


def load_pack() -> dict[str, Any]:
    return yaml.safe_load(PACK_YAML.read_text(encoding="utf-8"))


def engine_rule_ids(pack: dict[str, Any] | None = None) -> tuple[str, ...]:
    data = pack if pack is not None else load_pack()
    return tuple((data.get("engine") or {}).get("rule_ids") or ())


def mine_rule_ids(pack: dict[str, Any] | None = None) -> tuple[str, ...]:
    data = pack if pack is not None else load_pack()
    mine = data.get("mine") or {}
    return tuple(mine.get("rule_ids") or ())


def check_rule_ids(pack: dict[str, Any] | None = None) -> tuple[str, ...]:
    data = pack if pack is not None else load_pack()
    return tuple(dict.fromkeys([*engine_rule_ids(data), *mine_rule_ids(data)]))


def skill_enforcement_map(pack: dict[str, Any] | None = None) -> dict[str, str]:
    data = pack if pack is not None else load_pack()
    mapping: dict[str, str] = {}
    missing: list[str] = []
    invalid: list[str] = []
    for skill in data.get("skills") or []:
        name = str(skill.get("name") or skill.get("rule_id") or "<unnamed>")
        rule_id = skill.get("rule_id")
        enforcement = skill.get("enforcement")
        if not rule_id:
            missing.append(name)
            continue
        if enforcement not in VALID_ENFORCEMENT:
            invalid.append(f"{name}={enforcement!r}")
            continue
        mapping[str(rule_id)] = str(enforcement)
    if missing or invalid:
        parts: list[str] = []
        if missing:
            parts.append(f"skills missing rule_id: {', '.join(missing)}")
        if invalid:
            parts.append(
                "enforcement must be checker|teach-only: " + ", ".join(invalid)
            )
        raise SystemExit("; ".join(parts))
    for rule_id in check_rule_ids(data):
        if rule_id not in mapping:
            raise SystemExit(f"check rule {rule_id} has no skill enforcement")
    return mapping


def checker_rule_ids(pack: dict[str, Any] | None = None) -> tuple[str, ...]:
    data = pack if pack is not None else load_pack()
    mapping = skill_enforcement_map(data)
    return tuple(
        rule_id
        for rule_id in check_rule_ids(data)
        if mapping[rule_id] == ENFORCEMENT_CHECKER
    )


def teach_only_rule_ids(pack: dict[str, Any] | None = None) -> tuple[str, ...]:
    data = pack if pack is not None else load_pack()
    mapping = skill_enforcement_map(data)
    return tuple(
        rule_id
        for rule_id in check_rule_ids(data)
        if mapping[rule_id] == ENFORCEMENT_TEACH_ONLY
    )


def pack_frameworks(pack: dict[str, Any] | None = None) -> tuple[str, ...]:
    data = pack if pack is not None else load_pack()
    return tuple(data.get("frameworks") or ())


PACK_ALIASES = {
    "java": "deslop-java-spring-v1",
    "python": "deslop-python-fastapi-v1",
    "ts": "deslop-ts-node-v1",
    "typescript": "deslop-ts-node-v1",
    "go": "deslop-go-v1",
    "android": "deslop-android-v1",
}


def load_pack_by_id(pack_id: str) -> dict[str, Any]:
    wanted = PACK_ALIASES.get(pack_id, pack_id)
    for path in all_pack_yamls():
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if data and data.get("pack_id") == wanted:
            return data
    raise SystemExit(f"unknown pack {pack_id!r}")


def skill_dirs(skills_root: Path | None = None) -> tuple[Path, ...]:
    root = skills_root if skills_root is not None else SKILLS_ROOT
    if not root.is_dir():
        return ()
    return tuple(sorted(path for path in root.iterdir() if path.is_dir()))


def parse_skill_frontmatter(skill_dir: Path) -> dict[str, Any]:
    text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
    if not text.startswith("---"):
        return {}
    _, fm, _ = text.split("---", 2)
    return yaml.safe_load(fm) or {}


def _skill_pack_id(skill_dir: Path) -> str | None:
    metadata = parse_skill_frontmatter(skill_dir).get("metadata") or {}
    return metadata.get("pack")


def _is_pack_index(skill_dir: Path) -> bool:
    metadata = parse_skill_frontmatter(skill_dir).get("metadata") or {}
    return metadata.get("kind") == "pack-index"


def all_pack_yamls() -> tuple[Path, ...]:
    """Root pack.yaml plus per-pack pack.yaml files under skills/."""

    nested = sorted(SKILLS_ROOT.glob("*/pack.yaml"))
    return tuple([PACK_YAML, *nested])


def load_all_packs() -> list[dict[str, Any]]:
    return [yaml.safe_load(path.read_text(encoding="utf-8")) for path in all_pack_yamls()]


def invariant_skill_dirs(
    pack_id: str | None = None,
    *,
    skills_root: Path | None = None,
) -> tuple[Path, ...]:
    wanted = pack_id if pack_id is not None else load_pack()["pack_id"]
    missing: list[str] = []
    matched: list[Path] = []
    for path in skill_dirs(skills_root):
        if not (path / "SKILL.md").exists():
            continue
        if _is_pack_index(path):
            continue
        pid = _skill_pack_id(path)
        if not pid:
            missing.append(path.name)
            continue
        if pid == wanted:
            matched.append(path)
    if missing:
        raise SystemExit(
            "skills missing metadata.pack (would be silently dropped from "
            "install/export): " + ", ".join(sorted(missing))
        )
    return tuple(matched)


def pack_index_dir() -> Path:
    return SKILLS_ROOT / PACK_INDEX_NAME


def collision_hits(target: Path) -> tuple[str, ...]:
    hits: list[str] = []
    for marker in collision_markers():
        if (target / marker).exists():
            hits.append(marker)
    return tuple(hits)


def format_collision_report(target: Path, hits: tuple[str, ...]) -> str:
    if not hits:
        return f"No overlapping agent instructions under {target}"
    lines = [f"Collision report for {target}:"]
    lines.extend(f"  - {hit}" for hit in hits)
    return "\n".join(lines)
