"""Shared paths and pack metadata for the Java skill-pack experiment."""

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
    return tuple(data["engine"]["rule_ids"])


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
    for rule_id in engine_rule_ids(data):
        if rule_id not in mapping:
            raise SystemExit(f"engine rule {rule_id} has no skill enforcement")
    return mapping


def checker_rule_ids(pack: dict[str, Any] | None = None) -> tuple[str, ...]:
    data = pack if pack is not None else load_pack()
    mapping = skill_enforcement_map(data)
    return tuple(
        rule_id
        for rule_id in engine_rule_ids(data)
        if mapping[rule_id] == ENFORCEMENT_CHECKER
    )


def teach_only_rule_ids(pack: dict[str, Any] | None = None) -> tuple[str, ...]:
    data = pack if pack is not None else load_pack()
    mapping = skill_enforcement_map(data)
    return tuple(
        rule_id
        for rule_id in engine_rule_ids(data)
        if mapping[rule_id] == ENFORCEMENT_TEACH_ONLY
    )


def pack_frameworks(pack: dict[str, Any] | None = None) -> tuple[str, ...]:
    data = pack if pack is not None else load_pack()
    return tuple(data.get("frameworks") or ())


def skill_dirs() -> tuple[Path, ...]:
    return tuple(sorted(path for path in SKILLS_ROOT.iterdir() if path.is_dir()))


def invariant_skill_dirs() -> tuple[Path, ...]:
    return tuple(path for path in skill_dirs() if path.name != PACK_INDEX_NAME)


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
