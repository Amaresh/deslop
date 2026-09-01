"""Shared paths and pack metadata for stopthatslop packs."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

PACK_ROOT = Path(__file__).resolve().parents[1]
SKILLS_ROOT = PACK_ROOT / "skills"
ENGINE_SRC = PACK_ROOT / "src"
PACK_YAML = PACK_ROOT / "pack.yaml"
# Default Java pack-index folder. Prefer pack_folder_name(pack) for a given pack.
PACK_INDEX_NAME = "stopthatslop-java-spring"
ENFORCEMENT_CHECKER = "checker"
ENFORCEMENT_TEACH_ONLY = "teach-only"
VALID_ENFORCEMENT = frozenset({ENFORCEMENT_CHECKER, ENFORCEMENT_TEACH_ONLY})
_PACK_FOLDER_VERSION_SUFFIX = re.compile(r"-v\d+$")


def prefer_engine_src() -> None:
    """No-op unless a leftover src/engineering_rules tree is present."""

    if not (ENGINE_SRC / "engineering_rules").is_dir():
        return
    rendered = str(ENGINE_SRC)
    try:
        sys.path.remove(rendered)
    except ValueError:
        pass
    sys.path.insert(0, rendered)

# Overlapping always-on Java agent rules. Presence refuses install unless --force.
DEFAULT_COLLISION_MARKERS = (
    ".cursor/skills/engineering-rules/SKILL.md",
    ".cursor/rules/engineering-rules.mdc",
)

# Buyers already have AGENTS.md. Report it; never refuse install for it.
REPORT_ONLY_COLLISION_MARKERS = ("AGENTS.md",)


def collision_markers(pack: dict[str, Any] | None = None) -> tuple[str, ...]:
    data = pack if pack is not None else load_pack()
    extra = data.get("collisions") or []
    return tuple([*DEFAULT_COLLISION_MARKERS, *extra])


def report_collision_markers(pack: dict[str, Any] | None = None) -> tuple[str, ...]:
    return tuple([*collision_markers(pack), *REPORT_ONLY_COLLISION_MARKERS])


def load_pack() -> dict[str, Any]:
    return yaml.safe_load(PACK_YAML.read_text(encoding="utf-8"))


def pack_folder_name(pack: dict[str, Any] | None = None) -> str:
    """Directory name under skills/ and the installed pack-index folder."""

    data = pack if pack is not None else load_pack()
    return _PACK_FOLDER_VERSION_SUFFIX.sub("", str(data["pack_id"]))


def pack_skill_globs(pack: dict[str, Any] | None = None) -> dict[str, str]:
    data = pack if pack is not None else load_pack()
    return {str(skill["name"]): str(skill["globs"]) for skill in data.get("skills") or []}


def pack_glob_union(pack: dict[str, Any] | None = None) -> tuple[str, ...]:
    data = pack if pack is not None else load_pack()
    return tuple(dict.fromkeys(str(skill["globs"]) for skill in data.get("skills") or []))


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


_OVERRIDE_FILENAMES = (".engineering-rules.yaml", ".engineering-rules.yml")
_SPRING_POM_TOKENS = ("springframework", "spring-boot")
_JPA_POM_TOKENS = ("data-jpa", "hibernate", "jakarta.persistence")
_SPRING_GRADLE_TOKENS = ("org.springframework", "spring-boot")
_JPA_GRADLE_TOKENS = ("data-jpa", "hibernate")


def detect_java_frameworks(
    repo_root: Path, override_path: Path | None = None
) -> tuple[str, ...]:
    """Spring/JPA signals from pom/Gradle, replaced by override frameworks if set."""

    root = repo_root.resolve()
    found: list[str] = []
    pom = root / "pom.xml"
    if pom.is_file():
        try:
            text = pom.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        if any(token in text for token in _SPRING_POM_TOKENS):
            found.append("spring")
        if any(token in text for token in _JPA_POM_TOKENS):
            found.append("jpa")
    for gradle_name in ("build.gradle", "build.gradle.kts"):
        gradle = root / gradle_name
        if not gradle.is_file():
            continue
        try:
            text = gradle.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(token in text for token in _SPRING_GRADLE_TOKENS):
            found.append("spring")
        if any(token in text for token in _JPA_GRADLE_TOKENS):
            found.append("jpa")

    override = override_path
    if override is None:
        for name in _OVERRIDE_FILENAMES:
            candidate = root / name
            if candidate.is_file():
                override = candidate
                break
    if override is not None and override.is_file():
        try:
            data = yaml.safe_load(override.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            data = {}
        if isinstance(data, dict) and data.get("frameworks") is not None:
            found = [str(item) for item in data["frameworks"]]
    return tuple(dict.fromkeys(found))


PACK_ALIASES = {
    "java": "stopthatslop-java-spring-v1",
    "python": "stopthatslop-python-fastapi-v1",
    "ts": "stopthatslop-ts-node-v1",
    "typescript": "stopthatslop-ts-node-v1",
    "go": "stopthatslop-go-v1",
    "android": "stopthatslop-android-v1",
}


def load_pack_by_id(pack_id: str) -> dict[str, Any]:
    wanted = PACK_ALIASES.get(pack_id, pack_id)
    for path in all_pack_yamls():
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not data:
            continue
        if data.get("pack_id") == wanted:
            return data
        if pack_folder_name(data) == pack_id:
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


def skill_markdown_body(skill_dir: Path) -> str:
    text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
    if not text.startswith("---"):
        return text
    _, _, body = text.split("---", 2)
    return body.lstrip("\n")


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


def pack_index_dir(pack: dict[str, Any] | None = None) -> Path:
    return SKILLS_ROOT / pack_folder_name(pack)


def collision_hits(
    target: Path,
    pack: dict[str, Any] | None = None,
    *,
    refuse_only: bool = False,
) -> tuple[str, ...]:
    markers = collision_markers(pack) if refuse_only else report_collision_markers(pack)
    hits: list[str] = []
    for marker in markers:
        if (target / marker).exists():
            hits.append(marker)
    return tuple(hits)


def format_collision_report(
    target: Path,
    hits: tuple[str, ...],
    *,
    report_only: tuple[str, ...] = (),
) -> str:
    if not hits and not report_only:
        return f"No overlapping agent instructions under {target}"
    lines = [f"Collision report for {target}:"]
    lines.extend(f"  - {hit}" for hit in hits)
    lines.extend(
        f"  - {hit} (report-only; does not refuse install)" for hit in report_only
    )
    return "\n".join(lines)
