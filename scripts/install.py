#!/usr/bin/env python3
"""Install a pack-index skill plus glob-scoped harness files. Pin, report, rollback."""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml
from pack_lib import (
    collision_hits,
    format_collision_report,
    invariant_skill_dirs,
    load_pack_by_id,
    pack_folder_name,
    pack_glob_union,
    pack_index_dir,
    pack_skill_globs,
    parse_skill_frontmatter,
    skill_markdown_body,
)

_AGENTS_POINTER = (
    "StopThatSlop: glob-scoped Cursor rules in `.cursor/rules/stopthatslop-*.mdc` "
    "(the harness decides whether to load them)."
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install a stopthatslop pack-index plus glob-scoped Cursor rules."
    )
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument(
        "--pack",
        required=True,
        help="Pack alias (java, python, ts, go, android) or pack id.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Install even if overlapping Java agent skills/rules exist.",
    )
    parser.add_argument(
        "--write-agents-md",
        action="store_true",
        help="Append a one-line pointer to AGENTS.md (never a fat generated file).",
    )
    parser.add_argument(
        "--rollback",
        action="store_true",
        help="Restore the previously pinned pack version in the target.",
    )
    return parser.parse_args()


def _namespace(pack: dict) -> str:
    return str(pack.get("install_namespace") or "stopthatslop")


def _dest_root(target: Path, pack: dict) -> Path:
    return target / ".agents" / "skills" / _namespace(pack) / pack_folder_name(pack)


def _claude_dest(target: Path, pack: dict) -> Path:
    return target / ".claude" / "skills" / _namespace(pack) / pack_folder_name(pack)


def _versions_root(target: Path, pack: dict) -> Path:
    return target / ".stopthatslop" / "versions" / _namespace(pack) / pack_folder_name(pack)


def _manifest_path(dest: Path) -> Path:
    return dest / "installed.yaml"


def _mdc_path(target: Path, skill_name: str) -> Path:
    return target / ".cursor" / "rules" / f"stopthatslop-{skill_name}.mdc"


def _github_instructions_path(target: Path, pack: dict) -> Path:
    return (
        target
        / ".github"
        / "instructions"
        / f"{pack_folder_name(pack)}.instructions.md"
    )


def _one_line(text: str) -> str:
    return " ".join(str(text).split())


def _copy_pack(dest: Path, pack: dict) -> list[Path]:
    dest.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    skill = pack_index_dir(pack) / "SKILL.md"
    shutil.copy2(skill, dest / "SKILL.md")
    written.append(dest / "SKILL.md")
    references = dest / "references"
    if references.exists():
        shutil.rmtree(references)
    references.mkdir()
    for skill_dir in invariant_skill_dirs(pack_id=pack["pack_id"]):
        source = skill_dir / "SKILL.md"
        if source.exists():
            copied = references / f"{skill_dir.name}.md"
            shutil.copy2(source, copied)
            written.append(copied)
    return written


def _write_manifest(dest: Path, pack: dict) -> Path:
    payload = {
        "pack_id": pack["pack_id"],
        "version": pack["version"],
        "layout": "pack-index",
        "installed_at": datetime.now(UTC).isoformat(),
    }
    path = _manifest_path(dest)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def _emit_cursor_rules(target: Path, pack: dict) -> list[Path]:
    globs = pack_skill_globs(pack)
    written: list[Path] = []
    rules_dir = target / ".cursor" / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    for skill_dir in invariant_skill_dirs(pack_id=pack["pack_id"]):
        glob = globs[skill_dir.name]
        frontmatter = parse_skill_frontmatter(skill_dir)
        description = _one_line(frontmatter.get("description") or skill_dir.name)
        body = skill_markdown_body(skill_dir)
        payload = {
            "description": description,
            "globs": glob,
            "alwaysApply": False,
        }
        text = (
            "---\n"
            + yaml.safe_dump(payload, sort_keys=False)
            + "---\n\n"
            + body
        )
        dest = _mdc_path(target, skill_dir.name)
        dest.write_text(text, encoding="utf-8")
        written.append(dest)
    return written


def _emit_github_instructions(target: Path, pack: dict) -> Path:
    globs = pack_glob_union(pack)
    body = skill_markdown_body(pack_index_dir(pack))
    payload = {"applyTo": ",".join(globs)}
    text = "---\n" + yaml.safe_dump(payload, sort_keys=False) + "---\n\n" + body
    dest = _github_instructions_path(target, pack)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    return dest


def _maybe_write_agents_md(target: Path, *, write: bool) -> Path | None:
    if not write:
        return None
    path = target / "AGENTS.md"
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    if "stopthatslop-*.mdc" in existing or "stopthatslop-\\*.mdc" in existing:
        return path
    prefix = existing if existing.endswith("\n") or not existing else existing + "\n"
    if prefix and not prefix.endswith("\n\n"):
        prefix = prefix.rstrip("\n") + "\n\n"
    path.write_text(prefix + _AGENTS_POINTER + "\n", encoding="utf-8")
    return path


def _snapshot_if_present(target: Path, pack: dict, dest: Path) -> Path | None:
    manifest = _manifest_path(dest)
    if not dest.exists() or not manifest.exists():
        return None
    previous = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
    version = str(previous.get("version") or "previous")
    snapshot = _versions_root(target, pack) / version
    if snapshot.exists():
        shutil.rmtree(snapshot)
    snapshot.mkdir(parents=True)
    shutil.copytree(dest, snapshot / "agents-skill")
    rules_dir = snapshot / "cursor-rules"
    rules_dir.mkdir()
    for skill_dir in invariant_skill_dirs(pack_id=pack["pack_id"]):
        src = _mdc_path(target, skill_dir.name)
        if src.exists():
            shutil.copy2(src, rules_dir / src.name)
    claude = _claude_dest(target, pack)
    if claude.exists():
        shutil.copytree(claude, snapshot / "claude-skill")
    github = _github_instructions_path(target, pack)
    if github.exists():
        shutil.copy2(github, snapshot / "github-instructions.md")
    return snapshot


def _restore_snapshot(target: Path, pack: dict, latest: Path, dest: Path) -> None:
    agents = latest / "agents-skill"
    if dest.exists():
        shutil.rmtree(dest)
    if agents.exists():
        shutil.copytree(agents, dest)
    else:
        shutil.copytree(latest, dest)
    rules_snap = latest / "cursor-rules"
    if rules_snap.exists():
        for skill_dir in invariant_skill_dirs(pack_id=pack["pack_id"]):
            src = rules_snap / f"stopthatslop-{skill_dir.name}.mdc"
            if src.exists():
                dest_mdc = _mdc_path(target, skill_dir.name)
                dest_mdc.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dest_mdc)
    claude_snap = latest / "claude-skill"
    claude = _claude_dest(target, pack)
    if claude_snap.exists():
        if claude.exists():
            shutil.rmtree(claude)
        shutil.copytree(claude_snap, claude)
    github_snap = latest / "github-instructions.md"
    if github_snap.exists():
        dest_gh = _github_instructions_path(target, pack)
        dest_gh.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(github_snap, dest_gh)


def rollback(*, target: Path, pack: str) -> tuple[Path, ...]:
    data = load_pack_by_id(pack)
    target = target.resolve()
    dest = _dest_root(target, data)
    versions = _versions_root(target, data)
    if not versions.exists():
        raise SystemExit(f"No snapshots to rollback under {versions}")
    snapshots = sorted(path for path in versions.iterdir() if path.is_dir())
    if not snapshots:
        raise SystemExit(f"No snapshots to rollback under {versions}")
    latest = snapshots[-1]
    _restore_snapshot(target, data, latest, dest)
    return (dest,)


def install(
    *,
    target: Path,
    pack: str,
    force: bool = False,
    write_agents_md: bool = False,
) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    data = load_pack_by_id(pack)
    target = target.resolve()
    refuse = collision_hits(target, data, refuse_only=True)
    reported = collision_hits(target, data, refuse_only=False)
    report_only = tuple(hit for hit in reported if hit not in refuse)
    print(format_collision_report(target, refuse, report_only=report_only))
    if refuse and not force:
        raise SystemExit(
            "Refusing to install. Pass --force after reviewing the collision report."
        )
    dest = _dest_root(target, data)
    _snapshot_if_present(target, data, dest)
    if dest.exists():
        shutil.rmtree(dest)
    written = _copy_pack(dest, data)
    written.append(_write_manifest(dest, data))
    written.extend(_emit_cursor_rules(target, data))
    if (target / ".claude").is_dir():
        claude = _claude_dest(target, data)
        if claude.exists():
            shutil.rmtree(claude)
        shutil.copytree(dest, claude)
        written.append(claude / "SKILL.md")
    if (target / ".github").is_dir():
        written.append(_emit_github_instructions(target, data))
    agents = _maybe_write_agents_md(target, write=write_agents_md)
    if agents is not None:
        written.append(agents)
    return tuple(written), refuse


def main() -> int:
    args = _parse_args()
    if args.rollback:
        restored = rollback(target=args.target, pack=args.pack)
        print(f"Rolled back to snapshot at {restored[0]}")
        return 0
    written, _hits = install(
        target=args.target,
        pack=args.pack,
        force=args.force,
        write_agents_md=args.write_agents_md,
    )
    print(f"Installed {len(written)} files (pack-index {pack_folder_name(load_pack_by_id(args.pack))})")
    for path in written:
        print(f"  {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
