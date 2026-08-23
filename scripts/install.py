#!/usr/bin/env python3
"""Install the pack-index skill (not N sibling auto-skills). Pin, report, rollback."""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml
from pack_lib import (
    PACK_INDEX_NAME,
    collision_hits,
    format_collision_report,
    invariant_skill_dirs,
    load_pack,
    pack_index_dir,
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install deslop-java-spring as one pack-index skill."
    )
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument(
        "--force",
        action="store_true",
        help="Install even if overlapping Java agent skills/rules exist.",
    )
    parser.add_argument(
        "--rollback",
        action="store_true",
        help="Restore the previously pinned pack version in the target.",
    )
    return parser.parse_args()


def _dest_root(target: Path, namespace: str) -> Path:
    return target / ".agents" / "skills" / namespace / PACK_INDEX_NAME


def _versions_root(target: Path, namespace: str) -> Path:
    return target / ".deslop" / "versions" / namespace / PACK_INDEX_NAME


def _manifest_path(dest: Path) -> Path:
    return dest / "installed.yaml"


def _copy_pack(dest: Path) -> list[Path]:
    dest.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    skill = pack_index_dir() / "SKILL.md"
    shutil.copy2(skill, dest / "SKILL.md")
    written.append(dest / "SKILL.md")
    references = dest / "references"
    if references.exists():
        shutil.rmtree(references)
    references.mkdir()
    for skill_dir in invariant_skill_dirs():
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


def _snapshot_if_present(target: Path, namespace: str, dest: Path) -> Path | None:
    manifest = _manifest_path(dest)
    if not dest.exists() or not manifest.exists():
        return None
    previous = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
    version = str(previous.get("version") or "previous")
    snapshot = _versions_root(target, namespace) / version
    if snapshot.exists():
        shutil.rmtree(snapshot)
    shutil.copytree(dest, snapshot)
    return snapshot


def rollback(*, target: Path) -> tuple[Path, ...]:
    pack = load_pack()
    namespace = pack["install_namespace"]
    dest = _dest_root(target.resolve(), namespace)
    versions = _versions_root(target.resolve(), namespace)
    if not versions.exists():
        raise SystemExit(f"No snapshots to rollback under {versions}")
    snapshots = sorted(path for path in versions.iterdir() if path.is_dir())
    if not snapshots:
        raise SystemExit(f"No snapshots to rollback under {versions}")
    latest = snapshots[-1]
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(latest, dest)
    return (dest,)


def install(*, target: Path, force: bool = False) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    pack = load_pack()
    target = target.resolve()
    hits = collision_hits(target)
    print(format_collision_report(target, hits))
    if hits and not force:
        raise SystemExit(
            "Refusing to install. Pass --force after reviewing the collision report."
        )
    namespace = pack["install_namespace"]
    dest = _dest_root(target, namespace)
    _snapshot_if_present(target, namespace, dest)
    if dest.exists():
        shutil.rmtree(dest)
    written = _copy_pack(dest)
    written.append(_write_manifest(dest, pack))
    return tuple(written), hits


def main() -> int:
    args = _parse_args()
    if args.rollback:
        restored = rollback(target=args.target)
        print(f"Rolled back to snapshot at {restored[0]}")
        return 0
    written, _hits = install(target=args.target, force=args.force)
    print(f"Installed {len(written)} files (pack-index {PACK_INDEX_NAME})")
    for path in written:
        print(f"  {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
