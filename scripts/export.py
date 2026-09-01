#!/usr/bin/env python3
"""Export authored pack-index + invariant skill references."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pack_lib import (
    PACK_INDEX_NAME,
    PACK_ROOT,
    invariant_skill_dirs,
    load_pack,
    pack_index_dir,
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export stopthatslop-java-spring as a generated pack-index."
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=PACK_ROOT / "generated" / PACK_INDEX_NAME,
        help="Directory to write the exported pack into.",
    )
    return parser.parse_args()


def export_pack(*, out: Path) -> tuple[Path, ...]:
    load_pack()
    if out.exists():
        for child in out.rglob("*"):
            if child.is_file():
                child.unlink()
    out.mkdir(parents=True, exist_ok=True)
    (out / "references").mkdir(exist_ok=True)
    written: list[Path] = []

    index_source = pack_index_dir() / "SKILL.md"
    dest_index = out / "SKILL.md"
    dest_index.write_text(index_source.read_text(encoding="utf-8"), encoding="utf-8")
    written.append(dest_index)

    for skill_dir in invariant_skill_dirs():
        source = skill_dir / "SKILL.md"
        if not source.exists():
            continue
        dest = out / "references" / f"{skill_dir.name}.md"
        dest.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        written.append(dest)

    (out / "pack.yaml").write_text(
        (PACK_ROOT / "pack.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    written.append(out / "pack.yaml")
    return tuple(written)


def main() -> int:
    args = _parse_args()
    written = export_pack(out=args.out)
    print(f"Exported {len(written)} files to {args.out}")
    for path in written:
        print(f"  {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
