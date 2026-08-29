#!/usr/bin/env python3
"""Export existing RuleDefinitions + authored skills into a pack-index tree."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pack_lib import (
    PACK_INDEX_NAME,
    PACK_ROOT,
    engine_rule_ids,
    invariant_skill_dirs,
    load_pack,
    pack_index_dir,
    prefer_engine_src,
)

prefer_engine_src()

from engineering_rules.registry import create_default_registry  # noqa: E402


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
    pack = load_pack()
    registry = create_default_registry()
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

    by_rule = {item["rule_id"]: item["name"] for item in pack["skills"]}
    missing: list[str] = []
    for rule_id in engine_rule_ids(pack):
        rule = registry.get(rule_id)
        if rule is None:
            missing.append(rule_id)
            continue
        slug = by_rule.get(rule_id, rule_id.replace(".", "-"))
        authored = next(
            (path / "SKILL.md" for path in invariant_skill_dirs() if path.name == slug),
            None,
        )
        dest = out / "references" / f"{slug}.md"
        if authored is not None and authored.exists():
            dest.write_text(authored.read_text(encoding="utf-8"), encoding="utf-8")
        else:
            dest.write_text(
                f"# {rule.name}\n\nEngine rule: `{rule.rule_id}`\n\n{rule.summary}\n",
                encoding="utf-8",
            )
        written.append(dest)

    if missing:
        raise SystemExit(f"Unknown engine rule ids: {', '.join(missing)}")

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
