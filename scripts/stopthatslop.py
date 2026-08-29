#!/usr/bin/env python3
"""v1 stopthatslop CLI: export, review, install, update, rollback, check, learn."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from check import main as check_main
from export import export_pack
from install import install, rollback
from pack_lib import PACK_INDEX_NAME, PACK_ROOT, load_all_packs, load_pack, pack_frameworks


def _add_check_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument(
        "--pack",
        action="append",
        default=[],
        help="Pack id or alias (java, python, ts, go, android). Repeatable.",
    )
    parser.add_argument("--rule", action="append", default=[])
    parser.add_argument("--changed-file", action="append", default=[])
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--report-collisions", action="store_true")
    parser.add_argument("--fail-on-teach-only", action="store_true")
    parser.add_argument("--override-file", type=Path)


def _review() -> int:
    for pack in load_all_packs():
        print(f"pack_id: {pack['pack_id']}")
        print(f"version: {pack.get('version', '-')}")
        print(f"frameworks: {', '.join(pack_frameworks(pack)) or '-'}")
        print("skills:")
        for skill in pack.get("skills") or []:
            print(
                f"  - {skill['name']}  {skill['enforcement']}  "
                f"{skill['rule_id']}  {skill['globs']}"
            )
        print()
    print("Accept or reject in pack.yaml. This command does not write.")
    return 0


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv[:1] == ["learn"]:
        from learn import main as learn_main

        return learn_main(argv[1:])

    parser = argparse.ArgumentParser(
        description="stopthatslop v1 — export/install/check a pack"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    export_p = sub.add_parser("export", help="Write pack-index tree from RuleDefinitions")
    export_p.add_argument(
        "--out",
        type=Path,
        default=PACK_ROOT / "generated" / PACK_INDEX_NAME,
    )

    sub.add_parser("review", help="Print skills and enforcement for human accept/reject")

    install_p = sub.add_parser("install", help="Install pack-index into a repo")
    install_p.add_argument("--target", type=Path, required=True)
    install_p.add_argument("--force", action="store_true")

    update_p = sub.add_parser("update", help="Re-install current pack (snapshots previous)")
    update_p.add_argument("--target", type=Path, required=True)
    update_p.add_argument("--force", action="store_true")

    rollback_p = sub.add_parser("rollback", help="Restore last installed snapshot")
    rollback_p.add_argument("--target", type=Path, required=True)

    check_p = sub.add_parser("check", help="Run checker; exit 1 on checker findings")
    _add_check_args(check_p)

    sub.add_parser("learn", help="Extract implicit rules from a codebase")

    args = parser.parse_args(argv)

    if args.cmd == "export":
        written = export_pack(out=args.out)
        print(f"Exported {len(written)} files to {args.out}")
        return 0
    if args.cmd == "review":
        return _review()
    if args.cmd in {"install", "update"}:
        written, _hits = install(target=args.target, force=args.force)
        print(f"Installed {len(written)} files (pack-index {PACK_INDEX_NAME})")
        return 0
    if args.cmd == "rollback":
        restored = rollback(target=args.target)
        print(f"Rolled back to snapshot at {restored[0]}")
        return 0
    if args.cmd == "check":
        sys.argv = [
            "check.py",
            "--repo-root",
            str(args.repo_root),
            "--format",
            args.format,
        ]
        for pack in args.pack:
            sys.argv.extend(["--pack", pack])
        for rule in args.rule:
            sys.argv.extend(["--rule", rule])
        for path in args.changed_file:
            sys.argv.extend(["--changed-file", str(path)])
        if args.report_collisions:
            sys.argv.append("--report-collisions")
        if args.fail_on_teach_only:
            sys.argv.append("--fail-on-teach-only")
        if args.override_file is not None:
            sys.argv.extend(["--override-file", str(args.override_file)])
        return check_main()
    raise SystemExit(f"Unknown command {args.cmd}")


if __name__ == "__main__":
    sys.exit(main())
