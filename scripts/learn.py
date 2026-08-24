#!/usr/bin/env python3
"""deslop learn — extract the implicit rules of a codebase.

Usage:
  python3 mine/learn.py --repo PATH --lang go|python|ts|java [--out DIR]
"""
from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "learn"))
    # (module lives alongside this CLI)

from stats import to_yaml  # noqa: E402


def _load_analyzer(lang: str):
    module = importlib.import_module(f"{lang}_analyzer")
    return module


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--lang", required=True,
                    choices=("go", "python", "ts", "java"))
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)

    if not args.repo.is_dir():
        print(f"repo not found: {args.repo}", file=sys.stderr)
        return 2

    mod = _load_analyzer(args.lang)
    candidates = mod.analyze(args.repo)

    if not candidates:
        print("no candidates — repo too small or conventions not detectably "
              "strong", file=sys.stderr)
        return 0

    print(f"{'rule_id':<48} {'ratio':>6} {'n':>4}  invariant")
    for c in candidates:
        print(f"{c.rule_id:<48} {c.ratio:>6.2f} {c.total:>4}  {c.invariant[:60]}")

    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "candidates.yaml").write_text(to_yaml(candidates))
        print(f"\nwrote {len(candidates)} candidates -> "
              f"{args.out / 'candidates.yaml'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
