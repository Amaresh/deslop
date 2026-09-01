#!/usr/bin/env python3
"""stopthatslop learn — extract the implicit rules of a codebase.

Usage:
  python3 scripts/stopthatslop.py learn --repo PATH --lang go|python|ts|java [--out DIR]
  python3 scripts/learn.py --repo PATH --lang go|python|ts|java [--out DIR]
  python3 scripts/learn.py --repo PATH --lang python --print-induce-prompt [--out DIR]
"""
from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path

_LEARN_DIR = Path(__file__).resolve().parent / "learn"
sys.path.insert(0, str(_LEARN_DIR))

from stats import to_yaml  # noqa: E402
from walk import discover, sample_rel_files  # noqa: E402


def _load_analyzer(lang: str):
    module = importlib.import_module(f"{lang}_analyzer")
    return module


def _induce_prompt_path(lang: str) -> Path | None:
    name = f"{lang}-induce.md"
    here = _LEARN_DIR / "prompts" / name
    return here if here.is_file() else None


def _write_induce_prompt(lang: str, repo: Path, out_dir: Path) -> Path:
    prompt_path = _induce_prompt_path(lang)
    if prompt_path is None:
        raise FileNotFoundError(
            f"no induce prompt for {lang} (expected learn/prompts/{lang}-induce.md)"
        )
    files = discover(repo, lang)
    sample = sample_rel_files(files, repo, n=30)
    listing = "\n".join(f"- `{p}`" for p in sample) if sample else "(no source files found)"
    body = (
        prompt_path.read_text(encoding="utf-8").rstrip()
        + "\n\n## Sampled files (relative to --repo)\n\n"
        "This CLI does not call a model. Paste the listed files into your session.\n\n"
        + listing
        + "\n"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    prompt_out = out_dir / "induce-prompt.md"
    prompt_out.write_text(body, encoding="utf-8")
    sample_out = out_dir / "sampled-files.txt"
    sample_out.write_text(
        ("\n".join(sample) + "\n") if sample else "",
        encoding="utf-8",
    )
    print(f"wrote {prompt_out} and {sample_out} ({len(sample)} files)")
    return prompt_out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--lang", required=True,
                    choices=("go", "python", "ts", "java"))
    ap.add_argument("--out", type=Path)
    ap.add_argument(
        "--print-induce-prompt",
        action="store_true",
        help="Write induce-prompt.md and sampled-files.txt; does not call an LLM",
    )
    args = ap.parse_args(argv)

    if not args.repo.is_dir():
        print(f"repo not found: {args.repo}", file=sys.stderr)
        return 2

    out_dir = args.out if args.out is not None else Path(".")
    if args.print_induce_prompt:
        try:
            _write_induce_prompt(args.lang, args.repo, out_dir)
        except FileNotFoundError as exc:
            print(str(exc), file=sys.stderr)
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
