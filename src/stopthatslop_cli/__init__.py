"""Console entry for the `stopthatslop` command."""

from __future__ import annotations

import sys
from pathlib import Path


def _scripts_dir() -> Path:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "scripts"
        if (candidate / "stopthatslop.py").is_file() and (parent / "pack.yaml").is_file():
            return candidate
    raise RuntimeError(
        "cannot locate scripts/stopthatslop.py; install from a git checkout "
        "with `pip install -e .`"
    )


def main(argv: list[str] | None = None) -> int:
    scripts = _scripts_dir()
    rendered = str(scripts)
    if rendered in sys.path:
        sys.path.remove(rendered)
    sys.path.insert(0, rendered)
    from stopthatslop import main as cli_main

    return cli_main(argv)
