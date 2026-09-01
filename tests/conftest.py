from __future__ import annotations

import sys
from pathlib import Path

PACK_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = PACK_ROOT / "scripts"
SRC = PACK_ROOT / "src"


def _prefer(path: Path) -> None:
    if not path.is_dir():
        return
    rendered = str(path)
    try:
        sys.path.remove(rendered)
    except ValueError:
        pass
    sys.path.insert(0, rendered)


_prefer(SRC)
_prefer(SCRIPTS)
