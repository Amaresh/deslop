"""Optional remote review hooks for local engineering-rules runs."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from .models import RunSource


class RemoteExecutionProofError(RuntimeError):
    """Retained for compatibility with older CLI error handling."""


def require_remote_execution_proof(
    *, repo_root: Path, source: RunSource, changed_files: Sequence[str] | None
) -> None:
    """Remote execution proofs are no longer required for local runs."""

    del repo_root, source, changed_files
    return None
