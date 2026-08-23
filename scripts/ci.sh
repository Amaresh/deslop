#!/usr/bin/env bash
# Copy-paste CI for a vendored deslop pack. Not a hosted product.
#
# Exit 0: no checker findings.
# Exit 1: one or more checker (enforceable) findings.
# Exit 2: usage / unknown rule id / missing python.
#
# Teach-only findings print in the report and do not fail the job.
# Collisions print; they do not fail the job (install still refuses without --force).
#
# Usage:
#   scripts/ci.sh /path/to/repo
#   FORMAT=json scripts/ci.sh /path/to/repo
#   ENGINE_PYTHON=/path/to/python scripts/ci.sh /path/to/repo
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '2,16p' "$0"
  exit 0
fi

REPO_ROOT="$(cd "${1:-.}" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACK_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FORMAT="${FORMAT:-text}"
DEFAULT_PYTHON="$PACK_ROOT/../isolated-engineering-rules/.venv/bin/python"
ENGINE_PYTHON="${ENGINE_PYTHON:-}"

if [[ -z "$ENGINE_PYTHON" ]]; then
  if [[ -x "$DEFAULT_PYTHON" ]]; then
    ENGINE_PYTHON="$DEFAULT_PYTHON"
  elif command -v python3 >/dev/null 2>&1; then
    ENGINE_PYTHON="$(command -v python3)"
  else
    echo "ci.sh: no python interpreter (set ENGINE_PYTHON)" >&2
    exit 2
  fi
fi

export PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}"

echo "deslop ci: repo=$REPO_ROOT format=$FORMAT" >&2
exec "$ENGINE_PYTHON" "$SCRIPT_DIR/check.py" \
  --repo-root "$REPO_ROOT" \
  --format "$FORMAT" \
  --report-collisions
