"""Detector: typescript.performance.no-eager-heavy-dependency-import

Static `import … from 'lodash'|'moment'|…` pulls a heavy package into the
module graph. Dynamic `import()` is the fix. Type-only imports are silent.
"""
from __future__ import annotations

from common import Finding
from tsast_client import is_out_of_scope, load_facts

LANG = "ts"
RULE_ID = "typescript.performance.no-eager-heavy-dependency-import"

# Motorrad allowlist, plus common subpath imports (lodash/union).
_HEAVY_EXACT = frozenset({
    "jsqr", "pdf-lib", "chart.js", "xlsx", "jspdf", "html2canvas", "mammoth",
    "fabric", "konva", "three", "lodash", "moment", "date-fns",
    "recharts", "echarts", "plotly.js", "d3",
    "zxcvbn", "bcryptjs", "argon2", "crypto-js",
    "tensorflow", "opencv", "tesseract.js", "sharp", "ffmpeg",
    "wavesurfer.js", "howler", "tone",
})
_HEAVY_PREFIX = (
    "@react-pdf/", "@date-io/", "@d3/", "@tensorflow/",
    "@ffmpeg/", "lodash/", "date-fns/", "moment/",
)


def _is_heavy(source: str) -> bool:
    if source in _HEAVY_EXACT:
        return True
    return any(source.startswith(p) for p in _HEAVY_PREFIX)


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_out_of_scope(filename):
        return []
    facts = load_facts(source, filename)
    if facts is None:
        return []
    out: list[Finding] = []
    seen: set[int] = set()
    for node in facts.get("imports") or []:
        if node.get("kind") != "static":
            continue
        if node.get("is_type_only"):
            continue
        src = node.get("source") or ""
        if not _is_heavy(src):
            continue
        line = int(node.get("line") or 1)
        if line in seen:
            continue
        seen.add(line)
        out.append(Finding(
            line=line,
            message=f"static import of heavy dependency '{src}'; use "
                    "import() / next/dynamic so the module is not in the "
                    "critical path",
            rule_id=RULE_ID,
        ))
    return out
