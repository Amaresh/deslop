"""Run portable AST checkers (not Java-engine adapters)."""
from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

CHECKERS = Path(__file__).resolve().parent
_CHECKERS_PATH = str(CHECKERS)
if _CHECKERS_PATH not in sys.path:
    sys.path.insert(0, _CHECKERS_PATH)

from common import LANG_GLOBS, Finding, is_skipped  # noqa: E402

# Already gated by the Java engine; do not double-run via mine.
ENGINE_OWNED_RULE_IDS = frozenset(
    {
        "java.architecture.no-service-layer-transactional-external-io",
        "java.architecture.no-service-layer-rest-template-without-timeout-shaping",
    }
)


@dataclass(frozen=True)
class Location:
    path: str
    line: int | None = None


@dataclass(frozen=True)
class CheckFinding:
    rule_id: str
    message: str
    location: Location | None
    waived: bool = False


@dataclass(frozen=True)
class Detector:
    rule_id: str
    lang: str
    detect: Callable[..., list[Finding]]


def load_all_detectors() -> dict[str, Detector]:
    out: dict[str, Detector] = {}
    for path in sorted(CHECKERS.glob("no_*.py")):
        spec = importlib.util.spec_from_file_location(path.stem, path)
        if spec is None or spec.loader is None:
            continue
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        rule_id = getattr(mod, "RULE_ID", None)
        detect = getattr(mod, "detect", None)
        if not rule_id or not callable(detect):
            continue
        lang = getattr(mod, "LANG", "go")
        out[str(rule_id)] = Detector(rule_id=str(rule_id), lang=str(lang), detect=detect)
    return out


def _name_matches_lang(name: str, lang: str) -> bool:
    for pattern in LANG_GLOBS[lang]:
        if pattern.startswith("*.") and name.endswith(pattern[1:]):
            return True
    return False


def iter_sources(
    repo: Path,
    lang: str,
    changed_files: Sequence[str] | None = None,
):
    repo = repo.resolve()
    if changed_files:
        for raw in changed_files:
            path = Path(raw)
            path = path if path.is_absolute() else repo / path
            if not path.is_file():
                continue
            try:
                rel = path.resolve().relative_to(repo).as_posix()
            except ValueError:
                continue
            if is_skipped(rel, lang=lang):
                continue
            if _name_matches_lang(path.name, lang):
                yield rel, path.resolve()
        return
    seen: set[Path] = set()
    for pattern in LANG_GLOBS[lang]:
        for path in sorted(repo.rglob(pattern)):
            if path in seen:
                continue
            seen.add(path)
            rel = path.relative_to(repo).as_posix()
            if is_skipped(rel, lang=lang):
                continue
            yield rel, path


def run_mine(
    *,
    repo_root: Path,
    rule_ids: Sequence[str],
    changed_files: Sequence[str] | None = None,
) -> list[CheckFinding]:
    catalog = load_all_detectors()
    selected = [rid for rid in rule_ids if rid in catalog and rid not in ENGINE_OWNED_RULE_IDS]
    if not selected:
        return []
    by_lang: dict[str, list[Detector]] = {}
    for rid in selected:
        det = catalog[rid]
        by_lang.setdefault(det.lang, []).append(det)
    findings: list[CheckFinding] = []
    for lang, detectors in by_lang.items():
        for rel, path in iter_sources(repo_root, lang, changed_files):
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            abs_path = str(path.resolve())
            for det in detectors:
                try:
                    hits = det.detect(source, filename=abs_path)
                except FileNotFoundError:
                    raise
                except RuntimeError:
                    raise
                except Exception:
                    continue
                for hit in hits:
                    findings.append(
                        CheckFinding(
                            rule_id=hit.rule_id,
                            message=hit.message,
                            location=Location(path=rel, line=hit.line),
                        )
                    )
    return findings
