"""Detector: java.performance.no-n-plus-one-without-entity-graph

Paginated / collection JPA queries on an entity with lazy to-many
associations need @EntityGraph or JOIN FETCH. Otherwise each row triggers
follow-up loads (N+1).

Cross-file join is naming, not a compiler: InvoiceRepository.java looks up
Invoice.java next to it, or in domain/model/entity beside a repository/
folder. Same compilation unit is also enough (samples). Missing entity
file is silence (FP-biased).

EAGER collections are out of scope here — java.performance.no-eager-to-many-fetch
already covers them. Inherited JpaRepository.findAll is flagged on the type
when the sibling entity has a lazy to-many and no fetch plan on the repo.
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from common import Finding, is_skipped
from javaast_client import load_facts

LANG = "java"
RULE_ID = "java.performance.no-n-plus-one-without-entity-graph"

_REPO_SUFFIX = re.compile(r"(?:Jpa)?(Repository|Dao|Repo)$")
_SKIP_REPO = re.compile(r"(Impl|Custom)$")
_GENERIC_ENTITY = re.compile(
    r"(?:JpaRepository|CrudRepository|PagingAndSortingRepository|"
    r"ListCrudRepository|ListPagingAndSortingRepository|"
    r"Repository)\s*<\s*([A-Z]\w+)"
)
_FIND = re.compile(r"^(find|query|read|search)(?!ById$|ByUuid$)", re.I)
_SINGLE = {
    "findById", "getById", "getOne", "getReferenceById", "findOne",
    "existsById", "deleteById",
}
_MUTATE = {
    "save", "saveAll", "saveAndFlush", "delete", "deleteAll", "deleteAllInBatch",
    "count", "flush", "deleteInBatch",
}
_COLLECTION = re.compile(
    r"\b(Pageable|Page|Slice|List|Set|Collection|Stream|Iterable)\b"
)
_EAGER_NAME = re.compile(
    r"(?i)(Eager|EntityGraph|JoinFetch|WithToOne|WithToMany|WithGraph)"
)
_TO_MANY = ("OneToMany", "ManyToMany")
_REPO_DIRS = frozenset({
    "repository", "repositories", "repo", "dao", "data",
})
_ENTITY_SUBS = ("domain", "model", "entity", "entities", "core")


def _simple(name: str) -> str:
    return (name or "").rsplit(".", 1)[-1]


def _is_repo_type(name: str) -> bool:
    simple = _simple(name)
    if _SKIP_REPO.search(simple):
        return False
    return bool(_REPO_SUFFIX.search(simple))


def _entity_stems(cls: dict) -> list[str]:
    stems: list[str] = []
    seen: set[str] = set()

    def add(stem: str) -> None:
        if stem and stem not in seen:
            seen.add(stem)
            stems.append(stem)

    for sup in cls.get("supers") or []:
        m = _GENERIC_ENTITY.search(sup or "")
        if m:
            add(m.group(1))
    m = _REPO_SUFFIX.search(_simple(cls.get("name") or ""))
    if m:
        add(_REPO_SUFFIX.sub("", _simple(cls.get("name") or "")))
    return stems


def _has_fetch_plan(blobs: list[str]) -> bool:
    text = " ".join(blobs).lower()
    if "entitygraph" in text:
        return True
    if "join fetch" in text or "join\n fetch" in text:
        return True
    return False


def _method_blobs(method: dict) -> list[str]:
    anns = [str(a) for a in (method.get("annotations") or [])]
    returns = [str(method.get("returns") or "")]
    return anns + returns


def _is_collection_finder(method: dict) -> bool:
    name = method.get("name") or ""
    if not name or name.startswith("<") or name in _SINGLE or name in _MUTATE:
        return False
    if not (_FIND.match(name) or name == "findAll"):
        return False
    if _has_fetch_plan(_method_blobs(method)):
        return False
    if _EAGER_NAME.search(method.get("name") or ""):
        return False
    returns = method.get("returns") or ""
    params = " ".join(
        str(p.get("type") or "")
        for p in (method.get("params") or [])
        if isinstance(p, dict)
    )
    return bool(_COLLECTION.search(returns) or _COLLECTION.search(params))


def _lazy_to_many(facts: dict, entity: str) -> list[str]:
    names: list[str] = []
    for field in facts.get("fields") or []:
        owner = _simple(field.get("owner") or "")
        if owner and owner != entity:
            continue
        for ann in field.get("annotations") or []:
            text = str(ann)
            if not any(tok in text for tok in _TO_MANY):
                continue
            if "EAGER" in text:
                continue
            names.append(field.get("name") or "collection")
    return names


def _entity_candidates(filename: str, entity: str) -> list[Path]:
    path = Path(filename)
    if filename in {"<inline>", "-"} or not path.suffix:
        return []
    parent = path.parent
    if not parent.parts:
        return []
    name = f"{entity}.java"
    out: list[Path] = [parent / name]
    if parent.name.lower() in _REPO_DIRS:
        root = parent.parent
        out.append(root / name)
        for sub in _ENTITY_SUBS:
            out.append(root / sub / name)
    else:
        out.append(parent.parent / name)
        for sub in _ENTITY_SUBS:
            out.append(parent.parent / sub / name)
            out.append(parent / sub / name)
    seen: set[Path] = set()
    uniq: list[Path] = []
    for cand in out:
        try:
            resolved = cand.resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        uniq.append(cand)
    return uniq


@lru_cache(maxsize=64)
def _facts_from_path(path: str) -> dict | None:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return load_facts(text, filename=path)


def _entity_facts(repo_facts: dict, filename: str, entity: str) -> dict | None:
    if _lazy_to_many(repo_facts, entity):
        return repo_facts
    classes = {_simple(c.get("name") or "") for c in (repo_facts.get("classes") or [])}
    if entity in classes:
        return repo_facts
    for cand in _entity_candidates(filename, entity):
        if not cand.is_file():
            continue
        facts = _facts_from_path(str(cand))
        if facts:
            return facts
    return None


def _spring_data_parent(cls: dict) -> bool:
    blob = " ".join(cls.get("supers") or [])
    return bool(_GENERIC_ENTITY.search(blob))


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename, lang="java"):
        return []
    facts = load_facts(source, filename)
    if not facts:
        return []
    out: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for cls in facts.get("classes") or []:
        name = cls.get("name") or ""
        if not _is_repo_type(name):
            continue
        stems = _entity_stems(cls)
        if not stems:
            continue
        entity = stems[0]
        entity_facts = _entity_facts(facts, filename, entity)
        if not entity_facts:
            continue
        lazy = _lazy_to_many(entity_facts, entity)
        if not lazy:
            continue
        coll = ", ".join(lazy[:3])
        methods = [
            m for m in (facts.get("methods") or [])
            if _simple(m.get("owner") or "") == _simple(name)
        ]
        flagged_method = False
        for method in methods:
            if not _is_collection_finder(method):
                continue
            line = int(method.get("line_start") or cls.get("line") or 1)
            key = (method.get("name") or "", line)
            if key in seen:
                continue
            seen.add(key)
            flagged_method = True
            out.append(Finding(
                line=line,
                message=f"{name}.{method.get('name')} loads {entity} with lazy "
                        f"{coll} and no EntityGraph/JOIN FETCH (N+1)",
                rule_id=RULE_ID,
            ))
        if flagged_method:
            continue
        if not _spring_data_parent(cls):
            continue
        declared = [
            m for m in methods
            if (m.get("name") or "") and not str(m.get("name")).startswith("<")
        ]
        if declared:
            continue
        if any(_has_fetch_plan(_method_blobs(m)) for m in methods):
            continue
        line = int(cls.get("line") or 1)
        key = (name, line)
        if key in seen:
            continue
        seen.add(key)
        out.append(Finding(
            line=line,
            message=f"{name} inherits findAll on {entity} with lazy {coll} "
                    "and no EntityGraph/JOIN FETCH (N+1)",
            rule_id=RULE_ID,
        ))
    return out
