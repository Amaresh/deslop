"""Detector: java.architecture.no-controller-direct-repository-access

A @Controller / @RestController must not inject a *Repository / *Dao field.
Route persistence through a service. @ControllerAdvice without a repository
is out of scope.
"""
from __future__ import annotations

import re

from common import Finding, is_skipped
from javaast_client import load_facts

LANG = "java"
RULE_ID = "java.architecture.no-controller-direct-repository-access"

_CONTROLLER = re.compile(r"@(?:Rest)?Controller\b")
_REPO_TYPE = re.compile(r"(Repository|Dao)$")


def _is_controller(cls: dict) -> bool:
    for ann in cls.get("annotations") or []:
        if _CONTROLLER.search(ann or ""):
            return True
    return False


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename, lang="java"):
        return []
    facts = load_facts(source, filename)
    if not facts:
        return []
    controller_owners = {
        (c.get("name") or "")
        for c in (facts.get("classes") or [])
        if _is_controller(c)
    }
    if not controller_owners:
        return []
    out: list[Finding] = []
    seen: set[int] = set()
    for field in facts.get("fields") or []:
        owner = (field.get("owner") or "").rsplit(".", 1)[-1]
        if owner not in controller_owners:
            continue
        typ = (field.get("type") or "").rsplit(".", 1)[-1]
        if not _REPO_TYPE.search(typ):
            continue
        line = int(field.get("line") or 1)
        if line in seen:
            continue
        seen.add(line)
        out.append(Finding(
            line=line,
            message=f"controller injects {typ} directly; delegate persistence "
                    "to a service",
            rule_id=RULE_ID,
        ))
    return out
