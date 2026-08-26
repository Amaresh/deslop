"""Detector: java.correctness.no-file-upload-without-validation

Public controller methods that take MultipartFile / CommonsMultipartFile /
Part must call getSize, getContentType, getOriginalFilename, or
Files.probeContentType in the same method. Non-public methods, tests, and
non-controller types are out of scope.

AST-facts implementation (JavaAstFacts methods.params + calls).
"""
from __future__ import annotations

import re

from common import Finding, is_skipped
from javaast_client import load_facts

LANG = "java"
RULE_ID = "java.correctness.no-file-upload-without-validation"

_UPLOAD_TYPES = frozenset({"MultipartFile", "CommonsMultipartFile", "Part"})
_VALIDATE = frozenset({
    "getSize", "getContentType", "getOriginalFilename", "probeContentType",
})
_MAPPING = re.compile(r"@(?:PostMapping|PutMapping|RequestMapping)\b")
_CONTROLLER = re.compile(r"@(?:Rest)?Controller\b")
_TYPE_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_SYNTHETIC = frozenset({"<instance-init>", "<clinit>"})


def _is_controller_class(cls: dict) -> bool:
    for ann in cls.get("annotations") or []:
        if _CONTROLLER.search(ann or ""):
            return True
    return False


def _has_mapping(meth: dict) -> bool:
    for ann in meth.get("annotations") or []:
        if _MAPPING.search(ann or ""):
            return True
    return False


def _simple_owner(meth: dict) -> str:
    return (meth.get("owner") or "").rsplit(".", 1)[-1]


def _is_constructor(meth: dict) -> bool:
    name = meth.get("name") or ""
    return name == _simple_owner(meth)


def _upload_param_type(meth: dict) -> str | None:
    for param in meth.get("params") or []:
        typ = param.get("type") or ""
        tokens = set(_TYPE_IDENT.findall(typ))
        hit = tokens & _UPLOAD_TYPES
        if hit:
            return sorted(hit)[0]
    return None


def _validates(meth: dict) -> bool:
    for call in meth.get("calls") or []:
        simple = (call.get("name") or "").rsplit(".", 1)[-1]
        if simple in _VALIDATE:
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
        if _is_controller_class(c)
    }
    out: list[Finding] = []
    seen: set[int] = set()
    for meth in facts.get("methods") or []:
        name = meth.get("name") or ""
        if name in _SYNTHETIC or _is_constructor(meth):
            continue
        if not meth.get("public"):
            continue
        if not (_has_mapping(meth) or _simple_owner(meth) in controller_owners):
            continue
        upload_type = _upload_param_type(meth)
        if not upload_type:
            continue
        if _validates(meth):
            continue
        line = int(meth.get("line_start") or 1)
        if line in seen:
            continue
        seen.add(line)
        out.append(Finding(
            line=line,
            message=f"public upload handler takes {upload_type} without "
                    "getSize/getContentType/getOriginalFilename/"
                    "probeContentType",
            rule_id=RULE_ID,
        ))
    return out
