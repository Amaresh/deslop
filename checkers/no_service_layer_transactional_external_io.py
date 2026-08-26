"""Detector: java.architecture.no-service-layer-transactional-external-io

A method annotated @Transactional (class-level counts; @Transactional(readOnly
= true) is out of scope) must not call outbound IO: HTTP clients, S3, or
messaging senders. Persistence calls are exempt.

AST-facts implementation (JavaAstFacts). FP-biased: random `.send(` without
message/sms/mail/kafka/jms evidence is not flagged; `.put(` requires an HTTP
or S3 receiver.

Interface: detect(source: str, filename: str = "<inline>") -> list[Finding]
"""
from __future__ import annotations

import re

from common import Finding, is_skipped
from javaast_client import load_facts

LANG = "java"
RULE_ID = "java.architecture.no-service-layer-transactional-external-io"

_SEG_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
_TX_RE = re.compile(r"@?Transactional\b")
_READONLY_RE = re.compile(r"readOnly\s*=\s*true")

_HTTP_TYPE_SEGS = {
    "resttemplate", "restclient", "webclient", "feign", "feignclient",
}
_HTTP_METHODS = {
    "getforobject", "getforentity", "postforentity", "postforobject",
    "exchange", "retrieve",
}
_S3_IDENTS = {"amazons3", "s3client", "s3"}
_S3_NAME_RE = re.compile(r"(?i)(?:amazon)?s3(?:client|filestorage|storage|file)?")
_MSG_SEGS = {"message", "messaging", "sms", "mail", "email", "kafka", "jms"}
_PERSIST_METHODS = {
    "save", "saveall", "saveandflush", "persist", "merge", "flush", "find",
    "findall", "findbyid", "findone", "remove", "delete", "deleteall",
    "deletebyid", "getreference", "getone", "refresh", "lock", "contains",
}
_REPO_SEGS = {"repository", "entitymanager", "dao", "crudrepository"}


def _segments(name: str) -> list[str]:
    segs: list[str] = []
    for part in re.split(r"[.\s()]+", name.replace("-", "_")):
        if not part:
            continue
        segs.extend(m.group(0).lower() for m in _SEG_RE.finditer(part))
    return segs


def _idents(expr: str) -> list[str]:
    return [p for p in re.split(r"[^A-Za-z0-9]+", expr) if p]


def _has_s3(call_name: str, field_type: str) -> bool:
    blob = f"{call_name} {field_type}"
    for ident in _idents(blob):
        low = ident.lower()
        if low in _S3_IDENTS:
            return True
        if _S3_NAME_RE.fullmatch(low):
            return True
        if "s3" in low and any(m in low for m in ("amazon", "client", "storage")):
            return True
    return False


def _last_method(call_name: str) -> str:
    return call_name.rsplit(".", 1)[-1].split("(")[0]


def _receiver(call_name: str) -> str:
    if "." not in call_name:
        return ""
    return call_name[: call_name.rfind(".")]


def _tx_mode(annotations: list[str]) -> str | None:
    mode = None
    for raw in annotations:
        if not _TX_RE.search(raw):
            continue
        mode = "ro" if _READONLY_RE.search(raw) else "rw"
    return mode


def _class_modes(facts: dict) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for cls in facts.get("classes", []):
        name = cls.get("name", "")
        mode = _tx_mode(cls.get("annotations") or [])
        out[name] = mode
        out[name.split(".")[-1]] = mode
    return out


def _field_types(facts: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for field in facts.get("fields") or []:
        out[field.get("name", "")] = field.get("type", "")
    return out


def _looks_repo(recv: str, field_type: str) -> bool:
    segs = set(_segments(recv)) | set(_segments(field_type))
    if segs & _REPO_SEGS:
        return True
    simple = field_type.split(".")[-1]
    return simple.endswith("Repository") or simple in {"EntityManager", "EntityManagerFactory"}


def _is_outbound_io(call_name: str, field_types: dict[str, str]) -> bool:
    method = _last_method(call_name)
    method_l = method.lower()
    recv = _receiver(call_name)
    recv_ident = recv.split(".")[-1] if recv else ""
    field_type = field_types.get(recv_ident, "")
    segs = set(_segments(call_name)) | set(_segments(field_type))

    if method_l in _PERSIST_METHODS and _looks_repo(recv, field_type):
        return False

    if segs & _HTTP_TYPE_SEGS:
        return True
    if method_l in _HTTP_METHODS:
        return True
    if method_l == "put" and (segs & _HTTP_TYPE_SEGS or _has_s3(call_name, field_type)):
        return True
    if _has_s3(call_name, field_type):
        return True
    if "messagingclient" in call_name.lower().replace("_", ""):
        return True
    if method_l == "send":
        type_segs = set(_segments(field_type)) | set(_segments(recv_ident))
        if type_segs & _MSG_SEGS:
            return True
        return False
    return False


def _method_is_rw_tx(method: dict, class_modes: dict[str, str | None]) -> bool:
    own = _tx_mode(method.get("annotations") or [])
    if own is not None:
        return own == "rw"
    owner = method.get("owner") or ""
    simple = owner.rsplit(".", 1)[-1]
    class_mode = class_modes.get(owner) or class_modes.get(simple)
    return class_mode == "rw"


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename, lang="java"):
        return []
    facts = load_facts(source, filename)
    if facts is None:
        return []
    class_modes = _class_modes(facts)
    field_types = _field_types(facts)
    findings: list[Finding] = []
    seen: set[int] = set()
    for method in facts.get("methods") or []:
        if method.get("name") in {"<instance-init>", "<clinit>"}:
            continue
        if not _method_is_rw_tx(method, class_modes):
            continue
        for call in method.get("calls") or []:
            line = int(call.get("line") or 0)
            if line in seen:
                continue
            name = call.get("name") or ""
            if _is_outbound_io(name, field_types):
                seen.add(line)
                findings.append(Finding(
                    line=line,
                    message=(
                        f"@Transactional method '{method.get('name')}' calls "
                        f"outbound IO '{name}'; persist in the transaction and "
                        "send HTTP/S3/messaging after commit"
                    ),
                    rule_id=RULE_ID,
                ))
    return findings
