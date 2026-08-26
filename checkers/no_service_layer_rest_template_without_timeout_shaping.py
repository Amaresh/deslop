"""Detector: java.architecture.no-service-layer-rest-template-without-timeout-shaping

`new RestTemplate()` (no-arg) is a violation unless the same variable is
timeout-shaped in the same method / instance initializer via setRequestFactory,
setTimeout, or setConnectTimeout. RestClient.builder().build() and
WebClient.create()/builder().build() need a timeout/request-factory step in
the builder chain.

AST-facts implementation (JavaAstFacts). `new RestTemplate(factory)` (arg
count > 0) is treated as already shaped.

Interface: detect(source: str, filename: str = "<inline>") -> list[Finding]
"""
from __future__ import annotations

from common import Finding, is_skipped
from javaast_client import load_facts

LANG = "java"
RULE_ID = (
    "java.architecture.no-service-layer-rest-template-without-timeout-shaping"
)

_SETTERS = {
    "setrequestfactory", "settimeout", "setconnecttimeout", "setreadtimeout",
}
_CHAIN_TIMEOUT = {
    "connecttimeout", "readtimeout", "requestfactory", "defaultrequest",
    "timeout", "responsetimeout", "clientconnector",
}
_CLIENT_TYPES = {"RestTemplate", "RestClient", "WebClient"}


def _simple(name: str) -> str:
    return name.replace("this.", "").rsplit(".", 1)[-1]


def _chain_has_timeout(chained: list[str]) -> bool:
    names = {c.lower() for c in chained}
    return bool(names & _CHAIN_TIMEOUT)


def _timeout_vars(method: dict) -> set[str]:
    found: set[str] = set()
    for call in method.get("calls") or []:
        name = call.get("name") or ""
        last = name.rsplit(".", 1)[-1].split("(")[0].lower()
        if last in _SETTERS:
            recv = name[: name.rfind(".")] if "." in name else ""
            found.add(_simple(recv))
    return found


def _assigned_var(method: dict, news: dict) -> str | None:
    line = news.get("line")
    ntype = news.get("type") or ""
    for asg in method.get("assigns") or []:
        if asg.get("line") != line:
            continue
        rhs = asg.get("rhs_summary") or ""
        if ntype and ntype in rhs:
            return _simple(asg.get("lhs") or "")
        if "new RestTemplate" in rhs or "RestClient.builder" in rhs or "WebClient." in rhs:
            return _simple(asg.get("lhs") or "")
    return None


def _flag_rest_template(news: dict, method: dict) -> bool:
    if (news.get("type") or "") != "RestTemplate":
        return False
    if int(news.get("arg_count") or 0) != 0:
        return False
    if _chain_has_timeout(news.get("chained") or []):
        return False
    var = _assigned_var(method, news)
    shaped = _timeout_vars(method)
    if var and var in shaped:
        return False
    return True


def _flag_builder(news: dict) -> bool:
    ntype = news.get("type") or ""
    chained = [c.lower() for c in (news.get("chained") or [])]
    if ntype == "RestClient" and "build" in chained:
        return not _chain_has_timeout(chained)
    if ntype == "WebClient":
        if "create" in chained:
            return not _chain_has_timeout(chained)
        if "build" in chained:
            names = set(chained)
            return not bool(names & {"responsetimeout", "clientconnector", "timeout"})
    return False


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    if is_skipped(filename, lang="java"):
        return []
    facts = load_facts(source, filename)
    if facts is None:
        return []
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    for method in facts.get("methods") or []:
        for news in method.get("news") or []:
            ntype = news.get("type") or ""
            if ntype not in _CLIENT_TYPES:
                continue
            line = int(news.get("line") or 0)
            guilty = False
            kind = ntype
            if ntype == "RestTemplate":
                guilty = _flag_rest_template(news, method)
            else:
                guilty = _flag_builder(news)
            if not guilty:
                continue
            key = (line, kind)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                line=line,
                message=(
                    f"{kind} constructed without timeout/request-factory "
                    "shaping; set connect/read timeouts before use"
                ),
                rule_id=RULE_ID,
            ))
    return findings
