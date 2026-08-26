"""Detector: go.security.no-plain-string-secret-comparison

Secrets/tokens from requests must be compared constant-time
(crypto/subtle), never with == / != / strings.EqualFold / bytes.Equal on
plain strings.

AST-facts implementation (goast-facts), hardened against naming FPs
(bench-run-0: 22 FPs / 280k LOC -> target ~0):

An operand counts as SECRET-BEARING only with source evidence:
  (a) the operand text itself contains a quoted argument naming a
      credential at word boundaries (r.Header.Get("Authorization"),
      os.Getenv("API_TOKEN")); or
  (b) it is a variable assigned (same function) from such an expression,
      or from another secret-bearing variable (intra-function dataflow
      over goast assigns facts, iterated to fixpoint).
Bare identifiers merely NAMED key/token/secret have no evidence and never
fire; field selectors like setting.Key / x.URLParams.Keys[k] fire only
under (a); literals never fire.

Dedupe: max one finding per line per comparison pair.
Kept exemptions: literal "" presence checks, subtle/hmac comparisons,
test/vendor/testdata files (via goast_client).
"""
from __future__ import annotations

import re

from common import Finding
from goast_client import (
    load_facts,
    quoted_strings,
)

RULE_ID = "go.security.no-plain-string-secret-comparison"

# comparison-shaped stdlib calls that ARE the fix, not the bug
SAFE_API_RE = re.compile(r"\b(subtle\.|hmac\.Equal\b)")

_CMP_OPS = {"==", "!=", "EqualFold", "bytes.Equal"}

# Credential words matched at word boundaries inside QUOTED arguments
# (separators -, _, . normalized to spaces first, so CI_JOB_TOKEN ->
# "ci job token" still matches \btoken\b; Content-Type does not).
_QUOTED_CRED_RE = re.compile(
    r"\b(token|tokens|secret|secrets|password|passwd|pwd|credential|"
    r"credentials|apikey|authorization|authorisation|bearer|"
    r"api key|secret key|private key|signing key|access token|"
    r"refresh token|auth token|access key)\b",
    re.IGNORECASE,
)

# Error / nil checks are not secret compares even if a credential name
# appears in a nearby sprintf ("authorization request") or cache tag.
_ERR_IDENT = re.compile(r"(?i)^(ok|e)$|err")

_WORD_RE = re.compile(r"[A-Za-z_]\w*")
# goast stores nested function bodies as assign RHS; those are not
# secret values and must not flood-taint the enclosing function.
_FUNC_LIT = re.compile(r"(?s)^\s*func\s*\(")


def _quoted_cred(q: str) -> bool:
    return bool(_QUOTED_CRED_RE.search(re.sub(r"[_\-.]+", " ", q)))


def _strip_kind(operand: str) -> tuple[str, str]:
    """'identifier x' -> ('identifier', 'x')."""
    kind, _, rest = operand.partition(" ")
    return kind, rest


def _sourced(text: str) -> bool:
    """Expression derives from a credential source?

    Only signal: a quoted argument naming a credential at word boundary
    (Header.Get("X-Agent-Secret"), os.Getenv("API_TOKEN")). Callee /
    field NAMES alone (f.key(), getApiKey(), setting.Key) are NOT
    evidence — that naming-shaped signal caused the bench-run-0 FP
    families.
    """
    return any(_quoted_cred(q) for q in quoted_strings(text))


def _is_secret_operand(kind: str, text: str,
                       secret_vars: set[str]) -> bool:
    if kind == "literal":
        return False  # literals containing "token" are NOT secrets (C6 FP)
    if kind == "identifier":
        # bare identifiers need intra-function source evidence (rule b);
        # a credential-ish NAME alone is not evidence (FP family 1)
        return text in secret_vars
    # selector / call / other: direct source evidence (rule a), or the
    # trailing name refers to a known secret variable
    last = text.split(".")[-1].split("(", 1)[0]
    if last in secret_vars:
        return True
    return _sourced(text)


def _secret_vars(fn: dict) -> set[str]:
    """Variables whose value comes from a credential-ish source (rule b).

    Seed: assigned directly from a sourced expression. Propagate: a var
    assigned from an expression referencing an already-secret var.
    Iterated to fixpoint over the function's assigns.
    """
    assigns = [
        (asg.get("lhs", ""), asg.get("rhs_summary", ""))
        for asg in fn.get("assigns", [])
    ]

    def lhs_names(lhs: str) -> list[str]:
        return [p.strip() for p in lhs.split(",")
                if p.strip() and p.strip() != "_"]

    out: set[str] = set()
    for _ in range(len(assigns) + 1):
        grew = False
        for lhs, rhs in assigns:
            if _FUNC_LIT.match(rhs):
                continue
            sourced = _sourced(rhs) or bool(
                set(_WORD_RE.findall(rhs)) & out)
            if not sourced:
                continue
            for name in lhs_names(lhs):
                if _ERR_IDENT.search(name):
                    continue
                if name not in out:
                    out.add(name)
                    grew = True
        if not grew:
            break
    return out


def detect(source: str, filename: str = "<inline>") -> list[Finding]:
    facts = load_facts(source, filename)
    if facts is None:
        return []
    findings: list[Finding] = []
    seen_pairs: set[tuple] = set()
    for fn in facts.get("functions", []):
        secret_vars = _secret_vars(fn)
        for cmp in fn.get("string_comparisons", []):
            op = cmp.get("op")
            if op not in _CMP_OPS:
                continue  # subtle.ConstantTimeCompare / hmac.Equal records
            operands = [
                _strip_kind(o) for o in cmp.get("operands", []) if " " in o
            ]
            if any(SAFE_API_RE.search(t) for _, t in operands):
                continue
            if any(k == "identifier" and t == "nil" for k, t in operands):
                continue
            if any(k == "identifier" and _ERR_IDENT.search(t) for k, t in operands):
                continue
            secret_hits = [
                t for k, t in operands
                if _is_secret_operand(k, t, secret_vars)
            ]
            if not secret_hits:
                continue
            # presence-check exemption: other side is the empty literal
            if op in ("==", "!="):
                others = [
                    (k, t) for k, t in operands if t not in secret_hits
                ]
                if others and all(
                    k == "literal" and t in ('""', "''") for k, t in others
                ):
                    continue
            # dedupe: one finding per line per comparison pair
            key = (cmp.get("line", 0), tuple(sorted(set(operands))))
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            findings.append(Finding(
                line=cmp.get("line", 0),
                message=f"plain {op} comparison involving secret-derived "
                        f"value ({', '.join(sorted(set(secret_hits)))}); use "
                        "crypto/subtle.ConstantTimeCompare",
                rule_id=RULE_ID,
            ))
    return findings
