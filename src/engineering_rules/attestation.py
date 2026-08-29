"""Deterministic CC8.1-oriented attestation payloads for engineering-rules runs."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .models import RulesRunResult

_ATTESTATION_SCHEMA = "stopthatslop.attestation.v1"
_PREDICATE_TYPE = "https://stopthatslop.dev/attestation/v1"


class AttestationSubject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_name: str
    repo_root: str
    git_head: str | None = None
    base_ref: str | None = None
    pull_request_url: str | None = None


class AttestationReviewer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity: str
    approved_at: datetime | None = None


class AttestationBundle(BaseModel):
    """Signed-ready attestation artifact for audit retention."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = _ATTESTATION_SCHEMA
    predicate_type: str = _PREDICATE_TYPE
    generated_at: datetime
    subject: AttestationSubject
    reviewer: AttestationReviewer | None = None
    run_result_schema: str = "rules.result.v1"
    passed: bool
    blocking_count: int = Field(ge=0)
    advisory_count: int = Field(ge=0)
    selected_rule_count: int = Field(ge=0)
    changed_file_count: int = Field(ge=0)
    finding_fingerprints: tuple[str, ...] = Field(default_factory=tuple)
    slop_score: dict[str, Any] | None = None
    coverage: dict[str, Any] | None = None
    digest_sha256: str
    signature_hmac_sha256: str | None = None


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest_payload(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def build_attestation_bundle(
    result: RulesRunResult,
    *,
    git_head: str | None = None,
    base_ref: str | None = None,
    pull_request_url: str | None = None,
    reviewer_identity: str | None = None,
    reviewer_approved_at: datetime | None = None,
    slop_score: dict[str, Any] | None = None,
    signing_key: str | None = None,
    generated_at: datetime | None = None,
) -> AttestationBundle:
    """Build a deterministic attestation artifact from a rules run."""

    resolved_generated_at = generated_at or datetime.now(tz=UTC)
    finding_fingerprints = tuple(
        sorted(
            fingerprint
            for fingerprint in (finding.fingerprint for finding in result.findings)
            if fingerprint
        )
    )

    unsigned_core = {
        "schema_version": _ATTESTATION_SCHEMA,
        "predicate_type": _PREDICATE_TYPE,
        "generated_at": resolved_generated_at.isoformat(),
        "subject": {
            "repo_name": result.repo_profile.repo_name,
            "repo_root": result.repo_profile.repo_root,
            "git_head": git_head,
            "base_ref": base_ref,
            "pull_request_url": pull_request_url,
        },
        "reviewer": None
        if reviewer_identity is None
        else {
            "identity": reviewer_identity,
            "approved_at": (
                reviewer_approved_at.isoformat() if reviewer_approved_at is not None else None
            ),
        },
        "run_result_schema": result.schema_version,
        "passed": result.passed,
        "blocking_count": result.blocking_count,
        "advisory_count": result.advisory_count,
        "selected_rule_count": len(result.selected_rule_ids),
        "changed_file_count": len(result.changed_files),
        "finding_fingerprints": list(finding_fingerprints),
        "slop_score": slop_score,
        "coverage": result.coverage.model_dump(mode="json") if result.coverage else None,
    }

    digest = _digest_payload(unsigned_core)
    signature = None
    if signing_key:
        signature = hmac.new(
            signing_key.encode("utf-8"),
            digest.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    reviewer = None
    if reviewer_identity is not None:
        reviewer = AttestationReviewer(
            identity=reviewer_identity,
            approved_at=reviewer_approved_at,
        )

    return AttestationBundle(
        generated_at=resolved_generated_at,
        subject=AttestationSubject(
            repo_name=result.repo_profile.repo_name,
            repo_root=result.repo_profile.repo_root,
            git_head=git_head,
            base_ref=base_ref,
            pull_request_url=pull_request_url,
        ),
        reviewer=reviewer,
        passed=result.passed,
        blocking_count=result.blocking_count,
        advisory_count=result.advisory_count,
        selected_rule_count=len(result.selected_rule_ids),
        changed_file_count=len(result.changed_files),
        finding_fingerprints=finding_fingerprints,
        slop_score=slop_score,
        coverage=result.coverage.model_dump(mode="json") if result.coverage else None,
        digest_sha256=digest,
        signature_hmac_sha256=signature,
    )
