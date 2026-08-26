"""Pre-outcome sealing and reconciliation for generated-test campaigns."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .model import utc_now
from .test_generation_quality import (
    _SUBJECT_FIELDS,
    MAX_QUALITY_SAMPLES,
    TEST_GENERATION_CAMPAIGN_CORPUS_FORMAT,
)
from .test_generation_quality_campaign import (
    _BASE_POLICY_FIELDS,
    _CAMPAIGN_COUNT_POLICY_FIELDS,
    _CAMPAIGN_GOVERNANCE_FIELDS,
    _CAMPAIGN_POLICY_FIELDS,
    _ROOT_FIELDS,
    _SAMPLE_FIELDS,
    _bounded_count,
    _labels,
    _rate,
    _text,
    _timestamp,
)

CAMPAIGN_PLAN_FORMAT = "pysfmea-test-generation-campaign-plan-1"
CAMPAIGN_PLAN_VERIFICATION_FORMAT = (
    "pysfmea-test-generation-campaign-plan-verification-1"
)
_PLAN_GOVERNANCE_FIELDS = _CAMPAIGN_GOVERNANCE_FIELDS - {"outcomes_observed_at"}
_PLAN_SAMPLE_FIELDS = _SAMPLE_FIELDS - {"artifacts"}
_PLAN_FIELDS = {
    "format",
    "name",
    "subject",
    "governance",
    "policy",
    "samples",
    "sealed_at",
    "producer",
    "notice",
    "content_sha256",
}


def _projection(corpus: dict[str, Any]) -> dict[str, Any]:
    if (
        set(corpus) != _ROOT_FIELDS
        or corpus.get("format") != TEST_GENERATION_CAMPAIGN_CORPUS_FORMAT
    ):
        raise ValueError("campaign corpus must match the closed format-3 root contract")
    governance = corpus.get("governance")
    if (
        not isinstance(governance, dict)
        or set(governance) != _CAMPAIGN_GOVERNANCE_FIELDS
    ):
        raise ValueError("campaign governance must match the closed format-3 contract")
    _frozen_text, frozen_at = _timestamp(
        governance.get("selection_frozen_at"), "selection_frozen_at"
    )
    _observed_text, observed_at = _timestamp(
        governance.get("outcomes_observed_at"), "outcomes_observed_at"
    )
    if frozen_at > observed_at:
        raise ValueError("selection_frozen_at must not follow outcomes_observed_at")
    if not isinstance(governance.get("independent"), bool):
        raise ValueError("campaign governance independent must be boolean")
    for field in _PLAN_GOVERNANCE_FIELDS - {"independent", "selection_frozen_at"}:
        _text(governance.get(field), f"campaign governance {field}")
    subject = corpus.get("subject")
    if not isinstance(subject, dict) or set(subject) != _SUBJECT_FIELDS:
        raise ValueError("campaign subject must match the closed contract")
    normalized_subject = {
        field: _text(subject.get(field), f"campaign subject {field}")
        for field in sorted(_SUBJECT_FIELDS)
    }
    policy = corpus.get("policy")
    if not isinstance(policy, dict) or set(policy) != _CAMPAIGN_POLICY_FIELDS:
        raise ValueError("campaign policy must match the closed format-3 contract")
    for field in _BASE_POLICY_FIELDS:
        if field in {"min_samples", "min_proposed_samples", "min_refused_samples"}:
            _bounded_count(policy.get(field), field)
        else:
            _rate(policy.get(field), field)
    for field in _CAMPAIGN_COUNT_POLICY_FIELDS:
        _bounded_count(policy.get(field), field)
    _rate(
        policy.get("max_single_repository_fraction"),
        "max_single_repository_fraction",
    )
    if not isinstance(policy.get("require_decision_balance_per_repository"), bool):
        raise ValueError("require_decision_balance_per_repository must be boolean")
    samples = corpus.get("samples")
    if (
        not isinstance(samples, list)
        or not samples
        or len(samples) > MAX_QUALITY_SAMPLES
    ):
        raise ValueError("campaign samples must be a bounded non-empty array")
    projected_samples: list[dict[str, Any]] = []
    ids: set[str] = set()
    for index, sample in enumerate(samples, start=1):
        if not isinstance(sample, dict) or set(sample) != _SAMPLE_FIELDS:
            raise ValueError(f"campaign sample {index} must match the closed contract")
        sample_id = _text(sample.get("id"), f"sample {index} id")
        if sample_id in ids:
            raise ValueError("campaign sample ids must be unique")
        ids.add(sample_id)
        decision = sample.get("expected_decision")
        if decision not in {"proposed", "refused"}:
            raise ValueError(f"sample {index} expected_decision is unsupported")
        fault_category = sample.get("fault_category")
        projected_samples.append(
            {
                "id": sample_id,
                "expected_decision": decision,
                "repository_id": _text(
                    sample.get("repository_id"), f"sample {index} repository_id"
                ),
                "frameworks": _labels(
                    sample.get("frameworks"), f"sample {index} frameworks"
                ),
                "domains": _labels(sample.get("domains"), f"sample {index} domains"),
                "fault_category": (
                    None
                    if fault_category is None
                    else _text(fault_category, f"sample {index} fault_category")
                ),
            }
        )
    return {
        "name": _text(corpus.get("name"), "campaign name"),
        "subject": normalized_subject,
        "governance": {
            field: copy.deepcopy(governance[field])
            for field in sorted(_PLAN_GOVERNANCE_FIELDS)
        },
        "policy": copy.deepcopy(policy),
        "samples": projected_samples,
    }


def create_test_generation_campaign_plan(
    corpus: dict[str, Any], *, producer: str
) -> dict[str, Any]:
    """Seal only labels, sampling policy, and thresholds before outcome inspection."""

    projected = _projection(corpus)
    plan = {
        "format": CAMPAIGN_PLAN_FORMAT,
        **projected,
        "sealed_at": utc_now(),
        "producer": _text(producer, "campaign plan producer"),
        "notice": (
            "This content seal fixes declared campaign design, not reviewer identity, "
            "independence, representativeness, or timestamp authority. Authenticate this "
            "artifact with assurance-evidence-sign before observing outcomes."
        ),
    }
    plan["content_sha256"] = canonical_json_sha256(plan)
    return plan


def export_test_generation_campaign_plan(
    plan: dict[str, Any], destination: str | Path
) -> Path:
    verification = verify_test_generation_campaign_plan(plan)
    if not verification["plan_valid"]:
        raise ValueError("campaign plan must pass content and contract verification")
    return atomic_publish_text(
        destination,
        json.dumps(plan, indent=2, ensure_ascii=False) + "\n",
        label="generated-test campaign plan",
    )


def verify_test_generation_campaign_plan(
    plan: dict[str, Any], corpus: dict[str, Any] | None = None
) -> dict[str, Any]:
    checks = {
        "plan_contract": False,
        "content_integrity": False,
        "selection_precedes_seal": False,
        "corpus_design_binding": None if corpus is None else False,
        "seal_precedes_outcomes": None if corpus is None else False,
    }
    errors: list[str] = []
    try:
        if not isinstance(plan, dict) or set(plan) != _PLAN_FIELDS:
            raise ValueError("campaign plan must match the closed root contract")
        if plan.get("format") != CAMPAIGN_PLAN_FORMAT:
            raise ValueError("campaign plan format is unsupported")
        supplied_digest = plan.get("content_sha256")
        if not isinstance(supplied_digest, str):
            raise ValueError("campaign plan content_sha256 is missing")
        unsigned = {
            key: copy.deepcopy(value)
            for key, value in plan.items()
            if key != "content_sha256"
        }
        checks["content_integrity"] = canonical_json_sha256(unsigned) == supplied_digest
        if not checks["content_integrity"]:
            raise ValueError("campaign plan content seal does not verify")
        _text(plan.get("producer"), "campaign plan producer")
        _text(plan.get("notice"), "campaign plan notice")
        sealed_text, sealed_at = _timestamp(plan.get("sealed_at"), "sealed_at")
        del sealed_text
        governance = plan.get("governance")
        if (
            not isinstance(governance, dict)
            or set(governance) != _PLAN_GOVERNANCE_FIELDS
        ):
            raise ValueError(
                "campaign plan governance does not match the closed contract"
            )
        _frozen_text, frozen_at = _timestamp(
            governance.get("selection_frozen_at"), "selection_frozen_at"
        )
        if frozen_at > sealed_at:
            raise ValueError("selection_frozen_at must not follow sealed_at")
        checks["selection_precedes_seal"] = True
        samples = plan.get("samples")
        if (
            not isinstance(samples, list)
            or not samples
            or any(
                not isinstance(sample, dict) or set(sample) != _PLAN_SAMPLE_FIELDS
                for sample in samples
            )
        ):
            raise ValueError("campaign plan samples do not match the closed projection")
        synthetic_corpus = {
            "format": TEST_GENERATION_CAMPAIGN_CORPUS_FORMAT,
            "name": copy.deepcopy(plan.get("name")),
            "subject": copy.deepcopy(plan.get("subject")),
            "governance": {
                **copy.deepcopy(governance),
                "outcomes_observed_at": plan["sealed_at"],
            },
            "policy": copy.deepcopy(plan.get("policy")),
            "samples": [
                {**copy.deepcopy(sample), "artifacts": {}} for sample in samples
            ],
        }
        expected_projection = {
            field: copy.deepcopy(plan.get(field))
            for field in ("name", "subject", "governance", "policy", "samples")
        }
        if _projection(synthetic_corpus) != expected_projection:
            raise ValueError("campaign plan semantic projection does not reconcile")
        checks["plan_contract"] = True
        if corpus is not None:
            projected = _projection(corpus)
            checks["corpus_design_binding"] = all(
                plan.get(key) == value for key, value in projected.items()
            )
            if not checks["corpus_design_binding"]:
                errors.append("campaign corpus design differs from the sealed plan")
            _observed_text, observed_at = _timestamp(
                corpus["governance"]["outcomes_observed_at"], "outcomes_observed_at"
            )
            checks["seal_precedes_outcomes"] = sealed_at <= observed_at
            if not checks["seal_precedes_outcomes"]:
                errors.append("campaign plan was sealed after outcomes_observed_at")
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(str(exc))
    required = [value for value in checks.values() if value is not None]
    valid = all(required) and not errors
    return {
        "format": CAMPAIGN_PLAN_VERIFICATION_FORMAT,
        "valid": valid,
        "plan_valid": bool(
            checks["plan_contract"]
            and checks["content_integrity"]
            and checks["selection_precedes_seal"]
        ),
        "checks": checks,
        "errors": errors,
        "notice": (
            "Chronology is a declared comparison unless the plan is authenticated before "
            "outcomes by a trusted key or external timestamping authority."
        ),
    }
