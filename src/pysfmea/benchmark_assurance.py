"""Independent benchmark protocol and statistical qualification evidence.

This layer strengthens an exact PySFMEA qualification campaign with a
predeclared holdout design, uncertainty bounds, reviewer agreement, and
change-triggered requalification. It never self-approves tool qualification.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from pathlib import Path
from statistics import NormalDist
from typing import Any

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import BoundedJsonDocument, load_bounded_json_document
from .model import utc_now
from .qualification import (
    load_qualification_campaign_result,
    verify_qualification_campaign_file,
)

BENCHMARK_PROTOCOL_FORMAT = "pysfmea-independent-benchmark-protocol-1"
BENCHMARK_ASSESSMENT_FORMAT = "pysfmea-independent-benchmark-assessment-1"
BENCHMARK_VERIFICATION_FORMAT = "pysfmea-independent-benchmark-verification-1"
MAX_BENCHMARK_BYTES = 100_000_000
MAX_TEXT = 20_000

METRIC_NAMES = (
    "finding_recall",
    "finding_precision",
    "call_recall",
    "call_precision",
    "control_recall",
    "control_precision",
    "semantic_recall",
    "semantic_precision",
)
REQUALIFICATION_TRIGGERS = frozenset(
    {
        "scanner_or_rule_change",
        "python_or_dependency_change",
        "benchmark_or_label_change",
        "llm_model_prompt_or_policy_change",
        "intended_environment_change",
        "new_or_changed_known_anomaly",
    }
)


def _bounded_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT:
        raise ValueError(f"{label} must be non-empty bounded text")
    return value.strip()


def _protocol(document: dict[str, Any]) -> dict[str, Any]:
    required = {
        "format",
        "id",
        "title",
        "pre_registered_at",
        "pre_registration_evidence_ref",
        "governance",
        "design",
        "statistics",
        "reviewer_agreement",
        "requalification_triggers",
    }
    if set(document) != required or document.get("format") != BENCHMARK_PROTOCOL_FORMAT:
        raise ValueError("benchmark protocol fields or format do not match format 1")
    for field in (
        "id",
        "title",
        "pre_registered_at",
        "pre_registration_evidence_ref",
    ):
        _bounded_text(document[field], f"protocol {field}")
    governance = document.get("governance")
    if not isinstance(governance, dict) or set(governance) != {
        "protocol_owner",
        "label_authority",
        "approval_authority",
        "independence_basis",
    }:
        raise ValueError("benchmark governance fields do not match format 1")
    identities = [
        _bounded_text(governance[field], f"governance {field}")
        for field in ("protocol_owner", "label_authority", "approval_authority")
    ]
    _bounded_text(governance["independence_basis"], "governance independence_basis")
    if len({value.casefold() for value in identities}) != len(identities):
        raise ValueError("benchmark governance roles must use distinct identities")
    design = document.get("design")
    if not isinstance(design, dict) or set(design) != {
        "frozen_before_execution",
        "blinded_holdout",
        "minimum_holdout_repositories",
        "holdout_repository_ids",
        "selection_method",
        "represented_populations",
        "excluded_populations",
    }:
        raise ValueError("benchmark design fields do not match format 1")
    if (
        design["frozen_before_execution"] is not True
        or design["blinded_holdout"] is not True
    ):
        raise ValueError(
            "industry benchmark protocol requires a frozen blinded holdout"
        )
    minimum_holdout = design["minimum_holdout_repositories"]
    holdout_ids = design["holdout_repository_ids"]
    if (
        not isinstance(minimum_holdout, int)
        or isinstance(minimum_holdout, bool)
        or minimum_holdout < 1
        or minimum_holdout > 1_000
        or not isinstance(holdout_ids, list)
        or len(holdout_ids) != len(set(holdout_ids))
        or len(holdout_ids) < minimum_holdout
        or any(not isinstance(value, str) or not value.strip() for value in holdout_ids)
    ):
        raise ValueError("benchmark holdout population is invalid")
    _bounded_text(design["selection_method"], "design selection_method")
    for field in ("represented_populations", "excluded_populations"):
        values = design[field]
        if (
            not isinstance(values, list)
            or not values
            or len(values) > 1_000
            or any(not isinstance(value, str) or not value.strip() for value in values)
        ):
            raise ValueError(f"design {field} must contain bounded population labels")
    statistics = document.get("statistics")
    if not isinstance(statistics, dict) or set(statistics) != {
        "confidence_level",
        "minimum_lower_bounds",
        "minimum_cohen_kappa",
    }:
        raise ValueError("benchmark statistics fields do not match format 1")
    confidence = statistics["confidence_level"]
    kappa = statistics["minimum_cohen_kappa"]
    lower_bounds = statistics["minimum_lower_bounds"]
    if (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not 0.8 <= float(confidence) < 1.0
        or not isinstance(kappa, (int, float))
        or isinstance(kappa, bool)
        or not -1.0 <= float(kappa) <= 1.0
        or not isinstance(lower_bounds, dict)
        or set(lower_bounds) != set(METRIC_NAMES)
        or any(
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not 0.0 <= float(value) <= 1.0
            for value in lower_bounds.values()
        )
    ):
        raise ValueError("benchmark statistical thresholds are invalid")
    agreement = document.get("reviewer_agreement")
    if not isinstance(agreement, dict) or set(agreement) != {
        "both_positive",
        "primary_only",
        "secondary_only",
        "both_negative",
        "adjudication_evidence_ref",
    }:
        raise ValueError("reviewer agreement fields do not match format 1")
    counts = [
        agreement[field]
        for field in (
            "both_positive",
            "primary_only",
            "secondary_only",
            "both_negative",
        )
    ]
    if (
        any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in counts
        )
        or sum(counts) < 2
    ):
        raise ValueError(
            "reviewer agreement requires at least two independently rated items"
        )
    _bounded_text(
        agreement["adjudication_evidence_ref"],
        "reviewer agreement adjudication_evidence_ref",
    )
    triggers = document.get("requalification_triggers")
    if not isinstance(triggers, list) or set(triggers) != REQUALIFICATION_TRIGGERS:
        raise ValueError(
            "benchmark protocol must declare the closed requalification trigger set"
        )
    return copy.deepcopy(document)


def load_benchmark_protocol(source: str | Path) -> BoundedJsonDocument:
    document = load_bounded_json_document(
        source,
        label="independent benchmark protocol",
        max_bytes=5_000_000,
        max_depth=30,
        max_nodes=100_000,
    )
    if not isinstance(document.value, dict):
        raise ValueError("independent benchmark protocol must contain an object")
    _protocol(document.value)
    return document


def _binding(document: BoundedJsonDocument) -> dict[str, Any]:
    return {
        "reference": document.path.name,
        "bytes": document.size,
        "sha256": hashlib.sha256(document.raw).hexdigest(),
        "canonical_sha256": canonical_json_sha256(document.value),
    }


def _wilson(matched: int, population: int, confidence: float) -> dict[str, Any]:
    if population <= 0:
        return {
            "matched": matched,
            "population": population,
            "estimate": None,
            "lower": 0.0,
            "upper": 1.0,
        }
    estimate = matched / population
    z = NormalDist().inv_cdf(0.5 + confidence / 2.0)
    denominator = 1.0 + z * z / population
    center = (estimate + z * z / (2.0 * population)) / denominator
    margin = (
        z
        * math.sqrt(
            estimate * (1.0 - estimate) / population
            + z * z / (4.0 * population * population)
        )
        / denominator
    )
    return {
        "matched": matched,
        "population": population,
        "estimate": round(estimate, 6),
        "lower": round(max(0.0, center - margin), 6),
        "upper": round(min(1.0, center + margin), 6),
    }


def _cohen_kappa(agreement: dict[str, Any]) -> dict[str, Any]:
    both_positive = int(agreement["both_positive"])
    primary_only = int(agreement["primary_only"])
    secondary_only = int(agreement["secondary_only"])
    both_negative = int(agreement["both_negative"])
    count = both_positive + primary_only + secondary_only + both_negative
    observed = (both_positive + both_negative) / count
    primary_positive = both_positive + primary_only
    primary_negative = secondary_only + both_negative
    secondary_positive = both_positive + secondary_only
    secondary_negative = primary_only + both_negative
    expected = (
        primary_positive * secondary_positive + primary_negative * secondary_negative
    ) / (count * count)
    value = (
        1.0
        if expected == 1.0 and observed == 1.0
        else (observed - expected) / (1.0 - expected)
    )
    return {
        "items": count,
        "observed_agreement": round(observed, 6),
        "expected_agreement": round(expected, 6),
        "cohen_kappa": round(value, 6),
    }


def _metric_counts(result: dict[str, Any]) -> dict[str, tuple[int, int]]:
    features = result.get("features", {})
    mapping = {
        "finding": "finding_detection",
        "call": "call_resolution",
        "control": "control_detection",
        "semantic": "semantic_output",
    }
    counts: dict[str, tuple[int, int]] = {}
    for prefix, key in mapping.items():
        metric = features.get(key, {}) if isinstance(features, dict) else {}
        if not isinstance(metric, dict):
            metric = {}
        matched = int(metric.get("matched", 0) or 0)
        counts[f"{prefix}_recall"] = (matched, int(metric.get("expected", 0) or 0))
        counts[f"{prefix}_precision"] = (matched, int(metric.get("actual", 0) or 0))
    return counts


def _derive(
    protocol: dict[str, Any], result: dict[str, Any], qualification_valid: bool
) -> tuple[dict[str, Any], dict[str, bool], dict[str, Any]]:
    confidence = float(protocol["statistics"]["confidence_level"])
    intervals = {
        name: _wilson(matched, population, confidence)
        for name, (matched, population) in _metric_counts(result).items()
    }
    agreement = _cohen_kappa(protocol["reviewer_agreement"])
    result_repository_ids = {
        str(repository.get("id", ""))
        for repository in result.get("repositories", [])
        if isinstance(repository, dict)
    }
    holdout_ids = set(protocol["design"]["holdout_repository_ids"])
    bounds = protocol["statistics"]["minimum_lower_bounds"]
    checks = {
        "qualification_integrity": qualification_valid,
        "qualification_eligible": bool(result.get("eligible_for_independent_review")),
        "independent_governance": True,
        "frozen_blinded_holdout": bool(
            protocol["design"]["frozen_before_execution"]
            and protocol["design"]["blinded_holdout"]
        ),
        "holdout_population": bool(
            len(holdout_ids) >= protocol["design"]["minimum_holdout_repositories"]
            and holdout_ids <= result_repository_ids
        ),
        "confidence_bounds": all(
            intervals[name]["population"] > 0
            and float(intervals[name]["lower"]) >= float(bounds[name])
            for name in METRIC_NAMES
        ),
        "reviewer_agreement": float(agreement["cohen_kappa"])
        >= float(protocol["statistics"]["minimum_cohen_kappa"]),
        "requalification_policy": set(protocol["requalification_triggers"])
        == REQUALIFICATION_TRIGGERS,
    }
    passed = all(checks.values())
    summary = {
        "passed": passed,
        "status": "eligible_for_authorized_tool_qualification_review"
        if passed
        else "benchmark_evidence_incomplete",
        "confidence_level": confidence,
        "holdout_repositories": len(holdout_ids),
        "intervals_passing": sum(
            intervals[name]["population"] > 0
            and float(intervals[name]["lower"]) >= float(bounds[name])
            for name in METRIC_NAMES
        ),
        "intervals_required": len(METRIC_NAMES),
        "cohen_kappa": agreement["cohen_kappa"],
        "failed_checks": sorted(name for name, value in checks.items() if not value),
    }
    return (
        {"confidence_intervals": intervals, "reviewer_agreement": agreement},
        checks,
        summary,
    )


def benchmark_assessment(
    protocol_source: str | Path,
    qualification_result_source: str | Path,
    qualification_manifest_source: str | Path,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a statistically governed assessment over an exact campaign result."""

    protocol_document = load_benchmark_protocol(protocol_source)
    result_document = load_bounded_json_document(
        qualification_result_source,
        label="qualification campaign result",
        max_bytes=MAX_BENCHMARK_BYTES,
        max_depth=100,
        max_nodes=2_000_000,
    )
    manifest_document = load_bounded_json_document(
        qualification_manifest_source,
        label="qualification campaign manifest",
        max_bytes=10_000_000,
        max_depth=60,
        max_nodes=500_000,
    )
    result = load_qualification_campaign_result(result_document.path)
    qualification_verification = verify_qualification_campaign_file(
        result_document.path,
        manifest=manifest_document.path,
    )
    statistics, checks, summary = _derive(
        _protocol(protocol_document.value),
        result,
        bool(qualification_verification.get("valid")),
    )
    assessment: dict[str, Any] = {
        "format": BENCHMARK_ASSESSMENT_FORMAT,
        "generated_at": generated_at or utc_now(),
        "protocol": copy.deepcopy(protocol_document.value),
        "bindings": {
            "protocol": _binding(protocol_document),
            "qualification_result": _binding(result_document),
            "qualification_manifest": _binding(manifest_document),
        },
        "statistics": statistics,
        "checks": checks,
        "summary": summary,
        "notice": "Passing establishes statistically governed evidence eligible for authorized review; it does not qualify the tool, certify a product, or prove population-wide completeness.",
    }
    assessment["content_sha256"] = canonical_json_sha256(assessment)
    return assessment


def verify_benchmark_assessment(assessment: dict[str, Any]) -> dict[str, Any]:
    """Verify assessment integrity and all derived statistical semantics."""

    errors: list[str] = []
    required = {
        "format",
        "generated_at",
        "protocol",
        "bindings",
        "statistics",
        "checks",
        "summary",
        "notice",
        "content_sha256",
    }
    closed = (
        set(assessment) == required
        and assessment.get("format") == BENCHMARK_ASSESSMENT_FORMAT
    )
    if not closed:
        errors.append("assessment fields or format do not match format 1")
    content = copy.deepcopy(assessment)
    claimed = str(content.pop("content_sha256", ""))
    integrity = bool(
        re.fullmatch(r"[0-9a-f]{64}", claimed)
        and canonical_json_sha256(content) == claimed
    )
    if not integrity:
        errors.append("assessment content digest does not match")
    semantic = False
    try:
        protocol = _protocol(assessment["protocol"])
        qualification_valid = bool(assessment["checks"]["qualification_integrity"])
        # The retained interval populations and estimates are recomputed from themselves;
        # exact source bindings are verified separately by the file verifier below.
        statistics = assessment["statistics"]
        agreement = _cohen_kappa(protocol["reviewer_agreement"])
        interval_values = statistics["confidence_intervals"]
        expected_intervals = {
            name: _wilson(
                int(interval_values[name]["matched"]),
                int(interval_values[name]["population"]),
                float(protocol["statistics"]["confidence_level"]),
            )
            for name in METRIC_NAMES
        }
        bounds = protocol["statistics"]["minimum_lower_bounds"]
        expected_confidence = all(
            interval_values[name]["population"] > 0
            and float(interval_values[name]["lower"]) >= float(bounds[name])
            for name in METRIC_NAMES
        )
        expected_checks = dict(assessment["checks"])
        expected_checks["independent_governance"] = True
        expected_checks["frozen_blinded_holdout"] = True
        expected_checks["confidence_bounds"] = expected_confidence
        expected_checks["reviewer_agreement"] = float(
            agreement["cohen_kappa"]
        ) >= float(protocol["statistics"]["minimum_cohen_kappa"])
        expected_checks["requalification_policy"] = (
            set(protocol["requalification_triggers"]) == REQUALIFICATION_TRIGGERS
        )
        expected_summary = {
            "passed": all(expected_checks.values()),
            "status": "eligible_for_authorized_tool_qualification_review"
            if all(expected_checks.values())
            else "benchmark_evidence_incomplete",
            "confidence_level": float(protocol["statistics"]["confidence_level"]),
            "holdout_repositories": len(protocol["design"]["holdout_repository_ids"]),
            "intervals_passing": sum(
                interval_values[name]["population"] > 0
                and float(interval_values[name]["lower"]) >= float(bounds[name])
                for name in METRIC_NAMES
            ),
            "intervals_required": len(METRIC_NAMES),
            "cohen_kappa": agreement["cohen_kappa"],
            "failed_checks": sorted(
                name for name, value in expected_checks.items() if not value
            ),
        }
        semantic = bool(
            qualification_valid in {True, False}
            and interval_values == expected_intervals
            and statistics["reviewer_agreement"] == agreement
            and assessment["checks"] == expected_checks
            and assessment["summary"] == expected_summary
        )
    except (KeyError, TypeError, ValueError, OverflowError):
        semantic = False
    if not semantic:
        errors.append(
            "assessment protocol, checks, or derived statistics do not reconcile"
        )
    bindings = assessment.get("bindings")
    binding_shape = (
        isinstance(bindings, dict)
        and set(bindings)
        == {"protocol", "qualification_result", "qualification_manifest"}
        and all(
            isinstance(value, dict)
            and set(value) == {"reference", "bytes", "sha256", "canonical_sha256"}
            and isinstance(value["bytes"], int)
            and value["bytes"] >= 0
            and bool(re.fullmatch(r"[0-9a-f]{64}", str(value["sha256"])))
            and bool(re.fullmatch(r"[0-9a-f]{64}", str(value["canonical_sha256"])))
            for value in bindings.values()
        )
    )
    if not binding_shape:
        errors.append("assessment source bindings are malformed")
    valid = closed and integrity and semantic and binding_shape
    summary = assessment.get("summary", {})
    return {
        "format": BENCHMARK_VERIFICATION_FORMAT,
        "valid": valid,
        "passed": bool(valid and isinstance(summary, dict) and summary.get("passed")),
        "checks": {
            "closed_structure": closed,
            "content_integrity": integrity,
            "semantic_reconciliation": semantic,
            "binding_structure": binding_shape,
            "source_regeneration": None,
        },
        "errors": errors,
        "content_sha256": claimed,
        "notice": "Verification establishes artifact integrity and internal statistical consistency, not benchmark independence, label truth, or tool qualification.",
    }


def verify_benchmark_assessment_file(
    source: str | Path,
    *,
    protocol_source: str | Path | None = None,
    qualification_result_source: str | Path | None = None,
    qualification_manifest_source: str | Path | None = None,
) -> dict[str, Any]:
    try:
        document = load_bounded_json_document(
            source,
            label="independent benchmark assessment",
            max_bytes=MAX_BENCHMARK_BYTES,
            max_depth=100,
            max_nodes=2_000_000,
        )
        if not isinstance(document.value, dict):
            raise ValueError("independent benchmark assessment must contain an object")
        verdict = {
            "path": str(document.path),
            **verify_benchmark_assessment(document.value),
        }
        supplied = (
            protocol_source,
            qualification_result_source,
            qualification_manifest_source,
        )
        if any(value is not None for value in supplied):
            if not all(value is not None for value in supplied):
                verdict["valid"] = False
                verdict["passed"] = False
                verdict["checks"]["source_regeneration"] = False
                verdict["errors"].append(
                    "protocol, qualification result, and qualification manifest must be supplied together"
                )
            else:
                regenerated = benchmark_assessment(
                    protocol_source or "",
                    qualification_result_source or "",
                    qualification_manifest_source or "",
                    generated_at=str(document.value.get("generated_at", "")),
                )
                source_match = regenerated == document.value
                verdict["checks"]["source_regeneration"] = source_match
                if not source_match:
                    verdict["valid"] = False
                    verdict["passed"] = False
                    verdict["errors"].append(
                        "assessment does not exactly regenerate from supplied sources"
                    )
        else:
            verdict["checks"]["source_regeneration"] = None
        return verdict
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "path": str(Path(source).expanduser().absolute()),
            "format": BENCHMARK_VERIFICATION_FORMAT,
            "valid": False,
            "passed": False,
            "checks": {
                "closed_structure": False,
                "content_integrity": False,
                "semantic_reconciliation": False,
                "binding_structure": False,
                "source_regeneration": False,
            },
            "errors": [str(exc)],
            "content_sha256": "",
            "notice": "The independent benchmark assessment could not be safely verified.",
        }


def export_benchmark_assessment(
    assessment: dict[str, Any], destination: str | Path
) -> Path:
    verdict = verify_benchmark_assessment(assessment)
    if not verdict["valid"]:
        raise ValueError("independent benchmark assessment is not internally valid")
    return atomic_publish_text(
        destination,
        json.dumps(assessment, indent=2, ensure_ascii=False) + "\n",
        label="independent benchmark assessment",
    )
