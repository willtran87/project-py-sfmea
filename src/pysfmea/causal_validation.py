"""Runtime validation of statically predicted failure cascades and resilience controls."""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from .governed_artifact import bounded_text, load_json, publish_json, seal, verify_seal
from .model import utc_now

CAUSAL_VALIDATION_FORMAT = "pysfmea-causal-validation-2"
CAUSAL_VALIDATION_VERIFICATION_FORMAT = "pysfmea-causal-validation-verification-1"


def _edges(path: list[str]) -> set[tuple[str, str]]:
    return set(zip(path, path[1:]))


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _metrics(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    path_counts = {
        "predicted": 0,
        "observed": 0,
        "matched": 0,
        "unexpected": 0,
        "unobserved": 0,
    }
    effect_counts = dict(path_counts)
    exact_paths = exact_effects = 0
    for item in scenarios:
        predicted_edges = _edges(item["predicted_path"])
        observed_edges = _edges(item["observed_path"])
        edge_match = predicted_edges & observed_edges
        path_counts["predicted"] += len(predicted_edges)
        path_counts["observed"] += len(observed_edges)
        path_counts["matched"] += len(edge_match)
        path_counts["unexpected"] += len(observed_edges - predicted_edges)
        path_counts["unobserved"] += len(predicted_edges - observed_edges)
        predicted_effects = set(item["predicted_effects"])
        observed_effects = set(item["observed_effects"])
        effect_match = predicted_effects & observed_effects
        effect_counts["predicted"] += len(predicted_effects)
        effect_counts["observed"] += len(observed_effects)
        effect_counts["matched"] += len(effect_match)
        effect_counts["unexpected"] += len(observed_effects - predicted_effects)
        effect_counts["unobserved"] += len(predicted_effects - observed_effects)
        exact_paths += item["predicted_path"] == item["observed_path"]
        exact_effects += predicted_effects == observed_effects
    timed = [item for item in scenarios if item["deadline_ms"] is not None]
    breakers = [
        item for item in scenarios if item["expected_breaker_state"] != "not_applicable"
    ]
    recovery = [item for item in scenarios if item["recovery_deadline_ms"] is not None]
    return {
        "scenarios": len(scenarios),
        "path_edge_precision": _ratio(path_counts["matched"], path_counts["predicted"]),
        "path_edge_recall": _ratio(path_counts["matched"], path_counts["observed"]),
        "effect_precision": _ratio(
            effect_counts["matched"], effect_counts["predicted"]
        ),
        "effect_recall": _ratio(effect_counts["matched"], effect_counts["observed"]),
        "exact_ordered_path_rate": _ratio(exact_paths, len(scenarios)),
        "exact_effect_set_rate": _ratio(exact_effects, len(scenarios)),
        "deadline_population": len(timed),
        "breaker_population": len(breakers),
        "recovery_population": len(recovery),
        "deadline_conformance": _ratio(
            sum(item["observed_duration_ms"] <= item["deadline_ms"] for item in timed),
            len(timed),
        ),
        "breaker_transition_accuracy": _ratio(
            sum(
                item["observed_breaker_state"] == item["expected_breaker_state"]
                for item in breakers
            ),
            len(breakers),
        ),
        "recovery_conformance": _ratio(
            sum(
                item["observed_recovery_ms"] is not None
                and item["observed_recovery_ms"] <= item["recovery_deadline_ms"]
                for item in recovery
            ),
            len(recovery),
        ),
        "unexpected_edges": path_counts["unexpected"],
        "unobserved_predicted_edges": path_counts["unobserved"],
        "unexpected_effects": effect_counts["unexpected"],
        "unobserved_predicted_effects": effect_counts["unobserved"],
    }


def _valid_scenario(item: Any) -> bool:
    fields = {
        "id",
        "finding_id",
        "injection_point",
        "fault",
        "predicted_path",
        "observed_path",
        "predicted_effects",
        "observed_effects",
        "deadline_ms",
        "observed_duration_ms",
        "expected_breaker_state",
        "observed_breaker_state",
        "recovery_deadline_ms",
        "observed_recovery_ms",
        "trace_sha256",
        "execution_evidence_ref",
    }
    states = {"closed", "open", "half_open", "not_applicable"}
    return bool(
        isinstance(item, dict)
        and set(item) == fields
        and all(
            isinstance(item[name], str) and item[name]
            for name in (
                "id",
                "finding_id",
                "injection_point",
                "fault",
                "execution_evidence_ref",
            )
        )
        and all(
            isinstance(item[name], list)
            and len(item[name]) <= 10_000
            and all(isinstance(value, str) and value for value in item[name])
            for name in (
                "predicted_path",
                "observed_path",
                "predicted_effects",
                "observed_effects",
            )
        )
        and len(item["predicted_path"]) >= 1
        and len(item["observed_path"]) >= 1
        and all(
            item[name] is None or _finite_nonnegative(item[name])
            for name in ("deadline_ms", "recovery_deadline_ms", "observed_recovery_ms")
        )
        and _finite_nonnegative(item["observed_duration_ms"])
        and item["expected_breaker_state"] in states
        and item["observed_breaker_state"] in states
        and bool(re.fullmatch(r"[0-9a-f]{64}", item["trace_sha256"]))
        and item["trace_sha256"] != "0" * 64
    )


def _finite_nonnegative(value: Any) -> bool:
    return bool(
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and value >= 0
    )


def causal_validation(
    scenarios: list[dict[str, Any]],
    *,
    analysis_sha256: str,
    producer: str,
    reviewer: str,
    authority: str,
) -> dict[str, Any]:
    if (
        not scenarios
        or len(scenarios) > 100_000
        or not all(_valid_scenario(item) for item in scenarios)
    ):
        raise ValueError("causal-validation scenarios are invalid")
    if len({item["id"] for item in scenarios}) != len(scenarios):
        raise ValueError("causal-validation scenario ids must be unique")
    result = seal(
        {
            "format": CAUSAL_VALIDATION_FORMAT,
            "generated_at": utc_now(),
            "authority": bounded_text(authority, "causal-validation authority"),
            "analysis_sha256": analysis_sha256,
            "governance": {
                "producer": bounded_text(producer, "causal-validation producer"),
                "reviewer": bounded_text(reviewer, "causal-validation reviewer"),
                "independent": producer != reviewer,
            },
            "scenarios": scenarios,
            "metrics": _metrics(scenarios),
            "claim_boundary": "This receipt compares static predictions with content-addressed runtime observations. Causality remains scoped to declared injection scenarios, trace instrumentation, oracles, and reviewed execution evidence.",
        }
    )
    if not verify_causal_validation(result)["valid"]:
        raise ValueError("causal validation failed internal verification")
    return result


def _structure(value: dict[str, Any]) -> bool:
    try:
        scenarios = value["scenarios"]
        return bool(
            set(value)
            == {
                "format",
                "generated_at",
                "authority",
                "analysis_sha256",
                "governance",
                "scenarios",
                "metrics",
                "claim_boundary",
                "content_sha256",
            }
            and bool(re.fullmatch(r"[0-9a-f]{64}", value["analysis_sha256"]))
            and set(value["governance"]) == {"producer", "reviewer", "independent"}
            and value["governance"]["independent"]
            == (value["governance"]["producer"] != value["governance"]["reviewer"])
            and isinstance(scenarios, list)
            and 0 < len(scenarios) <= 100_000
            and all(_valid_scenario(item) for item in scenarios)
            and len({item["id"] for item in scenarios}) == len(scenarios)
        )
    except (KeyError, TypeError):
        return False


def verify_causal_validation(value: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value, label="causal validation", format_value=CAUSAL_VALIDATION_FORMAT
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure = _structure(checked)
    reconciliation = bool(
        structure and checked["metrics"] == _metrics(checked["scenarios"])
    )
    independent = bool(structure and checked["governance"]["independent"])
    if not structure:
        errors.append("causal-validation fields are invalid")
    if structure and not reconciliation:
        errors.append("causal-validation metrics do not reconcile")
    if structure and not independent:
        errors.append("causal-validation reviewer is not independent of the producer")
    return seal(
        {
            "format": CAUSAL_VALIDATION_VERIFICATION_FORMAT,
            "valid": integrity and structure and reconciliation,
            "eligible_for_independent_claim": integrity
            and structure
            and reconciliation
            and independent,
            "checks": {
                "content_integrity_and_structure": integrity and structure,
                "metric_reconciliation": reconciliation,
                "independent_review": independent,
            },
            "errors": errors,
            "notice": "Eligibility establishes independently reviewed scenario evidence, not universal runtime causality or certification.",
        }
    )


def export_causal_validation(value: dict[str, Any], destination: str | Path) -> Path:
    if not verify_causal_validation(value)["valid"]:
        raise ValueError("causal-validation artifact is invalid")
    return publish_json(value, destination)


def verify_causal_validation_file(source: str | Path) -> dict[str, Any]:
    try:
        return verify_causal_validation(load_json(source, label="causal validation"))
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": CAUSAL_VALIDATION_VERIFICATION_FORMAT,
                "valid": False,
                "eligible_for_independent_claim": False,
                "checks": {
                    "content_integrity_and_structure": False,
                    "metric_reconciliation": False,
                    "independent_review": False,
                },
                "errors": [str(exc)],
                "notice": "Causal-validation verification failed closed.",
            }
        )
