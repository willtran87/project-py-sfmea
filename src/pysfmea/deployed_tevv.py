"""Governed post-deployment TEVV campaigns for AI-assisted assurance workflows."""

from __future__ import annotations

import copy
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .governed_artifact import (
    bounded_text,
    load_json,
    publish_json,
    seal,
    unique_text_list,
    verify_seal,
)
from .model import utc_now
from .operational_evidence import (
    change_history_consistent,
    evidence_bindings,
    replay_operational_evidence,
)

DEPLOYED_TEVV_SOURCE_FORMAT = "pysfmea-deployed-tevv-source-3"
DEPLOYED_TEVV_ASSESSMENT_FORMAT = "pysfmea-deployed-tevv-assessment-3"
DEPLOYED_TEVV_VERIFICATION_FORMAT = "pysfmea-deployed-tevv-verification-3"
MONITORING_CATEGORIES = (
    "functionality",
    "operational",
    "human_factors",
    "security",
    "compliance",
    "large_scale_impacts",
)
MAX_WINDOWS = 10_000


def deployed_tevv_template(*, authority: str) -> dict[str, Any]:
    return seal(
        {
            "format": DEPLOYED_TEVV_SOURCE_FORMAT,
            "generated_at": utc_now(),
            "authority": {
                "campaign_owner": bounded_text(authority, "TEVV campaign authority"),
                "monitoring_authority": "replace-with-monitoring-authority",
                "incident_authority": "replace-with-incident-authority",
                "approval_authority": "replace-with-approval-authority",
                "independence_basis": "replace-with-role-and-reporting-line-separation",
            },
            "system": {
                "id": "replace-with-system-id",
                "version": "replace-with-system-version",
                "model": "replace-with-model-id",
                "model_version": "replace-with-model-version",
                "prompt_sha256": "0" * 64,
                "tool_policy_sha256": "0" * 64,
                "deployment_environment": "replace-with-deployment-environment",
                "intended_use": "replace-with-approved-intended-use",
            },
            "policy": {
                "minimum_monitoring_windows": 2,
                "minimum_evaluations_per_window": 1,
                "minimum_evaluation_pass_rate": 0.95,
                "maximum_error_rate": 0.01,
                "maximum_p95_latency_ms": 30_000.0,
                "maximum_drift_score": 0.1,
                "maximum_open_incidents": 0,
                "maximum_recovery_seconds": 300.0,
                "require_circuit_breaker_test": True,
                "require_rollback_test": True,
            },
            "baseline": {
                "system_version": "replace-with-system-version",
                "model_version": "replace-with-model-version",
                "evidence_ref": "replace-with-predeployment-evidence",
                "evidence_sha256": "0" * 64,
                "evaluation_count": 0,
                "evaluation_pass_rate": 0.0,
            },
            "monitoring_windows": [],
            "category_evidence": {name: [] for name in MONITORING_CATEGORIES},
            "controls": {
                "circuit_breaker": {
                    "tested": False,
                    "activated": False,
                    "evidence_ref": "replace-with-circuit-breaker-evidence",
                },
                "rollback": {
                    "tested": False,
                    "succeeded": False,
                    "recovery_seconds": 0.0,
                    "evidence_ref": "replace-with-rollback-evidence",
                },
            },
            "change_records": [],
            "limitations": [],
            "claim_boundary": (
                "This source records a deployed monitoring and repeated-TEVV campaign. A passing "
                "assessment supports an authorized operational decision only; it does not prove "
                "model safety, eliminate emergent risk, accept risk, or grant certification."
            ),
        }
    )


def _timestamp(value: Any, label: str) -> datetime:
    text = bounded_text(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed


def _number(value: Any, label: str, *, minimum: float = 0.0) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{label} must be numeric")
    result = float(value)
    if not result == result or result < minimum:
        raise ValueError(f"{label} is outside its allowed range")
    return result


def _integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{label} must be an integer of at least {minimum}")
    return value


def _ratio(value: Any, label: str) -> float:
    result = _number(value, label)
    if result > 1:
        raise ValueError(f"{label} must not exceed one")
    return result


def _digest(value: Any, label: str, *, placeholder_allowed: bool = True) -> str:
    text = bounded_text(value, label)
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    if not placeholder_allowed and text == "0" * 64:
        raise ValueError(f"{label} must not be a placeholder digest")
    return text


def _placeholder(value: Any) -> bool:
    return not isinstance(value, str) or not value or value.startswith("replace-")


def _source(value: dict[str, Any]) -> dict[str, Any]:
    result = verify_seal(
        value,
        label="deployed TEVV source",
        format_value=DEPLOYED_TEVV_SOURCE_FORMAT,
    )
    if set(result) != {
        "format",
        "generated_at",
        "authority",
        "system",
        "policy",
        "baseline",
        "monitoring_windows",
        "category_evidence",
        "controls",
        "change_records",
        "limitations",
        "claim_boundary",
        "content_sha256",
    }:
        raise ValueError("deployed TEVV source fields are invalid")
    authority = result["authority"]
    authority_fields = {
        "campaign_owner",
        "monitoring_authority",
        "incident_authority",
        "approval_authority",
        "independence_basis",
    }
    if not isinstance(authority, dict) or set(authority) != authority_fields:
        raise ValueError("deployed TEVV authority fields are invalid")
    for field in authority_fields:
        bounded_text(authority[field], f"TEVV authority {field}")
    system = result["system"]
    system_fields = {
        "id",
        "version",
        "model",
        "model_version",
        "prompt_sha256",
        "tool_policy_sha256",
        "deployment_environment",
        "intended_use",
    }
    if not isinstance(system, dict) or set(system) != system_fields:
        raise ValueError("deployed TEVV system fields are invalid")
    for field in system_fields - {"prompt_sha256", "tool_policy_sha256"}:
        bounded_text(system[field], f"TEVV system {field}")
    _digest(system["prompt_sha256"], "TEVV prompt digest")
    _digest(system["tool_policy_sha256"], "TEVV tool-policy digest")
    policy = result["policy"]
    policy_fields = {
        "minimum_monitoring_windows",
        "minimum_evaluations_per_window",
        "minimum_evaluation_pass_rate",
        "maximum_error_rate",
        "maximum_p95_latency_ms",
        "maximum_drift_score",
        "maximum_open_incidents",
        "maximum_recovery_seconds",
        "require_circuit_breaker_test",
        "require_rollback_test",
    }
    if not isinstance(policy, dict) or set(policy) != policy_fields:
        raise ValueError("deployed TEVV policy fields are invalid")
    _integer(
        policy["minimum_monitoring_windows"], "minimum monitoring windows", minimum=1
    )
    _integer(
        policy["minimum_evaluations_per_window"],
        "minimum evaluations per window",
        minimum=1,
    )
    _ratio(policy["minimum_evaluation_pass_rate"], "minimum evaluation pass rate")
    _ratio(policy["maximum_error_rate"], "maximum error rate")
    _number(policy["maximum_p95_latency_ms"], "maximum p95 latency", minimum=0.001)
    _ratio(policy["maximum_drift_score"], "maximum drift score")
    _integer(policy["maximum_open_incidents"], "maximum open incidents")
    _number(
        policy["maximum_recovery_seconds"], "maximum recovery seconds", minimum=0.001
    )
    for field in ("require_circuit_breaker_test", "require_rollback_test"):
        if type(policy[field]) is not bool:
            raise ValueError(f"{field} must be boolean")
    baseline = result["baseline"]
    if not isinstance(baseline, dict) or set(baseline) != {
        "system_version",
        "model_version",
        "evidence_ref",
        "evidence_sha256",
        "evaluation_count",
        "evaluation_pass_rate",
    }:
        raise ValueError("deployed TEVV baseline fields are invalid")
    for field in ("system_version", "model_version", "evidence_ref"):
        bounded_text(baseline[field], f"TEVV baseline {field}")
    _digest(baseline["evidence_sha256"], "TEVV baseline evidence digest")
    _integer(baseline["evaluation_count"], "TEVV baseline evaluation count")
    _ratio(baseline["evaluation_pass_rate"], "TEVV baseline pass rate")
    windows = result["monitoring_windows"]
    if not isinstance(windows, list) or len(windows) > MAX_WINDOWS:
        raise ValueError("deployed TEVV monitoring windows are invalid")
    window_fields = {
        "id",
        "started_at",
        "ended_at",
        "system_version",
        "model_version",
        "telemetry_schema",
        "telemetry_schema_version",
        "telemetry_ref",
        "telemetry_sha256",
        "collection_ref",
        "collection_sha256",
        "requests",
        "errors",
        "p95_latency_ms",
        "drift_score",
        "evaluation_ref",
        "evaluation_sha256",
        "evaluation_count",
        "evaluation_pass_rate",
        "threshold_breaches",
        "open_incidents",
    }
    seen: set[str] = set()
    prior_end: datetime | None = None
    for window in windows:
        if not isinstance(window, dict) or set(window) != window_fields:
            raise ValueError("deployed TEVV monitoring-window fields are invalid")
        identifier = bounded_text(window["id"], "TEVV monitoring window id")
        if identifier in seen:
            raise ValueError("TEVV monitoring window ids must be unique")
        seen.add(identifier)
        started = _timestamp(window["started_at"], "TEVV window start")
        ended = _timestamp(window["ended_at"], "TEVV window end")
        if ended <= started or (prior_end is not None and started < prior_end):
            raise ValueError(
                "TEVV monitoring windows must be ordered and non-overlapping"
            )
        prior_end = ended
        for field in (
            "system_version",
            "model_version",
            "telemetry_schema",
            "telemetry_schema_version",
            "telemetry_ref",
            "evaluation_ref",
            "collection_ref",
        ):
            bounded_text(window[field], f"TEVV window {field}")
        _digest(window["telemetry_sha256"], "TEVV telemetry digest")
        _digest(window["evaluation_sha256"], "TEVV evaluation digest")
        _digest(window["collection_sha256"], "TEVV collection digest")
        requests = _integer(window["requests"], "TEVV request count", minimum=1)
        errors = _integer(window["errors"], "TEVV error count")
        if errors > requests:
            raise ValueError("TEVV errors cannot exceed requests")
        _number(window["p95_latency_ms"], "TEVV p95 latency")
        _ratio(window["drift_score"], "TEVV drift score")
        _integer(window["evaluation_count"], "TEVV evaluation count")
        _ratio(window["evaluation_pass_rate"], "TEVV evaluation pass rate")
        unique_text_list(window["threshold_breaches"], "TEVV threshold breaches")
        _integer(window["open_incidents"], "TEVV open incidents")
    categories = result["category_evidence"]
    if not isinstance(categories, dict) or set(categories) != set(
        MONITORING_CATEGORIES
    ):
        raise ValueError("deployed TEVV monitoring categories are invalid")
    for name, refs in categories.items():
        unique_text_list(refs, f"{name} monitoring evidence")
    controls = result["controls"]
    if not isinstance(controls, dict) or set(controls) != {
        "circuit_breaker",
        "rollback",
    }:
        raise ValueError("deployed TEVV control fields are invalid")
    breaker = controls["circuit_breaker"]
    rollback = controls["rollback"]
    if not isinstance(breaker, dict) or set(breaker) != {
        "tested",
        "activated",
        "evidence_ref",
    }:
        raise ValueError("circuit-breaker evidence fields are invalid")
    if not isinstance(rollback, dict) or set(rollback) != {
        "tested",
        "succeeded",
        "recovery_seconds",
        "evidence_ref",
    }:
        raise ValueError("rollback evidence fields are invalid")
    for field in ("tested", "activated"):
        if type(breaker[field]) is not bool:
            raise ValueError("circuit-breaker states must be boolean")
    for field in ("tested", "succeeded"):
        if type(rollback[field]) is not bool:
            raise ValueError("rollback states must be boolean")
    bounded_text(breaker["evidence_ref"], "circuit-breaker evidence reference")
    bounded_text(rollback["evidence_ref"], "rollback evidence reference")
    _number(rollback["recovery_seconds"], "rollback recovery seconds")
    changes = result["change_records"]
    if not isinstance(changes, list) or len(changes) > MAX_WINDOWS:
        raise ValueError("deployed TEVV change records are invalid")
    change_ids: set[str] = set()
    for change in changes:
        if not isinstance(change, dict) or set(change) != {
            "id",
            "effective_at",
            "previous_system_version",
            "new_system_version",
            "previous_model_version",
            "new_model_version",
            "approval_ref",
            "regression_evidence_ref",
        }:
            raise ValueError("deployed TEVV change-record fields are invalid")
        identifier = bounded_text(change["id"], "TEVV change id")
        if identifier in change_ids:
            raise ValueError("TEVV change ids must be unique")
        change_ids.add(identifier)
        _timestamp(change["effective_at"], "TEVV change effective time")
        for field in set(change) - {"id", "effective_at"}:
            bounded_text(change[field], f"TEVV change {field}")
    unique_text_list(result["limitations"], "TEVV limitations")
    bounded_text(result["claim_boundary"], "TEVV claim boundary")
    return copy.deepcopy(result)


def seal_deployed_tevv_source(source: str | Path, destination: str | Path) -> Path:
    value = load_json(source, label="deployed TEVV source")
    return publish_json(_source(seal(value)), destination)


def deployed_tevv_assessment(source: str | Path) -> dict[str, Any]:
    value = _source(load_json(source, label="deployed TEVV source"))
    policy = value["policy"]
    roles = [
        value["authority"][name]
        for name in (
            "campaign_owner",
            "monitoring_authority",
            "incident_authority",
            "approval_authority",
        )
    ]
    windows = value["monitoring_windows"]
    window_results = []
    for window in windows:
        error_rate = window["errors"] / window["requests"]
        result = {
            "id": window["id"],
            "system_version": window["system_version"],
            "model_version": window["model_version"],
            "error_rate": error_rate,
            "p95_latency_ms": float(window["p95_latency_ms"]),
            "drift_score": float(window["drift_score"]),
            "evaluation_count": window["evaluation_count"],
            "evaluation_pass_rate": float(window["evaluation_pass_rate"]),
            "open_incidents": window["open_incidents"],
            "threshold_breaches": list(window["threshold_breaches"]),
        }
        result["passed"] = bool(
            error_rate <= policy["maximum_error_rate"]
            and window["p95_latency_ms"] <= policy["maximum_p95_latency_ms"]
            and window["drift_score"] <= policy["maximum_drift_score"]
            and window["evaluation_count"] >= policy["minimum_evaluations_per_window"]
            and window["evaluation_pass_rate"] >= policy["minimum_evaluation_pass_rate"]
            and window["open_incidents"] <= policy["maximum_open_incidents"]
            and not window["threshold_breaches"]
        )
        window_results.append(result)
    baseline = value["baseline"]
    controls = value["controls"]
    checks = {
        "raw_measurement_replay": replay_operational_evidence(
            value, Path(source).resolve().parent
        ),
        "change_history_consistent": change_history_consistent(value),
        "governance_separation": bool(
            len({item.casefold() for item in roles}) == len(roles)
            and not any(_placeholder(item) for item in roles)
            and not _placeholder(value["authority"]["independence_basis"])
        ),
        "exact_system_identity": bool(
            not any(
                _placeholder(value["system"][field])
                for field in (
                    "id",
                    "version",
                    "model",
                    "model_version",
                    "deployment_environment",
                    "intended_use",
                )
            )
            and value["system"]["prompt_sha256"] != "0" * 64
            and value["system"]["tool_policy_sha256"] != "0" * 64
        ),
        "predeployment_baseline": bool(
            change_history_consistent(value)
            and not _placeholder(baseline["evidence_ref"])
            and baseline["evidence_sha256"] != "0" * 64
            and baseline["evaluation_count"] > 0
            and baseline["evaluation_pass_rate"]
            >= policy["minimum_evaluation_pass_rate"]
        ),
        "repeated_postdeployment_tevv": bool(
            len(windows) >= policy["minimum_monitoring_windows"]
            and window_results
            and all(item["passed"] for item in window_results)
        ),
        "all_six_monitoring_categories": all(
            bool(value["category_evidence"][name]) for name in MONITORING_CATEGORIES
        ),
        "threshold_conformance": bool(
            window_results and all(item["passed"] for item in window_results)
        ),
        "incident_closure": bool(
            windows
            and all(
                window["open_incidents"] <= policy["maximum_open_incidents"]
                for window in windows
            )
        ),
        "circuit_breaker_verified": bool(
            (not policy["require_circuit_breaker_test"])
            or (
                controls["circuit_breaker"]["tested"]
                and controls["circuit_breaker"]["activated"]
                and not _placeholder(controls["circuit_breaker"]["evidence_ref"])
            )
        ),
        "rollback_recovery_verified": bool(
            (not policy["require_rollback_test"])
            or (
                controls["rollback"]["tested"]
                and controls["rollback"]["succeeded"]
                and controls["rollback"]["recovery_seconds"]
                <= policy["maximum_recovery_seconds"]
                and not _placeholder(controls["rollback"]["evidence_ref"])
            )
        ),
        "version_and_telemetry_traceability": bool(
            windows
            and all(
                change_history_consistent(value)
                and window["telemetry_sha256"] != "0" * 64
                and window["evaluation_sha256"] != "0" * 64
                and not _placeholder(window["telemetry_schema"])
                and not _placeholder(window["telemetry_schema_version"])
                for window in windows
            )
        ),
    }
    passed = all(checks.values())
    return seal(
        {
            "format": DEPLOYED_TEVV_ASSESSMENT_FORMAT,
            "generated_at": value["generated_at"],
            "source_sha256": value["content_sha256"],
            "evidence_digests": evidence_bindings(value, Path(source).resolve().parent),
            "system": copy.deepcopy(value["system"]),
            "policy": copy.deepcopy(policy),
            "windows": window_results,
            "checks": checks,
            "summary": {
                "passed": passed,
                "status": "eligible_for_authorized_operational_review"
                if passed
                else "operational_evidence_incomplete",
                "windows": len(windows),
                "checks_passed": sum(checks.values()),
                "checks_required": len(checks),
                "failed_checks": sorted(
                    name for name, state in checks.items() if not state
                ),
            },
            "limitations": copy.deepcopy(value["limitations"]),
            "claim_boundary": (
                "Passing establishes exact threshold accounting over the supplied monitoring "
                "and repeated-evaluation evidence. It does not prove model safety, causality, "
                "telemetry completeness, authority authenticity, or regulatory acceptance."
            ),
        }
    )


def verify_deployed_tevv_assessment(
    value: dict[str, Any], *, source: str | Path | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value,
            label="deployed TEVV assessment",
            format_value=DEPLOYED_TEVV_ASSESSMENT_FORMAT,
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    expected_checks = {
        "raw_measurement_replay",
        "change_history_consistent",
        "governance_separation",
        "exact_system_identity",
        "predeployment_baseline",
        "repeated_postdeployment_tevv",
        "all_six_monitoring_categories",
        "threshold_conformance",
        "incident_closure",
        "circuit_breaker_verified",
        "rollback_recovery_verified",
        "version_and_telemetry_traceability",
    }
    try:
        checks = checked["checks"]
        summary = checked["summary"]
        structure = bool(
            set(checked)
            == {
                "format",
                "generated_at",
                "source_sha256",
                "evidence_digests",
                "system",
                "policy",
                "windows",
                "checks",
                "summary",
                "limitations",
                "claim_boundary",
                "content_sha256",
            }
            and set(checks) == expected_checks
            and all(isinstance(state, bool) for state in checks.values())
            and summary["passed"] == all(checks.values())
            and summary["checks_passed"] == sum(checks.values())
            and summary["checks_required"] == len(checks)
            and summary["failed_checks"]
            == sorted(name for name, state in checks.items() if not state)
            and summary["windows"] == len(checked["windows"])
            and summary["status"]
            == (
                "eligible_for_authorized_operational_review"
                if all(checks.values())
                else "operational_evidence_incomplete"
            )
        )
    except (KeyError, TypeError):
        structure = False
    if not structure:
        errors.append("deployed TEVV assessment fields do not reconcile")
    replay: bool | None = None
    if source is not None:
        try:
            replay = deployed_tevv_assessment(source) == value
        except (OSError, TypeError, ValueError):
            replay = False
        if not replay:
            errors.append("deployed TEVV assessment does not exactly replay")
    valid = integrity and structure and replay is not False
    passed = bool(valid and checked.get("summary", {}).get("passed"))
    return seal(
        {
            "format": DEPLOYED_TEVV_VERIFICATION_FORMAT,
            "valid": valid,
            "passed": passed,
            "eligible_for_authorized_operational_review": bool(
                passed and replay is True
            ),
            "checks": {
                "content_integrity": integrity,
                "semantic_reconciliation": structure,
                "exact_source_replay": replay,
            },
            "errors": errors,
            "notice": "Eligibility supports an authorized operational review; it is not certification or risk acceptance.",
        }
    )


def export_deployed_tevv_assessment(
    value: dict[str, Any], destination: str | Path
) -> Path:
    if not verify_deployed_tevv_assessment(value)["valid"]:
        raise ValueError("deployed TEVV assessment is invalid")
    return publish_json(value, destination)


def verify_deployed_tevv_assessment_file(
    source: str | Path, *, campaign_source: str | Path | None = None
) -> dict[str, Any]:
    try:
        value = load_json(source, label="deployed TEVV assessment")
        return verify_deployed_tevv_assessment(value, source=campaign_source)
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": DEPLOYED_TEVV_VERIFICATION_FORMAT,
                "valid": False,
                "passed": False,
                "eligible_for_authorized_operational_review": False,
                "checks": {
                    "content_integrity": False,
                    "semantic_reconciliation": False,
                    "exact_source_replay": False
                    if campaign_source is not None
                    else None,
                },
                "errors": [str(exc)],
                "notice": "Deployed TEVV verification failed closed.",
            }
        )


def export_deployed_tevv_source(value: dict[str, Any], destination: str | Path) -> Path:
    return publish_json(value, destination)
