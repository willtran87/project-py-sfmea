"""Executable assurance contracts derived from governed SFMEA findings."""

from __future__ import annotations

import copy
import csv
import fnmatch
import hashlib
import json
import os
import re
import shutil
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from .model import stable_id, utc_now

ASSURANCE_SCHEMA_VERSION = "1.0"
PLANNER_VERSION = "deterministic-verification-planner-3"
ASSURANCE_SCAFFOLD_FORMAT = "pysfmea-pytest-assurance-scaffold-6"
ASSURANCE_SCAFFOLD_VERIFICATION_FORMAT = (
    "pysfmea-assurance-scaffold-verification-5"
)
MAX_ASSURANCE_SCAFFOLD_MANIFEST_BYTES = 64 * 1024 * 1024
ASSURANCE_NOTICE = (
    "Verification obligations are deterministic planning drafts. A proposed or implemented "
    "test is not evidence. Passing execution cannot close a finding until the recorded "
    "stimulus, oracles, acceptance criteria, environment, freshness, and evidence sufficiency "
    "have been independently reviewed. Repository code must run only in an approved sandbox."
)

ASSURANCE_STATUSES = {
    "candidate",
    "confirmed",
    "control_missing",
    "control_implemented",
    "verification_planned",
    "test_proposed",
    "evidence_collected",
    "partially_verified",
    "verified",
    "residual_risk_review",
    "accepted_risk",
    "closed",
    "reopened",
    "not_applicable",
    "retired",
}
PLANNING_REVIEW_STATUSES = {
    "candidate",
    "confirmed",
    "control_missing",
    "control_implemented",
    "verification_planned",
    "test_proposed",
    "residual_risk_review",
    "reopened",
    "not_applicable",
}
IMPLEMENTATION_STATUSES = {"not_implemented", "proposed", "implemented"}
EVIDENCE_STATUSES = {
    "missing",
    "collected_unreviewed",
    "insufficient",
    "partial",
    "sufficient",
    "stale",
}
VERIFICATION_METHODS = {
    "unit_test",
    "integration_test",
    "contract_test",
    "property_test",
    "fuzz_test",
    "state_transition_test",
    "concurrency_test",
    "fault_injection_test",
    "stress_test",
    "security_test",
    "static_analysis",
    "configuration_inspection",
    "architecture_review",
}


def _slug(value: str, limit: int = 48) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")
    return (cleaned or "failure_mode")[:limit].rstrip("_")


def _text_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(entry) for entry in value if entry not in (None, "")]


def _contract_sha256(obligation: dict[str, Any]) -> str:
    contract = {
        key: obligation.get(key)
        for key in (
            "finding_id",
            "source_fingerprint",
            "failure_condition",
            "operational_context",
            "preconditions",
            "stimulus",
            "expected_results",
            "oracles",
            "acceptance_criteria",
            "verification_method",
            "method_rationale",
            "required_environment",
            "repeatability",
            "evidence_requirements",
            "planning_gaps",
        )
    }
    return hashlib.sha256(
        json.dumps(
            contract,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _scaffold_contract_records(
    analysis: dict[str, Any], obligations: list[dict[str, Any]]
) -> list[dict[str, str]]:
    """Return the minimal governed state that determines scaffold applicability."""

    dispositions = {
        str(item.get("id", "")): str(
            item.get("review", {}).get("disposition", "unreviewed")
        )
        for item in analysis.get("items", [])
        if isinstance(item, dict)
    }
    return sorted(
        (
            {
                "id": str(value.get("id", "")),
                "finding_id": str(value.get("finding_id", "")),
                "contract_sha256": str(
                    value.get("provenance", {}).get("contract_sha256", "")
                    or _contract_sha256(value)
                ),
                "disposition": dispositions.get(
                    str(value.get("finding_id", "")), "unreviewed"
                ),
                "source_status": str(value.get("source_status", "active")),
                "implementation_status": str(
                    value.get("automation", {}).get(
                        "implementation_status", "not_implemented"
                    )
                ),
            }
            for value in obligations
            if isinstance(value, dict)
        ),
        key=lambda value: (value["id"], value["finding_id"]),
    )


def _scaffold_contracts_sha256(records: list[dict[str, str]]) -> str:
    return hashlib.sha256(
        json.dumps(
            records,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _select_scaffold_obligations(
    analysis: dict[str, Any],
    register: dict[str, Any],
    *,
    scope: str,
    limit: int,
    disposition: str,
    include_implemented: bool,
) -> list[dict[str, Any]]:
    """Apply the persisted scaffold selection contract deterministically."""

    disposition_by_finding = {
        str(item.get("id", "")): str(
            item.get("review", {}).get("disposition", "unreviewed")
        )
        for item in analysis.get("items", [])
        if isinstance(item, dict)
    }
    selected: list[dict[str, Any]] = []
    for value in register.get("obligations", []):
        if not isinstance(value, dict):
            continue
        if value.get("source_status", "active") != "active":
            continue
        if (
            disposition != "all"
            and disposition_by_finding.get(
                str(value.get("finding_id", "")), "unreviewed"
            )
            != disposition
        ):
            continue
        if (
            not include_implemented
            and value.get("automation", {}).get("implementation_status")
            == "implemented"
        ):
            continue
        reference = ":".join(
            (
                str(value.get("source", {}).get("path", "")),
                str(value.get("component", "")),
            )
        )
        if not any(
            fnmatch.fnmatchcase(candidate, scope)
            for candidate in (
                reference,
                str(value.get("finding_id", "")),
                str(value.get("id", "")),
            )
        ):
            continue
        selected.append(value)
        if len(selected) >= limit:
            break
    return selected


def _method_for(item: dict[str, Any]) -> tuple[str, str]:
    scanner = item.get("scanner", {})
    rule = str(scanner.get("rule_id", ""))
    failure_class = str(scanner.get("failure_class", ""))
    if rule.startswith("resilience.circuit_breaker_"):
        return "fault_injection_test", "Exercise trip, isolation, degraded fallback, and timed recovery across controlled breaker-state transitions."
    if rule.startswith(("storage.", "persistence.")):
        return "fault_injection_test", "Exercise rollback and externally visible side effects at persistence failure boundaries."
    if rule.startswith("state."):
        return "state_transition_test", "Exercise valid and invalid state transitions and their invariants."
    if rule.startswith("timing."):
        return "concurrency_test", "Exercise ordering, timeout, cancellation, and repeated interleavings."
    if rule.startswith("resource."):
        return "stress_test", "Exercise declared resource bounds and controlled degradation."
    if rule.startswith("detection."):
        return "fault_injection_test", "Trigger the failure and demonstrate detection, alerting, and containment."
    if rule.startswith("configuration.") or rule.startswith("environment."):
        return "configuration_inspection", "Validate configuration constraints and fail-safe startup behavior."
    if rule.startswith("interface.contract"):
        return "contract_test", "Exercise compatible and incompatible interface contracts at the real boundary."
    if rule.startswith("interface."):
        return "integration_test", "Exercise unavailable, malformed, delayed, and partial interface responses."
    if rule.startswith("common_cause."):
        return "architecture_review", "Demonstrate independence or containment against the common cause."
    if failure_class in {"calculation", "data"}:
        return "property_test", "Generate boundary and adversarial values and verify declared invariants."
    if failure_class == "security" or any(
        token in rule for token in ("access", "auth", "trust", "untrusted", "outbound")
    ):
        return "security_test", "Exercise the trust boundary with unauthorized and adversarial inputs."
    if failure_class == "logic":
        return "property_test", "Exercise branch and sequence invariants across representative input classes."
    if failure_class == "functional":
        return "unit_test", "Exercise the required behavior and negative behavior at the function boundary."
    return "integration_test", "Exercise the failure at the nearest representative system boundary."


def _stimulus(method: str, item: dict[str, Any]) -> dict[str, Any]:
    review = item.get("review", {})
    trigger = str(review.get("trigger") or item.get("scanner", {}).get("trigger", ""))
    verbs = {
        "fault_injection_test": "Inject or force",
        "property_test": "Generate boundary, invalid, and adversarial inputs representing",
        "fuzz_test": "Generate malformed and unexpected inputs representing",
        "state_transition_test": "Drive the component through valid and invalid transitions representing",
        "concurrency_test": "Control scheduling and repeat interleavings representing",
        "stress_test": "Apply bounded load and resource pressure representing",
        "security_test": "Submit unauthorized or adversarial requests representing",
        "configuration_inspection": "Evaluate valid, missing, and conflicting configuration representing",
        "architecture_review": "Inspect and challenge architectural independence for",
        "contract_test": "Provide compatible, missing, malformed, and incompatible contracts representing",
        "unit_test": "Invoke the component with controlled inputs representing",
        "integration_test": "Stimulate the representative boundary with",
        "static_analysis": "Evaluate the source and configuration for",
    }
    obligation = {
        "method": method,
        "description": f"{verbs.get(method, 'Stimulate')} {trigger or 'the documented failure condition'}.",
        "injection_required": method in {
            "fault_injection_test",
            "concurrency_test",
            "stress_test",
            "security_test",
        },
    }
    return obligation


def _detected_circuit_breaker(scanner: dict[str, Any]) -> dict[str, Any]:
    return next(
        (
            copy.deepcopy(value)
            for value in scanner.get("detected_controls", [])
            if isinstance(value, dict) and value.get("kind") == "circuit_breaker"
        ),
        {},
    )


def _obligation(item: dict[str, Any], baseline_id: str) -> dict[str, Any]:
    review = item.get("review", {})
    scanner = item.get("scanner", {})
    circuit_breaker = _detected_circuit_breaker(scanner)
    component = item.get("component", {})
    source = item.get("source", {})
    method, method_rationale = _method_for(item)
    finding_id = str(item.get("id", ""))
    obligation_id = stable_id("VO", finding_id, method, PLANNER_VERSION)
    failure_mode = str(review.get("failure_mode") or scanner.get("failure_mode", ""))
    local_effect = str(review.get("local_effect", ""))
    next_effect = str(review.get("next_higher_effect", ""))
    end_effect = str(review.get("end_effect", ""))
    safe_state = str(review.get("required_safe_state", ""))
    degraded_behavior = str(review.get("degraded_behavior", ""))
    recovery_behavior = str(review.get("recovery_behavior", ""))
    prevention = _text_list(review.get("prevention_controls", []))
    detection = _text_list(review.get("detection_controls", []))
    # Item snapshots do not duplicate the full component evidence; textual test references
    # remain candidate links only and are recovered from scanner evidence when present.
    existing_tests = [
        value.split(":", 1)[1].strip()
        for value in _text_list(scanner.get("evidence", []))
        if value.startswith("Textual test references:")
    ]
    gaps = []
    if not next_effect:
        gaps.append("next-higher effect requires engineering definition")
    if not end_effect:
        gaps.append("system/end effect requires engineering definition")
    if not prevention and not detection:
        gaps.append("required prevention, detection, containment, or recovery control is not confirmed")
    if not safe_state and not degraded_behavior and not recovery_behavior:
        gaps.append("required safe-state, degraded, or recovery behavior is not defined")
    proposed_name = f"test_assurance_{_slug(component.get('qualname', 'component'), 28)}_{obligation_id[-8:].casefold()}"
    proposed_path = f"tests/assurance/{proposed_name}.py"
    expected_control = (
        "; ".join([*prevention, *detection])
        if prevention or detection
        else "The failure is prevented, detected, contained, recovered, or transitions to an explicitly approved safe/degraded state."
    )
    citations = [
        str(link.get("citation_id", ""))
        for link in scanner.get("citations", [])
        if isinstance(link, dict) and link.get("citation_id")
    ]
    obligation = {
        "id": obligation_id,
        "finding_id": finding_id,
        "component_id": item.get("component_id", ""),
        "source_status": item.get("source_status", "active"),
        "baseline_id": baseline_id,
        "source_fingerprint": scanner.get("source_fingerprint", ""),
        "rule_id": scanner.get("rule_id", ""),
        "failure_class": scanner.get("failure_class", ""),
        "priority": scanner.get("screening_priority", ""),
        "component": component.get("qualname", ""),
        "source": copy.deepcopy(source),
        "title": f"Demonstrate controlled behavior when: {failure_mode}",
        "objective": (
            "Demonstrate with observable evidence that the specified failure condition is "
            "prevented, detected, contained, recovered, or safely tolerated without the "
            "documented effects escaping the approved boundary."
        ),
        "failure_condition": failure_mode,
        "detected_control_model": circuit_breaker,
        "operational_context": {
            "mode": str(review.get("operational_mode", "")),
            "state": str(review.get("operational_state", "")),
        },
        "preconditions": [
            str(review.get("trigger") or scanner.get("trigger", "The failure trigger is established.")),
            "The test records proof that the intended failure path was actually exercised.",
        ],
        "stimulus": _stimulus(method, item),
        "expected_results": {
            "local": local_effect
            or "The component exhibits only the explicitly approved local failure behavior.",
            "next_higher": next_effect
            or "The next-higher effect must be defined before this obligation can be approved.",
            "system": end_effect
            or "The system/end effect must be defined before this obligation can be approved.",
            "control_or_safe_state": expected_control,
            "required_safe_state": safe_state
            or "The required safe state must be defined or explicitly declared not applicable.",
            "degraded_behavior": degraded_behavior
            or "Permitted degraded behavior must be defined or explicitly declared not applicable.",
            "recovery_behavior": recovery_behavior
            or "Required recovery behavior must be defined or explicitly declared not applicable.",
        },
        "oracles": [
            "Record an assertion or captured state proving the failure stimulus occurred.",
            "Observe the component result, exception, state transition, and relevant side effects.",
            "Observe next-higher/system state, including prohibited side effects and asynchronous work.",
            "Observe the required control, recovery, degradation, or safe-state behavior.",
        ],
        "acceptance_criteria": [
            "The intended failure condition is demonstrably exercised; a false-pass path is rejected.",
            "Observed local behavior matches the reviewer-approved expected local behavior.",
            "No prohibited next-higher or system effect occurs during the full observation window.",
            "Required prevention, detection, containment, recovery, or safe-state controls are observed.",
            "The result is repeatable in the recorded environment and tied to the analyzed baseline.",
        ],
        "verification_method": method,
        "method_rationale": method_rationale,
        "required_environment": [
            "Approved disposable sandbox with repository credentials and external network disabled by default.",
            "Representative dependency versions and configuration captured in the execution manifest.",
            "Deterministic setup/cleanup for stateful dependencies and asynchronous work.",
        ],
        "repeatability": {"minimum_runs": 1, "additional_runs_when_nondeterministic": 10},
        "automation": {
            "framework": "pytest",
            "proposed_test_path": proposed_path,
            "proposed_test_name": proposed_name,
            "command_argv": ["python", "-m", "pytest", proposed_path, "-q"],
            "implementation_status": "not_implemented",
            "execution_policy": "approved_sandbox_required",
            "network_policy": "deny_by_default",
        },
        "existing_test_candidates": existing_tests,
        "evidence_requirements": [
            "test source and SHA-256 digest",
            "repository revision, dirty state, and analyzed baseline ID",
            "exact command argv, exit code, start/end time, and complete logs",
            "dependency lock/configuration and execution-environment identity",
            "assertion results and proof that the failure stimulus occurred",
            "captured local and system state needed by every acceptance criterion",
            "coverage or trace evidence where it materially supports path activation",
            "independent evidence-sufficiency decision with reviewer identity and rationale",
        ],
        "citation_ids": list(dict.fromkeys(citations)),
        "planning_gaps": gaps,
        "assurance_status": "retired" if item.get("source_status") == "removed" else "candidate",
        "evidence_status": "missing",
        "evidence_artifact_ids": [],
        "executions": [],
        "review": {
            "reviewer": "",
            "reviewed_at": "",
            "rationale": "",
            "owner": "",
            "acceptance_approved_by": "",
            "acceptance_approved_at": "",
        },
        "provenance": {
            "origin": "deterministic_derivation",
            "planner_version": PLANNER_VERSION,
            "generated_at": utc_now(),
            "finding_source_fingerprint": scanner.get("source_fingerprint", ""),
            "finding_context_fingerprint": scanner.get("analysis_context_fingerprint", ""),
        },
        "history": [{"event": "obligation_generated", "at": utc_now()}],
    }
    if circuit_breaker:
        obligation["preconditions"].extend(
            [
                "The dependency call count and breaker state are observable without relying only on logs.",
                "The test controls dependency success/failure, elapsed time, and concurrent admission attempts.",
            ]
        )
        obligation["oracles"].extend(
            [
                "Observe CLOSED, OPEN, and HALF-OPEN-equivalent state transitions and the exact transition trigger.",
                "Count real downstream calls before, at, and after the trip threshold; calls suppressed while open must be distinguishable from successful calls.",
                "Observe breaker state independently for each configured isolation key.",
                "Observe the caller-visible degraded/fallback contract and prohibited downstream side effects.",
            ]
        )
        obligation["acceptance_criteria"].extend(
            [
                "The breaker opens at the reviewer-approved consecutive-failure boundary and never admits a normal dependency call while open.",
                "A healthy dependency or unrelated isolation key is not tripped by another dependency's failures.",
                "Cooldown uses the approved clock semantics and does not recover before the full interval elapses.",
                "At most the approved number of HALF-OPEN probes execute concurrently; success closes and failure reopens the breaker deterministically.",
                "Fallback/degraded output is explicit, observable, and cannot be mistaken for a complete successful dependency result.",
            ]
        )
        obligation["required_environment"].append(
            "Controllable dependency double, monotonic/fake clock, scheduler barrier, and per-isolation-key call counters."
        )
        obligation["evidence_requirements"].extend(
            [
                "state-transition trace with timestamps, isolation key, failure count, and admitted/suppressed call decision",
                "controlled-clock and concurrent HALF-OPEN probe results at cooldown boundaries",
            ]
        )
        obligation["repeatability"] = {
            "minimum_runs": 3,
            "additional_runs_when_nondeterministic": 20,
        }
    obligation["provenance"]["contract_sha256"] = _contract_sha256(obligation)
    return obligation


def refresh_assurance_register(
    analysis: dict[str, Any], previous: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Regenerate deterministic obligations while preserving governed review/evidence fields."""

    previous = previous if isinstance(previous, dict) else analysis.get("assurance", {})
    old_by_id = {
        value.get("id"): value
        for value in previous.get("obligations", [])
        if isinstance(value, dict) and value.get("id")
    }
    old_by_finding_method = {
        (str(value.get("finding_id", "")), str(value.get("verification_method", ""))): value
        for value in previous.get("obligations", [])
        if isinstance(value, dict) and value.get("finding_id")
    }
    baseline_id = str(analysis.get("project", {}).get("baseline", {}).get("id", ""))
    obligations = []
    for item in analysis.get("items", []):
        obligation = _obligation(item, baseline_id)
        old = old_by_id.get(obligation["id"]) or old_by_finding_method.get(
            (obligation["finding_id"], obligation["verification_method"])
        )
        if old:
            for field in (
                "assurance_status",
                "evidence_status",
                "evidence_artifact_ids",
                "executions",
                "review",
                "history",
            ):
                if field in old:
                    obligation[field] = copy.deepcopy(old[field])
            old_automation = old.get("automation", {})
            for field in (
                "implementation_status",
                "implemented_test_path",
                "test_sha256",
                "implementation_origin",
            ):
                if field in old_automation:
                    obligation["automation"][field] = copy.deepcopy(
                        old_automation[field]
                    )
            old_fingerprint = old.get("source_fingerprint", "")
            if old.get("id") != obligation["id"]:
                obligation.setdefault("history", []).append(
                    {
                        "event": "obligation_planner_migrated",
                        "at": utc_now(),
                        "previous_id": old.get("id", ""),
                    }
                )
            change_reasons = []
            if old_fingerprint and old_fingerprint != obligation.get(
                "source_fingerprint"
            ):
                change_reasons.append("finding source fingerprint changed")
            old_contract_sha256 = str(
                old.get("provenance", {}).get("contract_sha256", "")
                or _contract_sha256(old)
            )
            new_contract_sha256 = str(
                obligation.get("provenance", {}).get("contract_sha256", "")
            )
            if old_contract_sha256 != new_contract_sha256:
                change_reasons.append("verification contract changed")
            if change_reasons and obligation.get("assurance_status") not in {
                "candidate",
                "not_applicable",
                "retired",
            }:
                obligation["assurance_status"] = "reopened"
                obligation["evidence_status"] = "stale"
                obligation.setdefault("history", []).append(
                    {
                        "event": "obligation_reopened",
                        "at": utc_now(),
                        "reason": "; ".join(change_reasons),
                        "previous_contract_sha256": old_contract_sha256,
                        "contract_sha256": new_contract_sha256,
                    }
                )
        obligations.append(obligation)
    register = {
        "schema_version": ASSURANCE_SCHEMA_VERSION,
        "planner_version": PLANNER_VERSION,
        "baseline_id": baseline_id,
        "generated_at": utc_now(),
        "notice": ASSURANCE_NOTICE,
        "obligations": obligations,
        "executions": copy.deepcopy(previous.get("executions", [])),
        "evidence_artifacts": copy.deepcopy(
            previous.get("evidence_artifacts", [])
        ),
    }
    register["summary"] = assurance_summary(register)
    analysis["assurance"] = register
    analysis.setdefault("summary", {})["assurance"] = copy.deepcopy(
        register["summary"]
    )
    return register


def ensure_assurance_register(analysis: dict[str, Any]) -> dict[str, Any]:
    register = analysis.get("assurance")
    if not isinstance(register, dict) or not isinstance(register.get("obligations"), list):
        return refresh_assurance_register(analysis, {})
    return register


def assurance_summary(register: dict[str, Any]) -> dict[str, Any]:
    values = [value for value in register.get("obligations", []) if isinstance(value, dict)]
    active = [value for value in values if value.get("source_status", "active") == "active"]
    executions = [
        value for value in register.get("executions", []) if isinstance(value, dict)
    ]
    return {
        "active_obligations": len(active),
        "retired_obligations": len(values) - len(active),
        "by_status": dict(sorted(Counter(str(value.get("assurance_status", "unknown")) for value in active).items())),
        "by_method": dict(sorted(Counter(str(value.get("verification_method", "unknown")) for value in active).items())),
        "by_evidence_status": dict(sorted(Counter(str(value.get("evidence_status", "unknown")) for value in active).items())),
        "implemented_tests": sum(
            value.get("automation", {}).get("implementation_status") == "implemented"
            for value in active
        ),
        "planning_gaps": sum(bool(value.get("planning_gaps")) for value in active),
        "executions": len(executions),
        "executions_by_status": dict(
            sorted(
                Counter(str(value.get("status", "unknown")) for value in executions).items()
            )
        ),
        "reviewed_executions": sum(bool(value.get("reviews")) for value in executions),
        "evidence_artifacts": len(register.get("evidence_artifacts", [])),
    }


def assurance_progress(analysis: dict[str, Any]) -> dict[str, Any]:
    """Summarize planning, implementation, execution, and verification truthfully."""

    register = ensure_assurance_register(analysis)
    active_items = {
        str(item.get("id", "")): item
        for item in analysis.get("items", [])
        if isinstance(item, dict)
        and item.get("source_status", "active") == "active"
        and item.get("id")
    }
    accepted_ids = {
        item_id
        for item_id, item in active_items.items()
        if item.get("review", {}).get("disposition") == "accepted"
    }
    active_obligations = [
        value
        for value in register.get("obligations", [])
        if isinstance(value, dict)
        and value.get("source_status", "active") == "active"
    ]
    by_finding: dict[str, list[dict[str, Any]]] = {}
    for obligation in active_obligations:
        by_finding.setdefault(str(obligation.get("finding_id", "")), []).append(
            obligation
        )
    applicable = [
        obligation
        for obligation in active_obligations
        if str(obligation.get("finding_id", "")) in accepted_ids
    ]
    planning_statuses = {
        "confirmed",
        "control_implemented",
        "verification_planned",
        "test_proposed",
        "evidence_collected",
        "partially_verified",
        "verified",
        "residual_risk_review",
        "accepted_risk",
        "closed",
        "not_applicable",
    }
    terminal_statuses = {"verified", "accepted_risk", "closed", "not_applicable"}

    def planning_ready(obligation: dict[str, Any]) -> bool:
        review = obligation.get("review", {})
        return bool(
            obligation.get("assurance_status") in planning_statuses
            and review.get("reviewer")
            and review.get("rationale")
            and not obligation.get("planning_gaps")
        )

    cardinality_gaps = sum(
        len(by_finding.get(finding_id, [])) != 1 for finding_id in accepted_ids
    )
    ready_findings = sum(
        len(by_finding.get(finding_id, [])) == 1
        and planning_ready(by_finding[finding_id][0])
        for finding_id in accepted_ids
    )
    terminal_findings = sum(
        len(by_finding.get(finding_id, [])) == 1
        and by_finding[finding_id][0].get("assurance_status") in terminal_statuses
        for finding_id in accepted_ids
    )
    test_required = [
        value
        for value in applicable
        if value.get("assurance_status") not in {"not_applicable", "accepted_risk"}
    ]
    implemented = [
        value
        for value in test_required
        if value.get("automation", {}).get("implementation_status") == "implemented"
    ]
    executions = [
        value
        for value in register.get("executions", [])
        if isinstance(value, dict)
    ]
    executed_obligation_ids = {
        str(value.get("obligation_id", "")) for value in executions
    }
    executed = [
        value
        for value in test_required
        if str(value.get("id", "")) in executed_obligation_ids
    ]

    def percent(numerator: int, denominator: int) -> float | None:
        return round((numerator / denominator) * 100, 1) if denominator else None

    applicable_count = len(accepted_ids)
    return {
        "active_obligations": len(active_obligations),
        "applicable_findings": applicable_count,
        "applicable_obligations": len(applicable),
        "excluded_by_finding_disposition": len(active_obligations) - len(applicable),
        "cardinality_gaps": cardinality_gaps,
        "planning_ready": ready_findings,
        "planning_pending": applicable_count - ready_findings,
        "planning_gaps": sum(bool(value.get("planning_gaps")) for value in applicable),
        "implemented_tests": len(implemented),
        "implementation_pending": len(test_required) - len(implemented),
        "executed_obligations": len(executed),
        "execution_pending": len(test_required) - len(executed),
        "sufficient_evidence": sum(
            value.get("evidence_status") == "sufficient" for value in applicable
        ),
        "verified_obligations": terminal_findings,
        "verification_pending": applicable_count - terminal_findings,
        "recorded_executions": len(executions),
        "unreviewed_executions": sum(not value.get("reviews") for value in executions),
        "failed_executions": sum(
            value.get("status") in {"failed", "timeout", "error"}
            for value in executions
        ),
        "planning_percent": percent(ready_findings, applicable_count),
        "implementation_percent": percent(len(implemented), len(test_required)),
        "verification_percent": percent(terminal_findings, applicable_count),
        "gates": {
            "register_complete": cardinality_gaps == 0,
            "plan_ready": cardinality_gaps == 0 and ready_findings == applicable_count,
            "verification_complete": (
                cardinality_gaps == 0 and terminal_findings == applicable_count
            ),
        },
    }


def review_obligation(
    analysis: dict[str, Any],
    obligation_id: str,
    *,
    status: str,
    reviewer: str,
    rationale: str,
    owner: str = "",
) -> dict[str, Any]:
    """Record a human assurance decision without fabricating execution evidence."""

    if status not in PLANNING_REVIEW_STATUSES:
        raise ValueError(
            "assurance-review cannot directly set execution-derived, verified, "
            "accepted-risk, closed, or retired states; use the governed evidence or "
            "approval workflow"
        )
    if not reviewer.strip() or not rationale.strip():
        raise ValueError("assurance review requires a reviewer and rationale")
    register = ensure_assurance_register(analysis)
    obligation = next(
        (value for value in register["obligations"] if value.get("id") == obligation_id),
        None,
    )
    if obligation is None:
        raise KeyError(obligation_id)
    current_status = str(obligation.get("assurance_status", "candidate"))
    if current_status in {
        "partially_verified",
        "accepted_risk",
        "closed",
        "retired",
    }:
        raise ValueError(
            f"{current_status} is evidence- or approval-controlled and cannot be "
            "changed through assurance planning"
        )
    if current_status == "verified" and status != "residual_risk_review":
        raise ValueError(
            "verified is evidence-controlled; assurance planning may only advance it "
            "to residual_risk_review"
        )
    if status == "residual_risk_review" and not (
        current_status == "verified" and obligation.get("evidence_status") == "sufficient"
    ):
        raise ValueError(
            "residual_risk_review requires an obligation verified by sufficient evidence"
        )
    at = utc_now()
    obligation["assurance_status"] = status
    obligation["review"] = {
        **obligation.get("review", {}),
        "reviewer": reviewer.strip(),
        "reviewed_at": at,
        "rationale": rationale.strip(),
        "owner": owner.strip(),
    }
    obligation.setdefault("history", []).append(
        {
            "event": "obligation_reviewed",
            "at": at,
            "status": status,
            "reviewer": reviewer.strip(),
            "rationale": rationale.strip(),
        }
    )
    register["summary"] = assurance_summary(register)
    analysis.setdefault("history", []).append(
        {
            "event": "assurance_obligation_reviewed",
            "at": at,
            "obligation_id": obligation_id,
            "status": status,
            "reviewer": reviewer.strip(),
        }
    )
    return obligation


ASSURANCE_CSV_FIELDS = [
    "id",
    "finding_id",
    "baseline_id",
    "source_status",
    "priority",
    "component",
    "path",
    "line",
    "failure_class",
    "rule_id",
    "failure_condition",
    "verification_method",
    "stimulus",
    "oracles",
    "acceptance_criteria",
    "proposed_test_path",
    "command_argv",
    "implementation_status",
    "assurance_status",
    "evidence_status",
    "planning_gaps",
    "citation_ids",
    "reviewer",
    "owner",
]


def _flat_row(value: dict[str, Any]) -> dict[str, Any]:
    automation = value.get("automation", {})
    return {
        "id": value.get("id", ""),
        "finding_id": value.get("finding_id", ""),
        "baseline_id": value.get("baseline_id", ""),
        "source_status": value.get("source_status", ""),
        "priority": value.get("priority", ""),
        "component": value.get("component", ""),
        "path": value.get("source", {}).get("path", ""),
        "line": value.get("source", {}).get("line", ""),
        "failure_class": value.get("failure_class", ""),
        "rule_id": value.get("rule_id", ""),
        "failure_condition": value.get("failure_condition", ""),
        "verification_method": value.get("verification_method", ""),
        "stimulus": value.get("stimulus", {}).get("description", ""),
        "oracles": " | ".join(_text_list(value.get("oracles", []))),
        "acceptance_criteria": " | ".join(_text_list(value.get("acceptance_criteria", []))),
        "proposed_test_path": automation.get("proposed_test_path", ""),
        "command_argv": " ".join(_text_list(automation.get("command_argv", []))),
        "implementation_status": automation.get("implementation_status", ""),
        "assurance_status": value.get("assurance_status", ""),
        "evidence_status": value.get("evidence_status", ""),
        "planning_gaps": " | ".join(_text_list(value.get("planning_gaps", []))),
        "citation_ids": " | ".join(_text_list(value.get("citation_ids", []))),
        "reviewer": value.get("review", {}).get("reviewer", ""),
        "owner": value.get("review", {}).get("owner", ""),
    }


def export_assurance_register(
    analysis: dict[str, Any], destination: str | Path, *, format: str = "json"
) -> Path:
    """Export the executable assurance checklist as JSON, CSV, or Markdown."""

    if format not in {"json", "csv", "markdown"}:
        raise ValueError("assurance format must be json, csv, or markdown")
    path = Path(destination).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    register = ensure_assurance_register(analysis)
    if format == "json":
        payload = {**register, "progress": assurance_progress(analysis)}
        path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return path
    if format == "csv":
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=ASSURANCE_CSV_FIELDS)
            writer.writeheader()
            for value in register.get("obligations", []):
                writer.writerow(_flat_row(value))
        return path
    progress = assurance_progress(analysis)
    planning_percent = progress["planning_percent"]
    planning_label = f"{planning_percent}%" if planning_percent is not None else "n/a"
    lines = [
        "# Executable assurance checklist",
        "",
        f"> {register.get('notice', ASSURANCE_NOTICE)}",
        "",
        (
            f"Planning: {progress['planning_ready']}/{progress['applicable_findings']} "
            f"accepted findings ready ({planning_label}); "
            f"implemented tests: {progress['implemented_tests']}; "
            f"recorded executions: {progress['recorded_executions']}; "
            f"verified/resolved: {progress['verified_obligations']}."
        ),
        "",
        "| Obligation | Finding | Component | Method | Status | Evidence | Proposed test |",
        "|---|---|---|---|---|---|---|",
    ]
    for value in register.get("obligations", []):
        row = _flat_row(value)
        cells = [
            row["id"],
            row["finding_id"],
            row["component"],
            row["verification_method"],
            row["assurance_status"],
            row["evidence_status"],
            row["proposed_test_path"],
        ]
        lines.append("| " + " | ".join(str(cell).replace("|", "\\|") for cell in cells) + " |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def export_pytest_scaffold(
    analysis: dict[str, Any],
    destination: str | Path,
    *,
    scope: str = "*",
    limit: int = 100,
    disposition: str = "accepted",
    include_implemented: bool = False,
    queue_id: str = "",
    owner: str = "",
    purpose: str = "",
    replace: bool = False,
) -> Path:
    """Create an intentionally failing pytest checklist for selected obligations.

    The scaffold forces each placeholder to remain visible in CI. Replacing a placeholder
    with a meaningful test still does not create evidence until an approved execution is
    captured and independently reviewed.
    """

    if not 1 <= limit <= 1000:
        raise ValueError("assurance scaffold limit must be from 1 through 1000")
    if disposition not in {"accepted", "rejected", "unreviewed", "all"}:
        raise ValueError(
            "assurance scaffold disposition must be accepted, rejected, unreviewed, or all"
        )
    owner = owner.strip()
    purpose = purpose.strip()
    if len(owner) > 200 or any(ord(value) < 32 for value in owner):
        raise ValueError("assurance scaffold owner must be at most 200 printable characters")
    if len(purpose) > 500 or any(ord(value) < 32 for value in purpose):
        raise ValueError(
            "assurance scaffold purpose must be at most 500 printable characters"
        )
    queue_id = queue_id.strip() or stable_id(
        "QUEUE",
        disposition,
        scope,
        str(limit),
        str(include_implemented),
        owner,
        purpose,
    )
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", queue_id):
        raise ValueError(
            "assurance scaffold queue ID must be 1-80 letters, digits, dots, dashes, "
            "or underscores and start with a letter or digit"
        )
    path = Path(destination).expanduser().resolve()
    replace_existing = False
    if path.exists():
        if not path.is_dir():
            raise ValueError(
                f"assurance scaffold destination must be a directory: {path}"
            )
        if any(path.iterdir()):
            if not replace:
                raise ValueError(
                    f"assurance scaffold destination must be an empty directory: {path}"
                )
            _require_untouched_scaffold(analysis, path, operation="replacement")
            replace_existing = True
    register = ensure_assurance_register(analysis)
    selected = _select_scaffold_obligations(
        analysis,
        register,
        scope=scope,
        limit=limit,
        disposition=disposition,
        include_implemented=include_implemented,
    )
    if not selected:
        raise ValueError(
            "no pending active assurance obligations match "
            f"disposition={disposition!r} and scope={scope!r}"
        )
    baseline_id = register.get("baseline_id", "")
    contract_snapshot = _scaffold_contract_records(analysis, selected)
    manifest = {
        "format": ASSURANCE_SCAFFOLD_FORMAT,
        "generated_at": utc_now(),
        "baseline_id": baseline_id,
        "queue": {"id": queue_id, "owner": owner, "purpose": purpose},
        "binding": {
            "baseline_id": baseline_id,
            "analysis_schema_version": str(analysis.get("schema_version", "")),
            "analysis_state_sha256": hashlib.sha256(
                json.dumps(
                    analysis,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest(),
            "scaffold_contracts_sha256": _scaffold_contracts_sha256(
                contract_snapshot
            ),
        },
        "selection": {
            "disposition": disposition,
            "scope": scope,
            "limit": limit,
            "include_implemented": include_implemented,
        },
        "notice": ASSURANCE_NOTICE,
        "contract_snapshot": contract_snapshot,
        "obligations": selected,
    }
    test_source = '''"""Generated PySFMEA assurance placeholders.

Every case fails intentionally until an engineer implements the recorded stimulus,
oracles, and acceptance criteria. A passing replacement is not assurance evidence until
its approved sandbox execution and independent evidence review are recorded.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest


def _load_manifest() -> dict:
    payload = json.loads(
        Path(__file__).with_name("assurance-manifest.json").read_text(encoding="utf-8")
    )
    canonical = dict(payload)
    expected = canonical.pop("manifest_sha256", "")
    actual = hashlib.sha256(
        json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    if not expected or actual != expected:
        raise RuntimeError(
            "assurance-manifest.json failed its SHA-256 integrity check; regenerate "
            "the scaffold from the governed analysis"
        )
    return payload


MANIFEST = _load_manifest()


@pytest.mark.parametrize(
    "obligation",
    MANIFEST["obligations"],
    ids=lambda value: value["id"],
)
def test_sfmea_assurance_obligation(obligation: dict) -> None:
    pytest.fail(
        f"{obligation['id']} is not implemented: "
        f"{obligation['verification_method']} for {obligation['failure_condition']} "
        f"(planned test: {obligation['automation']['proposed_test_path']})"
    )
'''
    readme_source = (
        "# PySFMEA assurance test scaffold\n\n"
        f"Queue: `{queue_id}`  \n"
        f"Owner: {owner or 'not assigned'}  \n"
        f"Purpose: {purpose or 'not recorded'}\n\n"
        "These pytest cases fail intentionally. Implement the stimulus, oracles, and "
        "acceptance criteria from `assurance-manifest.json`; do not convert them to "
        "empty, skipped, or assertion-free tests. Run only in an approved sandbox. "
        "Passing tests remain unreviewed execution results until evidence sufficiency "
        "is adjudicated. Replacing placeholders is expected: register implemented test "
        "source with `sfmea assurance-test-register` so it is content-hash bound to its "
        "obligation. The manifest binds the exact governed analysis state, the selected "
        "verification contracts, reproducible selection parameters, and the generated "
        "starting-file hashes for audit. This lets verification distinguish unrelated "
        "analysis edits from added, removed, or changed test contracts. Its digests are "
        "not authenticated approval signatures.\n"
    )
    manifest["generated_files"] = {
        "README.md": {
            "role": "operator_notice",
            "sha256": hashlib.sha256(readme_source.encode("utf-8")).hexdigest(),
        },
        "test_sfmea_assurance.py": {
            "role": "failing_pytest_placeholders",
            "sha256": hashlib.sha256(test_source.encode("utf-8")).hexdigest(),
        },
    }
    manifest["manifest_sha256"] = hashlib.sha256(
        json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    )
    backup: Path | None = None
    try:
        (staging / "assurance-manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        (staging / "test_sfmea_assurance.py").write_bytes(test_source.encode("utf-8"))
        (staging / "README.md").write_bytes(readme_source.encode("utf-8"))
        if replace_existing:
            backup = Path(
                tempfile.mkdtemp(
                    prefix="." + path.name + ".",
                    suffix=".backup",
                    dir=path.parent,
                )
            )
            backup.rmdir()
            os.replace(path, backup)
        elif path.exists():
            path.rmdir()
        os.replace(staging, path)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        if backup and backup.exists() and not path.exists():
            try:
                os.replace(backup, path)
            except OSError as restore_exc:
                raise RuntimeError(
                    "assurance scaffold refresh failed and the previous scaffold could not "
                    f"be restored from {backup}"
                ) from restore_exc
        raise
    if backup:
        shutil.rmtree(backup, ignore_errors=True)
    return path


def verify_pytest_scaffold(
    analysis: dict[str, Any], source: str | Path
) -> dict[str, Any]:
    """Verify scaffold integrity and its binding to a governed analysis state.

    Generated placeholder edits are reported separately because replacing them with
    substantive tests is an expected workflow transition, not scaffold corruption.
    """

    path = Path(source).expanduser().absolute()
    manifest_path = path / "assurance-manifest.json"
    findings: list[dict[str, str]] = []

    def add(rule_id: str, message: str, level: str = "error") -> None:
        findings.append({"rule_id": rule_id, "level": level, "message": message})

    manifest: dict[str, Any] = {}
    readable = False
    if path.is_symlink() or not path.is_dir():
        add("scaffold.directory_missing", f"Scaffold directory does not exist: {path}")
    elif manifest_path.is_symlink() or not manifest_path.is_file():
        add("scaffold.manifest_missing", "assurance-manifest.json is missing.")
    else:
        try:
            if manifest_path.stat().st_size > MAX_ASSURANCE_SCAFFOLD_MANIFEST_BYTES:
                raise ValueError(
                    "manifest exceeds the bounded verification size limit"
                )
            loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("manifest root must be an object")
            manifest = loaded
            readable = True
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            add("scaffold.manifest_unreadable", str(exc))

    canonical = dict(manifest)
    supplied_digest = str(canonical.pop("manifest_sha256", ""))
    digest_shape = len(supplied_digest) == 64 and all(
        value in "0123456789abcdefABCDEF" for value in supplied_digest
    )
    actual_digest = (
        hashlib.sha256(
            json.dumps(
                canonical,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        if readable
        else ""
    )
    manifest_integrity = bool(
        readable and digest_shape and supplied_digest.lower() == actual_digest
    )
    if readable and not manifest_integrity:
        add(
            "scaffold.manifest_integrity",
            "Manifest SHA-256 verification failed; regenerate the scaffold.",
        )

    format_valid = manifest.get("format") == ASSURANCE_SCAFFOLD_FORMAT
    if readable and not format_valid:
        add(
            "scaffold.format_unsupported",
            f"Expected scaffold format {ASSURANCE_SCAFFOLD_FORMAT!r}.",
        )
    supplied_obligations = manifest.get("obligations", [])
    manifest_obligations = (
        supplied_obligations if isinstance(supplied_obligations, list) else []
    )
    obligations_valid = bool(manifest_obligations)
    if readable and not obligations_valid:
        add("scaffold.obligations_missing", "Manifest has no assurance obligations.")

    binding = manifest.get("binding", {})
    if not isinstance(binding, dict):
        binding = {}
    contract_snapshot = manifest.get("contract_snapshot", [])
    contract_snapshot_valid = (
        isinstance(contract_snapshot, list)
        and bool(contract_snapshot)
        and len(contract_snapshot) == len(manifest_obligations)
        and all(
            isinstance(value, dict)
            and value.get("id")
            and value.get("finding_id")
            and len(str(value.get("contract_sha256", ""))) == 64
            and all(
                character in "0123456789abcdefABCDEF"
                for character in str(value.get("contract_sha256", ""))
            )
            and value.get("disposition")
            in {"accepted", "rejected", "unreviewed"}
            and value.get("source_status")
            and value.get("implementation_status")
            for value in contract_snapshot
        )
        and len(
            {
                str(value.get("id", ""))
                for value in contract_snapshot
                if isinstance(value, dict)
            }
        )
        == len(contract_snapshot)
        and {
            str(value.get("id", ""))
            for value in contract_snapshot
            if isinstance(value, dict)
        }
        == {
            str(value.get("id", ""))
            for value in manifest_obligations
            if isinstance(value, dict)
        }
    )
    snapshot_digest = (
        _scaffold_contracts_sha256(contract_snapshot)
        if contract_snapshot_valid
        else ""
    )
    contract_snapshot_integrity = bool(
        snapshot_digest
        and snapshot_digest
        == str(binding.get("scaffold_contracts_sha256", "")).lower()
    )
    if readable and not (contract_snapshot_valid and contract_snapshot_integrity):
        add(
            "scaffold.contract_snapshot",
            "Scaffold verification-contract snapshot is missing or inconsistent.",
        )
    selection = manifest.get("selection", {})
    selection_valid = bool(
        isinstance(selection, dict)
        and selection.get("disposition")
        in {"accepted", "rejected", "unreviewed", "all"}
        and isinstance(selection.get("scope"), str)
        and selection.get("scope")
        and isinstance(selection.get("limit"), int)
        and not isinstance(selection.get("limit"), bool)
        and 1 <= selection.get("limit", 0) <= 1000
        and isinstance(selection.get("include_implemented"), bool)
    )
    if readable and not selection_valid:
        add(
            "scaffold.selection_contract",
            "Scaffold selection parameters are missing or malformed.",
        )
    supplied_queue = manifest.get("queue", {})
    queue = {
        "id": str(supplied_queue.get("id", ""))
        if isinstance(supplied_queue, dict)
        else "",
        "owner": str(supplied_queue.get("owner", ""))
        if isinstance(supplied_queue, dict)
        else "",
        "purpose": str(supplied_queue.get("purpose", ""))
        if isinstance(supplied_queue, dict)
        else "",
    }
    queue_valid = bool(
        isinstance(supplied_queue, dict)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", queue["id"])
        and len(queue["owner"]) <= 200
        and not any(ord(value) < 32 for value in queue["owner"])
        and len(queue["purpose"]) <= 500
        and not any(ord(value) < 32 for value in queue["purpose"])
    )
    if readable and not queue_valid:
        add(
            "scaffold.queue_metadata",
            "Scaffold queue ID, owner, or purpose metadata is missing or malformed.",
        )
    current_register = ensure_assurance_register(analysis)
    current_selected = (
        _select_scaffold_obligations(
            analysis,
            current_register,
            scope=str(selection["scope"]),
            limit=int(selection["limit"]),
            disposition=str(selection["disposition"]),
            include_implemented=bool(selection["include_implemented"]),
        )
        if selection_valid
        else []
    )
    current_contracts = _scaffold_contract_records(
        analysis,
        current_selected,
    )
    previous_contracts_by_id = {
        str(value.get("id", "")): value
        for value in contract_snapshot
        if isinstance(value, dict)
    }
    current_contracts_by_id = {value["id"]: value for value in current_contracts}
    contract_changes: list[dict[str, Any]] = []
    contract_change_summary = {"current": 0, "added": 0, "removed": 0, "changed": 0}
    compared_fields = (
        "finding_id",
        "contract_sha256",
        "disposition",
        "source_status",
        "implementation_status",
    )
    for obligation_id in sorted(
        set(previous_contracts_by_id) | set(current_contracts_by_id)
    ):
        previous_record = previous_contracts_by_id.get(obligation_id)
        current_record = current_contracts_by_id.get(obligation_id)
        if previous_record is None:
            change_status = "added"
            changed_fields = list(compared_fields)
        elif current_record is None:
            change_status = "removed"
            changed_fields = list(compared_fields)
        else:
            changed_fields = [
                field
                for field in compared_fields
                if str(previous_record.get(field, ""))
                != str(current_record.get(field, ""))
            ]
            change_status = "changed" if changed_fields else "current"
        contract_change_summary[change_status] += 1
        if change_status != "current":
            contract_changes.append(
                {
                    "obligation_id": obligation_id,
                    "finding_id": str(
                        (current_record or previous_record or {}).get(
                            "finding_id", ""
                        )
                    ),
                    "status": change_status,
                    "changed_fields": changed_fields,
                    "previous": previous_record,
                    "current": current_record,
                }
            )
    current = {
        "baseline_id": str(
            analysis.get("project", {}).get("baseline", {}).get("id", "")
        ),
        "analysis_schema_version": str(analysis.get("schema_version", "")),
        "analysis_state_sha256": hashlib.sha256(
            json.dumps(
                analysis,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest(),
        "scaffold_contracts_sha256": _scaffold_contracts_sha256(
            current_contracts
        ),
    }
    binding_checks = {
        key: bool(binding.get(key)) and str(binding.get(key)).lower() == value.lower()
        for key, value in current.items()
    }
    critical_binding_keys = (
        "baseline_id",
        "analysis_schema_version",
        "scaffold_contracts_sha256",
    )
    contract_binding_valid = all(
        binding_checks.get(key, False) for key in critical_binding_keys
    )
    for key in critical_binding_keys:
        if readable and not binding_checks.get(key, False):
            add(
                f"scaffold.binding_{key}",
                f"Scaffold {key.replace('_', ' ')} does not match the current analysis.",
            )
    if (
        readable
        and contract_binding_valid
        and not binding_checks.get("analysis_state_sha256", False)
    ):
        add(
            "scaffold.analysis_state_advanced",
            "The governed analysis changed, but the selected scaffold contracts remain current.",
            "information",
        )

    generated_files: list[dict[str, Any]] = []
    declared_files = manifest.get("generated_files", {})
    generated_declarations_valid = isinstance(declared_files, dict) and all(
        isinstance(declared_files.get(name), dict)
        and len(str(declared_files[name].get("sha256", ""))) == 64
        and all(
            value in "0123456789abcdefABCDEF"
            for value in str(declared_files[name].get("sha256", ""))
        )
        for name in ("README.md", "test_sfmea_assurance.py")
    )
    if readable and not generated_declarations_valid:
        add(
            "scaffold.generated_file_manifest",
            "Generated starting-file hashes are missing or malformed.",
        )
    if isinstance(declared_files, dict):
        for name in ("README.md", "test_sfmea_assurance.py"):
            record = declared_files.get(name, {})
            target = path / name
            expected = str(record.get("sha256", "")) if isinstance(record, dict) else ""
            actual = ""
            if target.is_file() and not target.is_symlink():
                try:
                    actual = hashlib.sha256(target.read_bytes()).hexdigest()
                except OSError as exc:
                    add(
                        "scaffold.generated_file_unreadable",
                        f"Cannot read generated starting file {name}: {exc}",
                        "information",
                    )
            unchanged = bool(expected and actual == expected)
            generated_files.append(
                {
                    "path": str(name),
                    "exists": target.is_file(),
                    "unchanged_from_generated": unchanged,
                    "generated_sha256": expected,
                    "current_sha256": actual,
                }
            )
            if not unchanged:
                add(
                    "scaffold.generated_file_changed",
                    f"Generated starting file changed or is missing: {name}",
                    "information",
                )

    retirement_path = path / "retirement-record.json"
    retirement_present = retirement_path.exists()
    retirement_record: dict[str, Any] = {}
    retirement_valid = not retirement_present
    if retirement_present:
        try:
            if retirement_path.is_symlink() or not retirement_path.is_file():
                raise ValueError("retirement record must be a regular file")
            if retirement_path.stat().st_size > MAX_ASSURANCE_SCAFFOLD_MANIFEST_BYTES:
                raise ValueError("retirement record exceeds the bounded verification limit")
            loaded_retirement = json.loads(
                retirement_path.read_text(encoding="utf-8")
            )
            if not isinstance(loaded_retirement, dict):
                raise ValueError("retirement record root must be an object")
            retirement_record = loaded_retirement
            canonical_retirement = dict(retirement_record)
            retirement_digest = str(canonical_retirement.pop("record_sha256", ""))
            actual_retirement_digest = hashlib.sha256(
                json.dumps(
                    canonical_retirement,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest()
            recorded_archive = Path(
                str(retirement_record.get("archive_path", ""))
            ).expanduser().resolve()
            recorded_current = retirement_record.get("current_analysis", {})
            retirement_valid = bool(
                retirement_record.get("format")
                == "pysfmea-assurance-scaffold-retirement-1"
                and retirement_record.get("reason")
                == "selection_no_longer_matches_pending_obligations"
                and len(retirement_digest) == 64
                and retirement_digest.lower() == actual_retirement_digest
                and retirement_record.get("queue") == supplied_queue
                and retirement_record.get("previous_manifest_sha256")
                == supplied_digest
                and recorded_archive == path.resolve()
                and isinstance(recorded_current, dict)
                and all(
                    recorded_current.get(key)
                    for key in (
                        "baseline_id",
                        "analysis_schema_version",
                        "analysis_state_sha256",
                        "scaffold_contracts_sha256",
                    )
                )
                and isinstance(
                    retirement_record.get("contract_change_summary"), dict
                )
                and isinstance(retirement_record.get("contract_changes"), list)
            )
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            retirement_valid = False
        if not retirement_valid:
            add(
                "scaffold.retirement_record",
                "Retirement record integrity or archive binding verification failed.",
            )

    internal_valid = all(
        (
            readable,
            format_valid,
            manifest_integrity,
            obligations_valid,
            contract_snapshot_valid,
            contract_snapshot_integrity,
            selection_valid,
            queue_valid,
            generated_declarations_valid,
            retirement_valid,
        )
    )
    bound = internal_valid and contract_binding_valid
    exact_match = bound and binding_checks.get("analysis_state_sha256", False)
    lifecycle = (
        "archived"
        if internal_valid and retirement_present
        else "retirement_candidate"
        if internal_valid and not current_selected
        else "active"
    )
    status = (
        "matched"
        if exact_match
        else "contracts_current"
        if bound
        else "mismatched"
        if internal_valid
        else "invalid"
    )
    return {
        "format": ASSURANCE_SCAFFOLD_VERIFICATION_FORMAT,
        "path": str(path),
        "valid": bound,
        "status": status,
        "checks": {
            "readable": readable,
            "format": format_valid,
            "manifest_integrity": manifest_integrity,
            "obligations": obligations_valid,
            "contract_snapshot": contract_snapshot_valid,
            "contract_snapshot_integrity": contract_snapshot_integrity,
            "selection_contract": selection_valid,
            "queue_metadata": queue_valid,
            "generated_files_declared": generated_declarations_valid,
            "retirement_record": retirement_valid,
            **binding_checks,
        },
        "binding": {"current": current, "scaffold": binding},
        "obligation_count": (
            len(manifest.get("obligations", [])) if obligations_valid else 0
        ),
        "obligation_ids": [
            str(value.get("id", ""))
            for value in manifest_obligations
            if isinstance(value, dict) and value.get("id")
        ],
        "current_selection": {
            "obligation_count": len(current_selected),
            "obligation_ids": [
                str(value.get("id", ""))
                for value in current_selected
                if isinstance(value, dict) and value.get("id")
            ],
        },
        "lifecycle": lifecycle,
        "retirement": {
            "present": retirement_present,
            "valid": retirement_valid,
            "path": str(retirement_path) if retirement_present else "",
            "archived_at": str(retirement_record.get("archived_at", "")),
            "source_path": str(retirement_record.get("source_path", "")),
            "archive_path": str(retirement_record.get("archive_path", "")),
            "record_sha256": str(retirement_record.get("record_sha256", "")),
        },
        "queue": queue,
        "contract_change_summary": contract_change_summary,
        "contract_changes": contract_changes,
        "generated_files": generated_files,
        "findings": findings,
        "notice": (
            "Verification detects accidental integrity and freshness failures. Generated "
            "placeholder changes are informational because implementation is expected; "
            "unrelated analysis edits remain distinguishable from selected contract "
            "changes. Implementations become governed only after test registration. "
            "Digests are not approval signatures."
        ),
    }


def _require_untouched_scaffold(
    analysis: dict[str, Any], path: Path, *, operation: str
) -> dict[str, Any]:
    """Return verified scaffold state only when preservation-sensitive work is safe."""

    verification = verify_pytest_scaffold(analysis, path)
    safe_checks = (
        "readable",
        "format",
        "manifest_integrity",
        "obligations",
        "contract_snapshot",
        "contract_snapshot_integrity",
        "selection_contract",
        "queue_metadata",
        "generated_files_declared",
        "retirement_record",
    )
    if not all(verification.get("checks", {}).get(key) for key in safe_checks):
        raise ValueError(
            f"assurance scaffold {operation} requires an intact current-format manifest"
        )
    if verification.get("retirement", {}).get("present"):
        raise ValueError(
            f"assurance scaffold {operation} refused because archived queues are immutable"
        )
    if not verification.get("generated_files") or not all(
        value.get("unchanged_from_generated")
        for value in verification["generated_files"]
    ):
        raise ValueError(
            f"assurance scaffold {operation} refused because generated files were edited or "
            "removed; use a new destination to preserve implementation work"
        )
    return verification


def refresh_pytest_scaffold(
    analysis: dict[str, Any], destination: str | Path
) -> Path:
    """Safely regenerate an untouched scaffold using its governed selection and identity."""

    path = Path(destination).expanduser().resolve()
    _require_untouched_scaffold(analysis, path, operation="refresh")
    manifest = json.loads(
        (path / "assurance-manifest.json").read_text(encoding="utf-8")
    )
    selection = manifest["selection"]
    queue = manifest["queue"]
    return export_pytest_scaffold(
        analysis,
        path,
        scope=str(selection["scope"]),
        limit=int(selection["limit"]),
        disposition=str(selection["disposition"]),
        include_implemented=bool(selection["include_implemented"]),
        queue_id=str(queue["id"]),
        owner=str(queue["owner"]),
        purpose=str(queue["purpose"]),
        replace=True,
    )


def archive_pytest_scaffold(
    analysis: dict[str, Any],
    source: str | Path,
    destination: str | Path | None = None,
) -> Path:
    """Atomically archive an untouched queue whose selection is now empty."""

    path = Path(source).expanduser().resolve()
    verification = _require_untouched_scaffold(
        analysis, path, operation="archive"
    )
    if verification.get("lifecycle") != "retirement_candidate":
        raise ValueError(
            "assurance scaffold archive requires a retirement candidate whose current "
            "selection contains no pending obligations"
        )
    queue_id = str(verification.get("queue", {}).get("id", "queue"))
    timestamp = utc_now().replace("+00:00", "Z").replace("-", "").replace(":", "")
    archive = (
        Path(destination).expanduser().resolve()
        if destination is not None
        else path.parent / ".sfmea-archive" / f"{path.name}-{queue_id}-{timestamp}"
    )
    if archive == path or archive.is_relative_to(path):
        raise ValueError("assurance scaffold archive destination must be outside the queue")
    if path.anchor.casefold() != archive.anchor.casefold():
        raise ValueError(
            "assurance scaffold archive destination must be on the same filesystem volume"
        )
    if archive.exists():
        raise ValueError(
            f"assurance scaffold archive destination already exists: {archive}"
        )
    retirement_path = path / "retirement-record.json"
    if retirement_path.exists():
        raise ValueError(
            "assurance scaffold already contains a retirement record; inspect it manually"
        )
    archive.parent.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(
        (path / "assurance-manifest.json").read_text(encoding="utf-8")
    )
    record = {
        "format": "pysfmea-assurance-scaffold-retirement-1",
        "archived_at": utc_now(),
        "reason": "selection_no_longer_matches_pending_obligations",
        "source_path": str(path),
        "archive_path": str(archive),
        "queue": dict(verification["queue"]),
        "previous_manifest_sha256": str(manifest.get("manifest_sha256", "")),
        "current_analysis": dict(verification["binding"]["current"]),
        "contract_change_summary": dict(verification["contract_change_summary"]),
        "contract_changes": list(verification["contract_changes"]),
    }
    record["record_sha256"] = hashlib.sha256(
        json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    try:
        retirement_path.write_text(
            json.dumps(record, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        os.replace(path, archive)
    except Exception:
        if path.exists():
            retirement_path.unlink(missing_ok=True)
        raise
    return archive
