"""Executable assurance contracts derived from governed SFMEA findings."""

from __future__ import annotations

import copy
import csv
import fnmatch
import hashlib
import io
import json
import os
import re
import shutil
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_file
from .model import preserve_unchanged_generated_at, stable_id, utc_now
from .version import __version__

ASSURANCE_SCHEMA_VERSION = "1.0"
ASSURANCE_WORK_QUEUE_FORMAT = "pysfmea-assurance-work-queue-2"
ASSURANCE_WORK_QUEUE_VERIFICATION_FORMAT = "pysfmea-assurance-work-queue-verification-1"
ASSURANCE_REGISTER_VERIFICATION_FORMAT = "pysfmea-assurance-register-verification-1"
MAX_ASSURANCE_WORK_QUEUE_BYTES = 100 * 1024 * 1024
MAX_ASSURANCE_JSON_DEPTH = 100
MAX_ASSURANCE_SCAFFOLD_JSON_NODES = 500_000
MAX_ASSURANCE_WORK_QUEUE_JSON_NODES = 1_000_000
ASSURANCE_WORK_STATES = (
    "contract_gap",
    "definition_required",
    "plan_review_required",
    "ready_for_implementation",
    "ready_for_execution",
    "execution_remediation_required",
    "evidence_remediation_required",
    "evidence_review_required",
    "verification_review_required",
    "resolved",
)
ASSURANCE_WORK_NEXT_ACTIONS = (
    "repair_assurance_register",
    "define_assurance_contract",
    "review_assurance_plan",
    "implement_test",
    "execute_test",
    "remediate_execution",
    "remediate_evidence",
    "review_execution_evidence",
    "complete_verification_review",
    "none",
)
_WORK_STATE_ACTION = dict(zip(ASSURANCE_WORK_STATES, ASSURANCE_WORK_NEXT_ACTIONS))
PLANNER_VERSION = "deterministic-verification-planner-6"
ASSURANCE_SCAFFOLD_FORMAT = "pysfmea-pytest-assurance-scaffold-6"
ASSURANCE_SCAFFOLD_VERIFICATION_FORMAT = "pysfmea-assurance-scaffold-verification-5"
MAX_ASSURANCE_SCAFFOLD_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_ASSURANCE_SCAFFOLD_GENERATED_FILE_BYTES = 64 * 1024 * 1024
ASSURANCE_NOTICE = (
    "Verification obligations are deterministic planning drafts. A proposed or implemented "
    "test is not evidence. Passing execution cannot close a finding until the recorded "
    "stimulus, oracles, acceptance criteria, environment, freshness, and evidence sufficiency "
    "have been independently reviewed. Repository code must run only in an approved sandbox."
)


def _read_assurance_json_object(path: Path, *, label: str) -> dict[str, Any]:
    """Read one strict, bounded, identity-stable assurance JSON object."""

    try:
        _path, loaded, _size = load_bounded_json_file(
            path,
            label=label,
            max_bytes=MAX_ASSURANCE_SCAFFOLD_MANIFEST_BYTES,
            max_depth=MAX_ASSURANCE_JSON_DEPTH,
            max_nodes=MAX_ASSURANCE_SCAFFOLD_JSON_NODES,
        )
    except ValueError as exc:
        if str(exc) == (
            f"{label} exceeds the {MAX_ASSURANCE_SCAFFOLD_MANIFEST_BYTES}-byte limit"
        ):
            raise ValueError(
                f"{label} exceeds the {MAX_ASSURANCE_SCAFFOLD_MANIFEST_BYTES}-byte "
                "verification limit"
            ) from exc
        raise
    if not isinstance(loaded, dict):
        raise ValueError(f"{label} root must be an object")
    return loaded


def _sha256_assurance_file_bounded(path: Path) -> str:
    """Hash a regular generated scaffold file without buffering it unboundedly."""

    if path.is_symlink() or not path.is_file():
        raise ValueError("generated scaffold file must be a regular file")
    digest = hashlib.sha256()
    consumed = 0
    with path.open("rb") as source_file:
        while chunk := source_file.read(1024 * 1024):
            consumed += len(chunk)
            if consumed > MAX_ASSURANCE_SCAFFOLD_GENERATED_FILE_BYTES:
                raise ValueError(
                    "generated scaffold file exceeds the "
                    f"{MAX_ASSURANCE_SCAFFOLD_GENERATED_FILE_BYTES}-byte verification "
                    "limit"
                )
            digest.update(chunk)
    return digest.hexdigest()


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
PLANNING_READY_STATUSES = {
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
TERMINAL_ASSURANCE_STATUSES = {
    "verified",
    "accepted_risk",
    "closed",
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
        return (
            "fault_injection_test",
            "Exercise trip, isolation, degraded fallback, and timed recovery across controlled breaker-state transitions.",
        )
    if rule.startswith(("storage.", "persistence.")):
        return (
            "fault_injection_test",
            "Exercise rollback and externally visible side effects at persistence failure boundaries.",
        )
    if rule.startswith("state."):
        return (
            "state_transition_test",
            "Exercise valid and invalid state transitions and their invariants.",
        )
    if rule.startswith("timing."):
        return (
            "concurrency_test",
            "Exercise ordering, timeout, cancellation, and repeated interleavings.",
        )
    if rule.startswith("resource."):
        return (
            "stress_test",
            "Exercise declared resource bounds and controlled degradation.",
        )
    if rule.startswith("detection."):
        return (
            "fault_injection_test",
            "Trigger the failure and demonstrate detection, alerting, and containment.",
        )
    if rule.startswith("configuration.") or rule.startswith("environment."):
        return (
            "configuration_inspection",
            "Validate configuration constraints and fail-safe startup behavior.",
        )
    if rule.startswith("interface.contract"):
        return (
            "contract_test",
            "Exercise compatible and incompatible interface contracts at the real boundary.",
        )
    if rule.startswith("interface."):
        return (
            "integration_test",
            "Exercise unavailable, malformed, delayed, and partial interface responses.",
        )
    if rule.startswith("common_cause."):
        return (
            "architecture_review",
            "Demonstrate independence or containment against the common cause.",
        )
    if failure_class in {"calculation", "data"}:
        return (
            "property_test",
            "Generate boundary and adversarial values and verify declared invariants.",
        )
    if failure_class == "security" or any(
        token in rule for token in ("access", "auth", "trust", "untrusted", "outbound")
    ):
        return (
            "security_test",
            "Exercise the trust boundary with unauthorized and adversarial inputs.",
        )
    if failure_class == "logic":
        return (
            "property_test",
            "Exercise branch and sequence invariants across representative input classes.",
        )
    if failure_class == "functional":
        return (
            "unit_test",
            "Exercise the required behavior and negative behavior at the function boundary.",
        )
    return (
        "integration_test",
        "Exercise the failure at the nearest representative system boundary.",
    )


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
        "injection_required": method
        in {
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


def _circuit_breaker_review_questions(control: dict[str, Any]) -> list[str]:
    """Return non-gating questions for breaker details absent from static evidence."""

    roles = set(_text_list(control.get("roles", [])))
    questions = []
    if not control.get("threshold_expressions"):
        questions.append(
            "What exact failure-count or rate threshold opens the breaker?"
        )
    if "recovery_timer" in roles and not control.get("cooldown_expressions"):
        questions.append("What exact cooldown boundary permits a recovery probe?")
    if "recovery_timer" in roles and not control.get("clock_sources"):
        questions.append("Which controlled elapsed-time source governs recovery?")
    if "recovery_timer" in roles and "half_open" not in set(
        _text_list(control.get("observed_states", control.get("states", [])))
    ):
        questions.append(
            "How is the bounded recovery-probe or HALF-OPEN policy represented?"
        )
    if "recovery_timer" in roles and "success_reset" not in roles:
        questions.append(
            "What observed transition returns a successful recovery probe to CLOSED?"
        )
    if "recovery_timer" in roles and not control.get("synchronization"):
        questions.append("How are concurrent recovery probes serialized or bounded?")
    if not control.get("scope_keys"):
        questions.append(
            "What dependency, tenant, or instance identity scopes breaker state?"
        )
    if "degraded_fallback" not in roles:
        questions.append(
            "Is a caller-visible degraded contract required, or explicitly not applicable?"
        )
    return questions


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
    direct_callers = _text_list(scanner.get("called_by", []))[:50]
    upstream_paths = [
        _text_list(path)[:7]
        for path in scanner.get("upstream_paths", [])[:25]
        if isinstance(path, list) and len(path) > 1
    ]
    upstream_path_analysis = copy.deepcopy(scanner.get("upstream_path_analysis", {}))
    gaps = []
    if not next_effect:
        gaps.append("next-higher effect requires engineering definition")
    if not end_effect:
        gaps.append("system/end effect requires engineering definition")
    if not prevention and not detection:
        gaps.append(
            "required prevention, detection, containment, or recovery control is not confirmed"
        )
    if not safe_state and not degraded_behavior and not recovery_behavior:
        gaps.append(
            "required safe-state, degraded, or recovery behavior is not defined"
        )
    if upstream_paths and not upstream_path_analysis.get(
        "complete_within_static_call_model", True
    ):
        gaps.append(
            "static caller-path inventory is bounded; verification scope must address the recorded path/depth limitations"
        )
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
        "control_review_questions": _circuit_breaker_review_questions(circuit_breaker)
        if circuit_breaker
        else [],
        "cascade_context": {
            "direct_callers": direct_callers,
            "static_upstream_paths": upstream_paths,
            "static_path_analysis": upstream_path_analysis,
            "notice": str(
                scanner.get(
                    "propagation_notice",
                    "Static caller paths indicate potential exposure, not confirmed causal propagation.",
                )
            ),
        },
        "operational_context": {
            "mode": str(review.get("operational_mode", "")),
            "state": str(review.get("operational_state", "")),
        },
        "preconditions": [
            str(
                review.get("trigger")
                or scanner.get("trigger", "The failure trigger is established.")
            ),
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
        "repeatability": {
            "minimum_runs": 1,
            "additional_runs_when_nondeterministic": 10,
        },
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
        "assurance_status": "retired"
        if item.get("source_status") == "removed"
        else "candidate",
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
            "finding_context_fingerprint": scanner.get(
                "analysis_context_fingerprint", ""
            ),
        },
        "history": [{"event": "obligation_generated", "at": utc_now()}],
    }
    if upstream_paths:
        obligation["preconditions"].append(
            "The test identifies which bounded static caller path is being exercised and records any unresolved dynamic dispatch."
        )
        obligation["oracles"].append(
            "Observe the failed component, immediate caller, and outermost exercised caller independently; do not infer propagation from call linkage alone."
        )
        obligation["acceptance_criteria"].append(
            "Observed behavior across the exercised caller path matches the approved local, next-higher, and system-effect boundaries."
        )
        obligation["evidence_requirements"].append(
            "selected static caller path plus runtime trace or explicit test instrumentation showing which caller boundaries were exercised"
        )
        if not upstream_path_analysis.get("complete_within_static_call_model", True):
            obligation["acceptance_criteria"].append(
                "The verification record identifies caller paths omitted by discovery limits and documents compensating runtime, integration, or architectural evidence."
            )
    if circuit_breaker:
        rule_id = str(scanner.get("rule_id", ""))
        obligation["preconditions"].extend(
            [
                "The dependency call count and breaker state are observable without relying only on logs.",
                "The test controls dependency success/failure and proves whether each downstream call was admitted or suppressed.",
            ]
        )
        obligation["oracles"].extend(
            [
                "Observe each exercised breaker state transition and its exact trigger.",
                "Count real downstream calls; suppressed calls must be distinguishable from successful calls.",
            ]
        )
        if rule_id == "resilience.circuit_breaker_containment":
            obligation["preconditions"].append(
                "The test can place failures immediately before, at, and after the approved trip boundary."
            )
            obligation["acceptance_criteria"].extend(
                [
                    "The breaker opens at the reviewer-approved consecutive-failure boundary and never admits a normal dependency call while open.",
                    "Success/reset and concurrent failure accounting cannot bypass or prematurely trigger containment.",
                ]
            )
            obligation["required_environment"].append(
                "Controllable dependency double, exact call counter, and scheduler barrier for threshold interleavings."
            )
        elif rule_id == "resilience.circuit_breaker_recovery":
            obligation["preconditions"].append(
                "The test controls elapsed time and concurrent recovery-admission attempts."
            )
            obligation["oracles"].append(
                "Observe OPEN, recovery-probe/HALF-OPEN-equivalent, re-open, and close decisions at cooldown boundaries."
            )
            obligation["acceptance_criteria"].extend(
                [
                    "Cooldown uses the approved clock semantics and does not recover before the full interval elapses.",
                    "At most the approved number of HALF-OPEN probes execute concurrently; success closes and failure reopens the breaker deterministically.",
                ]
            )
            obligation["required_environment"].append(
                "Controllable dependency double, monotonic/fake clock, and scheduler barrier for concurrent recovery probes."
            )
            obligation["evidence_requirements"].append(
                "controlled-clock and concurrent recovery-probe results immediately before, at, and after cooldown boundaries"
            )
        elif rule_id == "resilience.circuit_breaker_isolation":
            obligation["preconditions"].append(
                "At least two independently identifiable breaker scopes can fail and recover separately."
            )
            obligation["oracles"].append(
                "Observe breaker state and downstream call decisions independently for every exercised isolation key."
            )
            obligation["acceptance_criteria"].append(
                "A healthy dependency, tenant, or unrelated isolation key is not tripped, reset, or bypassed by another scope's state."
            )
            obligation["required_environment"].append(
                "Controllable dependency doubles and independent call/state counters for every exercised isolation key."
            )
        elif rule_id == "resilience.circuit_breaker_fallback":
            obligation["preconditions"].append(
                "The breaker is held open while every caller-visible fallback path is exercised."
            )
            obligation["oracles"].append(
                "Observe the caller-visible degraded/fallback contract and all prohibited downstream side effects."
            )
            obligation["acceptance_criteria"].append(
                "Fallback/degraded output is explicit, observable, and cannot be mistaken for a complete successful dependency result.",
            )
            obligation["required_environment"].append(
                "Controllable dependency double and caller-side side-effect instrumentation while the breaker remains open."
            )
        obligation["evidence_requirements"].append(
            "state-transition trace with timestamps, isolation identity, failure count, and admitted/suppressed call decision"
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
        (
            str(value.get("finding_id", "")),
            str(value.get("verification_method", "")),
        ): value
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
            else:
                previous_generated_at = old.get("provenance", {}).get("generated_at")
                if isinstance(previous_generated_at, str) and previous_generated_at:
                    obligation["provenance"]["generated_at"] = previous_generated_at
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
        "evidence_artifacts": copy.deepcopy(previous.get("evidence_artifacts", [])),
    }
    register["summary"] = assurance_summary(register)
    preserve_unchanged_generated_at(previous, register)
    analysis["assurance"] = register
    analysis.setdefault("summary", {})["assurance"] = copy.deepcopy(register["summary"])
    return register


def ensure_assurance_register(analysis: dict[str, Any]) -> dict[str, Any]:
    register = analysis.get("assurance")
    if not isinstance(register, dict) or not isinstance(
        register.get("obligations"), list
    ):
        return refresh_assurance_register(analysis, {})
    return register


def assurance_summary(register: dict[str, Any]) -> dict[str, Any]:
    values = [
        value for value in register.get("obligations", []) if isinstance(value, dict)
    ]
    active = [
        value for value in values if value.get("source_status", "active") == "active"
    ]
    executions = [
        value for value in register.get("executions", []) if isinstance(value, dict)
    ]
    return {
        "active_obligations": len(active),
        "retired_obligations": len(values) - len(active),
        "by_status": dict(
            sorted(
                Counter(
                    str(value.get("assurance_status", "unknown")) for value in active
                ).items()
            )
        ),
        "by_method": dict(
            sorted(
                Counter(
                    str(value.get("verification_method", "unknown")) for value in active
                ).items()
            )
        ),
        "by_evidence_status": dict(
            sorted(
                Counter(
                    str(value.get("evidence_status", "unknown")) for value in active
                ).items()
            )
        ),
        "implemented_tests": sum(
            value.get("automation", {}).get("implementation_status") == "implemented"
            for value in active
        ),
        "planning_gaps": sum(bool(value.get("planning_gaps")) for value in active),
        "executions": len(executions),
        "executions_by_status": dict(
            sorted(
                Counter(
                    str(value.get("status", "unknown")) for value in executions
                ).items()
            )
        ),
        "reviewed_executions": sum(bool(value.get("reviews")) for value in executions),
        "evidence_artifacts": len(register.get("evidence_artifacts", [])),
    }


def _planning_ready(obligation: dict[str, Any]) -> bool:
    review = obligation.get("review", {})
    return bool(
        obligation.get("assurance_status") in PLANNING_READY_STATUSES
        and review.get("reviewer")
        and review.get("rationale")
        and not obligation.get("planning_gaps")
    )


def assurance_work_queue(analysis: dict[str, Any]) -> dict[str, Any]:
    """Project accepted findings into explicit, evidence-backed engineering work states."""

    analysis_state_sha256 = canonical_json_sha256(analysis)
    register = ensure_assurance_register(analysis)
    accepted_items = {
        str(item.get("id", "")): item
        for item in analysis.get("items", [])
        if isinstance(item, dict)
        and item.get("source_status", "active") == "active"
        and item.get("review", {}).get("disposition") == "accepted"
        and item.get("id")
    }
    by_finding: dict[str, list[dict[str, Any]]] = {}
    for obligation in register.get("obligations", []):
        if (
            isinstance(obligation, dict)
            and obligation.get("source_status", "active") == "active"
        ):
            by_finding.setdefault(str(obligation.get("finding_id", "")), []).append(
                obligation
            )
    executions_by_obligation: dict[str, list[dict[str, Any]]] = {}
    for execution in register.get("executions", []):
        if isinstance(execution, dict):
            executions_by_obligation.setdefault(
                str(execution.get("obligation_id", "")), []
            ).append(execution)

    items = []
    for finding_id, finding in accepted_items.items():
        obligations = by_finding.get(finding_id, [])
        if len(obligations) != 1:
            count = len(obligations)
            items.append(
                {
                    "finding_id": finding_id,
                    "obligation_id": "",
                    "priority": str(
                        finding.get("scanner", {}).get("screening_priority", "")
                    ),
                    "component": str(finding.get("component", {}).get("qualname", "")),
                    "state": "contract_gap",
                    "actionable": True,
                    "automation_eligible": False,
                    "next_action_id": "repair_assurance_register",
                    "blockers": [
                        (
                            "accepted finding has no verification obligation"
                            if count == 0
                            else f"accepted finding has {count} verification obligations"
                        )
                    ],
                    "latest_execution_id": "",
                    "latest_execution_status": "",
                }
            )
            continue

        obligation = obligations[0]
        obligation_id = str(obligation.get("id", ""))
        assurance_status = str(obligation.get("assurance_status", "candidate"))
        evidence_status = str(obligation.get("evidence_status", "missing"))
        implementation_status = str(
            obligation.get("automation", {}).get(
                "implementation_status", "not_implemented"
            )
        )
        executions = executions_by_obligation.get(obligation_id, [])
        latest = executions[-1] if executions else {}
        latest_status = str(latest.get("status", ""))
        blockers: list[str] = []

        if assurance_status in TERMINAL_ASSURANCE_STATUSES:
            state = "resolved"
            next_action = "none"
        elif obligation.get("planning_gaps"):
            state = "definition_required"
            next_action = "define_assurance_contract"
            blockers.extend(_text_list(obligation.get("planning_gaps", [])))
        elif not _planning_ready(obligation):
            state = "plan_review_required"
            next_action = "review_assurance_plan"
            review = obligation.get("review", {})
            if assurance_status not in PLANNING_READY_STATUSES:
                blockers.append(
                    f"assurance status {assurance_status!r} is not planning-ready"
                )
            if not str(review.get("reviewer", "")).strip():
                blockers.append("named assurance-plan reviewer is missing")
            if not str(review.get("rationale", "")).strip():
                blockers.append("assurance-plan rationale is missing")
        elif implementation_status != "implemented":
            state = "ready_for_implementation"
            next_action = "implement_test"
        elif not executions:
            state = "ready_for_execution"
            next_action = "execute_test"
        elif latest_status in {"failed", "timeout", "error"}:
            state = "execution_remediation_required"
            next_action = "remediate_execution"
            blockers.append(f"latest execution status is {latest_status}")
        elif evidence_status in {"insufficient", "partial", "stale"}:
            state = "evidence_remediation_required"
            next_action = "remediate_evidence"
            blockers.append(f"evidence status is {evidence_status}")
        elif not latest.get("reviews") or evidence_status in {
            "missing",
            "collected_unreviewed",
        }:
            state = "evidence_review_required"
            next_action = "review_execution_evidence"
        else:
            state = "verification_review_required"
            next_action = "complete_verification_review"

        items.append(
            {
                "finding_id": finding_id,
                "obligation_id": obligation_id,
                "priority": str(obligation.get("priority", "")),
                "component": str(obligation.get("component", "")),
                "state": state,
                "actionable": state != "resolved",
                "automation_eligible": state
                in {"ready_for_implementation", "ready_for_execution"},
                "next_action_id": next_action,
                "blockers": blockers,
                "latest_execution_id": str(latest.get("id", "")),
                "latest_execution_status": latest_status,
            }
        )

    state_order = {
        "contract_gap": 0,
        "definition_required": 1,
        "plan_review_required": 2,
        "execution_remediation_required": 3,
        "evidence_remediation_required": 4,
        "ready_for_implementation": 5,
        "ready_for_execution": 6,
        "evidence_review_required": 7,
        "verification_review_required": 8,
        "resolved": 9,
    }
    priority_order = {"high": 0, "medium": 1, "low": 2}
    items.sort(
        key=lambda value: (
            state_order.get(value["state"], 99),
            priority_order.get(value["priority"], 3),
            value["component"],
            value["finding_id"],
        )
    )
    by_state = dict(sorted(Counter(value["state"] for value in items).items()))
    payload = {
        "format": ASSURANCE_WORK_QUEUE_FORMAT,
        "generator": {"name": "PySFMEA", "version": __version__},
        "binding": {
            "format": ASSURANCE_WORK_QUEUE_FORMAT,
            "baseline_id": str(
                analysis.get("project", {}).get("baseline", {}).get("id", "")
            ),
            "analysis_schema_version": str(analysis.get("schema_version", "")),
            "analysis_state_sha256": analysis_state_sha256,
        },
        "summary": {
            "total": len(items),
            "actionable": sum(value["actionable"] for value in items),
            "automation_eligible": sum(value["automation_eligible"] for value in items),
            "implementation_ready": by_state.get("ready_for_implementation", 0),
            "execution_ready": by_state.get("ready_for_execution", 0),
            "by_state": by_state,
        },
        "items": items,
        "notice": (
            "Work states are deterministic lifecycle projections, not engineering "
            "approval, execution evidence, or authorization to run repository code."
        ),
    }
    payload["integrity"] = {
        "algorithm": "sha256",
        "canonicalization": "json-sort-keys-compact-utf8",
        "content_sha256": canonical_json_sha256(payload),
    }
    return payload


def _work_queue_content_sha256(queue: dict[str, Any]) -> str:
    content = dict(queue)
    content.pop("integrity", None)
    return canonical_json_sha256(content)


def _work_queue_structure_valid(queue: dict[str, Any]) -> bool:
    """Apply the closed queue contract and local reconciliation without dependencies."""

    top_fields = {
        "format",
        "generator",
        "binding",
        "summary",
        "items",
        "notice",
        "integrity",
    }
    if set(queue) != top_fields:
        return False
    generator = queue.get("generator")
    binding = queue.get("binding")
    summary = queue.get("summary")
    items = queue.get("items")
    integrity = queue.get("integrity")
    if not (
        isinstance(generator, dict)
        and set(generator) == {"name", "version"}
        and generator.get("name") == "PySFMEA"
        and isinstance(generator.get("version"), str)
        and bool(generator.get("version"))
        and isinstance(binding, dict)
        and set(binding)
        == {
            "format",
            "baseline_id",
            "analysis_schema_version",
            "analysis_state_sha256",
        }
        and binding.get("format") == ASSURANCE_WORK_QUEUE_FORMAT
        and isinstance(binding.get("baseline_id"), str)
        and bool(binding.get("baseline_id"))
        and isinstance(binding.get("analysis_schema_version"), str)
        and bool(binding.get("analysis_schema_version"))
        and re.fullmatch(
            r"[0-9a-f]{64}",
            str(binding.get("analysis_state_sha256", "")),
        )
        and isinstance(summary, dict)
        and set(summary)
        == {
            "total",
            "actionable",
            "automation_eligible",
            "implementation_ready",
            "execution_ready",
            "by_state",
        }
        and isinstance(items, list)
        and len(items) <= 1_000_000
        and isinstance(queue.get("notice"), str)
        and bool(queue.get("notice"))
        and isinstance(integrity, dict)
        and set(integrity) == {"algorithm", "canonicalization", "content_sha256"}
    ):
        return False

    item_fields = {
        "finding_id",
        "obligation_id",
        "priority",
        "component",
        "state",
        "actionable",
        "automation_eligible",
        "next_action_id",
        "blockers",
        "latest_execution_id",
        "latest_execution_status",
    }
    identifiers: list[str] = []
    for item in items:
        if not isinstance(item, dict) or set(item) != item_fields:
            return False
        state = item.get("state")
        identifier = item.get("finding_id")
        blockers = item.get("blockers")
        if not (
            isinstance(identifier, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", identifier)
            and all(
                isinstance(item.get(name), str)
                for name in (
                    "obligation_id",
                    "priority",
                    "component",
                    "latest_execution_id",
                    "latest_execution_status",
                )
            )
            and state in ASSURANCE_WORK_STATES
            and type(item.get("actionable")) is bool
            and item.get("actionable") == (state != "resolved")
            and type(item.get("automation_eligible")) is bool
            and item.get("automation_eligible")
            == (state in {"ready_for_implementation", "ready_for_execution"})
            and item.get("next_action_id") == _WORK_STATE_ACTION[state]
            and isinstance(blockers, list)
            and len(blockers) <= 100
            and all(isinstance(value, str) and bool(value) for value in blockers)
        ):
            return False
        identifiers.append(identifier)
    if len(identifiers) != len(set(identifiers)):
        return False

    by_state = summary.get("by_state")
    if not isinstance(by_state, dict) or not set(by_state) <= set(
        ASSURANCE_WORK_STATES
    ):
        return False
    if not all(type(value) is int and value >= 0 for value in by_state.values()):
        return False
    actual_by_state = dict(sorted(Counter(item["state"] for item in items).items()))
    expected_summary = {
        "total": len(items),
        "actionable": sum(item["actionable"] for item in items),
        "automation_eligible": sum(item["automation_eligible"] for item in items),
        "implementation_ready": actual_by_state.get("ready_for_implementation", 0),
        "execution_ready": actual_by_state.get("ready_for_execution", 0),
        "by_state": actual_by_state,
    }
    return summary == expected_summary


def verify_assurance_work_queue(
    queue: dict[str, Any], *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Verify queue integrity and, when supplied, its exact analysis projection."""

    check_names = (
        "format",
        "structure",
        "content_integrity",
        "baseline",
        "schema",
        "analysis_state",
        "semantic_projection",
    )
    checks: dict[str, bool | None] = {name: None for name in check_names}
    errors: list[dict[str, str]] = []

    def reject(code: str, message: str, path: str) -> None:
        errors.append({"code": code, "message": message, "path": path})

    checks["format"] = queue.get("format") == ASSURANCE_WORK_QUEUE_FORMAT
    if not checks["format"]:
        reject(
            "assurance_work_queue.format",
            "Assurance work queue format is missing or unsupported.",
            "format",
        )

    binding = queue.get("binding")
    summary = queue.get("summary")
    integrity = queue.get("integrity")
    structure_valid = _work_queue_structure_valid(queue)
    checks["structure"] = structure_valid
    if not structure_valid:
        reject(
            "assurance_work_queue.structure",
            "Assurance work queue is missing required provenance, binding, content, or integrity fields.",
            "",
        )

    expected_digest = (
        str(integrity.get("content_sha256", "")).lower()
        if isinstance(integrity, dict)
        else ""
    )
    integrity_valid = bool(
        isinstance(integrity, dict)
        and integrity.get("algorithm") == "sha256"
        and integrity.get("canonicalization") == "json-sort-keys-compact-utf8"
        and re.fullmatch(r"[0-9a-f]{64}", expected_digest)
        and expected_digest == _work_queue_content_sha256(queue)
    )
    checks["content_integrity"] = integrity_valid
    if not integrity_valid:
        reject(
            "assurance_work_queue.integrity",
            "Assurance work queue content digest is missing, malformed, or does not match.",
            "integrity.content_sha256",
        )

    if analysis is not None and isinstance(binding, dict):
        checks["baseline"] = str(binding.get("baseline_id", "")) == str(
            analysis.get("project", {}).get("baseline", {}).get("id", "")
        )
        checks["schema"] = str(binding.get("analysis_schema_version", "")) == str(
            analysis.get("schema_version", "")
        )
        checks["analysis_state"] = str(
            binding.get("analysis_state_sha256", "")
        ).lower() == canonical_json_sha256(analysis)
        expected = assurance_work_queue(copy.deepcopy(analysis))
        semantic_fields = ("format", "binding", "summary", "items", "notice")
        checks["semantic_projection"] = all(
            queue.get(name) == expected.get(name) for name in semantic_fields
        )
        for name, message, path in (
            (
                "baseline",
                "Queue baseline does not match the supplied analysis.",
                "binding.baseline_id",
            ),
            (
                "schema",
                "Queue schema version does not match the supplied analysis.",
                "binding.analysis_schema_version",
            ),
            (
                "analysis_state",
                "Queue analysis-state digest does not match the supplied analysis.",
                "binding.analysis_state_sha256",
            ),
            (
                "semantic_projection",
                "Queue content is not the deterministic projection of the supplied analysis.",
                "items",
            ),
        ):
            if checks[name] is False:
                reject(f"assurance_work_queue.{name}", message, path)

    failed_checks = [name for name, value in checks.items() if value is False]
    unchecked_checks = [name for name, value in checks.items() if value is None]
    binding_requested = analysis is not None
    binding_checked = binding_requested and all(
        checks[name] is not None
        for name in ("baseline", "schema", "analysis_state", "semantic_projection")
    )
    local_valid = all(
        checks[name] is True for name in ("format", "structure", "content_integrity")
    )
    valid = not failed_checks and (not binding_requested or binding_checked)
    if not local_valid:
        status = "invalid"
    elif valid:
        status = "matched" if binding_requested else "valid_binding_not_checked"
    else:
        status = "mismatched" if binding_requested and binding_checked else "invalid"
    return {
        "format": ASSURANCE_WORK_QUEUE_VERIFICATION_FORMAT,
        "verifier": {"name": "PySFMEA", "version": __version__},
        "path": "<memory>",
        "valid": valid,
        "status": status,
        "binding_requested": binding_requested,
        "binding_checked": binding_checked,
        "checks": checks,
        "failed_checks": failed_checks,
        "unchecked_checks": unchecked_checks,
        "errors": errors,
        "queue_format": str(queue.get("format", "")),
        "content_sha256": _work_queue_content_sha256(queue),
        "binding": copy.deepcopy(binding) if isinstance(binding, dict) else {},
        "summary": copy.deepcopy(summary) if isinstance(summary, dict) else {},
        "notice": (
            "Integrity and binding checks detect unreconciled queue changes and staleness; "
            "they do not authenticate an author, approve work, or authorize test execution."
        ),
    }


def verify_assurance_work_queue_file(
    source: str | Path, *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Load and verify a bounded, regular assurance work-queue JSON file."""

    path, queue, _size = load_bounded_json_file(
        source,
        label="assurance work queue",
        max_bytes=MAX_ASSURANCE_WORK_QUEUE_BYTES,
        max_depth=MAX_ASSURANCE_JSON_DEPTH,
        max_nodes=MAX_ASSURANCE_WORK_QUEUE_JSON_NODES,
    )
    if not isinstance(queue, dict):
        raise ValueError("assurance work queue root must be an object")
    verdict = verify_assurance_work_queue(queue, analysis=analysis)
    verdict["path"] = str(path)
    return verdict


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
        if isinstance(value, dict) and value.get("source_status", "active") == "active"
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
    cardinality_gaps = sum(
        len(by_finding.get(finding_id, [])) != 1 for finding_id in accepted_ids
    )
    ready_findings = sum(
        len(by_finding.get(finding_id, [])) == 1
        and _planning_ready(by_finding[finding_id][0])
        for finding_id in accepted_ids
    )
    terminal_findings = sum(
        len(by_finding.get(finding_id, [])) == 1
        and by_finding[finding_id][0].get("assurance_status")
        in TERMINAL_ASSURANCE_STATUSES
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
        value for value in register.get("executions", []) if isinstance(value, dict)
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
    work_queue_summary = assurance_work_queue(analysis)["summary"]
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
        "work_queue": work_queue_summary,
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
        (
            value
            for value in register["obligations"]
            if value.get("id") == obligation_id
        ),
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
        current_status == "verified"
        and obligation.get("evidence_status") == "sufficient"
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
    "work_state",
    "automation_eligible",
    "next_action_id",
    "work_blockers",
    "assurance_status",
    "evidence_status",
    "planning_gaps",
    "control_review_questions",
    "direct_callers",
    "static_upstream_paths",
    "cascade_path_inventory_complete",
    "cascade_path_inventory_emitted",
    "cascade_path_inventory_limitations",
    "cascade_notice",
    "citation_ids",
    "reviewer",
    "owner",
]


def _flat_row(
    value: dict[str, Any], work: dict[str, Any] | None = None
) -> dict[str, Any]:
    automation = value.get("automation", {})
    work = work or {}
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
        "acceptance_criteria": " | ".join(
            _text_list(value.get("acceptance_criteria", []))
        ),
        "proposed_test_path": automation.get("proposed_test_path", ""),
        "command_argv": " ".join(_text_list(automation.get("command_argv", []))),
        "implementation_status": automation.get("implementation_status", ""),
        "work_state": work.get("state", ""),
        "automation_eligible": work.get("automation_eligible", ""),
        "next_action_id": work.get("next_action_id", ""),
        "work_blockers": " | ".join(_text_list(work.get("blockers", []))),
        "assurance_status": value.get("assurance_status", ""),
        "evidence_status": value.get("evidence_status", ""),
        "planning_gaps": " | ".join(_text_list(value.get("planning_gaps", []))),
        "control_review_questions": " | ".join(
            _text_list(value.get("control_review_questions", []))
        ),
        "direct_callers": " | ".join(
            _text_list(value.get("cascade_context", {}).get("direct_callers", []))
        ),
        "static_upstream_paths": " | ".join(
            " -> ".join(_text_list(path))
            for path in value.get("cascade_context", {}).get(
                "static_upstream_paths", []
            )
            if isinstance(path, list)
        ),
        "cascade_path_inventory_complete": value.get("cascade_context", {})
        .get("static_path_analysis", {})
        .get("complete_within_static_call_model", ""),
        "cascade_path_inventory_emitted": value.get("cascade_context", {})
        .get("static_path_analysis", {})
        .get("emitted_paths", ""),
        "cascade_path_inventory_limitations": " | ".join(
            _text_list(
                value.get("cascade_context", {})
                .get("static_path_analysis", {})
                .get("limitations", [])
            )
        ),
        "cascade_notice": value.get("cascade_context", {}).get("notice", ""),
        "citation_ids": " | ".join(_text_list(value.get("citation_ids", []))),
        "reviewer": value.get("review", {}).get("reviewer", ""),
        "owner": value.get("review", {}).get("owner", ""),
    }


def assurance_register_document(analysis: dict[str, Any]) -> dict[str, Any]:
    """Build the deterministic machine-readable assurance register projection."""

    register = ensure_assurance_register(analysis)
    return {
        **copy.deepcopy(register),
        "progress": assurance_progress(analysis),
        "work_queue": assurance_work_queue(analysis),
    }


def verify_assurance_register(
    document: dict[str, Any],
    *,
    analysis: dict[str, Any],
    standalone_work_queue: dict[str, Any],
) -> dict[str, Any]:
    """Reconcile the full register and its two queue representations with analysis."""

    expected = assurance_register_document(copy.deepcopy(analysis))
    actual_queue = document.get("work_queue")
    structure_valid = bool(
        set(document) == set(expected)
        and isinstance(document.get("obligations"), list)
        and isinstance(document.get("executions"), list)
        and isinstance(document.get("evidence_artifacts"), list)
        and isinstance(document.get("progress"), dict)
        and isinstance(actual_queue, dict)
    )
    actual_without_queue = dict(document)
    actual_without_queue.pop("work_queue", None)
    expected_without_queue = dict(expected)
    expected_without_queue.pop("work_queue", None)
    semantic_projection = actual_without_queue == expected_without_queue
    embedded_verification = (
        verify_assurance_work_queue(actual_queue, analysis=analysis)
        if isinstance(actual_queue, dict)
        else None
    )
    embedded_work_queue = bool(embedded_verification and embedded_verification["valid"])
    standalone_consistency = bool(
        isinstance(actual_queue, dict) and actual_queue == standalone_work_queue
    )
    checks = {
        "structure": structure_valid,
        "semantic_projection": semantic_projection,
        "embedded_work_queue": embedded_work_queue,
        "standalone_work_queue_consistency": standalone_consistency,
    }
    messages = {
        "structure": "Assurance register structure does not match the current projection contract.",
        "semantic_projection": "Assurance register content is not the deterministic projection of packaged analysis.",
        "embedded_work_queue": "Embedded work queue failed integrity or analysis reconciliation.",
        "standalone_work_queue_consistency": "Embedded and standalone work queues differ.",
    }
    errors = [
        {
            "code": f"assurance_register.{name}",
            "message": messages[name],
            "path": "work_queue" if "work_queue" in name else "",
        }
        for name, passed in checks.items()
        if not passed
    ]
    return {
        "format": ASSURANCE_REGISTER_VERIFICATION_FORMAT,
        "valid": all(checks.values()),
        "checks": checks,
        "errors": errors,
        "obligation_count": len(document.get("obligations", []))
        if isinstance(document.get("obligations"), list)
        else 0,
        "notice": (
            "Register reconciliation establishes deterministic consistency with packaged "
            "analysis, not verification sufficiency, approval, or risk acceptance."
        ),
    }


def export_assurance_register(
    analysis: dict[str, Any], destination: str | Path, *, format: str = "json"
) -> Path:
    """Export the executable assurance checklist or focused work queue."""

    if format not in {"json", "work-json", "csv", "markdown"}:
        raise ValueError("assurance format must be json, work-json, csv, or markdown")
    register = ensure_assurance_register(analysis)
    work_queue = assurance_work_queue(analysis)
    work_by_obligation = {
        str(value.get("obligation_id", "")): value
        for value in work_queue["items"]
        if value.get("obligation_id")
    }
    if format == "work-json":
        return atomic_publish_text(
            destination,
            json.dumps(work_queue, indent=2, ensure_ascii=False) + "\n",
            label="assurance work queue JSON export",
        )
    if format == "json":
        payload = assurance_register_document(analysis)
        return atomic_publish_text(
            destination,
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            label="assurance register JSON export",
        )
    if format == "csv":
        handle = io.StringIO(newline="")
        writer = csv.DictWriter(handle, fieldnames=ASSURANCE_CSV_FIELDS)
        writer.writeheader()
        for value in register.get("obligations", []):
            writer.writerow(
                _flat_row(value, work_by_obligation.get(str(value.get("id", ""))))
            )
        return atomic_publish_text(
            destination,
            handle.getvalue(),
            encoding="utf-8-sig",
            label="assurance register CSV export",
        )
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
        "| Obligation | Finding | Component | Work state | Next action | Method | Status | Evidence | Proposed test |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for value in register.get("obligations", []):
        row = _flat_row(value, work_by_obligation.get(str(value.get("id", ""))))
        cells = [
            row["id"],
            row["finding_id"],
            row["component"],
            row["work_state"],
            row["next_action_id"],
            row["verification_method"],
            row["assurance_status"],
            row["evidence_status"],
            row["proposed_test_path"],
        ]
        lines.append(
            "| " + " | ".join(str(cell).replace("|", "\\|") for cell in cells) + " |"
        )
    return atomic_publish_text(
        destination,
        "\n".join(lines) + "\n",
        label="assurance register Markdown export",
    )


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
    _expected_manifest_sha256: str = "",
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
        raise ValueError(
            "assurance scaffold owner must be at most 200 printable characters"
        )
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
            "scaffold_contracts_sha256": _scaffold_contracts_sha256(contract_snapshot),
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
import math
from pathlib import Path

import pytest

MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_DEPTH = 100
MAX_MANIFEST_NODES = 500_000


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite number: {value}")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite number")
    return parsed


def _validate_structure(payload: object) -> None:
    nodes = 0
    stack = [(payload, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if depth > MAX_MANIFEST_DEPTH or nodes > MAX_MANIFEST_NODES:
            raise RuntimeError(
                "assurance-manifest.json exceeds its bounded JSON structure limits; "
                "regenerate the scaffold from the governed analysis"
            )
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)


def _load_manifest() -> dict:
    path = Path(__file__).with_name("assurance-manifest.json")
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(
            "assurance-manifest.json must be a regular non-symbolic-link file; "
            "regenerate the scaffold from the governed analysis"
        )
    try:
        with path.open("rb") as source_file:
            raw = source_file.read(MAX_MANIFEST_BYTES + 1)
    except OSError as exc:
        raise RuntimeError(
            "assurance-manifest.json could not be read safely; regenerate the scaffold "
            "from the governed analysis"
        ) from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        raise RuntimeError(
            f"assurance-manifest.json exceeds the {MAX_MANIFEST_BYTES}-byte collection "
            "limit; inspect or regenerate the scaffold"
        )
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise RuntimeError(
            "assurance-manifest.json must be valid bounded UTF-8 JSON with "
            "unambiguous objects and finite numbers; regenerate the scaffold from the "
            "governed analysis"
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeError(
            "assurance-manifest.json root must be an object; regenerate the scaffold "
            "from the governed analysis"
        )
    _validate_structure(payload)
    if payload.get("format") != "pysfmea-pytest-assurance-scaffold-6":
        raise RuntimeError(
            "assurance-manifest.json has an unsupported scaffold format; regenerate it "
            "from the governed analysis"
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
    obligations = payload.get("obligations")
    if not isinstance(obligations, list) or not obligations or not all(
        isinstance(value, dict) and value.get("id") for value in obligations
    ):
        raise RuntimeError(
            "assurance-manifest.json has no valid obligation list; regenerate the "
            "scaffold from the governed analysis"
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
            _replacement_verification, replacement_manifest = (
                _require_untouched_scaffold(
                    analysis,
                    path,
                    operation="replacement",
                )
            )
            replacement_digest = str(
                replacement_manifest.get("manifest_sha256", "")
            ).lower()
            if (
                _expected_manifest_sha256
                and replacement_digest != _expected_manifest_sha256.lower()
            ):
                raise ValueError(
                    "assurance scaffold changed after guarded refresh verification; "
                    "inspect the queue and retry without overwriting concurrent work"
                )
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


def _verify_pytest_scaffold_snapshot(
    analysis: dict[str, Any], source: str | Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify a scaffold and return the exact manifest snapshot that was checked.

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
            manifest = _read_assurance_json_object(
                manifest_path,
                label="assurance scaffold manifest",
            )
            readable = True
        except (OSError, ValueError) as exc:
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
            and value.get("disposition") in {"accepted", "rejected", "unreviewed"}
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
        _scaffold_contracts_sha256(contract_snapshot) if contract_snapshot_valid else ""
    )
    contract_snapshot_integrity = bool(
        snapshot_digest
        and snapshot_digest == str(binding.get("scaffold_contracts_sha256", "")).lower()
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
                        (current_record or previous_record or {}).get("finding_id", "")
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
        "scaffold_contracts_sha256": _scaffold_contracts_sha256(current_contracts),
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
            regular_target = target.is_file() and not target.is_symlink()
            if regular_target:
                try:
                    actual = _sha256_assurance_file_bounded(target)
                except (OSError, ValueError) as exc:
                    add(
                        "scaffold.generated_file_unreadable",
                        f"Cannot read generated starting file {name}: {exc}",
                        "information",
                    )
            unchanged = bool(expected and actual == expected)
            generated_files.append(
                {
                    "path": str(name),
                    "exists": regular_target,
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
    retirement_present = os.path.lexists(retirement_path)
    retirement_record: dict[str, Any] = {}
    retirement_valid = not retirement_present
    if retirement_present:
        try:
            retirement_record = _read_assurance_json_object(
                retirement_path,
                label="retirement record",
            )
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
            recorded_archive = (
                Path(str(retirement_record.get("archive_path", "")))
                .expanduser()
                .resolve()
            )
            recorded_current = retirement_record.get("current_analysis", {})
            retirement_valid = bool(
                retirement_record.get("format")
                == "pysfmea-assurance-scaffold-retirement-1"
                and retirement_record.get("reason")
                == "selection_no_longer_matches_pending_obligations"
                and len(retirement_digest) == 64
                and retirement_digest.lower() == actual_retirement_digest
                and retirement_record.get("queue") == supplied_queue
                and retirement_record.get("previous_manifest_sha256") == supplied_digest
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
                and isinstance(retirement_record.get("contract_change_summary"), dict)
                and isinstance(retirement_record.get("contract_changes"), list)
            )
        except (OSError, ValueError):
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
    verification = {
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
    return verification, manifest


def verify_pytest_scaffold(
    analysis: dict[str, Any], source: str | Path
) -> dict[str, Any]:
    """Verify scaffold integrity and its binding to a governed analysis state."""

    verification, _manifest = _verify_pytest_scaffold_snapshot(analysis, source)
    return verification


def _require_untouched_scaffold(
    analysis: dict[str, Any], path: Path, *, operation: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return one verified snapshot when preservation-sensitive work is safe."""

    verification, manifest = _verify_pytest_scaffold_snapshot(analysis, path)
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
    return verification, manifest


def refresh_pytest_scaffold(analysis: dict[str, Any], destination: str | Path) -> Path:
    """Safely regenerate an untouched scaffold using its governed selection and identity."""

    path = Path(destination).expanduser().absolute()
    _verification, manifest = _require_untouched_scaffold(
        analysis,
        path,
        operation="refresh",
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
        _expected_manifest_sha256=str(manifest.get("manifest_sha256", "")),
    )


def archive_pytest_scaffold(
    analysis: dict[str, Any],
    source: str | Path,
    destination: str | Path | None = None,
) -> Path:
    """Atomically archive an untouched queue whose selection is now empty."""

    path = Path(source).expanduser().absolute()
    verification, manifest = _require_untouched_scaffold(
        analysis,
        path,
        operation="archive",
    )
    if verification.get("lifecycle") != "retirement_candidate":
        raise ValueError(
            "assurance scaffold archive requires a retirement candidate whose current "
            "selection contains no pending obligations"
        )
    queue_id = str(verification.get("queue", {}).get("id", "queue"))
    timestamp = utc_now().replace("+00:00", "Z").replace("-", "").replace(":", "")
    archive = (
        Path(destination).expanduser().absolute()
        if destination is not None
        else path.parent / ".sfmea-archive" / f"{path.name}-{queue_id}-{timestamp}"
    )
    if archive == path or archive.is_relative_to(path):
        raise ValueError(
            "assurance scaffold archive destination must be outside the queue"
        )
    if path.anchor.casefold() != archive.anchor.casefold():
        raise ValueError(
            "assurance scaffold archive destination must be on the same filesystem volume"
        )
    if os.path.lexists(archive):
        raise ValueError(
            f"assurance scaffold archive destination already exists: {archive}"
        )
    retirement_path = path / "retirement-record.json"
    if os.path.lexists(retirement_path):
        raise ValueError(
            "assurance scaffold already contains a retirement record; inspect it manually"
        )
    archive.parent.mkdir(parents=True, exist_ok=True)
    current_verification, current_manifest = _require_untouched_scaffold(
        analysis,
        path,
        operation="archive",
    )
    if str(current_manifest.get("manifest_sha256", "")).lower() != str(
        manifest.get("manifest_sha256", "")
    ).lower():
        raise ValueError(
            "assurance scaffold changed after guarded archive verification; inspect the "
            "queue and retry without overwriting concurrent work"
        )
    verification = current_verification
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
