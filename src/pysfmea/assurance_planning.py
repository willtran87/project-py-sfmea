"""Typed deterministic planning policy for verification obligations."""

from __future__ import annotations

from typing import Any

from .interfaces import FindingRecord


def verification_method_for(item: FindingRecord) -> tuple[str, str]:
    """Choose a conservative verification method and explain the selection."""

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


def stimulus_for(method: str, item: FindingRecord) -> dict[str, Any]:
    """Create the explicit stimulus draft for a selected verification method."""

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
    return {
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
