"""Executable assurance contracts derived from governed SFMEA findings."""

from __future__ import annotations

import copy
import csv
import fnmatch
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from .model import stable_id, utc_now


ASSURANCE_SCHEMA_VERSION = "1.0"
PLANNER_VERSION = "deterministic-verification-planner-1"
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


def _method_for(item: dict[str, Any]) -> tuple[str, str]:
    scanner = item.get("scanner", {})
    rule = str(scanner.get("rule_id", ""))
    failure_class = str(scanner.get("failure_class", ""))
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
    return {
        "method": method,
        "description": f"{verbs.get(method, 'Stimulate')} {trigger or 'the documented failure condition'}.",
        "injection_required": method in {
            "fault_injection_test",
            "concurrency_test",
            "stress_test",
            "security_test",
        },
    }


def _obligation(item: dict[str, Any], baseline_id: str) -> dict[str, Any]:
    review = item.get("review", {})
    scanner = item.get("scanner", {})
    component = item.get("component", {})
    source = item.get("source", {})
    method, method_rationale = _method_for(item)
    finding_id = str(item.get("id", ""))
    obligation_id = stable_id("VO", finding_id, method, PLANNER_VERSION)
    failure_mode = str(review.get("failure_mode") or scanner.get("failure_mode", ""))
    local_effect = str(review.get("local_effect", ""))
    next_effect = str(review.get("next_higher_effect", ""))
    end_effect = str(review.get("end_effect", ""))
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
    return {
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
    baseline_id = str(analysis.get("project", {}).get("baseline", {}).get("id", ""))
    obligations = []
    for item in analysis.get("items", []):
        obligation = _obligation(item, baseline_id)
        old = old_by_id.get(obligation["id"])
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
            if (
                old_fingerprint
                and old_fingerprint != obligation.get("source_fingerprint")
                and obligation.get("assurance_status")
                not in {"candidate", "not_applicable", "retired"}
            ):
                obligation["assurance_status"] = "reopened"
                obligation["evidence_status"] = "stale"
                obligation.setdefault("history", []).append(
                    {
                        "event": "obligation_reopened",
                        "at": utc_now(),
                        "reason": "finding source fingerprint changed",
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

    if status not in ASSURANCE_STATUSES - {"verified", "closed", "accepted_risk"}:
        raise ValueError(
            "assurance-review cannot directly set verified, accepted_risk, or closed; "
            "those states require governed evidence and approval"
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
        path.write_text(json.dumps(register, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return path
    if format == "csv":
        with path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=ASSURANCE_CSV_FIELDS)
            writer.writeheader()
            for value in register.get("obligations", []):
                writer.writerow(_flat_row(value))
        return path
    lines = [
        "# Executable assurance checklist",
        "",
        f"> {register.get('notice', ASSURANCE_NOTICE)}",
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
) -> Path:
    """Create an intentionally failing pytest checklist for selected obligations.

    The scaffold forces each placeholder to remain visible in CI. Replacing a placeholder
    with a meaningful test still does not create evidence until an approved execution is
    captured and independently reviewed.
    """

    if not 1 <= limit <= 1000:
        raise ValueError("assurance scaffold limit must be from 1 through 1000")
    path = Path(destination).expanduser().resolve()
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise ValueError(f"assurance scaffold destination must be an empty directory: {path}")
    register = ensure_assurance_register(analysis)
    selected = []
    for value in register.get("obligations", []):
        if value.get("source_status", "active") != "active":
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
    if not selected:
        raise ValueError(f"no active assurance obligations match scope: {scope}")
    path.mkdir(parents=True, exist_ok=True)
    manifest = {
        "format": "pysfmea-pytest-assurance-scaffold-1",
        "generated_at": utc_now(),
        "baseline_id": register.get("baseline_id", ""),
        "notice": ASSURANCE_NOTICE,
        "obligations": selected,
    }
    (path / "assurance-manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    test_source = '''"""Generated PySFMEA assurance placeholders.

Every case fails intentionally until an engineer implements the recorded stimulus,
oracles, and acceptance criteria. A passing replacement is not assurance evidence until
its approved sandbox execution and independent evidence review are recorded.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


MANIFEST = json.loads(
    Path(__file__).with_name("assurance-manifest.json").read_text(encoding="utf-8")
)


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
    (path / "test_sfmea_assurance.py").write_text(test_source, encoding="utf-8")
    (path / "README.md").write_text(
        "# PySFMEA assurance test scaffold\n\n"
        "These pytest cases fail intentionally. Implement the stimulus, oracles, and "
        "acceptance criteria from `assurance-manifest.json`; do not convert them to empty, "
        "skipped, or assertion-free tests. Run only in an approved sandbox. Passing tests "
        "remain unreviewed execution results until evidence sufficiency is adjudicated.\n",
        encoding="utf-8",
    )
    return path
