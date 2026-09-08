"""ISO/IEC/IEEE 29119-aligned projection of assurance obligations.

This is an original evidence structure and does not reproduce licensed standard text.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .assurance import ensure_assurance_register
from .conformance import standards_catalog
from .governed_artifact import bounded_text, load_json, publish_json, seal, verify_seal
from .integrity import canonical_json_sha256
from .model import utc_now

TEST_DOSSIER_FORMAT = "pysfmea-test-dossier-1"
TEST_DOSSIER_VERIFICATION_FORMAT = "pysfmea-test-dossier-verification-1"

_TECHNIQUES = {
    "property_test": [
        "equivalence_partitioning",
        "boundary_value_analysis",
        "property_based_testing",
    ],
    "integration_test": ["scenario_testing", "interface_testing", "error_guessing"],
    "fault_injection_test": ["fault_injection", "negative_testing", "scenario_testing"],
    "concurrency_test": [
        "state_transition_testing",
        "concurrency_interleaving",
        "boundary_value_analysis",
    ],
    "state_transition_test": ["state_transition_testing", "decision_table_testing"],
    "security_test": ["attack_based_testing", "negative_testing", "interface_testing"],
    "unit_test": ["statement_and_branch_testing", "equivalence_partitioning"],
}


def _valid_case(value: Any) -> bool:
    fields = {
        "id",
        "obligation_id",
        "finding_id",
        "component_id",
        "rule_id",
        "source",
        "risk_priority",
        "test_condition",
        "objective",
        "techniques",
        "technique_selection_rationale",
        "preconditions",
        "stimulus",
        "expected_results",
        "oracle_basis",
        "acceptance_criteria",
        "test_data_requirements",
        "environment_requirements",
        "procedure",
        "keyword_layer",
        "traceability",
        "status",
        "contract_sha256",
    }
    if not isinstance(value, dict) or set(value) != fields:
        return False
    text_fields = (
        "id",
        "obligation_id",
        "finding_id",
        "component_id",
        "rule_id",
        "test_condition",
        "objective",
        "contract_sha256",
    )
    if not all(
        isinstance(value[name], str) and value[name].strip() for name in text_fields
    ):
        return False
    if len(value["contract_sha256"]) != 64 or any(
        character not in "0123456789abcdef" for character in value["contract_sha256"]
    ):
        return False
    list_fields = (
        "techniques",
        "preconditions",
        "oracle_basis",
        "acceptance_criteria",
        "test_data_requirements",
        "environment_requirements",
    )
    if not all(
        isinstance(value[name], list) and len(value[name]) <= 10_000
        for name in list_fields
    ):
        return False
    if not isinstance(value["procedure"], dict) or set(value["procedure"]) != {
        "framework",
        "test_path",
        "test_name",
        "command_argv",
        "network_policy",
        "execution_policy",
    }:
        return False
    if not isinstance(value["procedure"]["command_argv"], list) or not all(
        isinstance(item, str) for item in value["procedure"]["command_argv"]
    ):
        return False
    if (
        not isinstance(value["keyword_layer"], list)
        or len(value["keyword_layer"]) != 5
        or not all(
            isinstance(item, dict)
            and set(item) == {"keyword", "purpose"}
            and all(isinstance(entry, str) and entry.strip() for entry in item.values())
            for item in value["keyword_layer"]
        )
    ):
        return False
    if not isinstance(value["traceability"], dict) or set(value["traceability"]) != {
        "citation_ids",
        "caller_paths",
        "control_model",
    }:
        return False
    if not isinstance(value["status"], dict) or set(value["status"]) != {
        "assurance",
        "implementation",
        "evidence",
        "planning_gaps",
    }:
        return False
    return all(
        isinstance(value[name], dict)
        for name in ("source", "stimulus", "expected_results")
    )


def _techniques(method: str) -> list[str]:
    return list(_TECHNIQUES.get(method, ["scenario_testing", "error_guessing"]))


def _test_case(obligation: dict[str, Any]) -> dict[str, Any]:
    method = str(obligation.get("verification_method", "unit_test"))
    automation = obligation.get("automation", {})
    return {
        "id": f"TC-{obligation['id']}",
        "obligation_id": obligation["id"],
        "finding_id": obligation["finding_id"],
        "component_id": obligation["component_id"],
        "rule_id": obligation["rule_id"],
        "source": obligation["source"],
        "risk_priority": obligation["priority"],
        "test_condition": obligation["failure_condition"],
        "objective": obligation["objective"],
        "techniques": _techniques(method),
        "technique_selection_rationale": obligation.get("method_rationale", ""),
        "preconditions": list(obligation.get("preconditions", [])),
        "stimulus": obligation.get("stimulus", {}),
        "expected_results": obligation.get("expected_results", {}),
        "oracle_basis": list(obligation.get("oracles", [])),
        "acceptance_criteria": list(obligation.get("acceptance_criteria", [])),
        "test_data_requirements": [
            "Retain exact input values, generated examples, seeds, fixtures, and relevant data-classification constraints.",
            "Include nominal, boundary, invalid, missing, repeated, reordered, and corrupted data where applicable.",
        ],
        "environment_requirements": list(obligation.get("required_environment", [])),
        "procedure": {
            "framework": automation.get("framework", "pytest"),
            "test_path": automation.get("proposed_test_path", ""),
            "test_name": automation.get("proposed_test_name", ""),
            "command_argv": automation.get("command_argv", []),
            "network_policy": automation.get("network_policy", "deny_by_default"),
            "execution_policy": automation.get(
                "execution_policy", "approved_sandbox_required"
            ),
        },
        "keyword_layer": [
            {
                "keyword": "arrangeFailureContext",
                "purpose": "Establish the governed preconditions and exact environment.",
            },
            {
                "keyword": "activateFailureStimulus",
                "purpose": "Demonstrate that the intended failure condition was exercised.",
            },
            {
                "keyword": "observeLocalAndSystemEffects",
                "purpose": "Capture local, propagated, degraded, recovery, and prohibited effects.",
            },
            {
                "keyword": "verifyAssuranceCriteria",
                "purpose": "Evaluate every independent oracle and acceptance criterion.",
            },
            {
                "keyword": "retainExecutionEvidence",
                "purpose": "Bind logs, artifacts, environment, coverage or trace evidence, and review.",
            },
        ],
        "traceability": {
            "citation_ids": list(obligation.get("citation_ids", [])),
            "caller_paths": obligation.get("cascade_context", {}).get(
                "static_upstream_paths", []
            ),
            "control_model": obligation.get("detected_control_model", {}),
        },
        "status": {
            "assurance": obligation.get("assurance_status", "candidate"),
            "implementation": automation.get(
                "implementation_status", "not_implemented"
            ),
            "evidence": obligation.get("evidence_status", "missing"),
            "planning_gaps": list(obligation.get("planning_gaps", [])),
        },
        "contract_sha256": obligation.get("provenance", {}).get(
            "contract_sha256", canonical_json_sha256(obligation)
        ),
    }


def test_dossier(analysis: dict[str, Any], *, authority: str) -> dict[str, Any]:
    register = ensure_assurance_register(analysis)
    obligations = [
        item
        for item in register.get("obligations", [])
        if item.get("source_status") == "active"
    ]
    cases = [_test_case(item) for item in obligations]
    technique_counts = {
        technique: sum(technique in case["techniques"] for case in cases)
        for technique in sorted(
            {technique for case in cases for technique in case["techniques"]}
        )
    }
    result = seal(
        {
            "format": TEST_DOSSIER_FORMAT,
            "generated_at": utc_now(),
            "authority": bounded_text(authority, "test dossier authority"),
            "analysis": {
                "content_sha256": analysis.get("content_sha256", ""),
                "state_sha256": canonical_json_sha256(analysis),
                "baseline_id": analysis.get("project", {})
                .get("baseline", {})
                .get("id", ""),
            },
            "standards_basis": [
                {
                    "id": "iso-25010-29119",
                    "role": "ISO/IEC/IEEE 29119-2:2021 test process planning and control",
                },
                {"id": "iso-29119-3-2021", "role": "test documentation package"},
                {
                    "id": "iso-29119-4-2021",
                    "role": "test-design technique selection and coverage",
                },
                {
                    "id": "iso-29119-5-2024",
                    "role": "keyword-driven test representation and exchange",
                },
                {
                    "id": "iso-29119-6-2021",
                    "role": "agile lifecycle tailoring guidance",
                },
            ],
            "policy": {
                "document_control": "content-addressed exact-analysis-bound projection",
                "approval_required": True,
                "independent_oracle_review_required": True,
                "execution_environment": "approved sandbox with exact configuration evidence",
                "completion_rule": "every applicable case executed, reconciled, and independently reviewed; deviations and unresolved anomalies remain visible",
            },
            "plan": {
                "objective": "Verify every active SFMEA failure condition with observable local, propagated, control, degradation, recovery, and safe-state evidence.",
                "population": len(cases),
                "selection_basis": "all active deterministic assurance obligations",
                "agile_tailoring": "Cases retain stable identities and exact analysis bindings so they can be planned per iteration without losing portfolio reconciliation.",
            },
            "test_cases": cases,
            "technique_coverage": technique_counts,
            "completion": {
                "planned": len(cases),
                "implemented": sum(
                    case["status"]["implementation"] == "implemented" for case in cases
                ),
                "evidence_available": sum(
                    case["status"]["evidence"]
                    in {"sufficient", "partial", "collected_unreviewed"}
                    for case in cases
                ),
                "verified": sum(
                    case["status"]["assurance"] in {"verified", "closed"}
                    for case in cases
                ),
                "planning_gaps": sum(
                    bool(case["status"]["planning_gaps"]) for case in cases
                ),
            },
            "claim_boundary": "This original projection supports project use of the ISO/IEC/IEEE 29119 family but is not a copy of licensed requirements and does not establish conformity. Generated cases and keywords remain plans until implemented, executed, evidenced, and independently reviewed.",
        }
    )
    if not verify_test_dossier(result)["valid"]:
        raise ValueError("test dossier failed internal verification")
    return result


def verify_test_dossier(
    value: dict[str, Any], *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    integrity = structure = reconciliation = source_binding = False
    try:
        checked = verify_seal(
            value, label="test dossier", format_value=TEST_DOSSIER_FORMAT
        )
        required = {
            "format",
            "generated_at",
            "authority",
            "analysis",
            "standards_basis",
            "policy",
            "plan",
            "test_cases",
            "technique_coverage",
            "completion",
            "claim_boundary",
            "content_sha256",
        }
        if (
            set(checked) != required
            or not isinstance(checked["test_cases"], list)
            or len(checked["test_cases"]) > 1_000_000
            or not all(_valid_case(item) for item in checked["test_cases"])
        ):
            raise ValueError("test dossier fields are invalid")
        ids = [
            item.get("id") for item in checked["test_cases"] if isinstance(item, dict)
        ]
        if len(ids) != len(checked["test_cases"]) or len(ids) != len(set(ids)):
            raise ValueError("test dossier case identities are invalid")
        catalog_ids = {profile["id"] for profile in standards_catalog()["profiles"]}
        basis_ids = {
            item.get("id")
            for item in checked["standards_basis"]
            if isinstance(item, dict)
        }
        if (
            len(basis_ids) != len(checked["standards_basis"])
            or not basis_ids <= catalog_ids
        ):
            raise ValueError(
                "test dossier standards basis does not resolve to the governed catalog"
            )
        technique_counts = {
            technique: sum(
                technique in case.get("techniques", [])
                for case in checked["test_cases"]
            )
            for technique in sorted(
                {
                    technique
                    for case in checked["test_cases"]
                    for technique in case.get("techniques", [])
                }
            )
        }
        completion = {
            "planned": len(checked["test_cases"]),
            "implemented": sum(
                case.get("status", {}).get("implementation") == "implemented"
                for case in checked["test_cases"]
            ),
            "evidence_available": sum(
                case.get("status", {}).get("evidence")
                in {"sufficient", "partial", "collected_unreviewed"}
                for case in checked["test_cases"]
            ),
            "verified": sum(
                case.get("status", {}).get("assurance") in {"verified", "closed"}
                for case in checked["test_cases"]
            ),
            "planning_gaps": sum(
                bool(case.get("status", {}).get("planning_gaps"))
                for case in checked["test_cases"]
            ),
        }
        reconciliation = (
            checked["technique_coverage"] == technique_counts
            and checked["completion"] == completion
            and checked["plan"].get("population") == len(checked["test_cases"])
        )
        if not reconciliation:
            errors.append(
                "test dossier populations, techniques, or completion do not reconcile"
            )
        source_binding = analysis is None or checked["analysis"] == {
            "content_sha256": analysis.get("content_sha256", ""),
            "state_sha256": canonical_json_sha256(analysis),
            "baseline_id": analysis.get("project", {})
            .get("baseline", {})
            .get("id", ""),
        }
        if not source_binding:
            errors.append("test dossier does not bind the supplied analysis")
        integrity = structure = True
    except (TypeError, ValueError) as exc:
        errors.append(str(exc))
    valid = integrity and structure and reconciliation and source_binding and not errors
    return seal(
        {
            "format": TEST_DOSSIER_VERIFICATION_FORMAT,
            "valid": valid,
            "complete": bool(
                valid
                and value.get("completion", {}).get("planned", 0) > 0
                and value.get("completion", {}).get("verified")
                == value.get("completion", {}).get("planned")
                and value.get("completion", {}).get("planning_gaps") == 0
            ),
            "checks": {
                "content_integrity_and_structure": integrity and structure,
                "population_and_technique_reconciliation": reconciliation,
                "analysis_binding": source_binding,
            },
            "errors": errors,
            "notice": "Verification checks the dossier projection and exact binding, not test execution truth, independent approval, or ISO conformity.",
        }
    )


def export_test_dossier(value: dict[str, Any], destination: str | Path) -> Path:
    return publish_json(value, destination)


def verify_test_dossier_file(
    source: str | Path, *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    try:
        return verify_test_dossier(
            load_json(source, label="test dossier"), analysis=analysis
        )
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": TEST_DOSSIER_VERIFICATION_FORMAT,
                "valid": False,
                "complete": False,
                "checks": {
                    "content_integrity_and_structure": False,
                    "population_and_technique_reconciliation": False,
                    "analysis_binding": False,
                },
                "errors": [str(exc)],
                "notice": "Test dossier verification failed closed.",
            }
        )
