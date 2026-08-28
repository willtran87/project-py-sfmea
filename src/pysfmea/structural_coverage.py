"""Requirements-based structural coverage and MC/DC evidence validation.

This module validates supplied test vectors and independence pairs.  It does not
instrument code or claim that a coverage tool observed execution.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from .governed_artifact import (
    analysis_binding,
    bounded_text,
    load_json,
    publish_json,
    seal,
    unique_text_list,
    verify_analysis_binding,
    verify_seal,
)
from .integrity import canonical_json_sha256
from .model import utc_now

COVERAGE_SOURCE_FORMAT = "pysfmea-structural-coverage-source-1"
COVERAGE_ASSESSMENT_FORMAT = "pysfmea-structural-coverage-assessment-1"
COVERAGE_VERIFICATION_FORMAT = "pysfmea-structural-coverage-verification-1"
MAX_RECORDS = 100_000


def structural_coverage_template(
    analysis: dict[str, Any], *, authority: str
) -> dict[str, Any]:
    result = {
        "format": COVERAGE_SOURCE_FORMAT,
        "generated_at": utc_now(),
        "authority": bounded_text(authority, "coverage authority"),
        "analysis_binding": analysis_binding(analysis),
        "coverage_basis": {
            "standard": "project-selected requirements-based structural coverage basis",
            "criticality_basis": "replace-with-approved-criticality-and-coverage-objective",
            "measurement_tool": "replace-with-qualified-coverage-tool-and-version",
            "measurement_configuration_sha256": "0" * 64,
            "object_code_coverage_basis": "not_assessed",
        },
        "requirements": [],
        "decisions": [],
        "deactivated_code": [],
        "analysis_exclusions": [],
        "evidence_refs": [],
        "notice": (
            "Populate requirements, executable decisions, observed test vectors, MC/DC "
            "independence pairs, deactivated code, exclusions, and immutable evidence."
        ),
    }
    return seal(result)


def _source(value: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
    result = verify_seal(value, label="structural coverage source", format_value=COVERAGE_SOURCE_FORMAT)
    required = {
        "format", "generated_at", "authority", "analysis_binding", "coverage_basis",
        "requirements", "decisions", "deactivated_code", "analysis_exclusions",
        "evidence_refs", "notice", "content_sha256",
    }
    if set(result) != required:
        raise ValueError("structural coverage source fields are invalid")
    bounded_text(result["authority"], "coverage authority")
    verify_analysis_binding(result["analysis_binding"], analysis)
    basis = result["coverage_basis"]
    basis_fields = {
        "standard", "criticality_basis", "measurement_tool",
        "measurement_configuration_sha256", "object_code_coverage_basis",
    }
    if not isinstance(basis, dict) or set(basis) != basis_fields:
        raise ValueError("coverage basis fields are invalid")
    for name in basis_fields:
        bounded_text(basis[name], f"coverage basis {name}")
    if len(str(basis["measurement_configuration_sha256"])) != 64:
        raise ValueError("coverage measurement configuration digest is invalid")
    unique_text_list(result["evidence_refs"], "coverage evidence refs")
    unique_text_list(result["analysis_exclusions"], "coverage exclusions")
    requirements = result["requirements"]
    decisions = result["decisions"]
    deactivated = result["deactivated_code"]
    if any(not isinstance(items, list) or len(items) > MAX_RECORDS for items in (requirements, decisions, deactivated)):
        raise ValueError("coverage record collections are invalid")
    req_fields = {"id", "text", "criticality", "verification_method", "acceptance_criteria", "evidence_refs"}
    req_ids: list[str] = []
    for item in requirements:
        if not isinstance(item, dict) or set(item) != req_fields:
            raise ValueError("coverage requirement fields are invalid")
        req_ids.append(bounded_text(item["id"], "requirement id"))
        for name in ("text", "criticality", "verification_method", "acceptance_criteria"):
            bounded_text(item[name], f"requirement {name}")
        unique_text_list(item["evidence_refs"], "requirement evidence refs")
    if len(req_ids) != len(set(req_ids)):
        raise ValueError("coverage requirement ids must be unique")
    component_ids = {str(item.get("id")) for item in analysis.get("components", []) if isinstance(item, dict)}
    decision_ids: list[str] = []
    for decision in decisions:
        fields = {"id", "component_id", "source_ref", "requirement_ids", "conditions", "tests", "independence_pairs", "evidence_ref"}
        if not isinstance(decision, dict) or set(decision) != fields:
            raise ValueError("coverage decision fields are invalid")
        decision_ids.append(bounded_text(decision["id"], "decision id"))
        component_id = bounded_text(decision["component_id"], "decision component id")
        if component_id not in component_ids:
            raise ValueError(f"decision {decision['id']} references an unknown analysis component")
        bounded_text(decision["source_ref"], "decision source ref")
        bounded_text(decision["evidence_ref"], "decision evidence ref")
        linked_requirements = unique_text_list(decision["requirement_ids"], "decision requirement ids")
        if not linked_requirements or not set(linked_requirements) <= set(req_ids):
            raise ValueError(f"decision {decision['id']} has unresolved requirements")
        conditions = decision["conditions"]
        tests = decision["tests"]
        pairs = decision["independence_pairs"]
        if not isinstance(conditions, list) or not conditions or len(conditions) > 1000:
            raise ValueError("decision conditions are invalid")
        condition_ids: list[str] = []
        for condition in conditions:
            if not isinstance(condition, dict) or set(condition) != {"id", "expression"}:
                raise ValueError("decision condition fields are invalid")
            condition_ids.append(bounded_text(condition["id"], "condition id"))
            bounded_text(condition["expression"], "condition expression")
        if len(condition_ids) != len(set(condition_ids)):
            raise ValueError("condition ids must be unique within a decision")
        if not isinstance(tests, list) or len(tests) > MAX_RECORDS:
            raise ValueError("decision tests are invalid")
        test_map: dict[str, dict[str, Any]] = {}
        for test in tests:
            if not isinstance(test, dict) or set(test) != {"id", "condition_values", "decision_outcome", "evidence_ref"}:
                raise ValueError("coverage test fields are invalid")
            test_id = bounded_text(test["id"], "coverage test id")
            values = test["condition_values"]
            if not isinstance(values, dict) or set(values) != set(condition_ids) or any(type(value) is not bool for value in values.values()):
                raise ValueError(f"test {test_id} does not provide a Boolean value for every condition")
            if type(test["decision_outcome"]) is not bool:
                raise ValueError("coverage decision outcome must be Boolean")
            bounded_text(test["evidence_ref"], "coverage test evidence ref")
            if test_id in test_map:
                raise ValueError("coverage test ids must be unique within a decision")
            test_map[test_id] = test
        if not isinstance(pairs, list) or len(pairs) > MAX_RECORDS:
            raise ValueError("MC/DC independence pairs are invalid")
        pair_conditions: list[str] = []
        for pair in pairs:
            if not isinstance(pair, dict) or set(pair) != {"condition_id", "test_a_id", "test_b_id", "evidence_ref"}:
                raise ValueError("MC/DC pair fields are invalid")
            condition_id = bounded_text(pair["condition_id"], "MC/DC pair condition id")
            if condition_id not in condition_ids:
                raise ValueError("MC/DC pair references an unknown condition")
            test_a = test_map.get(bounded_text(pair["test_a_id"], "MC/DC pair test A"))
            test_b = test_map.get(bounded_text(pair["test_b_id"], "MC/DC pair test B"))
            bounded_text(pair["evidence_ref"], "MC/DC pair evidence ref")
            if test_a is None or test_b is None or test_a is test_b:
                raise ValueError("MC/DC pair references missing or identical tests")
            changed = {name for name in condition_ids if test_a["condition_values"][name] != test_b["condition_values"][name]}
            if changed != {condition_id} or test_a["decision_outcome"] == test_b["decision_outcome"]:
                raise ValueError(
                    f"MC/DC pair for {condition_id} does not independently change only that condition and the decision outcome"
                )
            pair_conditions.append(condition_id)
        if len(pair_conditions) != len(set(pair_conditions)):
            raise ValueError("a decision must declare at most one canonical pair per condition")
    if len(decision_ids) != len(set(decision_ids)):
        raise ValueError("coverage decision ids must be unique")
    deactivated_fields = {"id", "source_ref", "rationale", "authority", "evidence_ref"}
    deactivated_ids: list[str] = []
    for item in deactivated:
        if not isinstance(item, dict) or set(item) != deactivated_fields:
            raise ValueError("deactivated-code fields are invalid")
        deactivated_ids.append(bounded_text(item["id"], "deactivated-code id"))
        for name in deactivated_fields - {"id"}:
            bounded_text(item[name], f"deactivated-code {name}")
    if len(deactivated_ids) != len(set(deactivated_ids)):
        raise ValueError("deactivated-code ids must be unique")
    return copy.deepcopy(result)


def seal_structural_coverage_source(
    analysis: dict[str, Any], source: str | Path, destination: str | Path
) -> Path:
    value = load_json(source, label="structural coverage source")
    value = seal(value)
    validated = _source(value, analysis)
    return publish_json(validated, destination)


def structural_coverage_assessment(
    analysis: dict[str, Any], source: str | Path | dict[str, Any]
) -> dict[str, Any]:
    raw = load_json(source, label="structural coverage source") if not isinstance(source, dict) else source
    value = _source(raw, analysis)
    decisions: list[dict[str, Any]] = []
    requirement_decisions: dict[str, list[bool]] = {
        item["id"]: [] for item in value["requirements"]
    }
    total_conditions = covered_conditions = 0
    for item in value["decisions"]:
        condition_ids = [condition["id"] for condition in item["conditions"]]
        pair_ids = {pair["condition_id"] for pair in item["independence_pairs"]}
        full_mcdc = bool(condition_ids) and pair_ids == set(condition_ids)
        total_conditions += len(condition_ids)
        covered_conditions += len(pair_ids)
        for requirement_id in item["requirement_ids"]:
            requirement_decisions[requirement_id].append(full_mcdc)
        decisions.append({
            "id": item["id"],
            "decision_covered": bool(item["tests"]),
            "condition_count": len(condition_ids),
            "mcdc_condition_ids": sorted(pair_ids),
            "uncovered_condition_ids": sorted(set(condition_ids) - pair_ids),
            "mcdc_complete": full_mcdc,
        })
    req_ids = {item["id"] for item in value["requirements"]}
    covered_requirements = {
        identifier
        for identifier, results in requirement_decisions.items()
        if results and all(results)
    }
    basis = value["coverage_basis"]
    measurement_ready = (
        not str(basis["measurement_tool"]).startswith("replace-")
        and not str(basis["criticality_basis"]).startswith("replace-")
        and basis["measurement_configuration_sha256"] != "0" * 64
        and basis["object_code_coverage_basis"] in {"not_required", "required_complete"}
        and bool(value["evidence_refs"])
    )
    complete = bool(req_ids) and bool(decisions) and measurement_ready and all(item["mcdc_complete"] for item in decisions) and covered_requirements == req_ids
    assessment = {
        "format": COVERAGE_ASSESSMENT_FORMAT,
        "generated_at": value["generated_at"],
        "source_sha256": value["content_sha256"],
        "analysis_binding": copy.deepcopy(value["analysis_binding"]),
        "decisions": decisions,
        "summary": {
            "requirements": len(req_ids),
            "requirements_covered": len(covered_requirements),
            "decisions": len(decisions),
            "decisions_covered": sum(item["decision_covered"] for item in decisions),
            "conditions": total_conditions,
            "mcdc_conditions_covered": covered_conditions,
            "uncovered_requirement_ids": sorted(req_ids - covered_requirements),
            "deactivated_code_records": len(value["deactivated_code"]),
            "measurement_evidence_complete": measurement_ready,
            "complete": complete,
        },
        "notice": "Complete means supplied vectors satisfy unique-cause MC/DC relationships; it is not proof of runtime execution or certification.",
    }
    return seal(assessment)


def verify_structural_coverage_assessment(
    assessment: dict[str, Any], *, analysis: dict[str, Any] | None = None,
    source: dict[str, Any] | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        value = verify_seal(assessment, label="structural coverage assessment", format_value=COVERAGE_ASSESSMENT_FORMAT)
        if analysis is not None:
            verify_analysis_binding(value.get("analysis_binding"), analysis)
        if source is not None:
            if analysis is None:
                raise ValueError("analysis is required for exact source regeneration")
            expected = structural_coverage_assessment(analysis, source)
            if canonical_json_sha256(value) != canonical_json_sha256(expected):
                raise ValueError("assessment does not exactly regenerate from the supplied source")
        complete = bool(value.get("summary", {}).get("complete"))
    except (OSError, ValueError, TypeError) as exc:
        errors.append(str(exc))
        complete = False
    result = {
        "format": COVERAGE_VERIFICATION_FORMAT,
        "valid": not errors,
        "complete": not errors and complete,
        "errors": errors,
        "notice": "Verification establishes integrity and optional exact regeneration only.",
    }
    return seal(result)


def verify_structural_coverage_assessment_file(
    assessment_source: str | Path, *, analysis: dict[str, Any] | None = None,
    source_path: str | Path | None = None,
) -> dict[str, Any]:
    try:
        assessment = load_json(assessment_source, label="structural coverage assessment")
        source = load_json(source_path, label="structural coverage source") if source_path else None
        return verify_structural_coverage_assessment(assessment, analysis=analysis, source=source)
    except (OSError, ValueError, TypeError) as exc:
        return seal({"format": COVERAGE_VERIFICATION_FORMAT, "valid": False, "complete": False, "errors": [str(exc)], "notice": "Verification failed closed."})


def export_structural_coverage_source(value: dict[str, Any], destination: str | Path) -> Path:
    return publish_json(value, destination)


def export_structural_coverage_assessment(value: dict[str, Any], destination: str | Path) -> Path:
    return publish_json(value, destination)
