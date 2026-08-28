"""ISO/IEC 25040-aligned quality-evaluation campaign evidence."""

from __future__ import annotations

import copy
import re
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

QUALITY_EVALUATION_SOURCE_FORMAT = "pysfmea-quality-evaluation-source-1"
QUALITY_EVALUATION_ASSESSMENT_FORMAT = "pysfmea-quality-evaluation-assessment-1"
QUALITY_EVALUATION_VERIFICATION_FORMAT = "pysfmea-quality-evaluation-verification-1"
STAGES = ("establish_requirements", "specify_evaluation", "design_evaluation", "execute_evaluation", "conclude_evaluation")
MAX_RECORDS = 100_000


def quality_evaluation_template(analysis: dict[str, Any], *, authority: str) -> dict[str, Any]:
    result = {
        "format": QUALITY_EVALUATION_SOURCE_FORMAT,
        "generated_at": utc_now(),
        "authority": bounded_text(authority, "quality-evaluation authority"),
        "analysis_binding": analysis_binding(analysis),
        "evaluation_context": {"intended_use": "", "stakeholders": [], "quality_model": "", "scope": "", "independence_basis": "", "limitations": [], "decision_authority": ""},
        "stages": [{"id": stage, "responsible": "", "reviewer": "", "status": "planned", "evidence_refs": []} for stage in STAGES],
        "quality_requirements": [],
        "measures": [],
        "observations": [],
        "deviations": [],
        "conclusion": {"decision": "undetermined", "rationale": "", "approved_by": "", "approved_at": "", "residual_limitations": [], "evidence_refs": []},
        "notice": "Define the evaluation before execution, retain raw evidence and uncertainty, and reserve the final conclusion for the named authority.",
    }
    return seal(result)


def _source(value: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
    result = verify_seal(value, label="quality evaluation source", format_value=QUALITY_EVALUATION_SOURCE_FORMAT)
    required = {"format", "generated_at", "authority", "analysis_binding", "evaluation_context", "stages", "quality_requirements", "measures", "observations", "deviations", "conclusion", "notice", "content_sha256"}
    if set(result) != required:
        raise ValueError("quality evaluation source fields are invalid")
    bounded_text(result["authority"], "quality-evaluation authority")
    verify_analysis_binding(result["analysis_binding"], analysis)
    context = result["evaluation_context"]
    context_fields = {"intended_use", "stakeholders", "quality_model", "scope", "independence_basis", "limitations", "decision_authority"}
    if not isinstance(context, dict) or set(context) != context_fields:
        raise ValueError("quality evaluation context fields are invalid")
    for name in ("intended_use", "quality_model", "scope", "independence_basis", "decision_authority"):
        bounded_text(context[name], f"evaluation context {name}", allow_empty=True)
    unique_text_list(context["stakeholders"], "evaluation stakeholders")
    unique_text_list(context["limitations"], "evaluation limitations")
    stages = result["stages"]
    if not isinstance(stages, list) or len(stages) != len(STAGES) or [item.get("id") for item in stages if isinstance(item, dict)] != list(STAGES):
        raise ValueError("quality evaluation stages must be complete and ordered")
    for stage in stages:
        if set(stage) != {"id", "responsible", "reviewer", "status", "evidence_refs"} or stage["status"] not in {"planned", "in_progress", "complete", "accepted"}:
            raise ValueError("quality evaluation stage fields are invalid")
        bounded_text(stage["responsible"], "stage responsible", allow_empty=True)
        bounded_text(stage["reviewer"], "stage reviewer", allow_empty=True)
        unique_text_list(stage["evidence_refs"], "stage evidence refs")
    requirements = result["quality_requirements"]
    measures = result["measures"]
    observations = result["observations"]
    deviations = result["deviations"]
    if any(not isinstance(items, list) or len(items) > MAX_RECORDS for items in (requirements, measures, observations, deviations)):
        raise ValueError("quality evaluation record collections are invalid")
    req_fields = {"id", "statement", "characteristic", "priority", "acceptance_basis", "evidence_refs"}
    req_ids: list[str] = []
    for item in requirements:
        if not isinstance(item, dict) or set(item) != req_fields:
            raise ValueError("quality requirement fields are invalid")
        req_ids.append(bounded_text(item["id"], "quality requirement id"))
        for name in ("statement", "characteristic", "priority", "acceptance_basis"):
            bounded_text(item[name], f"quality requirement {name}")
        unique_text_list(item["evidence_refs"], "quality requirement evidence refs")
    if len(req_ids) != len(set(req_ids)):
        raise ValueError("quality requirement ids must be unique")
    measure_fields = {"id", "requirement_ids", "name", "unit", "method", "direction", "threshold", "uncertainty_limit", "tool_identity", "procedure_ref"}
    measure_ids: list[str] = []
    for item in measures:
        if not isinstance(item, dict) or set(item) != measure_fields:
            raise ValueError("quality measure fields are invalid")
        measure_ids.append(bounded_text(item["id"], "quality measure id"))
        if not set(unique_text_list(item["requirement_ids"], "measure requirement ids")) <= set(req_ids) or not item["requirement_ids"]:
            raise ValueError("quality measure has unresolved requirements")
        for name in ("name", "unit", "method", "tool_identity", "procedure_ref"):
            bounded_text(item[name], f"quality measure {name}")
        if item["direction"] not in {"minimum", "maximum", "equal"}:
            raise ValueError("quality measure direction is invalid")
        for name in ("threshold", "uncertainty_limit"):
            if isinstance(item[name], bool) or not isinstance(item[name], (int, float)):
                raise ValueError(f"quality measure {name} must be numeric")
    if len(measure_ids) != len(set(measure_ids)):
        raise ValueError("quality measure ids must be unique")
    observation_fields = {"id", "measure_id", "value", "uncertainty", "observed_at", "executor", "environment_sha256", "raw_evidence_ref"}
    observation_ids: list[str] = []
    observed_measure_ids: list[str] = []
    for item in observations:
        if not isinstance(item, dict) or set(item) != observation_fields:
            raise ValueError("quality observation fields are invalid")
        observation_ids.append(bounded_text(item["id"], "quality observation id"))
        if item["measure_id"] not in set(measure_ids):
            raise ValueError("quality observation references an unknown measure")
        observed_measure_ids.append(item["measure_id"])
        for name in ("value", "uncertainty"):
            if isinstance(item[name], bool) or not isinstance(item[name], (int, float)) or float(item[name]) < 0 and name == "uncertainty":
                raise ValueError(f"quality observation {name} is invalid")
        for name in ("observed_at", "executor", "raw_evidence_ref"):
            bounded_text(item[name], f"quality observation {name}")
        if not re.fullmatch(r"[0-9a-f]{64}", str(item["environment_sha256"])):
            raise ValueError("quality observation environment digest is invalid")
    if len(observation_ids) != len(set(observation_ids)):
        raise ValueError("quality observation ids must be unique")
    if len(observed_measure_ids) != len(set(observed_measure_ids)):
        raise ValueError("each quality measure must have at most one canonical observation")
    deviation_fields = {"id", "stage_id", "description", "impact", "disposition", "approved_by", "evidence_refs"}
    for item in deviations:
        if not isinstance(item, dict) or set(item) != deviation_fields or item["stage_id"] not in STAGES:
            raise ValueError("quality evaluation deviation fields are invalid")
        for name in ("id", "description", "impact", "disposition", "approved_by"):
            bounded_text(item[name], f"evaluation deviation {name}")
        unique_text_list(item["evidence_refs"], "evaluation deviation evidence refs")
    conclusion = result["conclusion"]
    conclusion_fields = {"decision", "rationale", "approved_by", "approved_at", "residual_limitations", "evidence_refs"}
    if not isinstance(conclusion, dict) or set(conclusion) != conclusion_fields or conclusion["decision"] not in {"undetermined", "acceptable", "conditionally_acceptable", "unacceptable"}:
        raise ValueError("quality evaluation conclusion fields are invalid")
    for name in ("rationale", "approved_by", "approved_at"):
        bounded_text(conclusion[name], f"evaluation conclusion {name}", allow_empty=True)
    unique_text_list(conclusion["residual_limitations"], "conclusion residual limitations")
    unique_text_list(conclusion["evidence_refs"], "conclusion evidence refs")
    return copy.deepcopy(result)


def quality_evaluation_assessment(analysis: dict[str, Any], source: str | Path | dict[str, Any]) -> dict[str, Any]:
    raw = load_json(source, label="quality evaluation source") if not isinstance(source, dict) else source
    value = _source(raw, analysis)
    observations = {item["measure_id"]: item for item in value["observations"]}
    results: list[dict[str, Any]] = []
    measure_passes: dict[str, bool] = {}
    for measure in value["measures"]:
        observation = observations.get(measure["id"])
        if observation is None:
            passed = False
            observed = False
            value_number = None
        else:
            observed = True
            value_number = float(observation["value"])
            uncertainty = float(observation["uncertainty"])
            threshold = float(measure["threshold"])
            if measure["direction"] == "minimum":
                passed = value_number - uncertainty >= threshold
            elif measure["direction"] == "maximum":
                passed = value_number + uncertainty <= threshold
            else:
                passed = abs(value_number - threshold) + uncertainty <= float(measure["uncertainty_limit"])
        measure_passes[measure["id"]] = passed
        results.append({"measure_id": measure["id"], "observed": observed, "value": value_number, "passed_with_uncertainty": passed})
    requirement_ids = {item["id"] for item in value["quality_requirements"]}
    requirement_measures = {
        requirement_id: [
            item["id"]
            for item in value["measures"]
            if requirement_id in item["requirement_ids"]
        ]
        for requirement_id in requirement_ids
    }
    satisfied_requirements = {
        requirement_id
        for requirement_id, measure_ids in requirement_measures.items()
        if measure_ids and all(measure_passes[measure_id] for measure_id in measure_ids)
    }
    context = value["evaluation_context"]
    stages_complete = all(item["status"] == "accepted" and item["responsible"] and item["reviewer"] and item["responsible"].casefold() != item["reviewer"].casefold() and item["evidence_refs"] for item in value["stages"])
    context_complete = all(context[name] for name in ("intended_use", "stakeholders", "quality_model", "scope", "independence_basis", "decision_authority"))
    conclusion = value["conclusion"]
    conclusion_complete = conclusion["decision"] != "undetermined" and all(conclusion[name] for name in ("rationale", "approved_by", "approved_at", "evidence_refs")) and conclusion["approved_by"] == context["decision_authority"]
    eligible = bool(requirement_ids and value["measures"] and stages_complete and context_complete and satisfied_requirements == requirement_ids and conclusion_complete)
    assessment = {
        "format": QUALITY_EVALUATION_ASSESSMENT_FORMAT,
        "generated_at": value["generated_at"],
        "source_sha256": value["content_sha256"],
        "analysis_binding": copy.deepcopy(value["analysis_binding"]),
        "measure_results": results,
        "summary": {"requirements": len(requirement_ids), "requirements_satisfied": len(satisfied_requirements), "measures": len(results), "measures_passing": sum(item["passed_with_uncertainty"] for item in results), "stages_accepted": sum(item["status"] == "accepted" for item in value["stages"]), "eligible_for_authorized_conclusion": eligible},
        "notice": "Eligibility reflects the supplied controlled campaign; it is not product certification or an ISO conformity claim.",
    }
    return seal(assessment)


def seal_quality_evaluation_source(analysis: dict[str, Any], source: str | Path, destination: str | Path) -> Path:
    return publish_json(_source(seal(load_json(source, label="quality evaluation source")), analysis), destination)


def verify_quality_evaluation_assessment(assessment: dict[str, Any], *, analysis: dict[str, Any] | None = None, source: dict[str, Any] | None = None) -> dict[str, Any]:
    errors: list[str] = []
    eligible = False
    try:
        value = verify_seal(assessment, label="quality evaluation assessment", format_value=QUALITY_EVALUATION_ASSESSMENT_FORMAT)
        if analysis is not None:
            verify_analysis_binding(value.get("analysis_binding"), analysis)
        if source is not None:
            if analysis is None:
                raise ValueError("analysis is required for exact source regeneration")
            if canonical_json_sha256(value) != canonical_json_sha256(quality_evaluation_assessment(analysis, source)):
                raise ValueError("quality evaluation assessment does not exactly regenerate")
        eligible = bool(value.get("summary", {}).get("eligible_for_authorized_conclusion"))
    except (OSError, ValueError, TypeError) as exc:
        errors.append(str(exc))
    return seal({"format": QUALITY_EVALUATION_VERIFICATION_FORMAT, "valid": not errors, "eligible_for_authorized_conclusion": not errors and eligible, "errors": errors, "notice": "Verification establishes integrity and optional exact regeneration only."})


def verify_quality_evaluation_assessment_file(assessment_source: str | Path, *, analysis: dict[str, Any] | None = None, source_path: str | Path | None = None) -> dict[str, Any]:
    try:
        assessment = load_json(assessment_source, label="quality evaluation assessment")
        source = load_json(source_path, label="quality evaluation source") if source_path else None
        return verify_quality_evaluation_assessment(assessment, analysis=analysis, source=source)
    except (OSError, ValueError, TypeError) as exc:
        return seal({"format": QUALITY_EVALUATION_VERIFICATION_FORMAT, "valid": False, "eligible_for_authorized_conclusion": False, "errors": [str(exc)], "notice": "Verification failed closed."})


def export_quality_evaluation_source(value: dict[str, Any], destination: str | Path) -> Path:
    return publish_json(value, destination)


def export_quality_evaluation_assessment(value: dict[str, Any], destination: str | Path) -> Path:
    return publish_json(value, destination)
