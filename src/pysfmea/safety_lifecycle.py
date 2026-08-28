"""Evidence-governed PHA/FHA/PSSA/SSA and common-cause review workbench.

The scanner can identify review scope and correlate existing project evidence.  It
cannot determine safety objectives, independence, acceptability, or certification.
Those decisions are captured here as attributable engineering records and are never
inferred from source code.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .model import stable_id, utc_now
from .report import analysis_state_sha256
from .sfta import build_sfta

SAFETY_LIFECYCLE_AUTHORING_FORMAT = "pysfmea-safety-lifecycle-authoring-1"
SAFETY_LIFECYCLE_ASSESSMENT_FORMAT = "pysfmea-safety-lifecycle-assessment-1"
SAFETY_LIFECYCLE_VERIFICATION_FORMAT = "pysfmea-safety-lifecycle-verification-1"
STAGES = ("PHA", "FHA", "PSSA", "SSA", "OPERATIONS")
STAGE_STATUSES = {"not_started", "in_progress", "reviewed", "approved", "not_applicable"}
DISPOSITIONS = {"open", "mitigated", "accepted", "rejected", "not_applicable"}
CCFA_CATEGORIES = {
    "environment",
    "location",
    "shared_resource",
    "human",
    "development",
    "tool",
    "configuration",
    "external_dependency",
    "quality_control",
    "other",
}
MAX_RECORDS = 250_000
MAX_TEXT = 20_000


def _text(value: Any, label: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > MAX_TEXT:
        raise ValueError(f"{label} must be bounded text")
    result = value.strip()
    if not empty and not result:
        raise ValueError(f"{label} must not be empty")
    return result


def _strings(value: Any, label: str, *, required: bool = False) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > MAX_RECORDS
        or any(not isinstance(item, str) or not item.strip() or len(item) > MAX_TEXT for item in value)
        or len(value) != len(set(value))
        or (required and not value)
    ):
        raise ValueError(f"{label} must be a bounded, unique text list")
    return [item.strip() for item in value]


def _empty_stage(stage: str) -> dict[str, Any]:
    return {
        "stage": stage,
        "status": "not_started",
        "rationale": "",
        "reviewer": "",
        "reviewed_at": "",
        "evidence_refs": [],
    }


def _hazard_template(hazard: dict[str, Any]) -> dict[str, Any]:
    identifier = str(hazard.get("id", ""))
    return {
        "hazard_id": identifier,
        "description": str(hazard.get("description", "")),
        "end_effect": str(hazard.get("end_effect", "")),
        "classification": str(hazard.get("severity_category", "")),
        "classification_rationale": "",
        "safety_objectives": [],
        "allocated_requirement_ids": [],
        "verification_refs": [],
        "residual_risk_disposition": "open",
        "decision_authority": "",
        "decision_rationale": "",
    }


def _ccfa_candidates(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    findings = {
        str(item.get("id", "")): item
        for item in analysis.get("items", [])
        if isinstance(item, dict) and item.get("id")
    }
    candidates: list[dict[str, Any]] = []
    for component in analysis.get("components", []):
        if not isinstance(component, dict) or component.get("kind") != "common_cause":
            continue
        component_id = str(component.get("id", ""))
        linked = sorted(
            identifier
            for identifier, finding in findings.items()
            if str(finding.get("component_id", "")) == component_id
        )
        candidates.append(
            {
                "candidate_id": stable_id("CCFA-CANDIDATE", component_id),
                "source": "project_defined_common_cause",
                "description": str(component.get("docstring_summary", component.get("qualname", ""))),
                "involved_component_ids": sorted(str(value) for value in component.get("affected_component_ids", []) if value),
                "linked_finding_ids": linked,
            }
        )
    fault_model = build_sfta(analysis)
    for tree in fault_model.get("trees", []):
        cut_sets = tree.get("cut_set_analysis", {})
        if cut_sets.get("status") != "computed":
            continue
        for cut_set in cut_sets.get("cut_sets", []):
            candidates.append(
                {
                    "candidate_id": str(cut_set.get("id", "")),
                    "source": "approved_sfta_qualitative_cut_set",
                    "description": f"Approved qualitative cut set for hazard {tree.get('hazard_id', '')}",
                    "involved_component_ids": [],
                    "linked_finding_ids": sorted(str(value) for value in cut_set.get("linked_finding_ids", []) if value),
                }
            )
    return sorted(candidates, key=lambda item: item["candidate_id"])


def safety_lifecycle_authoring_template(
    analysis: dict[str, Any], *, authority: str, generated_at: str | None = None
) -> dict[str, Any]:
    """Create an exact-analysis-bound lifecycle and CCFA review workspace."""

    hazards = [
        _hazard_template(item)
        for item in analysis.get("context", {}).get("hazards", [])
        if isinstance(item, dict) and item.get("id")
    ]
    result: dict[str, Any] = {
        "format": SAFETY_LIFECYCLE_AUTHORING_FORMAT,
        "generated_at": generated_at or utc_now(),
        "authority": _text(authority, "safety authority"),
        "analysis_binding": {
            "baseline_id": str(analysis.get("project", {}).get("baseline", {}).get("id", "")),
            "analysis_state_sha256": analysis_state_sha256(analysis),
        },
        "stages": [_empty_stage(stage) for stage in STAGES],
        "hazards": hazards,
        "ccfa_candidates": _ccfa_candidates(analysis),
        "ccfa_reviews": [],
        "operational_feedback": {
            "review_period": "",
            "authority": "",
            "evidence_refs": [],
            "records": [],
        },
        "assumptions": [],
        "limitations": [],
        "notice": (
            "Static analysis generated review scope only. Authorized engineers must supply "
            "safety objectives, allocations, independence evidence, verification, and risk decisions."
        ),
    }
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def _load_authoring(source: str | Path, analysis: dict[str, Any]) -> tuple[dict[str, Any], bytes, Path]:
    document = load_bounded_json_document(
        source, label="safety lifecycle authoring", max_bytes=100_000_000,
        max_depth=150, max_nodes=3_000_000,
    )
    if not isinstance(document.value, dict):
        raise ValueError("safety lifecycle authoring must contain an object")
    value = copy.deepcopy(document.value)
    expected = {
        "format", "generated_at", "authority", "analysis_binding", "stages", "hazards",
        "ccfa_candidates", "ccfa_reviews", "operational_feedback", "assumptions", "limitations", "notice", "content_sha256",
    }
    if set(value) != expected or value.get("format") != SAFETY_LIFECYCLE_AUTHORING_FORMAT:
        raise ValueError("safety lifecycle authoring fields or format do not match format 1")
    unsigned = copy.deepcopy(value)
    claimed = unsigned.pop("content_sha256", "")
    if not isinstance(claimed, str) or not re.fullmatch(r"[0-9a-f]{64}", claimed) or canonical_json_sha256(unsigned) != claimed:
        raise ValueError("safety lifecycle authoring content digest does not match")
    binding = value.get("analysis_binding")
    if not isinstance(binding, dict) or set(binding) != {"baseline_id", "analysis_state_sha256"} or binding["analysis_state_sha256"] != analysis_state_sha256(analysis):
        raise ValueError("safety lifecycle authoring does not bind the exact analysis state")
    _text(value["authority"], "safety authority")
    return value, document.raw, document.path


def seal_safety_lifecycle_authoring(
    analysis: dict[str, Any], source: str | Path, destination: str | Path
) -> Path:
    document = load_bounded_json_document(
        source, label="safety lifecycle authoring", max_bytes=100_000_000,
        max_depth=150, max_nodes=3_000_000,
    )
    if not isinstance(document.value, dict):
        raise ValueError("safety lifecycle authoring must contain an object")
    value = copy.deepcopy(document.value)
    value.pop("content_sha256", None)
    value["content_sha256"] = canonical_json_sha256(value)
    expected = {
        "format", "generated_at", "authority", "analysis_binding", "stages", "hazards",
        "ccfa_candidates", "ccfa_reviews", "operational_feedback", "assumptions", "limitations", "notice", "content_sha256",
    }
    if set(value) != expected or value.get("format") != SAFETY_LIFECYCLE_AUTHORING_FORMAT:
        raise ValueError("safety lifecycle authoring fields or format do not match format 1")
    expected_binding = value.get("analysis_binding")
    if not isinstance(expected_binding, dict) or set(expected_binding) != {"baseline_id", "analysis_state_sha256"} or expected_binding.get("analysis_state_sha256") != analysis_state_sha256(analysis):
        raise ValueError("safety lifecycle authoring does not bind the exact analysis state")
    template = safety_lifecycle_authoring_template(
        analysis, authority=str(value["authority"]), generated_at=str(value["generated_at"])
    )
    if value["ccfa_candidates"] != template["ccfa_candidates"]:
        raise ValueError("CCFA candidate scope does not match regenerated exact-analysis scope")
    _stage_results(value["stages"])
    _hazard_results(value["hazards"], {item["hazard_id"] for item in template["hazards"]})
    _ccfa_results(value["ccfa_reviews"], template["ccfa_candidates"])
    _operational_feedback_result(value["operational_feedback"])
    _strings(value["assumptions"], "safety assumptions")
    _strings(value["limitations"], "safety limitations")
    return export_safety_lifecycle_authoring(value, destination)


def _stage_results(stages: Any) -> list[dict[str, Any]]:
    if not isinstance(stages, list) or len(stages) != len(STAGES):
        raise ValueError("safety lifecycle stages are invalid")
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in stages:
        fields = {"stage", "status", "rationale", "reviewer", "reviewed_at", "evidence_refs"}
        if not isinstance(record, dict) or set(record) != fields:
            raise ValueError("safety lifecycle stage fields are invalid")
        stage = str(record["stage"])
        status = str(record["status"])
        if stage not in STAGES or stage in seen or status not in STAGE_STATUSES:
            raise ValueError("safety lifecycle stage identity or status is invalid")
        seen.add(stage)
        evidence = _strings(record["evidence_refs"], f"{stage} evidence")
        complete = status in {"approved", "not_applicable"} and bool(str(record["rationale"]).strip()) and bool(str(record["reviewer"]).strip()) and bool(str(record["reviewed_at"]).strip()) and (status == "not_applicable" or bool(evidence))
        results.append({"stage": stage, "status": status, "complete": complete, "evidence_count": len(evidence)})
    if seen != set(STAGES):
        raise ValueError("safety lifecycle stages are incomplete")
    return results


def _hazard_results(records: Any, expected_ids: set[str]) -> list[dict[str, Any]]:
    fields = {
        "hazard_id", "description", "end_effect", "classification", "classification_rationale",
        "safety_objectives", "allocated_requirement_ids", "verification_refs",
        "residual_risk_disposition", "decision_authority", "decision_rationale",
    }
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError("hazard lifecycle records are invalid")
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != fields:
            raise ValueError("hazard lifecycle record fields are invalid")
        identifier = _text(record["hazard_id"], "hazard id")
        if identifier in seen or identifier not in expected_ids or record["residual_risk_disposition"] not in DISPOSITIONS:
            raise ValueError(f"hazard lifecycle record {identifier} is invalid")
        seen.add(identifier)
        objectives = _strings(record["safety_objectives"], f"{identifier} objectives")
        allocations = _strings(record["allocated_requirement_ids"], f"{identifier} allocations")
        verification = _strings(record["verification_refs"], f"{identifier} verification")
        disposition = str(record["residual_risk_disposition"])
        decision_complete = disposition in {"accepted", "rejected", "not_applicable"} and bool(str(record["decision_authority"]).strip()) and bool(str(record["decision_rationale"]).strip())
        complete = bool(str(record["classification"]).strip() and str(record["classification_rationale"]).strip() and objectives and allocations and verification and decision_complete)
        results.append({
            "hazard_id": identifier, "complete": complete, "objective_count": len(objectives),
            "allocation_count": len(allocations), "verification_count": len(verification),
            "residual_risk_disposition": disposition,
        })
    if seen != expected_ids:
        raise ValueError("hazard lifecycle population does not match the exact analysis")
    return results


def _ccfa_results(reviews: Any, candidates: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    fields = {
        "review_id", "candidate_ids", "category", "description", "involved_component_ids",
        "linked_finding_ids", "coupling_mechanism", "independence_claim", "separation_evidence_refs",
        "mitigations", "verification_refs", "disposition", "reviewer", "reviewed_at", "rationale",
    }
    if not isinstance(reviews, list) or len(reviews) > MAX_RECORDS:
        raise ValueError("CCFA reviews are invalid")
    candidate_ids = {item["candidate_id"] for item in candidates}
    covered: set[str] = set()
    results: list[dict[str, Any]] = []
    review_ids: set[str] = set()
    for review in reviews:
        if not isinstance(review, dict) or set(review) != fields:
            raise ValueError("CCFA review fields are invalid")
        identifier = _text(review["review_id"], "CCFA review id")
        if identifier in review_ids or review["category"] not in CCFA_CATEGORIES or review["disposition"] not in DISPOSITIONS:
            raise ValueError(f"CCFA review {identifier} is invalid")
        review_ids.add(identifier)
        links = _strings(review["candidate_ids"], f"{identifier} candidate ids", required=True)
        if not set(links) <= candidate_ids or covered.intersection(links):
            raise ValueError(f"CCFA review {identifier} has unknown or multiply covered candidates")
        covered.update(links)
        separation = _strings(review["separation_evidence_refs"], f"{identifier} separation evidence")
        mitigations = _strings(review["mitigations"], f"{identifier} mitigations")
        verification = _strings(review["verification_refs"], f"{identifier} verification")
        disposition = str(review["disposition"])
        complete = bool(
            str(review["coupling_mechanism"]).strip()
            and str(review["independence_claim"]).strip()
            and (separation or mitigations)
            and verification
            and disposition in {"mitigated", "accepted", "rejected", "not_applicable"}
            and str(review["reviewer"]).strip()
            and str(review["reviewed_at"]).strip()
            and str(review["rationale"]).strip()
        )
        results.append({"review_id": identifier, "candidate_ids": links, "complete": complete, "disposition": disposition})
    return results, sorted(candidate_ids - covered)


def _operational_feedback_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "review_period", "authority", "evidence_refs", "records"
    }:
        raise ValueError("operational feedback review fields are invalid")
    evidence = _strings(value["evidence_refs"], "operational feedback evidence")
    records = value["records"]
    fields = {
        "record_id", "detected_at", "source", "affected_hazard_ids",
        "affected_finding_ids", "affected_component_ids", "failure_description",
        "containment", "root_cause_ref", "corrective_actions", "owner", "due_date",
        "verification_refs", "effectiveness_status", "closed_by", "closed_at",
    }
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError("operational feedback records are invalid")
    seen: set[str] = set()
    results: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict) or set(record) != fields:
            raise ValueError("operational feedback record fields are invalid")
        identifier = _text(record["record_id"], "operational feedback record id")
        if identifier in seen or record["effectiveness_status"] not in {
            "open", "contained", "action_in_progress", "verified_effective", "verified_ineffective"
        }:
            raise ValueError(f"operational feedback record {identifier} is invalid")
        seen.add(identifier)
        for name in ("affected_hazard_ids", "affected_finding_ids", "affected_component_ids"):
            _strings(record[name], f"{identifier} {name}")
        actions = _strings(record["corrective_actions"], f"{identifier} corrective actions")
        verification = _strings(record["verification_refs"], f"{identifier} verification")
        closed = record["effectiveness_status"] in {"verified_effective", "verified_ineffective"}
        complete = bool(
            str(record["detected_at"]).strip()
            and str(record["source"]).strip()
            and str(record["failure_description"]).strip()
            and str(record["containment"]).strip()
            and str(record["root_cause_ref"]).strip()
            and actions
            and str(record["owner"]).strip()
            and str(record["due_date"]).strip()
            and verification
            and closed
            and str(record["closed_by"]).strip()
            and str(record["closed_at"]).strip()
        )
        results.append({"record_id": identifier, "effectiveness_status": record["effectiveness_status"], "complete": complete})
    review_complete = bool(
        str(value["review_period"]).strip()
        and str(value["authority"]).strip()
        and evidence
    )
    return {
        "review_period": str(value["review_period"]),
        "authority": str(value["authority"]),
        "evidence_count": len(evidence),
        "records": results,
        "complete": bool(review_complete and all(item["complete"] for item in results)),
    }


def safety_lifecycle_assessment(
    analysis: dict[str, Any], authoring_source: str | Path, *, generated_at: str | None = None
) -> dict[str, Any]:
    authoring, raw, path = _load_authoring(authoring_source, analysis)
    expected_template = safety_lifecycle_authoring_template(
        analysis, authority=authoring["authority"], generated_at=authoring["generated_at"]
    )
    expected_candidates = expected_template["ccfa_candidates"]
    if authoring["ccfa_candidates"] != expected_candidates:
        raise ValueError("CCFA candidate scope does not match regenerated exact-analysis scope")
    expected_hazards = {item["hazard_id"] for item in expected_template["hazards"]}
    stages = _stage_results(authoring["stages"])
    hazards = _hazard_results(authoring["hazards"], expected_hazards)
    ccfa, uncovered = _ccfa_results(authoring["ccfa_reviews"], expected_candidates)
    operational_feedback = _operational_feedback_result(authoring["operational_feedback"])
    assumptions = _strings(authoring["assumptions"], "safety assumptions", required=True)
    _strings(authoring["limitations"], "safety limitations")
    checks = {
        "analysis_binding": True,
        "lifecycle_stages_complete": all(item["complete"] for item in stages),
        "hazard_lifecycle_complete": bool(hazards) and all(item["complete"] for item in hazards),
        "ccfa_scope_covered": not uncovered,
        "ccfa_reviews_complete": bool(ccfa or not expected_candidates) and all(item["complete"] for item in ccfa),
        "operational_feedback_complete": operational_feedback["complete"],
        "assumptions_present": bool(assumptions),
    }
    complete = all(checks.values())
    result: dict[str, Any] = {
        "format": SAFETY_LIFECYCLE_ASSESSMENT_FORMAT,
        "generated_at": generated_at or utc_now(),
        "binding": {
            "analysis_state_sha256": analysis_state_sha256(analysis),
            "authoring_reference": path.name,
            "authoring_bytes": len(raw),
            "authoring_sha256": hashlib.sha256(raw).hexdigest(),
            "authoring_content_sha256": authoring["content_sha256"],
        },
        "authority": authoring["authority"],
        "stages": stages,
        "hazards": hazards,
        "ccfa": {"candidate_count": len(expected_candidates), "reviews": ccfa, "uncovered_candidate_ids": uncovered},
        "operational_feedback": operational_feedback,
        "checks": checks,
        "summary": {
            "complete": complete,
            "status": "eligible_for_authorized_safety_review" if complete else "engineering_evidence_incomplete",
            "failed_checks": sorted(name for name, state in checks.items() if not state),
        },
        "notice": (
            "Completeness means the governed records reconcile. It does not establish safety, "
            "independence, compliance, certification, or acceptance authority."
        ),
    }
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def verify_safety_lifecycle_assessment(value: dict[str, Any]) -> dict[str, Any]:
    expected = {"format", "generated_at", "binding", "authority", "stages", "hazards", "ccfa", "operational_feedback", "checks", "summary", "notice", "content_sha256"}
    errors: list[str] = []
    structure = bool(set(value) == expected and value.get("format") == SAFETY_LIFECYCLE_ASSESSMENT_FORMAT and isinstance(value.get("checks"), dict))
    if not structure:
        errors.append("safety lifecycle assessment fields do not match format 1")
    semantic = False
    try:
        complete = all(state is True for state in value["checks"].values())
        semantic = value["summary"] == {
            "complete": complete,
            "status": "eligible_for_authorized_safety_review" if complete else "engineering_evidence_incomplete",
            "failed_checks": sorted(name for name, state in value["checks"].items() if not state),
        }
    except (KeyError, TypeError):
        semantic = False
    if not semantic:
        errors.append("safety lifecycle summary does not reconcile")
    unsigned = copy.deepcopy(value)
    claimed = str(unsigned.pop("content_sha256", ""))
    integrity = bool(re.fullmatch(r"[0-9a-f]{64}", claimed) and canonical_json_sha256(unsigned) == claimed)
    if not integrity:
        errors.append("safety lifecycle content digest does not match")
    return {
        "format": SAFETY_LIFECYCLE_VERIFICATION_FORMAT,
        "valid": bool(structure and semantic and integrity),
        "complete": bool(structure and semantic and integrity and value.get("summary", {}).get("complete")),
        "checks": {"closed_structure": structure, "content_integrity": integrity, "semantic_reconciliation": semantic, "source_regeneration": None},
        "errors": errors,
        "content_sha256": claimed,
        "notice": "Verification proves governed accounting, not safety or certification authority.",
    }


def verify_safety_lifecycle_assessment_file(
    source: str | Path, *, analysis: dict[str, Any] | None = None,
    authoring_source: str | Path | None = None,
) -> dict[str, Any]:
    try:
        document = load_bounded_json_document(source, label="safety lifecycle assessment", max_bytes=100_000_000, max_depth=150, max_nodes=3_000_000)
        if not isinstance(document.value, dict):
            raise ValueError("safety lifecycle assessment must contain an object")
        result = verify_safety_lifecycle_assessment(document.value)
        result["path"] = str(document.path)
        if analysis is not None and authoring_source is not None and result["valid"]:
            regenerated = safety_lifecycle_assessment(analysis, authoring_source, generated_at=str(document.value.get("generated_at", "")))
            source_regeneration = regenerated == document.value
            result["checks"]["source_regeneration"] = source_regeneration
            result["valid"] = bool(result["valid"] and source_regeneration)
            result["complete"] = bool(result["complete"] and source_regeneration)
            if not source_regeneration:
                result["errors"].append("assessment does not exactly regenerate from supplied sources")
        return result
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "path": str(Path(source).expanduser().absolute()),
            "format": SAFETY_LIFECYCLE_VERIFICATION_FORMAT,
            "valid": False, "complete": False,
            "checks": {"closed_structure": False, "content_integrity": False, "semantic_reconciliation": False, "source_regeneration": None},
            "errors": [str(exc)], "content_sha256": "",
            "notice": "The safety lifecycle assessment could not be safely verified.",
        }


def export_safety_lifecycle_authoring(value: dict[str, Any], destination: str | Path) -> Path:
    return atomic_publish_text(destination, json.dumps(value, indent=2, ensure_ascii=False) + "\n", label="safety lifecycle authoring")


def export_safety_lifecycle_assessment(value: dict[str, Any], destination: str | Path) -> Path:
    return atomic_publish_text(destination, json.dumps(value, indent=2, ensure_ascii=False) + "\n", label="safety lifecycle assessment")
