"""Governed STPA and CAST workbenches seeded from static-analysis scope.

The implementation checks traceability and method completeness.  It never
infers losses, hazards, unsafe control actions, causal factors, or blame.
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

STPA_CAST_SOURCE_FORMAT = "pysfmea-stpa-cast-source-1"
STPA_CAST_ASSESSMENT_FORMAT = "pysfmea-stpa-cast-assessment-1"
STPA_CAST_VERIFICATION_FORMAT = "pysfmea-stpa-cast-verification-1"
UCA_CONTEXTS = {"not_provided", "provided", "wrong_timing_or_order", "wrong_duration"}
MAX_RECORDS = 100_000


def stpa_cast_template(analysis: dict[str, Any], *, authority: str) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    for component in analysis.get("components", [])[:20_000]:
        if not isinstance(component, dict) or not component.get("id"):
            continue
        source = component.get("source", {})
        nodes.append({
            "id": str(component["id"]),
            "name": str(component.get("qualname", component.get("name", component["id"]))),
            "kind": "unclassified",
            "responsibilities": [],
            "process_model_variables": [],
            "source_ref": f"{source.get('path', '')}:{source.get('line', '')}" if isinstance(source, dict) else "static-analysis",
        })
    result = {
        "format": STPA_CAST_SOURCE_FORMAT,
        "generated_at": utc_now(),
        "authority": bounded_text(authority, "STPA/CAST authority"),
        "analysis_binding": analysis_binding(analysis),
        "system_definition": {
            "mission": "",
            "boundaries": [],
            "operating_modes": [],
            "assumptions": [],
            "decision_authority": "",
        },
        "control_structure": {"nodes": nodes, "links": [], "control_actions": []},
        "stpa": {"losses": [], "hazards": [], "constraints": [], "unsafe_control_actions": [], "loss_scenarios": []},
        "cast": {"incidents": [], "component_analyses": [], "recommendations": []},
        "evidence_refs": [],
        "notice": "Static analysis seeds component scope only. Authorized analysts must define system intent, control structure semantics, losses, hazards, UCAs, causal scenarios, incident factors, and actions.",
    }
    return seal(result)


def _records(value: Any, label: str, fields: set[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAX_RECORDS:
        raise ValueError(f"{label} must be a bounded list")
    result: list[dict[str, Any]] = []
    identifiers: list[str] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError(f"{label} record fields are invalid")
        identifiers.append(bounded_text(item["id"], f"{label} id"))
        result.append(item)
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"{label} ids must be unique")
    return result


def _source(value: dict[str, Any], analysis: dict[str, Any]) -> dict[str, Any]:
    result = verify_seal(value, label="STPA/CAST source", format_value=STPA_CAST_SOURCE_FORMAT)
    required = {"format", "generated_at", "authority", "analysis_binding", "system_definition", "control_structure", "stpa", "cast", "evidence_refs", "notice", "content_sha256"}
    if set(result) != required:
        raise ValueError("STPA/CAST source fields are invalid")
    bounded_text(result["authority"], "STPA/CAST authority")
    verify_analysis_binding(result["analysis_binding"], analysis)
    unique_text_list(result["evidence_refs"], "STPA/CAST evidence refs")
    definition = result["system_definition"]
    definition_fields = {"mission", "boundaries", "operating_modes", "assumptions", "decision_authority"}
    if not isinstance(definition, dict) or set(definition) != definition_fields:
        raise ValueError("STPA system definition fields are invalid")
    bounded_text(definition["mission"], "system mission", allow_empty=True)
    bounded_text(definition["decision_authority"], "decision authority", allow_empty=True)
    for name in ("boundaries", "operating_modes", "assumptions"):
        unique_text_list(definition[name], f"system {name}")

    control = result["control_structure"]
    if not isinstance(control, dict) or set(control) != {"nodes", "links", "control_actions"}:
        raise ValueError("control structure fields are invalid")
    nodes = _records(control["nodes"], "control node", {"id", "name", "kind", "responsibilities", "process_model_variables", "source_ref"})
    node_ids = {item["id"] for item in nodes}
    for node in nodes:
        for name in ("name", "kind", "source_ref"):
            bounded_text(node[name], f"control node {name}")
        unique_text_list(node["responsibilities"], "control node responsibilities")
        unique_text_list(node["process_model_variables"], "process model variables")
    links = _records(control["links"], "control link", {"id", "source_id", "target_id", "kind", "label", "evidence_ref"})
    for link in links:
        if link["source_id"] not in node_ids or link["target_id"] not in node_ids:
            raise ValueError(f"control link {link['id']} has an unresolved endpoint")
        for name in ("kind", "label", "evidence_ref"):
            bounded_text(link[name], f"control link {name}")
    actions = _records(control["control_actions"], "control action", {"id", "controller_id", "controlled_process_id", "action", "feedback_refs", "requirement_refs", "evidence_ref"})
    action_ids = {item["id"] for item in actions}
    for action in actions:
        if action["controller_id"] not in node_ids or action["controlled_process_id"] not in node_ids:
            raise ValueError(f"control action {action['id']} has an unresolved endpoint")
        bounded_text(action["action"], "control action")
        bounded_text(action["evidence_ref"], "control action evidence ref")
        unique_text_list(action["feedback_refs"], "control action feedback refs")
        unique_text_list(action["requirement_refs"], "control action requirement refs")

    stpa = result["stpa"]
    if not isinstance(stpa, dict) or set(stpa) != {"losses", "hazards", "constraints", "unsafe_control_actions", "loss_scenarios"}:
        raise ValueError("STPA fields are invalid")
    losses = _records(stpa["losses"], "loss", {"id", "description", "stakeholders", "evidence_refs"})
    loss_ids = {item["id"] for item in losses}
    for item in losses:
        bounded_text(item["description"], "loss description")
        unique_text_list(item["stakeholders"], "loss stakeholders")
        unique_text_list(item["evidence_refs"], "loss evidence refs")
    hazards = _records(stpa["hazards"], "hazard", {"id", "system_state", "loss_ids", "operating_modes", "evidence_refs"})
    hazard_ids = {item["id"] for item in hazards}
    for item in hazards:
        bounded_text(item["system_state"], "hazard system state")
        if not set(unique_text_list(item["loss_ids"], "hazard loss ids")) <= loss_ids:
            raise ValueError(f"hazard {item['id']} references an unknown loss")
        unique_text_list(item["operating_modes"], "hazard operating modes")
        unique_text_list(item["evidence_refs"], "hazard evidence refs")
    constraints = _records(stpa["constraints"], "safety constraint", {"id", "statement", "hazard_ids", "requirement_refs", "verification_refs"})
    constraint_ids = {item["id"] for item in constraints}
    for item in constraints:
        bounded_text(item["statement"], "safety constraint statement")
        if not set(unique_text_list(item["hazard_ids"], "constraint hazard ids")) <= hazard_ids:
            raise ValueError(f"constraint {item['id']} references an unknown hazard")
        unique_text_list(item["requirement_refs"], "constraint requirement refs")
        unique_text_list(item["verification_refs"], "constraint verification refs")
    ucas = _records(stpa["unsafe_control_actions"], "unsafe control action", {"id", "control_action_id", "context_type", "context", "hazard_ids", "constraint_ids", "rationale", "reviewer", "evidence_refs"})
    uca_ids = {item["id"] for item in ucas}
    for item in ucas:
        if item["control_action_id"] not in action_ids:
            raise ValueError(f"UCA {item['id']} references an unknown control action")
        if item["context_type"] not in UCA_CONTEXTS:
            raise ValueError(f"UCA {item['id']} context type is invalid")
        bounded_text(item["context"], "UCA context")
        bounded_text(item["rationale"], "UCA rationale")
        bounded_text(item["reviewer"], "UCA reviewer")
        if not set(unique_text_list(item["hazard_ids"], "UCA hazard ids")) <= hazard_ids:
            raise ValueError(f"UCA {item['id']} references an unknown hazard")
        if not set(unique_text_list(item["constraint_ids"], "UCA constraint ids")) <= constraint_ids:
            raise ValueError(f"UCA {item['id']} references an unknown constraint")
        unique_text_list(item["evidence_refs"], "UCA evidence refs")
    scenarios = _records(stpa["loss_scenarios"], "loss scenario", {"id", "uca_ids", "causal_factors", "process_model_flaws", "timing_and_ordering", "mitigation_refs", "test_refs", "evidence_refs"})
    for item in scenarios:
        if not set(unique_text_list(item["uca_ids"], "scenario UCA ids")) <= uca_ids:
            raise ValueError(f"scenario {item['id']} references an unknown UCA")
        for name in ("causal_factors", "process_model_flaws", "timing_and_ordering", "mitigation_refs", "test_refs", "evidence_refs"):
            unique_text_list(item[name], f"scenario {name}")

    cast = result["cast"]
    if not isinstance(cast, dict) or set(cast) != {"incidents", "component_analyses", "recommendations"}:
        raise ValueError("CAST fields are invalid")
    incidents = _records(cast["incidents"], "CAST incident", {"id", "description", "occurred_at", "loss_ids", "evidence_refs"})
    incident_ids = {item["id"] for item in incidents}
    for item in incidents:
        bounded_text(item["description"], "incident description")
        bounded_text(item["occurred_at"], "incident occurrence")
        if not set(unique_text_list(item["loss_ids"], "incident loss ids")) <= loss_ids:
            raise ValueError(f"incident {item['id']} references an unknown loss")
        unique_text_list(item["evidence_refs"], "incident evidence refs")
    component_analyses = _records(cast["component_analyses"], "CAST component analysis", {"id", "incident_ids", "component_id", "responsibility", "unsafe_decisions_or_actions", "context", "process_model_flaws", "coordination_and_communication", "evidence_refs"})
    cast_analysis_ids = {item["id"] for item in component_analyses}
    for item in component_analyses:
        if item["component_id"] not in node_ids or not set(unique_text_list(item["incident_ids"], "CAST analysis incident ids")) <= incident_ids:
            raise ValueError(f"CAST component analysis {item['id']} has an unresolved reference")
        for name in ("responsibility", "context"):
            bounded_text(item[name], f"CAST analysis {name}")
        for name in ("unsafe_decisions_or_actions", "process_model_flaws", "coordination_and_communication", "evidence_refs"):
            unique_text_list(item[name], f"CAST analysis {name}")
    recommendations = _records(cast["recommendations"], "CAST recommendation", {"id", "incident_ids", "component_analysis_ids", "action", "owner", "due_at", "status", "verification_refs", "approval_authority"})
    for item in recommendations:
        if not set(unique_text_list(item["incident_ids"], "recommendation incident ids")) <= incident_ids or not set(unique_text_list(item["component_analysis_ids"], "recommendation analysis ids")) <= cast_analysis_ids:
            raise ValueError(f"CAST recommendation {item['id']} has an unresolved reference")
        for name in ("action", "owner", "due_at", "status", "approval_authority"):
            bounded_text(item[name], f"CAST recommendation {name}")
        unique_text_list(item["verification_refs"], "recommendation verification refs")
    return copy.deepcopy(result)


def seal_stpa_cast_source(analysis: dict[str, Any], source: str | Path, destination: str | Path) -> Path:
    value = seal(load_json(source, label="STPA/CAST source"))
    return publish_json(_source(value, analysis), destination)


def stpa_cast_assessment(analysis: dict[str, Any], source: str | Path | dict[str, Any]) -> dict[str, Any]:
    raw = load_json(source, label="STPA/CAST source") if not isinstance(source, dict) else source
    value = _source(raw, analysis)
    stpa = value["stpa"]
    cast = value["cast"]
    loss_ids = {item["id"] for item in stpa["losses"]}
    hazard_ids = {item["id"] for item in stpa["hazards"]}
    losses_linked = {loss_id for item in stpa["hazards"] for loss_id in item["loss_ids"]}
    constrained = {hazard_id for item in stpa["constraints"] for hazard_id in item["hazard_ids"]}
    uca_hazards = {hazard_id for item in stpa["unsafe_control_actions"] for hazard_id in item["hazard_ids"]}
    scenario_ucas = {uca_id for item in stpa["loss_scenarios"] for uca_id in item["uca_ids"]}
    uca_ids = {item["id"] for item in stpa["unsafe_control_actions"]}
    incident_ids = {item["id"] for item in cast["incidents"]}
    analyzed_incidents = {incident_id for item in cast["component_analyses"] for incident_id in item["incident_ids"]}
    recommended_incidents = {incident_id for item in cast["recommendations"] for incident_id in item["incident_ids"]}
    definition = value["system_definition"]
    checks = {
        "system_definition": all([definition["mission"], definition["boundaries"], definition["operating_modes"], definition["assumptions"], definition["decision_authority"]]),
        "control_structure": bool(value["control_structure"]["nodes"] and value["control_structure"]["links"] and value["control_structure"]["control_actions"]),
        "control_action_requirements": bool(value["control_structure"]["control_actions"]) and all(item["requirement_refs"] and item["feedback_refs"] and item["evidence_ref"] for item in value["control_structure"]["control_actions"]),
        "loss_hazard_traceability": bool(loss_ids and hazard_ids) and losses_linked == loss_ids and all(item["loss_ids"] and item["operating_modes"] and item["evidence_refs"] for item in stpa["hazards"]),
        "hazard_constraints": bool(hazard_ids) and constrained == hazard_ids,
        "constraint_verification": bool(stpa["constraints"]) and all(item["hazard_ids"] and item["requirement_refs"] and item["verification_refs"] for item in stpa["constraints"]),
        "hazard_uca_coverage": bool(hazard_ids) and uca_hazards == hazard_ids and all(item["hazard_ids"] and item["constraint_ids"] and item["evidence_refs"] for item in stpa["unsafe_control_actions"]),
        "uca_scenario_coverage": bool(uca_ids) and scenario_ucas == uca_ids,
        "scenario_test_traceability": bool(stpa["loss_scenarios"]) and all(item["causal_factors"] and item["timing_and_ordering"] and item["mitigation_refs"] and item["test_refs"] and item["evidence_refs"] for item in stpa["loss_scenarios"]),
        "cast_incident_analysis": (not incident_ids) or analyzed_incidents == incident_ids,
        "cast_corrective_actions": (not incident_ids) or recommended_incidents == incident_ids,
    }
    assessment = {
        "format": STPA_CAST_ASSESSMENT_FORMAT,
        "generated_at": value["generated_at"],
        "source_sha256": value["content_sha256"],
        "analysis_binding": copy.deepcopy(value["analysis_binding"]),
        "checks": checks,
        "gaps": {
            "unconstrained_hazard_ids": sorted(hazard_ids - constrained),
            "hazards_without_uca_ids": sorted(hazard_ids - uca_hazards),
            "ucas_without_scenario_ids": sorted(uca_ids - scenario_ucas),
            "incidents_without_component_analysis_ids": sorted(incident_ids - analyzed_incidents),
            "incidents_without_recommendation_ids": sorted(incident_ids - recommended_incidents),
        },
        "summary": {"complete": all(checks.values()), "checks_passing": sum(checks.values()), "checks_required": len(checks)},
        "notice": "Completeness is method-structure readiness, not proof that hazards are exhaustive or risk is acceptable.",
    }
    return seal(assessment)


def verify_stpa_cast_assessment(assessment: dict[str, Any], *, analysis: dict[str, Any] | None = None, source: dict[str, Any] | None = None) -> dict[str, Any]:
    errors: list[str] = []
    complete = False
    try:
        value = verify_seal(assessment, label="STPA/CAST assessment", format_value=STPA_CAST_ASSESSMENT_FORMAT)
        if analysis is not None:
            verify_analysis_binding(value.get("analysis_binding"), analysis)
        if source is not None:
            if analysis is None:
                raise ValueError("analysis is required for exact source regeneration")
            if canonical_json_sha256(value) != canonical_json_sha256(stpa_cast_assessment(analysis, source)):
                raise ValueError("STPA/CAST assessment does not exactly regenerate")
        complete = bool(value.get("summary", {}).get("complete"))
    except (OSError, ValueError, TypeError) as exc:
        errors.append(str(exc))
    return seal({"format": STPA_CAST_VERIFICATION_FORMAT, "valid": not errors, "complete": not errors and complete, "errors": errors, "notice": "Verification establishes integrity and optional exact regeneration only."})


def verify_stpa_cast_assessment_file(assessment_source: str | Path, *, analysis: dict[str, Any] | None = None, source_path: str | Path | None = None) -> dict[str, Any]:
    try:
        assessment = load_json(assessment_source, label="STPA/CAST assessment")
        source = load_json(source_path, label="STPA/CAST source") if source_path else None
        return verify_stpa_cast_assessment(assessment, analysis=analysis, source=source)
    except (OSError, ValueError, TypeError) as exc:
        return seal({"format": STPA_CAST_VERIFICATION_FORMAT, "valid": False, "complete": False, "errors": [str(exc)], "notice": "Verification failed closed."})


def export_stpa_cast_source(value: dict[str, Any], destination: str | Path) -> Path:
    return publish_json(value, destination)


def export_stpa_cast_assessment(value: dict[str, Any], destination: str | Path) -> Path:
    return publish_json(value, destination)
