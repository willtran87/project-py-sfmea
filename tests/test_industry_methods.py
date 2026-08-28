from __future__ import annotations

import copy

import pytest
from jsonschema import Draft202012Validator

from pysfmea.governed_artifact import seal
from pysfmea.laboratory_governance import (
    DOMAINS,
    laboratory_governance_assessment,
    laboratory_governance_template,
    verify_laboratory_governance_assessment,
)
from pysfmea.quality_evaluation import (
    quality_evaluation_assessment,
    quality_evaluation_template,
    verify_quality_evaluation_assessment,
)
from pysfmea.quantitative_fta import (
    quantitative_fta_assessment,
    quantitative_fta_template,
    verify_quantitative_fta_assessment,
)
from pysfmea.schemas import schema_document
from pysfmea.security_prioritization import (
    parse_cvss_v4_vector,
    security_prioritization_assessment,
    security_prioritization_template,
    verify_security_prioritization_assessment,
)
from pysfmea.stpa_cast import (
    stpa_cast_assessment,
    stpa_cast_template,
    verify_stpa_cast_assessment,
)
from pysfmea.structural_coverage import (
    structural_coverage_assessment,
    structural_coverage_template,
    verify_structural_coverage_assessment,
)


def _analysis() -> dict:
    return {
        "project": {"baseline": {"id": "baseline-1"}},
        "components": [
            {"id": "controller", "name": "controller", "qualname": "app.controller", "source": {"path": "app.py", "line": 10}},
            {"id": "actuator", "name": "actuator", "qualname": "app.actuator", "source": {"path": "app.py", "line": 20}},
        ],
    }


def test_unique_cause_mcdc_is_derived_from_boolean_vectors() -> None:
    analysis = _analysis()
    source = structural_coverage_template(analysis, authority="coverage-owner")
    source["coverage_basis"].update({"criticality_basis": "project Level A basis", "measurement_tool": "qualified coverage tool 1.0", "measurement_configuration_sha256": "c" * 64, "object_code_coverage_basis": "not_required"})
    source["evidence_refs"] = ["coverage://run-1"]
    source["requirements"] = [{"id": "REQ-1", "text": "command when A or B", "criticality": "A", "verification_method": "requirements-based test", "acceptance_criteria": "decision outcome equals A or B", "evidence_refs": ["req://1"]}]
    source["decisions"] = [{
        "id": "D-1", "component_id": "controller", "source_ref": "app.py:10", "requirement_ids": ["REQ-1"],
        "conditions": [{"id": "A", "expression": "a"}, {"id": "B", "expression": "b"}],
        "tests": [
            {"id": "T0", "condition_values": {"A": False, "B": False}, "decision_outcome": False, "evidence_ref": "test://0"},
            {"id": "TA", "condition_values": {"A": True, "B": False}, "decision_outcome": True, "evidence_ref": "test://a"},
            {"id": "TB", "condition_values": {"A": False, "B": True}, "decision_outcome": True, "evidence_ref": "test://b"},
        ],
        "independence_pairs": [
            {"condition_id": "A", "test_a_id": "T0", "test_b_id": "TA", "evidence_ref": "pair://a"},
            {"condition_id": "B", "test_a_id": "T0", "test_b_id": "TB", "evidence_ref": "pair://b"},
        ],
        "evidence_ref": "coverage://run-1",
    }]
    source = seal(source)
    assessment = structural_coverage_assessment(analysis, source)
    assert assessment["summary"]["complete"] is True
    assert verify_structural_coverage_assessment(assessment, analysis=analysis, source=source)["complete"] is True
    partially_covered = copy.deepcopy(source)
    second_decision = copy.deepcopy(partially_covered["decisions"][0])
    second_decision["id"] = "D-2"
    second_decision["independence_pairs"] = second_decision["independence_pairs"][:1]
    partially_covered["decisions"].append(second_decision)
    partial_assessment = structural_coverage_assessment(analysis, seal(partially_covered))
    assert partial_assessment["summary"]["complete"] is False
    assert partial_assessment["summary"]["uncovered_requirement_ids"] == ["REQ-1"]
    invalid = copy.deepcopy(source)
    invalid["decisions"][0]["tests"][1]["condition_values"]["B"] = True
    with pytest.raises(ValueError, match="independently change"):
        structural_coverage_assessment(analysis, seal(invalid))


def test_stpa_cast_traceability_is_complete_and_unresolved_references_fail() -> None:
    analysis = _analysis()
    source = stpa_cast_template(analysis, authority="safety-lead")
    source["system_definition"] = {"mission": "control pressure", "boundaries": ["service"], "operating_modes": ["normal"], "assumptions": ["sensor available"], "decision_authority": "safety-board"}
    for node in source["control_structure"]["nodes"]:
        node["kind"] = "controller" if node["id"] == "controller" else "controlled_process"
        node["responsibilities"] = ["control"]
    source["control_structure"]["links"] = [{"id": "L-1", "source_id": "controller", "target_id": "actuator", "kind": "command", "label": "set", "evidence_ref": "arch://1"}]
    source["control_structure"]["control_actions"] = [{"id": "CA-1", "controller_id": "controller", "controlled_process_id": "actuator", "action": "set pressure", "feedback_refs": ["L-1"], "requirement_refs": ["REQ-1"], "evidence_ref": "arch://ca"}]
    source["stpa"] = {
        "losses": [{"id": "LSS-1", "description": "injury", "stakeholders": ["operator"], "evidence_refs": ["haz://1"]}],
        "hazards": [{"id": "H-1", "system_state": "unsafe pressure", "loss_ids": ["LSS-1"], "operating_modes": ["normal"], "evidence_refs": ["haz://h"]}],
        "constraints": [{"id": "SC-1", "statement": "pressure remains bounded", "hazard_ids": ["H-1"], "requirement_refs": ["REQ-1"], "verification_refs": ["test://pressure"]}],
        "unsafe_control_actions": [{"id": "UCA-1", "control_action_id": "CA-1", "context_type": "wrong_timing_or_order", "context": "after timeout", "hazard_ids": ["H-1"], "constraint_ids": ["SC-1"], "rationale": "late command defeats protection", "reviewer": "analyst", "evidence_refs": ["review://uca"]}],
        "loss_scenarios": [{"id": "LS-1", "uca_ids": ["UCA-1"], "causal_factors": ["retry queue"], "process_model_flaws": ["stale state"], "timing_and_ordering": ["command arrives after breaker opens"], "mitigation_refs": ["SC-1"], "test_refs": ["test://timing"], "evidence_refs": ["scenario://1"]}],
    }
    source["cast"] = {
        "incidents": [{"id": "INC-1", "description": "late command", "occurred_at": "2026-01-01T00:00:00Z", "loss_ids": ["LSS-1"], "evidence_refs": ["incident://1"]}],
        "component_analyses": [{"id": "CCA-1", "incident_ids": ["INC-1"], "component_id": "controller", "responsibility": "bound pressure", "unsafe_decisions_or_actions": ["late retry"], "context": "degraded network", "process_model_flaws": ["breaker state stale"], "coordination_and_communication": ["feedback delayed"], "evidence_refs": ["cast://1"]}],
        "recommendations": [{"id": "REC-1", "incident_ids": ["INC-1"], "component_analysis_ids": ["CCA-1"], "action": "reject stale commands", "owner": "team", "due_at": "2026-10-01", "status": "approved", "verification_refs": ["test://stale"], "approval_authority": "safety-board"}],
    }
    source = seal(source)
    assessment = stpa_cast_assessment(analysis, source)
    assert assessment["summary"]["complete"] is True
    assert verify_stpa_cast_assessment(assessment, analysis=analysis, source=source)["complete"] is True
    invalid = copy.deepcopy(source)
    invalid["stpa"]["hazards"][0]["loss_ids"] = ["missing"]
    with pytest.raises(ValueError, match="unknown loss"):
        stpa_cast_assessment(analysis, seal(invalid))


def test_exact_fta_handles_shared_events_and_derives_cut_sets() -> None:
    analysis = _analysis()
    source = quantitative_fta_template(analysis, authority="reliability-lead")
    source["model_scope"] = {"top_event": "loss of service", "system_boundary": "service", "mission_time_hours": 1.0, "operating_modes": ["normal"], "assumptions": ["stationary probabilities"], "exclusions": []}
    source["independence_basis"] = "A, B, and C are supported as independent by evidence; A is intentionally shared in both branches."
    source["evidence_refs"] = ["fta://review"]
    source["basic_events"] = [
        {"id": "A", "description": "shared dependency fails", "probability": 0.1, "probability_interval": [0.1, 0.1], "component_ids": ["controller"], "source_kind": "field estimate", "evidence_ref": "rel://a"},
        {"id": "B", "description": "branch B fails", "probability": 0.2, "probability_interval": [0.2, 0.2], "component_ids": ["actuator"], "source_kind": "field estimate", "evidence_ref": "rel://b"},
        {"id": "C", "description": "branch C fails", "probability": 0.3, "probability_interval": [0.3, 0.3], "component_ids": ["actuator"], "source_kind": "field estimate", "evidence_ref": "rel://c"},
    ]
    source["gates"] = [
        {"id": "G1", "kind": "and", "input_ids": ["A", "B"], "rationale": "branch 1", "evidence_ref": "fta://g1"},
        {"id": "G2", "kind": "and", "input_ids": ["A", "C"], "rationale": "branch 2", "evidence_ref": "fta://g2"},
        {"id": "TOP", "kind": "or", "input_ids": ["G1", "G2"], "rationale": "top event", "evidence_ref": "fta://top"},
    ]
    source["top_gate_id"] = "TOP"
    source = seal(source)
    assessment = quantitative_fta_assessment(analysis, source)
    assert assessment["evaluation"]["top_event_probability"] == pytest.approx(0.044)
    assert assessment["evaluation"]["minimal_cut_sets"] == [["A", "B"], ["A", "C"]]
    importance = {item["event_id"]: item["birnbaum_importance"] for item in assessment["evaluation"]["importance"]}
    assert importance["A"] == pytest.approx(0.44)
    assert verify_quantitative_fta_assessment(assessment, analysis=analysis, source=source)["complete"] is True
    unsupported_dependency = copy.deepcopy(source)
    unsupported_dependency["dependency_declarations"] = [{"id": "DEP-1", "kind": "correlation", "event_ids": ["B", "C"], "modeling_treatment": "correlation_coefficient_only", "basis": "declared correlation", "evidence_ref": "dep://1"}]
    with pytest.raises(ValueError, match="dependency treatment is unsupported"):
        quantitative_fta_assessment(analysis, seal(unsupported_dependency))


def test_quality_evaluation_applies_uncertainty_and_separation_of_duties() -> None:
    analysis = _analysis()
    source = quality_evaluation_template(analysis, authority="quality-owner")
    source["evaluation_context"] = {"intended_use": "release decision", "stakeholders": ["operator"], "quality_model": "ISO/IEC 25010 project model", "scope": "service", "independence_basis": "reviewer outside implementation team", "limitations": ["one platform"], "decision_authority": "quality-board"}
    for index, stage in enumerate(source["stages"]):
        stage.update({"responsible": f"executor-{index}", "reviewer": f"reviewer-{index}", "status": "accepted", "evidence_refs": [f"stage://{index}"]})
    source["quality_requirements"] = [{"id": "QR-1", "statement": "latency below limit", "characteristic": "performance efficiency", "priority": "critical", "acceptance_basis": "p99 <= 100 ms", "evidence_refs": ["req://latency"]}]
    source["measures"] = [{"id": "M-1", "requirement_ids": ["QR-1"], "name": "p99 latency", "unit": "ms", "method": "controlled load test", "direction": "maximum", "threshold": 100.0, "uncertainty_limit": 3.0, "tool_identity": "load-tool 1", "procedure_ref": "proc://latency"}]
    source["observations"] = [{"id": "OBS-1", "measure_id": "M-1", "value": 95.0, "uncertainty": 3.0, "observed_at": "2026-08-28T00:00:00Z", "executor": "lab", "environment_sha256": "a" * 64, "raw_evidence_ref": "raw://latency"}]
    source["conclusion"] = {"decision": "acceptable", "rationale": "all criteria pass with uncertainty", "approved_by": "quality-board", "approved_at": "2026-08-28T01:00:00Z", "residual_limitations": ["one platform"], "evidence_refs": ["approval://1"]}
    source = seal(source)
    assessment = quality_evaluation_assessment(analysis, source)
    assert assessment["summary"]["eligible_for_authorized_conclusion"] is True
    assert verify_quality_evaluation_assessment(assessment, analysis=analysis, source=source)["eligible_for_authorized_conclusion"] is True
    failing_second_measure = copy.deepcopy(source)
    second_measure = copy.deepcopy(failing_second_measure["measures"][0])
    second_measure.update({"id": "M-2", "name": "maximum latency", "threshold": 110.0})
    failing_second_measure["measures"].append(second_measure)
    second_observation = copy.deepcopy(failing_second_measure["observations"][0])
    second_observation.update({"id": "OBS-2", "measure_id": "M-2", "value": 120.0})
    failing_second_measure["observations"].append(second_observation)
    conservative = quality_evaluation_assessment(analysis, seal(failing_second_measure))
    assert conservative["summary"]["requirements_satisfied"] == 0
    assert conservative["summary"]["eligible_for_authorized_conclusion"] is False


def test_security_and_laboratory_governance_require_cross_referenced_evidence() -> None:
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A"
    assert parse_cvss_v4_vector(vector)["AV"] == "N"
    with pytest.raises(ValueError, match="canonical order"):
        parse_cvss_v4_vector("CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    security = security_prioritization_template(authority="security-owner")
    security["policy"].update({"ssvc_policy_ref": "ssvc://policy", "decision_authority": "security-board", "review_cadence": "30 days", "scope": "service"})
    security["vulnerabilities"] = [{"id": "CVE-TEST", "component_refs": ["pkg:pypi/example@1"], "cvss_vector": vector, "cvss_score": 9.3, "cvss_rating": "critical", "calculator_name": "FIRST calculator", "calculator_version": "4.0", "calculator_evidence_ref": "cvss://receipt", "asvs_requirement_refs": ["V1.1.1"], "asvs_evidence_refs": ["asvs://V1.1.1"], "ssvc_decision_ref": "ssvc://decision", "ssvc_outcome": "act", "disposition": "remediate", "owner": "team", "due_at": "2026-09-01", "reviewer": "security-reviewer", "reviewed_at": "2026-08-28", "evidence_refs": ["vuln://record"]}]
    security = seal(security)
    security_assessment = security_prioritization_assessment(security)
    assert verify_security_prioritization_assessment(security_assessment, source=security)["complete"] is True

    laboratory = laboratory_governance_template(authority="lab-owner", subject_sha256="b" * 64)
    laboratory["subject"].update({"id": "campaign-1", "scope": "independent benchmark"})
    laboratory["roles"] = {"laboratory_manager": "manager", "method_owner": "methodologist", "technical_reviewer": "reviewer", "decision_authority": "board", "organizational_independence_basis": "separate reporting line and funding approval"}
    for control in laboratory["controls"]:
        assert control["domain"] in DOMAINS
        control.update({"procedure_ref": f"procedure://{control['domain']}", "owner": f"owner-{control['domain']}", "status": "effective", "evidence_refs": [f"evidence://{control['domain']}"]})
    laboratory["approval"] = {"decision": "accepted", "approved_by": "board", "approved_at": "2026-08-28T02:00:00Z", "rationale": "controls effective", "evidence_refs": ["approval://lab"]}
    laboratory = seal(laboratory)
    lab_assessment = laboratory_governance_assessment(laboratory)
    assert verify_laboratory_governance_assessment(lab_assessment, source=laboratory)["eligible_for_governed_use"] is True


def test_all_industry_method_artifacts_conform_to_public_schemas() -> None:
    analysis = _analysis()
    bound = {
        "stpa-cast": (stpa_cast_template(analysis, authority="owner"), stpa_cast_assessment, verify_stpa_cast_assessment),
        "structural-coverage": (structural_coverage_template(analysis, authority="owner"), structural_coverage_assessment, verify_structural_coverage_assessment),
        "quantitative-fta": (quantitative_fta_template(analysis, authority="owner"), quantitative_fta_assessment, verify_quantitative_fta_assessment),
        "quality-evaluation": (quality_evaluation_template(analysis, authority="owner"), quality_evaluation_assessment, verify_quality_evaluation_assessment),
    }
    for name, (source, assess, verify) in bound.items():
        assessment = assess(analysis, source)
        verdict = verify(assessment, analysis=analysis, source=source)
        for suffix, artifact in (("source", source), ("assessment", assessment), ("verification", verdict)):
            Draft202012Validator(schema_document(f"{name}-{suffix}")).validate(artifact)
    unbound = {
        "security-prioritization": (security_prioritization_template(authority="owner"), security_prioritization_assessment, verify_security_prioritization_assessment),
        "laboratory-governance": (laboratory_governance_template(authority="owner"), laboratory_governance_assessment, verify_laboratory_governance_assessment),
    }
    for name, (source, assess, verify) in unbound.items():
        assessment = assess(source)
        verdict = verify(assessment, source=source)
        for suffix, artifact in (("source", source), ("assessment", assessment), ("verification", verdict)):
            Draft202012Validator(schema_document(f"{name}-{suffix}")).validate(artifact)
