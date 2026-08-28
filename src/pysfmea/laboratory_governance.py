"""ISO/IEC 17025-inspired evidence contract for independent evaluation work."""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

from .governed_artifact import (
    bounded_text,
    load_json,
    publish_json,
    seal,
    unique_text_list,
    verify_seal,
)
from .integrity import canonical_json_sha256
from .model import utc_now

LAB_SOURCE_FORMAT = "pysfmea-laboratory-governance-source-1"
LAB_ASSESSMENT_FORMAT = "pysfmea-laboratory-governance-assessment-1"
LAB_VERIFICATION_FORMAT = "pysfmea-laboratory-governance-verification-1"
DOMAINS = ("impartiality", "competence", "method_validation", "equipment_and_software", "metrological_traceability", "measurement_uncertainty", "proficiency_testing", "record_control", "deviation_control")


def laboratory_governance_template(*, authority: str, subject_sha256: str = "0" * 64) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{64}", subject_sha256):
        raise ValueError("laboratory subject digest is invalid")
    return seal({
            "format": LAB_SOURCE_FORMAT,
            "generated_at": utc_now(),
        "authority": bounded_text(authority, "laboratory authority"),
        "subject": {"kind": "benchmark_or_evaluation_campaign", "id": "", "content_sha256": subject_sha256, "scope": ""},
        "roles": {"laboratory_manager": "", "method_owner": "", "technical_reviewer": "", "decision_authority": "", "organizational_independence_basis": ""},
        "controls": [{"domain": domain, "procedure_ref": "", "owner": "", "status": "not_assessed", "evidence_refs": [], "limitations": []} for domain in DOMAINS],
        "nonconformities": [],
        "approval": {"decision": "undetermined", "approved_by": "", "approved_at": "", "rationale": "", "evidence_refs": []},
        "notice": "This evidence contract supports laboratory governance review. It does not confer ISO/IEC 17025 accreditation or manufacture organizational independence.",
    })


def _source(value: dict[str, Any]) -> dict[str, Any]:
    result = verify_seal(value, label="laboratory governance source", format_value=LAB_SOURCE_FORMAT)
    if set(result) != {"format", "generated_at", "authority", "subject", "roles", "controls", "nonconformities", "approval", "notice", "content_sha256"}:
        raise ValueError("laboratory governance source fields are invalid")
    bounded_text(result["authority"], "laboratory authority")
    subject = result["subject"]
    if not isinstance(subject, dict) or set(subject) != {"kind", "id", "content_sha256", "scope"}:
        raise ValueError("laboratory subject fields are invalid")
    for name in ("kind", "id", "scope"):
        bounded_text(subject[name], f"laboratory subject {name}", allow_empty=name != "kind")
    if not re.fullmatch(r"[0-9a-f]{64}", str(subject["content_sha256"])):
        raise ValueError("laboratory subject digest is invalid")
    roles = result["roles"]
    role_fields = {"laboratory_manager", "method_owner", "technical_reviewer", "decision_authority", "organizational_independence_basis"}
    if not isinstance(roles, dict) or set(roles) != role_fields:
        raise ValueError("laboratory role fields are invalid")
    for name in role_fields:
        bounded_text(roles[name], f"laboratory role {name}", allow_empty=True)
    controls = result["controls"]
    if not isinstance(controls, list) or [item.get("domain") for item in controls if isinstance(item, dict)] != list(DOMAINS):
        raise ValueError("laboratory controls must be complete and ordered")
    for item in controls:
        if set(item) != {"domain", "procedure_ref", "owner", "status", "evidence_refs", "limitations"} or item["status"] not in {"not_assessed", "partial", "effective", "ineffective"}:
            raise ValueError("laboratory control fields are invalid")
        bounded_text(item["procedure_ref"], "laboratory procedure ref", allow_empty=True)
        bounded_text(item["owner"], "laboratory control owner", allow_empty=True)
        unique_text_list(item["evidence_refs"], "laboratory control evidence refs")
        unique_text_list(item["limitations"], "laboratory control limitations")
    nonconformities = result["nonconformities"]
    if not isinstance(nonconformities, list) or len(nonconformities) > 100_000:
        raise ValueError("laboratory nonconformities are invalid")
    for item in nonconformities:
        if not isinstance(item, dict) or set(item) != {"id", "domain", "description", "impact", "corrective_action", "owner", "due_at", "status", "evidence_refs"} or item["domain"] not in DOMAINS:
            raise ValueError("laboratory nonconformity fields are invalid")
        for name in ("id", "description", "impact", "corrective_action", "owner", "due_at", "status"):
            bounded_text(item[name], f"laboratory nonconformity {name}")
        unique_text_list(item["evidence_refs"], "laboratory nonconformity evidence refs")
    approval = result["approval"]
    if not isinstance(approval, dict) or set(approval) != {"decision", "approved_by", "approved_at", "rationale", "evidence_refs"} or approval["decision"] not in {"undetermined", "accepted", "conditionally_accepted", "rejected"}:
        raise ValueError("laboratory approval fields are invalid")
    for name in ("approved_by", "approved_at", "rationale"):
        bounded_text(approval[name], f"laboratory approval {name}", allow_empty=True)
    unique_text_list(approval["evidence_refs"], "laboratory approval evidence refs")
    return copy.deepcopy(result)


def laboratory_governance_assessment(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    raw = load_json(source, label="laboratory governance source") if not isinstance(source, dict) else source
    value = _source(raw)
    roles = value["roles"]
    identities = [roles[name].casefold() for name in ("laboratory_manager", "method_owner", "technical_reviewer", "decision_authority") if roles[name]]
    roles_complete = len(identities) == 4 and len(set(identities)) == 4 and bool(roles["organizational_independence_basis"])
    controls_effective = all(item["status"] == "effective" and item["procedure_ref"] and item["owner"] and item["evidence_refs"] for item in value["controls"])
    open_nonconformities = [item["id"] for item in value["nonconformities"] if item["status"] not in {"closed", "accepted"}]
    approval = value["approval"]
    approval_complete = approval["decision"] in {"accepted", "conditionally_accepted"} and approval["approved_by"] == roles["decision_authority"] and all(approval[name] for name in ("approved_at", "rationale", "evidence_refs"))
    subject_complete = bool(value["subject"]["id"] and value["subject"]["scope"] and value["subject"]["content_sha256"] != "0" * 64)
    eligible = subject_complete and roles_complete and controls_effective and not open_nonconformities and approval_complete
    return seal({"format": LAB_ASSESSMENT_FORMAT, "generated_at": value["generated_at"], "source_sha256": value["content_sha256"], "subject": copy.deepcopy(value["subject"]), "summary": {"eligible_for_governed_use": eligible, "subject_complete": subject_complete, "roles_independent": roles_complete, "controls_effective": sum(item["status"] == "effective" for item in value["controls"]), "controls_required": len(DOMAINS), "open_nonconformity_ids": open_nonconformities, "approval_complete": approval_complete}, "notice": "Eligibility is an internal evidence result; only a recognized accreditation body can establish accreditation."})


def seal_laboratory_governance_source(source: str | Path, destination: str | Path) -> Path:
    return publish_json(_source(seal(load_json(source, label="laboratory governance source"))), destination)


def verify_laboratory_governance_assessment(assessment: dict[str, Any], *, source: dict[str, Any] | None = None) -> dict[str, Any]:
    errors: list[str] = []
    eligible = False
    try:
        value = verify_seal(assessment, label="laboratory governance assessment", format_value=LAB_ASSESSMENT_FORMAT)
        if source is not None and canonical_json_sha256(value) != canonical_json_sha256(laboratory_governance_assessment(source)):
            raise ValueError("laboratory governance assessment does not exactly regenerate")
        eligible = bool(value.get("summary", {}).get("eligible_for_governed_use"))
    except (OSError, ValueError, TypeError) as exc:
        errors.append(str(exc))
    return seal({"format": LAB_VERIFICATION_FORMAT, "valid": not errors, "eligible_for_governed_use": not errors and eligible, "errors": errors, "notice": "Verification establishes integrity and optional exact regeneration only."})


def verify_laboratory_governance_assessment_file(assessment_source: str | Path, *, source_path: str | Path | None = None) -> dict[str, Any]:
    try:
        assessment = load_json(assessment_source, label="laboratory governance assessment")
        source = load_json(source_path, label="laboratory governance source") if source_path else None
        return verify_laboratory_governance_assessment(assessment, source=source)
    except (OSError, ValueError, TypeError) as exc:
        return seal({"format": LAB_VERIFICATION_FORMAT, "valid": False, "eligible_for_governed_use": False, "errors": [str(exc)], "notice": "Verification failed closed."})


def export_laboratory_governance_source(value: dict[str, Any], destination: str | Path) -> Path:
    return publish_json(value, destination)


def export_laboratory_governance_assessment(value: dict[str, Any], destination: str | Path) -> Path:
    return publish_json(value, destination)
