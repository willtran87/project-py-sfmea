"""Evidence intake for CVSS v4.0, OWASP ASVS 5.0, and SSVC cross-references."""

from __future__ import annotations

import copy
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

SECURITY_SOURCE_FORMAT = "pysfmea-security-prioritization-source-1"
SECURITY_ASSESSMENT_FORMAT = "pysfmea-security-prioritization-assessment-1"
SECURITY_VERIFICATION_FORMAT = "pysfmea-security-prioritization-verification-1"
BASE_ORDER = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
OPTIONAL_ORDER = ("E", "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA", "S", "AU", "R", "V", "RE", "U")
VALUES = {
    "AV": set("NALP"), "AC": set("LH"), "AT": set("NP"), "PR": set("NLH"), "UI": set("NPA"),
    "VC": set("HLN"), "VI": set("HLN"), "VA": set("HLN"), "SC": set("HLN"), "SI": set("HLN"), "SA": set("HLN"),
    "E": set("XAPU"), "CR": set("XHML"), "IR": set("XHML"), "AR": set("XHML"),
    "MAV": set("XNALP"), "MAC": set("XLH"), "MAT": set("XNP"), "MPR": set("XNLH"), "MUI": set("XNPA"),
    "MVC": set("XHLN"), "MVI": set("XHLN"), "MVA": set("XHLN"), "MSC": set("XHLN"), "MSI": set("XSHLN"), "MSA": set("XSHLN"),
    "S": set("XNP"), "AU": set("XNY"), "R": set("XAUI"), "V": set("XDC"), "RE": set("XLMH"),
    "U": {"X", "Clear", "Green", "Amber", "Red"},
}
MAX_RECORDS = 100_000


def parse_cvss_v4_vector(vector: str) -> dict[str, str]:
    raw = bounded_text(vector, "CVSS v4 vector")
    parts = raw.split("/")
    if not parts or parts[0] != "CVSS:4.0":
        raise ValueError("CVSS vector must start with CVSS:4.0")
    metrics: dict[str, str] = {}
    order: list[str] = []
    for part in parts[1:]:
        if part.count(":") != 1:
            raise ValueError("CVSS metric token is invalid")
        name, metric_value = part.split(":")
        if name not in VALUES or metric_value not in VALUES[name] or name in metrics:
            raise ValueError(f"CVSS metric {name or '<empty>'} is invalid or duplicated")
        metrics[name] = metric_value
        order.append(name)
    if tuple(order[: len(BASE_ORDER)]) != BASE_ORDER or not set(BASE_ORDER) <= set(metrics):
        raise ValueError("CVSS v4 base metrics must be complete and in canonical order")
    expected_optional = [name for name in OPTIONAL_ORDER if name in metrics]
    if order[len(BASE_ORDER):] != expected_optional:
        raise ValueError("CVSS v4 optional metrics must follow canonical order")
    return metrics


def security_prioritization_template(*, authority: str) -> dict[str, Any]:
    return seal({
            "format": SECURITY_SOURCE_FORMAT,
            "generated_at": utc_now(),
        "authority": bounded_text(authority, "security authority"),
        "policy": {"cvss_nomenclature": "CVSS:4.0", "asvs_version": "5.0.0", "ssvc_policy_ref": "", "decision_authority": "", "review_cadence": "", "scope": ""},
        "vulnerabilities": [],
        "evidence_refs": [],
        "notice": "CVSS scores are externally observed, not calculated here. Prioritization must combine severity, application-control evidence, stakeholder-specific vulnerability context, and an authorized decision.",
    })


def _source(value: dict[str, Any]) -> dict[str, Any]:
    result = verify_seal(value, label="security prioritization source", format_value=SECURITY_SOURCE_FORMAT)
    if set(result) != {"format", "generated_at", "authority", "policy", "vulnerabilities", "evidence_refs", "notice", "content_sha256"}:
        raise ValueError("security prioritization source fields are invalid")
    bounded_text(result["authority"], "security authority")
    unique_text_list(result["evidence_refs"], "security evidence refs")
    policy = result["policy"]
    if not isinstance(policy, dict) or set(policy) != {"cvss_nomenclature", "asvs_version", "ssvc_policy_ref", "decision_authority", "review_cadence", "scope"}:
        raise ValueError("security policy fields are invalid")
    if policy["cvss_nomenclature"] != "CVSS:4.0" or policy["asvs_version"] != "5.0.0":
        raise ValueError("security policy versions must be CVSS:4.0 and ASVS 5.0.0")
    for name in ("ssvc_policy_ref", "decision_authority", "review_cadence", "scope"):
        bounded_text(policy[name], f"security policy {name}", allow_empty=True)
    records = result["vulnerabilities"]
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError("security vulnerability records are invalid")
    fields = {"id", "component_refs", "cvss_vector", "cvss_score", "cvss_rating", "calculator_name", "calculator_version", "calculator_evidence_ref", "asvs_requirement_refs", "asvs_evidence_refs", "ssvc_decision_ref", "ssvc_outcome", "disposition", "owner", "due_at", "reviewer", "reviewed_at", "evidence_refs"}
    ids: list[str] = []
    for item in records:
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError("security vulnerability fields are invalid")
        ids.append(bounded_text(item["id"], "vulnerability id"))
        parse_cvss_v4_vector(item["cvss_vector"])
        score = item["cvss_score"]
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= float(score) <= 10:
            raise ValueError("observed CVSS score is invalid")
        expected_rating = "none" if score == 0 else "low" if score < 4 else "medium" if score < 7 else "high" if score < 9 else "critical"
        if item["cvss_rating"] != expected_rating:
            raise ValueError("CVSS qualitative rating does not match the observed score")
        for name in ("calculator_name", "calculator_version", "calculator_evidence_ref", "ssvc_decision_ref", "ssvc_outcome", "disposition", "owner", "due_at", "reviewer", "reviewed_at"):
            bounded_text(item[name], f"vulnerability {name}")
        for name in ("component_refs", "asvs_requirement_refs", "asvs_evidence_refs", "evidence_refs"):
            unique_text_list(item[name], f"vulnerability {name}")
        if len(item["asvs_requirement_refs"]) != len(item["asvs_evidence_refs"]):
            raise ValueError("ASVS requirement and evidence reference counts must match")
    if len(ids) != len(set(ids)):
        raise ValueError("vulnerability ids must be unique")
    return copy.deepcopy(result)


def security_prioritization_assessment(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    raw = load_json(source, label="security prioritization source") if not isinstance(source, dict) else source
    value = _source(raw)
    policy = value["policy"]
    results = []
    for item in value["vulnerabilities"]:
        complete = bool(item["component_refs"] and item["calculator_evidence_ref"] and item["asvs_requirement_refs"] and item["ssvc_decision_ref"] and item["disposition"] and item["owner"] and item["reviewer"] and item["evidence_refs"])
        results.append({"id": item["id"], "complete": complete, "cvss_rating": item["cvss_rating"], "ssvc_outcome": item["ssvc_outcome"], "disposition": item["disposition"]})
    complete = bool(results and all(item["complete"] for item in results) and all(policy[name] for name in ("ssvc_policy_ref", "decision_authority", "review_cadence", "scope")))
    return seal({"format": SECURITY_ASSESSMENT_FORMAT, "generated_at": value["generated_at"], "source_sha256": value["content_sha256"], "results": results, "summary": {"complete": complete, "vulnerabilities": len(results), "records_complete": sum(item["complete"] for item in results)}, "notice": "Completeness confirms cross-referenced evidence, not vulnerability remediation or application-security conformity."})


def seal_security_prioritization_source(source: str | Path, destination: str | Path) -> Path:
    return publish_json(_source(seal(load_json(source, label="security prioritization source"))), destination)


def verify_security_prioritization_assessment(assessment: dict[str, Any], *, source: dict[str, Any] | None = None) -> dict[str, Any]:
    errors: list[str] = []
    complete = False
    try:
        value = verify_seal(assessment, label="security prioritization assessment", format_value=SECURITY_ASSESSMENT_FORMAT)
        if source is not None and canonical_json_sha256(value) != canonical_json_sha256(security_prioritization_assessment(source)):
            raise ValueError("security prioritization assessment does not exactly regenerate")
        complete = bool(value.get("summary", {}).get("complete"))
    except (OSError, ValueError, TypeError) as exc:
        errors.append(str(exc))
    return seal({"format": SECURITY_VERIFICATION_FORMAT, "valid": not errors, "complete": not errors and complete, "errors": errors, "notice": "Verification establishes integrity and optional exact regeneration only."})


def verify_security_prioritization_assessment_file(assessment_source: str | Path, *, source_path: str | Path | None = None) -> dict[str, Any]:
    try:
        assessment = load_json(assessment_source, label="security prioritization assessment")
        source = load_json(source_path, label="security prioritization source") if source_path else None
        return verify_security_prioritization_assessment(assessment, source=source)
    except (OSError, ValueError, TypeError) as exc:
        return seal({"format": SECURITY_VERIFICATION_FORMAT, "valid": False, "complete": False, "errors": [str(exc)], "notice": "Verification failed closed."})


def export_security_prioritization_source(value: dict[str, Any], destination: str | Path) -> Path:
    return publish_json(value, destination)


def export_security_prioritization_assessment(value: dict[str, Any], destination: str | Path) -> Path:
    return publish_json(value, destination)
