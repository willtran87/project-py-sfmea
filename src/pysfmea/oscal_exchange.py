"""OSCAL Assessment Results projection for PySFMEA analysis evidence.

This module emits a conservative OSCAL 1.2.3 Assessment Results document.
PySFMEA findings are observations, not assertions that a NIST control failed.
Normative conformance remains the job of the official NIST OSCAL schema.
"""

from __future__ import annotations

import copy
import re
import uuid
from pathlib import Path
from typing import Any

from .governed_artifact import bounded_text, publish_json, seal
from .model import utc_now
from .report import analysis_state_sha256
from .store import load_analysis

OSCAL_VERSION = "1.2.3"
OSCAL_SCHEMA = "https://github.com/usnistgov/OSCAL/releases/download/v1.2.3/oscal_assessment-results_schema.json"
OSCAL_VERIFICATION_FORMAT = "pysfmea-oscal-assessment-results-verification-1"
_NAMESPACE = uuid.UUID("6086af8e-66dc-5aec-b1ee-8e267e9f42ee")


def _uuid(*parts: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, "\0".join(parts)))


def _text(value: Any, fallback: str) -> str:
    if isinstance(value, str) and value.strip():
        return bounded_text(value, "OSCAL text")
    return fallback


def _finding_id(item: dict[str, Any], index: int) -> str:
    return _text(item.get("id"), f"finding-{index + 1}")


def _active_findings(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    raw = analysis.get("findings", analysis.get("failure_modes", []))
    if not isinstance(raw, list):
        return []
    result = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status", "open")).lower()
        if status not in {"closed", "resolved", "accepted"}:
            result.append(item)
    return result


def oscal_assessment_results(
    analysis: dict[str, Any],
    *,
    authority: str,
    title: str = "PySFMEA software assurance assessment results",
    assessment_plan_href: str | None = None,
    evidence_base_href: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Project analysis findings into an interoperable OSCAL AR document."""

    digest = analysis_state_sha256(analysis)
    timestamp = generated_at or utc_now()
    actor = bounded_text(authority, "OSCAL authority")
    ap_href = assessment_plan_href or f"urn:pysfmea:assessment-plan:{digest}"
    document_uuid = _uuid(
        "assessment-results",
        digest,
        timestamp,
        actor,
        title,
        ap_href,
        evidence_base_href or "",
    )
    party_uuid = _uuid("party", actor)
    result_uuid = _uuid("result", digest)
    observations = []
    for index, finding in enumerate(_active_findings(analysis)):
        identifier = _finding_id(finding, index)
        component_id = _text(
            finding.get("component_id") or finding.get("source_component_id"),
            "unmapped",
        )
        effect = _text(
            finding.get("effect") or finding.get("local_effect") or finding.get("description"),
            "Potential software failure effect requires engineering review.",
        )
        observations.append(
            {
                "uuid": _uuid("observation", digest, identifier),
                "title": _text(finding.get("title") or finding.get("failure_mode"), identifier),
                "description": effect,
                "props": [
                    {"name": "pysfmea-finding-id", "value": identifier},
                    {"name": "pysfmea-component-id", "value": component_id},
                    {"name": "pysfmea-disposition", "value": str(finding.get("status", "open"))},
                ],
                "methods": ["EXAMINE"],
                "types": ["finding"],
                "origins": [{"actors": [{"type": "party", "actor-uuid": party_uuid}]}],
                "collected": timestamp,
                "remarks": "Imported as an engineering observation; no NIST control-effectiveness conclusion is implied.",
            }
        )
    result: dict[str, Any] = {
        "$schema": OSCAL_SCHEMA,
        "assessment-results": {
            "uuid": document_uuid,
            "metadata": {
                "title": bounded_text(title, "OSCAL title"),
                "last-modified": timestamp,
                "version": digest[:12],
                "oscal-version": OSCAL_VERSION,
                "props": [
                    {"name": "pysfmea-analysis-state-sha256", "value": digest},
                    {"name": "pysfmea-baseline-id", "value": str(analysis.get("project", {}).get("baseline", {}).get("id", ""))},
                    {"name": "pysfmea-projection", "value": "assessment-observations"},
                ],
                "roles": [{"id": "assessment-authority", "title": "Assessment authority"}],
                "parties": [{"uuid": party_uuid, "type": "organization", "name": actor}],
                "responsible-parties": [{"role-id": "assessment-authority", "party-uuids": [party_uuid]}],
            },
            "import-ap": {"href": ap_href},
            "results": [
                {
                    "uuid": result_uuid,
                    "title": "Static software assurance observations",
                    "description": "Observations projected from the exact PySFMEA analysis state.",
                    "start": timestamp,
                    "reviewed-controls": {"control-selections": [{"include-all": {}}]},
                    "observations": observations,
                    "remarks": "Control applicability, tailoring, implementation status, and risk acceptance remain authority decisions.",
                }
            ],
        },
    }
    if evidence_base_href:
        result["assessment-results"]["back-matter"] = {
            "resources": [{"uuid": _uuid("evidence", digest), "title": "PySFMEA evidence base", "rlinks": [{"href": bounded_text(evidence_base_href, "OSCAL evidence URI")}]}]
        }
    return result


def _digest_from(value: dict[str, Any]) -> str | None:
    try:
        props = value["assessment-results"]["metadata"]["props"]
        matches = [p.get("value") for p in props if isinstance(p, dict) and p.get("name") == "pysfmea-analysis-state-sha256"]
        return matches[0] if len(matches) == 1 and isinstance(matches[0], str) else None
    except (KeyError, TypeError):
        return None


def verify_oscal_assessment_results(
    value: dict[str, Any], *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        root = value["assessment-results"]
        metadata = root["metadata"]
        results = root["results"]
        digest = _digest_from(value)
        structure = bool(
            set(value) <= {"$schema", "assessment-results"}
            and value.get("$schema") == OSCAL_SCHEMA
            and re.fullmatch(r"[0-9a-f]{64}", digest or "")
            and metadata.get("oscal-version") == OSCAL_VERSION
            and isinstance(results, list) and len(results) == 1
            and isinstance(results[0].get("observations", []), list)
            and len({item.get("uuid") for item in results[0].get("observations", [])}) == len(results[0].get("observations", []))
        )
    except (KeyError, TypeError):
        structure, digest = False, None
    if not structure:
        errors.append("OSCAL Assessment Results supported subset is invalid")
    binding: bool | None = None
    regeneration: bool | None = None
    if analysis is not None:
        binding = digest == analysis_state_sha256(analysis)
        if not binding:
            errors.append("OSCAL document does not bind the exact analysis state")
        if structure:
            try:
                root = value["assessment-results"]
                metadata = root["metadata"]
                party = metadata["parties"][0]["name"]
                back = root.get("back-matter", {}).get("resources", [])
                evidence = back[0]["rlinks"][0]["href"] if back else None
                expected = oscal_assessment_results(
                    analysis,
                    authority=party,
                    title=metadata["title"],
                    assessment_plan_href=root["import-ap"]["href"],
                    evidence_base_href=evidence,
                    generated_at=metadata["last-modified"],
                )
                regeneration = expected == value
                if not regeneration:
                    errors.append("OSCAL document does not exactly regenerate")
            except (KeyError, TypeError, ValueError):
                regeneration = False
                errors.append("OSCAL regeneration inputs are invalid")
    valid = structure and binding is not False and regeneration is not False
    return seal({"format": OSCAL_VERIFICATION_FORMAT, "valid": valid, "ready_for_normative_validation": valid, "checks": {"supported_subset": structure, "analysis_binding": binding, "exact_regeneration": regeneration}, "errors": errors, "notice": "This verifies the PySFMEA OSCAL subset and exact analysis binding. Validate against the official NIST OSCAL schema and the receiving system before use."})


def verify_oscal_assessment_results_file(source: str | Path, *, analysis: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        from .governed_artifact import load_json

        return verify_oscal_assessment_results(load_json(source, label="OSCAL Assessment Results"), analysis=analysis)
    except (OSError, TypeError, ValueError) as exc:
        return seal({"format": OSCAL_VERIFICATION_FORMAT, "valid": False, "ready_for_normative_validation": False, "checks": {"supported_subset": False, "analysis_binding": False if analysis is not None else None, "exact_regeneration": False if analysis is not None else None}, "errors": [str(exc)], "notice": "OSCAL verification failed closed."})


def export_oscal_assessment_results(value: dict[str, Any], destination: str | Path) -> Path:
    if not verify_oscal_assessment_results(value)["valid"]:
        raise ValueError("OSCAL Assessment Results document is internally invalid")
    return publish_json(copy.deepcopy(value), destination)


def export_oscal_from_analysis_file(source: str | Path, destination: str | Path, **kwargs: Any) -> Path:
    return export_oscal_assessment_results(oscal_assessment_results(load_analysis(source), **kwargs), destination)
