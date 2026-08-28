"""Governed CycloneDX 1.7 VEX publication from explicit human decisions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .interchange import cyclonedx_document
from .json_ingestion import load_bounded_json_document
from .report import analysis_state_sha256

VEX_DECISIONS_FORMAT = "pysfmea-vex-decisions-1"
VEX_VERIFICATION_FORMAT = "pysfmea-cyclonedx-vex-verification-1"
STATES = {
    "resolved",
    "resolved_with_pedigree",
    "exploitable",
    "in_triage",
    "false_positive",
    "not_affected",
}
JUSTIFICATIONS = {
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
}
RESPONSES = {
    "can_not_fix",
    "will_not_fix",
    "update",
    "rollback",
    "workaround_available",
}


def _decisions(value: Any) -> dict[str, Any]:
    required = {"format", "authority", "issued_at", "vulnerabilities"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("VEX decision fields do not match format 1")
    if value.get("format") != VEX_DECISIONS_FORMAT:
        raise ValueError("VEX decision format is unsupported")
    for field in ("authority", "issued_at"):
        if not isinstance(value[field], str) or not value[field].strip() or len(value[field]) > 20_000:
            raise ValueError(f"VEX {field} must be non-empty bounded text")
    entries = value["vulnerabilities"]
    fields = {
        "id",
        "source_name",
        "source_url",
        "state",
        "justification",
        "response",
        "detail",
        "affected_refs",
        "evidence_refs",
    }
    if not isinstance(entries, list) or len(entries) > 100_000:
        raise ValueError("VEX vulnerabilities must be a bounded list")
    identifiers: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != fields:
            raise ValueError("VEX vulnerability fields do not match format 1")
        identifier = entry["id"]
        if not isinstance(identifier, str) or not identifier.strip() or identifier in identifiers:
            raise ValueError("VEX vulnerability IDs must be non-empty and unique")
        identifiers.add(identifier)
        if entry["state"] not in STATES:
            raise ValueError("VEX analysis state is unsupported")
        justification = entry["justification"]
        if justification is not None and justification not in JUSTIFICATIONS:
            raise ValueError("VEX justification is unsupported")
        if entry["state"] == "not_affected" and justification not in JUSTIFICATIONS:
            raise ValueError("not_affected decisions require a recognized justification")
        response = entry["response"]
        if not isinstance(response, list) or len(response) != len(set(response)) or not set(response) <= RESPONSES:
            raise ValueError("VEX responses are invalid")
        for field in ("source_name", "source_url", "detail"):
            if not isinstance(entry[field], str) or not entry[field].strip() or len(entry[field]) > 20_000:
                raise ValueError(f"VEX vulnerability {field} must be non-empty bounded text")
        for field in ("affected_refs", "evidence_refs"):
            values = entry[field]
            if not isinstance(values, list) or not values or len(values) != len(set(values)) or any(not isinstance(item, str) or not item.strip() for item in values):
                raise ValueError(f"VEX {field} must contain unique non-empty references")
    return value


def cyclonedx_vex_document(
    analysis: dict[str, Any], decisions: dict[str, Any]
) -> dict[str, Any]:
    """Create a CycloneDX VEX BOM without inferring exploitability decisions."""

    governed = _decisions(decisions)
    document = cyclonedx_document(
        analysis, generated_at=str(governed["issued_at"])
    )
    known_refs = {"project", *(item["bom-ref"] for item in document["components"])}
    vulnerabilities = []
    for entry in governed["vulnerabilities"]:
        unknown = set(entry["affected_refs"]) - known_refs
        if unknown:
            raise ValueError(f"VEX decision refers to unknown BOM references: {sorted(unknown)}")
        analysis_entry: dict[str, Any] = {
            "state": entry["state"],
            "detail": entry["detail"],
            "firstIssued": governed["issued_at"],
            "lastUpdated": governed["issued_at"],
        }
        if entry["justification"] is not None:
            analysis_entry["justification"] = entry["justification"]
        if entry["response"]:
            analysis_entry["response"] = entry["response"]
        vulnerabilities.append(
            {
                "id": entry["id"],
                "source": {"name": entry["source_name"], "url": entry["source_url"]},
                "analysis": analysis_entry,
                "affects": [{"ref": value} for value in entry["affected_refs"]],
                "properties": [
                    {"name": "pysfmea:decision-authority", "value": governed["authority"]},
                    *(
                        {"name": "pysfmea:evidence-ref", "value": value}
                        for value in entry["evidence_refs"]
                    ),
                ],
            }
        )
    document["vulnerabilities"] = vulnerabilities
    document["metadata"].setdefault("properties", []).extend(
        [
            {"name": "pysfmea:analysis-state-sha256", "value": analysis_state_sha256(analysis)},
            {"name": "pysfmea:vex-decisions-canonical-sha256", "value": canonical_json_sha256(governed)},
            {"name": "pysfmea:vex-decision-authority", "value": governed["authority"]},
        ]
    )
    return document


def verify_cyclonedx_vex(
    document: dict[str, Any], analysis: dict[str, Any], decisions: dict[str, Any]
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        expected = cyclonedx_vex_document(analysis, decisions)
        structure = bool(
            document.get("bomFormat") == "CycloneDX"
            and document.get("specVersion") == "1.7"
            and isinstance(document.get("vulnerabilities"), list)
        )
        exact = canonical_json_sha256(document) == canonical_json_sha256(expected)
        decisions_valid = True
    except (KeyError, TypeError, ValueError) as exc:
        structure = False
        exact = False
        decisions_valid = False
        errors.append(str(exc))
    if not structure:
        errors.append("CycloneDX 1.7 VEX structure is invalid")
    if not exact:
        errors.append("VEX does not exactly regenerate from analysis and governed decisions")
    return {
        "format": VEX_VERIFICATION_FORMAT,
        "valid": structure and exact and decisions_valid,
        "checks": {
            "cyclonedx_1_7_structure": structure,
            "governed_decisions": decisions_valid,
            "exact_source_regeneration": exact,
        },
        "vulnerabilities": len(document.get("vulnerabilities", [])) if isinstance(document.get("vulnerabilities"), list) else 0,
        "errors": errors,
        "notice": "VEX states are attributed human decisions; this verifier does not independently establish exploitability or authenticate the authority.",
    }


def export_cyclonedx_vex(
    analysis: dict[str, Any], decisions_source: str | Path, destination: str | Path
) -> Path:
    source = load_bounded_json_document(
        decisions_source,
        label="VEX decisions",
        max_bytes=25_000_000,
        max_depth=40,
        max_nodes=1_000_000,
    )
    if not isinstance(source.value, dict):
        raise ValueError("VEX decisions must contain an object")
    document = cyclonedx_vex_document(analysis, source.value)
    return atomic_publish_text(
        destination,
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        label="CycloneDX VEX",
    )


def verify_cyclonedx_vex_file(
    artifact: str | Path, analysis: dict[str, Any], decisions_source: str | Path
) -> dict[str, Any]:
    try:
        artifact_path = Path(artifact).expanduser().resolve()
        raw = artifact_path.read_bytes()
        if len(raw) > 100_000_000:
            raise ValueError("CycloneDX VEX exceeds the byte limit")
        document = json.loads(raw.decode("utf-8"))
        decision_document = load_bounded_json_document(
            decisions_source,
            label="VEX decisions",
            max_bytes=25_000_000,
            max_depth=40,
            max_nodes=1_000_000,
        )
        if not isinstance(document, dict) or not isinstance(decision_document.value, dict):
            raise ValueError("VEX artifacts must contain JSON objects")
        return {
            "path": str(artifact_path),
            "sha256": hashlib.sha256(raw).hexdigest(),
            **verify_cyclonedx_vex(document, analysis, decision_document.value),
        }
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "path": str(Path(artifact).expanduser().absolute()),
            "format": VEX_VERIFICATION_FORMAT,
            "valid": False,
            "checks": {"cyclonedx_1_7_structure": False, "governed_decisions": False, "exact_source_regeneration": False},
            "vulnerabilities": 0,
            "errors": [str(exc)],
            "notice": "The CycloneDX VEX could not be safely verified.",
        }
