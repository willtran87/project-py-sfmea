"""OASIS CSAF 2.0 advisory projection from governed VEX decisions."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .report import analysis_state_sha256
from .vex import cyclonedx_vex_document

CSAF_VERIFICATION_FORMAT = "pysfmea-csaf-2-verification-1"
CSAF_VERSION = "2.0"
PRODUCT_ID = "CSAFPID-PYSFMEA-PROJECT"

_STATUS = {
    "resolved": "fixed",
    "resolved_with_pedigree": "fixed",
    "exploitable": "known_affected",
    "in_triage": "under_investigation",
    "false_positive": "known_not_affected",
    "not_affected": "known_not_affected",
}


def csaf_document(
    analysis: dict[str, Any], decisions: dict[str, Any]
) -> dict[str, Any]:
    """Create a deterministic CSAF security advisory without inferring status."""

    # Reuse the closed decision validation and known-product reconciliation.
    cyclonedx_vex_document(analysis, decisions)
    issued_at = str(decisions["issued_at"])
    authority = str(decisions["authority"])
    project_name = str(analysis.get("project", {}).get("name", "python-project"))
    state_sha = analysis_state_sha256(analysis)
    decision_sha = canonical_json_sha256(decisions)
    tracking_id = "PY-SFMEA-" + hashlib.sha256(
        f"{project_name}:{decision_sha}".encode("utf-8")
    ).hexdigest()[:20].upper()
    vulnerabilities: list[dict[str, Any]] = []
    for entry in decisions["vulnerabilities"]:
        status = _STATUS[str(entry["state"])]
        vulnerability: dict[str, Any] = {
            "ids": [
                {
                    "system_name": str(entry["source_name"]),
                    "text": str(entry["id"]),
                }
            ],
            "notes": [
                {
                    "category": "details",
                    "text": (
                        f"{entry['detail']} Decision authority: {authority}. "
                        f"State: {entry['state']}. Justification: "
                        f"{entry['justification'] or 'not supplied'}. Evidence: "
                        + ", ".join(entry["evidence_refs"])
                    ),
                    "title": "Governed product-status decision",
                }
            ],
            "product_status": {status: [PRODUCT_ID]},
            "references": [
                {
                    "category": "external",
                    "summary": f"{entry['source_name']} record for {entry['id']}",
                    "url": str(entry["source_url"]),
                }
            ],
            "title": str(entry["id"]),
        }
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", str(entry["id"]), re.IGNORECASE):
            vulnerability["cve"] = str(entry["id"]).upper()
        vulnerabilities.append(vulnerability)
    return {
        "document": {
            "category": "csaf_security_advisory",
            "csaf_version": CSAF_VERSION,
            "notes": [
                {
                    "category": "summary",
                    "text": (
                        f"PySFMEA analysis state SHA-256: {state_sha}; governed VEX "
                        f"decisions canonical SHA-256: {decision_sha}. Product status is "
                        "authority-attributed and is not inferred by static analysis."
                    ),
                    "title": "PySFMEA evidence binding",
                }
            ],
            "publisher": {
                "category": "vendor",
                "name": authority,
                "namespace": "https://github.com/willtran87/project-py-sfmea",
            },
            "title": f"{project_name} governed security advisory",
            "tracking": {
                "current_release_date": issued_at,
                "id": tracking_id,
                "initial_release_date": issued_at,
                "revision_history": [
                    {
                        "date": issued_at,
                        "number": "1",
                        "summary": "Initial governed PySFMEA advisory projection.",
                    }
                ],
                "status": "final",
                "version": "1",
            },
        },
        "product_tree": {
            "branches": [
                {
                    "category": "product_name",
                    "name": project_name,
                    "product": {"name": project_name, "product_id": PRODUCT_ID},
                }
            ]
        },
        "vulnerabilities": vulnerabilities,
    }


def verify_csaf(
    document: dict[str, Any], analysis: dict[str, Any], decisions: dict[str, Any]
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        expected = csaf_document(analysis, decisions)
        structure = bool(
            document.get("document", {}).get("csaf_version") == CSAF_VERSION
            and document.get("document", {}).get("category")
            == "csaf_security_advisory"
            and isinstance(document.get("product_tree"), dict)
            and isinstance(document.get("vulnerabilities"), list)
        )
        exact = canonical_json_sha256(document) == canonical_json_sha256(expected)
        governed = True
    except (KeyError, TypeError, ValueError) as exc:
        structure = False
        exact = False
        governed = False
        errors.append(str(exc))
    if not structure:
        errors.append("CSAF 2.0 security-advisory structure is invalid")
    if not exact:
        errors.append("CSAF advisory does not regenerate from exact governed sources")
    return {
        "format": CSAF_VERIFICATION_FORMAT,
        "valid": bool(structure and exact and governed),
        "checks": {
            "csaf_2_structure": structure,
            "governed_decisions": governed,
            "exact_source_regeneration": exact,
        },
        "vulnerabilities": (
            len(document.get("vulnerabilities", []))
            if isinstance(document.get("vulnerabilities"), list)
            else 0
        ),
        "errors": errors,
        "notice": (
            "Internal verification proves governed projection and exact binding. Use "
            "industry-schema-validate with the OASIS schema for normative validation."
        ),
    }


def export_csaf(
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
    document = csaf_document(analysis, source.value)
    verdict = verify_csaf(document, analysis, source.value)
    if not verdict["valid"]:
        raise RuntimeError("generated CSAF advisory failed internal verification")
    return atomic_publish_text(
        destination,
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        label="CSAF 2.0 advisory",
    )


def verify_csaf_file(
    artifact: str | Path, analysis: dict[str, Any], decisions_source: str | Path
) -> dict[str, Any]:
    try:
        artifact_document = load_bounded_json_document(
            artifact,
            label="CSAF advisory",
            max_bytes=100_000_000,
            max_depth=100,
            max_nodes=2_000_000,
        )
        decisions_document = load_bounded_json_document(
            decisions_source,
            label="VEX decisions",
            max_bytes=25_000_000,
            max_depth=40,
            max_nodes=1_000_000,
        )
        if not isinstance(artifact_document.value, dict) or not isinstance(
            decisions_document.value, dict
        ):
            raise ValueError("CSAF and decision artifacts must contain JSON objects")
        return {
            "path": str(artifact_document.path),
            "sha256": hashlib.sha256(artifact_document.raw).hexdigest(),
            **verify_csaf(
                artifact_document.value, analysis, decisions_document.value
            ),
        }
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "path": str(Path(artifact).expanduser().absolute()),
            "format": CSAF_VERIFICATION_FORMAT,
            "valid": False,
            "checks": {
                "csaf_2_structure": False,
                "governed_decisions": False,
                "exact_source_regeneration": False,
            },
            "vulnerabilities": 0,
            "errors": [str(exc)],
            "notice": "The CSAF advisory could not be safely verified.",
        }
