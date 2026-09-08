"""Lossless OpenSSF Scorecard JSON intake and controlled assurance mappings."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .governed_artifact import bounded_text, load_json, publish_json, seal, verify_seal
from .json_ingestion import load_bounded_json_document
from .model import utc_now

SCORECARD_EVIDENCE_FORMAT = "pysfmea-openssf-scorecard-evidence-1"
SCORECARD_EVIDENCE_VERIFICATION_FORMAT = (
    "pysfmea-openssf-scorecard-evidence-verification-1"
)

_MAPPINGS: dict[str, list[dict[str, str]]] = {
    "Binary-Artifacts": [
        {"framework": "OSPS", "target": "openssf-osps-2026-08-28/OSPS-BUILD"}
    ],
    "Branch-Protection": [
        {"framework": "OSPS", "target": "openssf-osps-2026-08-28/OSPS-QUALITY"}
    ],
    "CI-Tests": [
        {"framework": "OSPS", "target": "openssf-osps-2026-08-28/OSPS-QUALITY"}
    ],
    "Code-Review": [
        {"framework": "OSPS", "target": "openssf-osps-2026-08-28/OSPS-QUALITY"}
    ],
    "Contributors": [
        {"framework": "OSPS", "target": "openssf-osps-2026-08-28/OSPS-ACCESS"}
    ],
    "Dangerous-Workflow": [{"framework": "SSDF", "target": "nist-ssdf-1.1/SSDF-PS"}],
    "Dependency-Update-Tool": [
        {"framework": "SSDF", "target": "nist-ssdf-1.1/SSDF-PW"}
    ],
    "Fuzzing": [{"framework": "SSDF", "target": "nist-ssdf-1.1/SSDF-PW"}],
    "License": [
        {"framework": "OSPS", "target": "openssf-osps-2026-08-28/OSPS-DOCUMENT"}
    ],
    "Maintained": [
        {"framework": "OSPS", "target": "openssf-osps-2026-08-28/OSPS-DOCUMENT"}
    ],
    "Packaging": [
        {"framework": "SLSA", "target": "slsa-policy-assessment/build-source-integrity"}
    ],
    "Pinned-Dependencies": [
        {"framework": "OSPS", "target": "openssf-osps-2026-08-28/OSPS-BUILD"}
    ],
    "SAST": [{"framework": "SSDF", "target": "nist-ssdf-1.1/SSDF-PW"}],
    "Security-Policy": [
        {"framework": "OSPS", "target": "openssf-osps-2026-08-28/OSPS-VULNERABILITY"}
    ],
    "Signed-Releases": [
        {"framework": "SLSA", "target": "slsa-policy-assessment/release-integrity"}
    ],
    "Token-Permissions": [
        {"framework": "OSPS", "target": "openssf-osps-2026-08-28/OSPS-ACCESS"}
    ],
    "Vulnerabilities": [{"framework": "SSDF", "target": "nist-ssdf-1.1/SSDF-RV"}],
}


def _normalize_check(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Scorecard check must be an object")
    name = bounded_text(value.get("name"), "Scorecard check name")
    score = value.get("score")
    if not isinstance(score, int) or isinstance(score, bool) or not -1 <= score <= 10:
        raise ValueError(f"Scorecard check {name} has an invalid score")
    documentation = value.get("documentation", {})
    if not isinstance(documentation, dict):
        documentation = {}
    details = value.get("details", [])
    if not isinstance(details, list) or len(details) > 100_000:
        raise ValueError(f"Scorecard check {name} details are invalid")
    return {
        "name": name,
        "score": score,
        "reason": bounded_text(value.get("reason", "not supplied"), "Scorecard reason"),
        "documentation_url": str(documentation.get("url", ""))[:20_000],
        "detail_count": len(details),
        "raw_sha256": hashlib.sha256(
            json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode()
        ).hexdigest(),
        "mappings": _MAPPINGS.get(name, []),
    }


def import_scorecard_evidence(source: str | Path, *, authority: str) -> dict[str, Any]:
    document = load_bounded_json_document(
        source,
        label="OpenSSF Scorecard JSON",
        max_bytes=100 * 1024 * 1024,
        max_depth=100,
        max_nodes=5_000_000,
    )
    raw = document.value
    if not isinstance(raw, dict) or not isinstance(raw.get("checks"), list):
        raise ValueError("Scorecard JSON must contain a checks array")
    checks = [_normalize_check(item) for item in raw["checks"]]
    if len({item["name"] for item in checks}) != len(checks):
        raise ValueError("Scorecard check names must be unique")
    scorecard = raw.get("scorecard", {})
    if not isinstance(scorecard, dict):
        scorecard = {}
    result = seal(
        {
            "format": SCORECARD_EVIDENCE_FORMAT,
            "generated_at": utc_now(),
            "authority": bounded_text(authority, "Scorecard evidence authority"),
            "source": {
                "name": document.path.name,
                "bytes": document.size,
                "sha256": hashlib.sha256(document.raw).hexdigest(),
            },
            "run": {
                "date": str(raw.get("date", "unassigned"))[:20_000],
                "repository": str(
                    raw.get("repo", {}).get("name", "unassigned")
                    if isinstance(raw.get("repo"), dict)
                    else raw.get("repo", "unassigned")
                )[:20_000],
                "score": raw.get("score"),
                "scorecard_version": str(scorecard.get("version", "unassigned"))[
                    :20_000
                ],
                "scorecard_commit": str(scorecard.get("commit", "unassigned"))[:20_000],
            },
            "checks": checks,
            "summary": {
                "checks": len(checks),
                "mapped_checks": sum(bool(item["mappings"]) for item in checks),
                "unmapped_checks": sum(not item["mappings"] for item in checks),
                "failing_checks": sum(item["score"] < 10 for item in checks),
                "evidence_candidates": sum(len(item["mappings"]) for item in checks),
            },
            "claim_boundary": "Scorecard observations are candidate evidence mapped by a controlled crosswalk. Scores do not satisfy OSPS, SSDF, or SLSA objectives without scope, applicability, corroboration, and accountable review.",
        }
    )
    if not verify_scorecard_evidence(result)["valid"]:
        raise ValueError("Scorecard evidence failed internal verification")
    return result


def _summary(checks: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "checks": len(checks),
        "mapped_checks": sum(bool(item.get("mappings")) for item in checks),
        "unmapped_checks": sum(not item.get("mappings") for item in checks),
        "failing_checks": sum(item.get("score", -1) < 10 for item in checks),
        "evidence_candidates": sum(len(item.get("mappings", [])) for item in checks),
    }


def _structure(value: dict[str, Any]) -> bool:
    try:
        checks = value["checks"]
        return bool(
            set(value)
            == {
                "format",
                "generated_at",
                "authority",
                "source",
                "run",
                "checks",
                "summary",
                "claim_boundary",
                "content_sha256",
            }
            and set(value["source"]) == {"name", "bytes", "sha256"}
            and isinstance(value["source"]["bytes"], int)
            and value["source"]["bytes"] > 0
            and bool(re.fullmatch(r"[0-9a-f]{64}", value["source"]["sha256"]))
            and set(value["run"])
            == {"date", "repository", "score", "scorecard_version", "scorecard_commit"}
            and isinstance(checks, list)
            and len(checks) <= 10_000
            and len({item.get("name") for item in checks}) == len(checks)
            and all(
                isinstance(item, dict)
                and set(item)
                == {
                    "name",
                    "score",
                    "reason",
                    "documentation_url",
                    "detail_count",
                    "raw_sha256",
                    "mappings",
                }
                and isinstance(item["score"], int)
                and not isinstance(item["score"], bool)
                and -1 <= item["score"] <= 10
                and bool(re.fullmatch(r"[0-9a-f]{64}", item["raw_sha256"]))
                and item["mappings"] == _MAPPINGS.get(item["name"], [])
                for item in checks
            )
            and value["summary"] == _summary(checks)
        )
    except (KeyError, TypeError):
        return False


def verify_scorecard_evidence(value: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    try:
        checked = verify_seal(
            value, label="Scorecard evidence", format_value=SCORECARD_EVIDENCE_FORMAT
        )
        integrity = True
    except (TypeError, ValueError) as exc:
        checked, integrity = value, False
        errors.append(str(exc))
    structure = _structure(checked)
    if not structure:
        errors.append("Scorecard evidence fields, mappings, or summary are invalid")
    return seal(
        {
            "format": SCORECARD_EVIDENCE_VERIFICATION_FORMAT,
            "valid": integrity and structure,
            "eligible_as_review_input": integrity and structure,
            "checks": {
                "content_integrity": integrity,
                "closed_mapping_and_reconciliation": structure,
            },
            "errors": errors,
            "notice": "Eligibility permits accountable review only and is not framework conformance.",
        }
    )


def export_scorecard_evidence(value: dict[str, Any], destination: str | Path) -> Path:
    if not verify_scorecard_evidence(value)["valid"]:
        raise ValueError("Scorecard evidence is invalid")
    return publish_json(value, destination)


def verify_scorecard_evidence_file(source: str | Path) -> dict[str, Any]:
    try:
        return verify_scorecard_evidence(load_json(source, label="Scorecard evidence"))
    except (OSError, TypeError, ValueError) as exc:
        return seal(
            {
                "format": SCORECARD_EVIDENCE_VERIFICATION_FORMAT,
                "valid": False,
                "eligible_as_review_input": False,
                "checks": {
                    "content_integrity": False,
                    "closed_mapping_and_reconciliation": False,
                },
                "errors": [str(exc)],
                "notice": "Scorecard evidence verification failed closed.",
            }
        )
