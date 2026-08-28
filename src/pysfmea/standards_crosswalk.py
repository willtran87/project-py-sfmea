"""Exact-bound standards-objective to finding and evidence crosswalks."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .conformance import (
    load_conformance_workspace,
    verify_conformance_workspace,
)
from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import BoundedJsonDocument, load_bounded_json_document
from .model import utc_now
from .report import analysis_state_sha256

CROSSWALK_MAPPING_FORMAT = "pysfmea-standards-crosswalk-mapping-1"
CROSSWALK_FORMAT = "pysfmea-standards-crosswalk-1"
CROSSWALK_VERIFICATION_FORMAT = "pysfmea-standards-crosswalk-verification-1"
RELATIONSHIPS = {"direct", "supporting", "contextual"}
MAX_BYTES = 100_000_000
MAX_TEXT = 20_000
MAX_LINKS = 100_000


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT:
        raise ValueError(f"{label} must be non-empty bounded text")
    return value.strip()


def _document(source: str | Path, label: str) -> BoundedJsonDocument:
    return load_bounded_json_document(
        source,
        label=label,
        max_bytes=MAX_BYTES,
        max_depth=80,
        max_nodes=2_000_000,
    )


def _binding(document: BoundedJsonDocument) -> dict[str, Any]:
    return {
        "reference": document.path.name,
        "bytes": document.size,
        "sha256": hashlib.sha256(document.raw).hexdigest(),
        "canonical_sha256": canonical_json_sha256(document.value),
    }


def _digest(value: dict[str, Any]) -> str:
    unsigned = copy.deepcopy(value)
    unsigned.pop("content_sha256", None)
    return canonical_json_sha256(unsigned)


def _mapping(value: Any) -> list[dict[str, Any]]:
    if (
        not isinstance(value, dict)
        or set(value) != {"format", "links"}
        or value.get("format") != CROSSWALK_MAPPING_FORMAT
    ):
        raise ValueError("standards crosswalk mapping fields or format do not match format 1")
    links = value.get("links")
    if not isinstance(links, list) or len(links) > MAX_LINKS:
        raise ValueError("standards crosswalk links must be a bounded list")
    required = {
        "objective_id",
        "relationship",
        "finding_ids",
        "obligation_ids",
        "rationale",
        "authority",
        "evidence_refs",
    }
    seen: set[tuple[str, str]] = set()
    result: list[dict[str, Any]] = []
    for link in links:
        if not isinstance(link, dict) or set(link) != required:
            raise ValueError("standards crosswalk link fields do not match format 1")
        objective_id = _text(link["objective_id"], "crosswalk objective id")
        relationship = link["relationship"]
        if relationship not in RELATIONSHIPS:
            raise ValueError("crosswalk relationship is unsupported")
        key = (objective_id, relationship)
        if key in seen:
            raise ValueError("objective and relationship pairs must be unique")
        seen.add(key)
        for field in ("finding_ids", "obligation_ids", "evidence_refs"):
            values = link[field]
            if (
                not isinstance(values, list)
                or len(values) > MAX_LINKS
                or len(values) != len(set(values))
                or any(not isinstance(item, str) or not item.strip() for item in values)
            ):
                raise ValueError(f"crosswalk {field} must contain unique identifiers")
        if not link["finding_ids"] and not link["obligation_ids"] and not link["evidence_refs"]:
            raise ValueError("crosswalk links require a finding, obligation, or evidence reference")
        _text(link["rationale"], "crosswalk rationale")
        _text(link["authority"], "crosswalk authority")
        result.append(copy.deepcopy(link))
    return result


def standards_crosswalk(
    analysis: dict[str, Any],
    analysis_source: str | Path,
    workspace_source: str | Path,
    mapping_source: str | Path,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build an exact-bound, authority-attributed objective trace."""

    analysis_document = _document(analysis_source, "crosswalk analysis")
    if analysis_document.value != analysis:
        raise ValueError("supplied analysis does not match the exact analysis file")
    workspace_document = _document(workspace_source, "conformance workspace")
    mapping_document = _document(mapping_source, "standards crosswalk mapping")
    workspace = load_conformance_workspace(workspace_document.path)
    workspace_verdict = verify_conformance_workspace(workspace, analysis=analysis)
    if not workspace_verdict["valid"]:
        raise ValueError("conformance workspace is not valid for the supplied analysis")
    links = _mapping(mapping_document.value)
    active_findings = {
        str(item.get("id"))
        for item in analysis.get("items", [])
        if isinstance(item, dict) and item.get("source_status", "active") == "active"
    }
    obligations = {
        str(item.get("id")): str(item.get("finding_id", ""))
        for item in analysis.get("assurance", {}).get("obligations", [])
        if isinstance(item, dict)
    }
    objective_records = {
        str(objective["id"]): (str(profile["id"]), objective)
        for profile in workspace["profiles"]
        for objective in profile["objectives"]
    }
    for link in links:
        if link["objective_id"] not in objective_records:
            raise ValueError(f"unknown crosswalk objective: {link['objective_id']}")
        unknown_findings = set(link["finding_ids"]) - active_findings
        unknown_obligations = set(link["obligation_ids"]) - set(obligations)
        if unknown_findings or unknown_obligations:
            raise ValueError("crosswalk refers to unknown active findings or obligations")
        obligation_findings = {
            obligations[value] for value in link["obligation_ids"] if obligations[value]
        }
        if obligation_findings - active_findings:
            raise ValueError("crosswalk obligation does not belong to an active finding")
    by_objective: dict[str, list[dict[str, Any]]] = {
        identifier: [] for identifier in objective_records
    }
    for link in links:
        by_objective[link["objective_id"]].append(link)
    objectives: list[dict[str, Any]] = []
    mapped_findings: set[str] = set()
    for identifier, (profile_id, objective) in objective_records.items():
        objective_links = [
            {
                **copy.deepcopy(link),
                "finding_ids_via_obligations": sorted(
                    {
                        obligations[value]
                        for value in link["obligation_ids"]
                        if obligations[value]
                    }
                ),
            }
            for link in sorted(
                by_objective[identifier], key=lambda item: item["relationship"]
            )
        ]
        for link in objective_links:
            mapped_findings.update(link["finding_ids"])
            mapped_findings.update(
                link["finding_ids_via_obligations"]
            )
        objectives.append(
            {
                "profile_id": profile_id,
                "objective_id": identifier,
                "reference_locator": objective["reference_locator"],
                "applicability": objective["applicability"],
                "assessment_status": objective["status"],
                "workspace_evidence_refs": objective["evidence_refs"],
                "links": objective_links,
                "trace_status": "linked"
                if objective_links or objective["evidence_refs"]
                else (
                    "not_applicable"
                    if objective["applicability"] == "not_applicable"
                    else "unlinked"
                ),
            }
        )
    applicable = [
        item for item in objectives if item["applicability"] == "applicable"
    ]
    unlinked_objectives = [
        item["objective_id"] for item in applicable if item["trace_status"] == "unlinked"
    ]
    unmapped_findings = sorted(active_findings - mapped_findings)
    result: dict[str, Any] = {
        "format": CROSSWALK_FORMAT,
        "generated_at": generated_at or utc_now(),
        "binding": {
            "analysis": {
                **_binding(analysis_document),
                "analysis_state_sha256": analysis_state_sha256(analysis),
            },
            "conformance_workspace": _binding(workspace_document),
            "mapping": _binding(mapping_document),
        },
        "objectives": objectives,
        "summary": {
            "objectives": len(objectives),
            "applicable_objectives": len(applicable),
            "linked_applicable_objectives": len(applicable) - len(unlinked_objectives),
            "active_findings": len(active_findings),
            "mapped_findings": len(mapped_findings),
            "unlinked_objective_ids": sorted(unlinked_objectives),
            "unmapped_finding_ids": unmapped_findings,
            "trace_complete": not unlinked_objectives and not unmapped_findings,
        },
        "claim": "Crosswalk links are authority-attributed trace assertions, not proof of conformity, defect truth, or evidence sufficiency.",
        "content_sha256": "",
    }
    result["content_sha256"] = _digest(result)
    return result


def verify_standards_crosswalk(value: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    required = {"format", "generated_at", "binding", "objectives", "summary", "claim", "content_sha256"}
    closed = set(value) == required and value.get("format") == CROSSWALK_FORMAT
    if not closed:
        errors.append("crosswalk fields or format do not match format 1")
    integrity = bool(
        re.fullmatch(r"[0-9a-f]{64}", str(value.get("content_sha256", "")))
        and value.get("content_sha256") == _digest(value)
    )
    if not integrity:
        errors.append("crosswalk content digest does not match")
    semantic = True
    try:
        objectives = value["objectives"]
        identifiers = [item["objective_id"] for item in objectives]
        semantic = bool(
            isinstance(objectives, list)
            and len(identifiers) == len(set(identifiers))
            and all(
                item["trace_status"]
                == (
                    "linked"
                    if item["links"] or item["workspace_evidence_refs"]
                    else "not_applicable"
                    if item["applicability"] == "not_applicable"
                    else "unlinked"
                )
                and all(link["relationship"] in RELATIONSHIPS for link in item["links"])
                for item in objectives
            )
        )
        applicable = [item for item in objectives if item["applicability"] == "applicable"]
        unlinked = sorted(item["objective_id"] for item in applicable if item["trace_status"] == "unlinked")
        mapped = {
            finding
            for item in objectives
            for link in item["links"]
            for finding in [
                *link["finding_ids"],
                *link["finding_ids_via_obligations"],
            ]
        }
        summary = value["summary"]
        semantic = semantic and bool(
            summary["objectives"] == len(objectives)
            and summary["applicable_objectives"] == len(applicable)
            and summary["linked_applicable_objectives"] == len(applicable) - len(unlinked)
            and summary["unlinked_objective_ids"] == unlinked
            and summary["mapped_findings"] == len(mapped)
            and summary["active_findings"]
            == len(mapped) + len(summary["unmapped_finding_ids"])
            and summary["trace_complete"]
            == (not summary["unlinked_objective_ids"] and not summary["unmapped_finding_ids"])
        )
    except (KeyError, TypeError, ValueError):
        semantic = False
    if not semantic:
        errors.append("crosswalk objective links or summary do not reconcile")
    valid = closed and integrity and semantic
    return {
        "format": CROSSWALK_VERIFICATION_FORMAT,
        "valid": valid,
        "trace_complete": bool(valid and value.get("summary", {}).get("trace_complete")),
        "checks": {"closed_structure": closed, "content_integrity": integrity, "semantic_reconciliation": semantic, "source_regeneration": None},
        "errors": errors,
        "content_sha256": str(value.get("content_sha256", "")),
        "notice": "Verification establishes internal trace integrity; it does not authenticate authorities or establish standards conformity.",
    }


def verify_standards_crosswalk_file(
    source: str | Path,
    *,
    analysis_source: str | Path | None = None,
    workspace_source: str | Path | None = None,
    mapping_source: str | Path | None = None,
) -> dict[str, Any]:
    try:
        document = _document(source, "standards crosswalk")
        if not isinstance(document.value, dict):
            raise ValueError("standards crosswalk must contain an object")
        verdict = {"path": str(document.path), **verify_standards_crosswalk(document.value)}
        supplied = (analysis_source, workspace_source, mapping_source)
        if any(item is not None for item in supplied):
            if not all(item is not None for item in supplied):
                verdict["checks"]["source_regeneration"] = False
            else:
                analysis_document = _document(analysis_source or "", "crosswalk analysis")
                if not isinstance(analysis_document.value, dict):
                    raise ValueError("crosswalk analysis must contain an object")
                regenerated = standards_crosswalk(
                    analysis_document.value,
                    analysis_document.path,
                    workspace_source or "",
                    mapping_source or "",
                    generated_at=str(document.value.get("generated_at", "")),
                )
                verdict["checks"]["source_regeneration"] = regenerated == document.value
            if verdict["checks"]["source_regeneration"] is not True:
                verdict["valid"] = False
                verdict["trace_complete"] = False
                verdict["errors"].append("crosswalk does not exactly regenerate from all supplied sources")
        return verdict
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "path": str(Path(source).expanduser().absolute()),
            "format": CROSSWALK_VERIFICATION_FORMAT,
            "valid": False,
            "trace_complete": False,
            "checks": {"closed_structure": False, "content_integrity": False, "semantic_reconciliation": False, "source_regeneration": False},
            "errors": [str(exc)],
            "content_sha256": "",
            "notice": "The standards crosswalk could not be safely verified.",
        }


def export_standards_crosswalk(value: dict[str, Any], destination: str | Path) -> Path:
    verdict = verify_standards_crosswalk(value)
    if not verdict["valid"]:
        raise ValueError("standards crosswalk is invalid")
    return atomic_publish_text(
        destination,
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        label="standards crosswalk",
    )
