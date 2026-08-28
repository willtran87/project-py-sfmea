"""ISO 15026 / OMG SACM-aligned claims, arguments, and evidence exchange."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .conformance import load_conformance_workspace, verify_conformance_workspace
from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_file_snapshot, load_bounded_json_document
from .model import utc_now
from .report import analysis_state_sha256
from .version import __version__

ASSURANCE_CASE_FORMAT = "pysfmea-assurance-case-1"
ASSURANCE_CASE_VERIFICATION_FORMAT = "pysfmea-assurance-case-verification-1"
MAX_ASSURANCE_CASE_BYTES = 25_000_000
MAX_ASSURANCE_EVIDENCE_ARTIFACTS = 100
MAX_ASSURANCE_EVIDENCE_ARTIFACT_BYTES = 250_000_000
MAX_ASSURANCE_EVIDENCE_TOTAL_BYTES = 500_000_000
CLAIM_STATUSES = {"supported", "partially_supported", "unsupported", "indeterminate"}
RELATIONSHIP_TYPES = {"supports", "in_context_of", "challenges"}


def _binding(analysis: dict[str, Any]) -> dict[str, str]:
    return {
        "baseline_id": str(
            analysis.get("project", {}).get("baseline", {}).get("id", "")
        ),
        "analysis_schema_version": str(analysis.get("schema_version", "")),
        "analysis_state_sha256": analysis_state_sha256(analysis),
    }


def _digest(document: dict[str, Any]) -> str:
    content = copy.deepcopy(document)
    content.pop("content_sha256", None)
    return canonical_json_sha256(content)


def _status(values: list[str]) -> str:
    if values and all(value == "supported" for value in values):
        return "supported"
    if any(value in {"supported", "partially_supported"} for value in values):
        return "partially_supported"
    if values and all(value == "indeterminate" for value in values):
        return "indeterminate"
    return "unsupported"


def _artifact_evidence(
    identifier: str,
    kind: str,
    path: Path,
    *,
    content_sha256: str,
    description: str,
    authority: str,
    limitations: str,
    max_bytes: int,
) -> dict[str, Any]:
    snapshot = load_bounded_file_snapshot(
        path, label=f"{kind} assurance evidence", max_bytes=max_bytes
    )
    return {
        "id": identifier,
        "kind": kind,
        "artifact": str(snapshot.path),
        "bytes": snapshot.size,
        "sha256": hashlib.sha256(snapshot.raw).hexdigest(),
        "content_sha256": content_sha256,
        "description": description,
        "authority": authority,
        "limitations": limitations,
    }


def assurance_case(
    analysis: dict[str, Any],
    analysis_path: str | Path,
    *,
    conformance_path: str | Path | None = None,
    qualification_path: str | Path | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a conservative assurance case from exact governed artifacts.

    The top claim concerns evidence sufficiency for review, never system safety or
    standards conformance.  Unsupported subclaims remain explicit defeaters.
    """

    analysis_file = Path(analysis_path).expanduser().resolve()
    binding = _binding(analysis)
    evidence = [
        _artifact_evidence(
            "E-ANALYSIS",
            "pysfmea_analysis",
            analysis_file,
            content_sha256=binding["analysis_state_sha256"],
            description="Exact governed analysis used to derive this assurance case.",
            authority="tool_generated_candidate_analysis",
            limitations="Static and imported evidence require qualified engineering review; absence of a candidate is not proof of absence.",
            max_bytes=250_000_000,
        )
    ]

    active_items = [
        item
        for item in analysis.get("items", [])
        if isinstance(item, dict) and item.get("source_status", "active") == "active"
    ]
    reviewed_items = [
        item
        for item in active_items
        if item.get("review", {}).get("disposition") in {"accepted", "rejected"}
    ]
    review_status = (
        "supported"
        if active_items and len(reviewed_items) == len(active_items)
        else ("partially_supported" if reviewed_items else "unsupported")
    )

    inventory = analysis.get("repository_inventory", {})
    inventory_summary = (
        inventory.get("summary", {}) if isinstance(inventory, dict) else {}
    )
    unresolved = (
        int(inventory_summary.get("opaque_or_unresolved", 0) or 0)
        if isinstance(inventory_summary, dict)
        else 0
    )
    inventory_status = (
        "supported"
        if inventory_summary.get("files", 0) and unresolved == 0
        else (
            "partially_supported"
            if inventory_summary.get("files", 0)
            else "unsupported"
        )
    )

    obligations = analysis.get("assurance", {}).get("obligations", [])
    obligations = obligations if isinstance(obligations, list) else []
    sufficient = [
        item
        for item in obligations
        if isinstance(item, dict) and item.get("evidence_status") == "sufficient"
    ]
    verification_status = (
        "supported"
        if obligations and len(sufficient) == len(obligations)
        else ("partially_supported" if sufficient else "unsupported")
    )

    claims: list[dict[str, Any]] = [
        {
            "id": "C-INVENTORY",
            "title": "Repository coverage is bounded and explicit",
            "statement": "The analyzed repository boundary and unresolved or opaque coverage are explicitly represented for this baseline.",
            "status": inventory_status,
            "scope": "repository inventory only",
            "assumptions": [
                "The supplied repository snapshot is the intended review baseline."
            ],
        },
        {
            "id": "C-REVIEW",
            "title": "Failure-mode candidates received governed disposition",
            "statement": "Active SFMEA candidates have an explicit accepted or rejected engineering-review disposition.",
            "status": review_status,
            "scope": f"{len(reviewed_items)} of {len(active_items)} active findings",
            "assumptions": [
                "Reviewer identities are organizational labels unless separately authenticated."
            ],
        },
        {
            "id": "C-VERIFICATION",
            "title": "Accepted verification obligations have sufficient reviewed evidence",
            "statement": "Generated assurance obligations are supported by accepted execution evidence and acceptance-criterion review.",
            "status": verification_status,
            "scope": f"{len(sufficient)} of {len(obligations)} obligations",
            "assumptions": [
                "Evidence authenticity and reviewer authority are governed outside this local artifact unless separately signed."
            ],
        },
    ]
    arguments: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = []
    defeaters: list[dict[str, str]] = []

    for claim in claims:
        suffix = claim["id"].removeprefix("C-")
        arguments.append(
            {
                "id": f"A-{suffix}",
                "claim_id": claim["id"],
                "strategy": "bounded_evidence_projection",
                "reasoning": "Use deterministic analysis state and explicit population accounting; retain all missing or partial evidence as a visible challenge.",
                "status": claim["status"],
            }
        )
        relationships.extend(
            [
                {"source": f"A-{suffix}", "target": claim["id"], "type": "supports"},
                {"source": "E-ANALYSIS", "target": f"A-{suffix}", "type": "supports"},
            ]
        )
        if claim["status"] != "supported":
            defeaters.append(
                {
                    "id": f"D-{suffix}",
                    "claim_id": claim["id"],
                    "statement": f"Evidence for {claim['title'].lower()} is incomplete or unsupported.",
                    "resolution": "Complete the linked governed review or evidence workflow and regenerate the assurance case.",
                }
            )

    if conformance_path is not None:
        conformance_file = Path(conformance_path).expanduser().resolve()
        workspace = load_conformance_workspace(conformance_file)
        verdict = verify_conformance_workspace(workspace, analysis=analysis)
        evidence.append(
            _artifact_evidence(
                "E-CONFORMANCE",
                "standards_conformance_workspace",
                conformance_file,
                content_sha256=str(workspace.get("content_sha256", "")),
                description="Governed standards applicability and objective assessment workspace.",
                authority="authorized_assessment_workspace_not_certification",
                limitations=verdict["notice"],
                max_bytes=10_000_000,
            )
        )
        conformance_status = (
            "supported"
            if verdict["conformance_supported"]
            else (
                "partially_supported"
                if verdict["assessment_complete"]
                else "unsupported"
            )
        )
        claims.append(
            {
                "id": "C-CONFORMANCE",
                "title": "Selected standards objectives are assessed",
                "statement": "The selected standards profiles have complete, evidence-backed objective assessments for the exact analysis baseline.",
                "status": conformance_status,
                "scope": ", ".join(verdict["profile_ids"]),
                "assumptions": [
                    "The project authority selected the correct standards and consulted all required licensed normative text."
                ],
            }
        )
        arguments.append(
            {
                "id": "A-CONFORMANCE",
                "claim_id": "C-CONFORMANCE",
                "strategy": "objective_by_objective_conformance_argument",
                "reasoning": "Require exact analysis binding, governed catalog integrity, applicability decisions, evidence references, rationale, reviewer attribution, and summary reconciliation.",
                "status": conformance_status,
            }
        )
        relationships.extend(
            [
                {
                    "source": "A-CONFORMANCE",
                    "target": "C-CONFORMANCE",
                    "type": "supports",
                },
                {
                    "source": "E-CONFORMANCE",
                    "target": "A-CONFORMANCE",
                    "type": "supports",
                },
            ]
        )
        if conformance_status != "supported":
            defeaters.append(
                {
                    "id": "D-CONFORMANCE",
                    "claim_id": "C-CONFORMANCE",
                    "statement": "At least one selected objective is unassessed, partially satisfied, not satisfied, or has undetermined applicability.",
                    "resolution": "Resolve every blocking objective with authorized rationale and exact evidence references.",
                }
            )

    if qualification_path is not None:
        qualification_file = Path(qualification_path).expanduser().resolve()
        qualification_document = load_bounded_json_document(
            qualification_file,
            label="qualification campaign result",
            max_bytes=25_000_000,
            max_depth=80,
            max_nodes=1_000_000,
        )
        qualification = qualification_document.value
        if not isinstance(qualification, dict):
            raise ValueError("qualification campaign result must contain a JSON object")
        qualification_digest = str(qualification.get("content_sha256", ""))
        unsigned = copy.deepcopy(qualification)
        unsigned.pop("content_sha256", None)
        qualification_integrity = bool(
            re.fullmatch(r"[0-9a-f]{64}", qualification_digest)
            and qualification_digest == canonical_json_sha256(unsigned)
        )
        qualification_status = (
            "supported"
            if qualification_integrity and qualification.get("status") == "passed"
            else "unsupported"
        )
        evidence.append(
            _artifact_evidence(
                "E-QUALIFICATION",
                "qualification_campaign_result",
                qualification_file,
                content_sha256=qualification_digest,
                description="Independent multi-repository scanner qualification campaign result.",
                authority="campaign_governance_as_declared_in_artifact",
                limitations="Repository selection, label correctness, independence, and qualification authority remain external governance responsibilities.",
                max_bytes=25_000_000,
            )
        )
        claims.append(
            {
                "id": "C-QUALIFICATION",
                "title": "Scanner performance meets the declared qualification campaign",
                "statement": "The supplied content-addressed qualification campaign result passed all declared accuracy and population gates.",
                "status": qualification_status,
                "scope": str(
                    qualification.get("campaign", {}).get("id", "supplied campaign")
                ),
                "assumptions": [
                    "Campaign governance declarations and ground-truth labels were independently authenticated."
                ],
            }
        )
        arguments.append(
            {
                "id": "A-QUALIFICATION",
                "claim_id": "C-QUALIFICATION",
                "strategy": "independent_benchmark_argument",
                "reasoning": "Use a content-addressed campaign with independently declared corpora, exact regeneration, population gates, and precision/recall thresholds.",
                "status": qualification_status,
            }
        )
        relationships.extend(
            [
                {
                    "source": "A-QUALIFICATION",
                    "target": "C-QUALIFICATION",
                    "type": "supports",
                },
                {
                    "source": "E-QUALIFICATION",
                    "target": "A-QUALIFICATION",
                    "type": "supports",
                },
            ]
        )
        if qualification_status != "supported":
            defeaters.append(
                {
                    "id": "D-QUALIFICATION",
                    "claim_id": "C-QUALIFICATION",
                    "statement": "The supplied qualification result is not integrity-valid and passed.",
                    "resolution": "Run and independently approve a representative qualification campaign meeting declared gates.",
                }
            )

    subclaim_statuses = [claim["status"] for claim in claims]
    top_status = _status(subclaim_statuses)
    top_claim = {
        "id": "C-TOP",
        "title": "Bounded software-assurance evidence is ready for authorized decision",
        "statement": "For the identified baseline and declared scope, the available PySFMEA evidence supports an authorized engineering assurance decision to the extent stated by the subclaims.",
        "status": top_status,
        "scope": "analysis process and supplied evidence only; no claim that the software or system is safe",
        "assumptions": [
            "The system boundary, hazards, requirements, operating context, and external evidence supplied by the organization are correct and current."
        ],
    }
    claims.insert(0, top_claim)
    arguments.insert(
        0,
        {
            "id": "A-TOP",
            "claim_id": "C-TOP",
            "strategy": "conjunctive_subclaim_argument",
            "reasoning": "The bounded assurance decision is supported only to the weakest status of repository coverage, finding review, verification evidence, and any supplied conformance or qualification claims.",
            "status": top_status,
        },
    )
    relationships.append({"source": "A-TOP", "target": "C-TOP", "type": "supports"})
    for claim in claims[1:]:
        relationships.append(
            {"source": claim["id"], "target": "A-TOP", "type": "supports"}
        )
    if top_status != "supported":
        defeaters.insert(
            0,
            {
                "id": "D-TOP",
                "claim_id": "C-TOP",
                "statement": "One or more required subclaims are not fully supported.",
                "resolution": "Resolve the listed defeaters; do not treat this case as evidence that the software or system is safe.",
            },
        )

    result = {
        "format": ASSURANCE_CASE_FORMAT,
        "generated_at": generated_at or utc_now(),
        "tool": {"name": "PySFMEA", "version": __version__},
        "binding": binding,
        "standards_alignment": {
            "iso_iec_ieee_15026_2": "claims_arguments_evidence_and_assurance_case_report_concepts",
            "omg_sacm_2_3": "claim_argument_artifact_and_asserted_relationship_semantics",
            "conformance": "aligned_interchange_not_certified_sacm_xmi",
        },
        "claims": claims,
        "arguments": arguments,
        "evidence": evidence,
        "relationships": relationships,
        "defeaters": defeaters,
        "summary": {
            "top_claim_id": "C-TOP",
            "top_claim_status": top_status,
            "claims": len(claims),
            "supported_claims": sum(claim["status"] == "supported" for claim in claims),
            "arguments": len(arguments),
            "evidence": len(evidence),
            "open_defeaters": len(defeaters),
        },
        "authority": "decision_support_not_system_safety_case_approval",
        "notice": "This machine-readable assurance case organizes bounded claims, arguments, evidence, assumptions, and defeaters. It does not prove system safety, standards conformance, certification, or risk acceptance.",
        "content_sha256": "",
    }
    result["content_sha256"] = _digest(result)
    verification = verify_assurance_case(result, analysis=analysis)
    if not verification["valid"]:
        raise RuntimeError(
            "generated assurance case failed internal verification: "
            + "; ".join(verification["errors"])
        )
    return result


def load_assurance_case(source: str | Path) -> dict[str, Any]:
    document = load_bounded_json_document(
        source,
        label="assurance case",
        max_bytes=MAX_ASSURANCE_CASE_BYTES,
        max_depth=80,
        max_nodes=1_000_000,
    )
    if not isinstance(document.value, dict):
        raise ValueError("assurance case must contain a JSON object")
    return document.value


def verify_assurance_case(
    case: dict[str, Any], *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    checks: dict[str, bool | None] = {
        "closed_structure": True,
        "content_integrity": False,
        "unique_identifiers": False,
        "evidence_artifact_integrity": False,
        "relationship_integrity": False,
        "claim_argument_coverage": False,
        "status_reconciliation": False,
        "analysis_binding": None,
    }
    required = {
        "format",
        "generated_at",
        "tool",
        "binding",
        "standards_alignment",
        "claims",
        "arguments",
        "evidence",
        "relationships",
        "defeaters",
        "summary",
        "authority",
        "notice",
        "content_sha256",
    }
    if set(case) != required or case.get("format") != ASSURANCE_CASE_FORMAT:
        checks["closed_structure"] = False
        errors.append("assurance case fields or format do not match format 1")
    declared_digest = str(case.get("content_sha256", ""))
    checks["content_integrity"] = bool(
        re.fullmatch(r"[0-9a-f]{64}", declared_digest)
        and declared_digest == _digest(case)
    )
    if not checks["content_integrity"]:
        errors.append("assurance case content digest does not match")

    collections: dict[str, list[Any]] = {}
    typed_collections = True
    for name in ("claims", "arguments", "evidence", "defeaters"):
        value = case.get(name)
        if not isinstance(value, list) or len(value) > 10_000:
            typed_collections = False
            collections[name] = []
        else:
            collections[name] = value
    identifiers: list[str] = []
    nodes: set[str] = set()
    if typed_collections:
        for values in collections.values():
            for value in values:
                if (
                    isinstance(value, dict)
                    and isinstance(value.get("id"), str)
                    and value["id"]
                ):
                    identifiers.append(value["id"])
                    nodes.add(value["id"])
                else:
                    identifiers.append("")
    checks["unique_identifiers"] = (
        typed_collections
        and "" not in identifiers
        and len(identifiers) == len(set(identifiers))
    )
    if not checks["unique_identifiers"]:
        errors.append("assurance case node identifiers are missing or duplicated")

    evidence_records = collections["evidence"]
    evidence_integrity = bool(
        typed_collections
        and 0 < len(evidence_records) <= MAX_ASSURANCE_EVIDENCE_ARTIFACTS
    )
    consumed = 0
    if evidence_integrity:
        for record in evidence_records:
            if not isinstance(record, dict):
                evidence_integrity = False
                break
            artifact = record.get("artifact")
            declared_bytes = record.get("bytes")
            declared_sha256 = record.get("sha256")
            if (
                not isinstance(artifact, str)
                or not artifact
                or not isinstance(declared_bytes, int)
                or isinstance(declared_bytes, bool)
                or not 0 <= declared_bytes <= MAX_ASSURANCE_EVIDENCE_ARTIFACT_BYTES
                or not re.fullmatch(r"[0-9a-f]{64}", str(declared_sha256))
                or consumed + declared_bytes > MAX_ASSURANCE_EVIDENCE_TOTAL_BYTES
            ):
                evidence_integrity = False
                break
            try:
                snapshot = load_bounded_file_snapshot(
                    artifact,
                    label="assurance-case evidence artifact",
                    max_bytes=MAX_ASSURANCE_EVIDENCE_ARTIFACT_BYTES,
                )
            except (OSError, ValueError):
                evidence_integrity = False
                break
            consumed += snapshot.size
            if (
                snapshot.size != declared_bytes
                or hashlib.sha256(snapshot.raw).hexdigest() != declared_sha256
            ):
                evidence_integrity = False
                break
    checks["evidence_artifact_integrity"] = evidence_integrity
    if not evidence_integrity:
        errors.append(
            "assurance case evidence artifacts are missing, changed, or exceed bounds"
        )

    claims: list[Any] = collections["claims"]
    arguments: list[Any] = collections["arguments"]
    relationships_value = case.get("relationships")
    relationships: list[Any] = (
        relationships_value if isinstance(relationships_value, list) else []
    )
    claim_ids = {str(value.get("id")) for value in claims if isinstance(value, dict)}
    relationship_integrity = (
        isinstance(case.get("relationships"), list) and len(relationships) <= 50_000
    )
    for relationship in relationships:
        relationship_integrity = bool(
            relationship_integrity
            and isinstance(relationship, dict)
            and set(relationship) == {"source", "target", "type"}
            and relationship.get("source") in nodes
            and relationship.get("target") in nodes
            and relationship.get("type") in RELATIONSHIP_TYPES
        )
    checks["relationship_integrity"] = relationship_integrity
    if not relationship_integrity:
        errors.append(
            "assurance case relationships contain invalid or dangling references"
        )

    argument_claims = {
        str(value.get("claim_id"))
        for value in arguments
        if isinstance(value, dict) and value.get("claim_id") in claim_ids
    }
    checks["claim_argument_coverage"] = bool(claim_ids and claim_ids == argument_claims)
    if not checks["claim_argument_coverage"]:
        errors.append("each claim must have exactly addressable argument coverage")

    claim_statuses_valid = all(
        isinstance(value, dict) and value.get("status") in CLAIM_STATUSES
        for value in claims
    )
    by_id = {str(value.get("id")): value for value in claims if isinstance(value, dict)}
    substatuses = [
        value.get("status") for key, value in by_id.items() if key != "C-TOP"
    ]
    expected_top = _status([str(value) for value in substatuses])
    top = by_id.get("C-TOP", {})
    summary_value = case.get("summary")
    summary: dict[str, Any] = summary_value if isinstance(summary_value, dict) else {}
    expected_summary = {
        "top_claim_id": "C-TOP",
        "top_claim_status": expected_top,
        "claims": len(claims),
        "supported_claims": sum(
            isinstance(value, dict) and value.get("status") == "supported"
            for value in claims
        ),
        "arguments": len(arguments),
        "evidence": len(case.get("evidence", []))
        if isinstance(case.get("evidence"), list)
        else 0,
        "open_defeaters": len(case.get("defeaters", []))
        if isinstance(case.get("defeaters"), list)
        else 0,
    }
    checks["status_reconciliation"] = bool(
        claim_statuses_valid
        and top.get("status") == expected_top
        and summary == expected_summary
    )
    if not checks["status_reconciliation"]:
        errors.append(
            "claim statuses or summary do not reconcile with the top-level argument"
        )
    if analysis is not None:
        checks["analysis_binding"] = case.get("binding") == _binding(analysis)
        if not checks["analysis_binding"]:
            errors.append("assurance case does not match the supplied analysis state")
    valid = all(value is not False for value in checks.values())
    return {
        "format": ASSURANCE_CASE_VERIFICATION_FORMAT,
        "valid": valid,
        "top_claim_status": str(summary.get("top_claim_status", "indeterminate")),
        "decision_ready": bool(
            valid
            and summary.get("top_claim_status") == "supported"
            and summary.get("open_defeaters") == 0
        ),
        "checks": checks,
        "errors": errors,
        "content_sha256": declared_digest,
        "notice": "Verification establishes artifact integrity and internal argument consistency, not the truth of external evidence, system safety, certification, or risk acceptance.",
    }


def export_assurance_case(case: dict[str, Any], destination: str | Path) -> Path:
    return atomic_publish_text(
        destination,
        json.dumps(case, indent=2, ensure_ascii=False) + "\n",
        label="structured assurance case",
    )


def verify_assurance_case_file(
    source: str | Path, *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    try:
        return {
            "path": str(Path(source).expanduser().resolve()),
            **verify_assurance_case(load_assurance_case(source), analysis=analysis),
        }
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "path": str(Path(source).expanduser().absolute()),
            "format": ASSURANCE_CASE_VERIFICATION_FORMAT,
            "valid": False,
            "top_claim_status": "indeterminate",
            "decision_ready": False,
            "checks": {
                "closed_structure": False,
                "content_integrity": False,
                "unique_identifiers": False,
                "evidence_artifact_integrity": False,
                "relationship_integrity": False,
                "claim_argument_coverage": False,
                "status_reconciliation": False,
                "analysis_binding": None if analysis is None else False,
            },
            "errors": [str(exc)],
            "content_sha256": "",
            "notice": "The assurance case could not be safely verified.",
        }
