"""Auditable, human-controlled editing for grounded machine suggestions."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .discovery import (
    ALLOWED_CONTENT_FIELDS,
    LIST_CONTENT_FIELDS,
    MAX_GENERATED_LIST_ITEMS,
    MAX_GENERATED_TEXT_CHARS,
    review_suggestion,
)
from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .model import utc_now

SYNTHESIS_DRAFT_FORMAT = "pysfmea-synthesis-workspace-draft-1"
SYNTHESIS_FORMAT = "pysfmea-synthesis-workspace-1"
SYNTHESIS_VERIFICATION_FORMAT = "pysfmea-synthesis-workspace-verification-1"
SYNTHESIS_APPLY_RECEIPT_FORMAT = "pysfmea-synthesis-apply-receipt-1"
SYNTHESIS_APPLY_VERIFICATION_FORMAT = (
    "pysfmea-synthesis-apply-receipt-verification-1"
)
MAX_SYNTHESIS_BYTES = 20_000_000
MAX_SYNTHESIS_ENTRIES = 5_000
MAX_SYNTHESIS_DEPTH = 80
MAX_SYNTHESIS_NODES = 500_000

_OPPOSITES = (
    ("available", "unavailable"),
    ("enabled", "disabled"),
    ("allows", "denies"),
    ("allow", "deny"),
    ("accepted", "rejected"),
    ("success", "failure"),
    ("succeeds", "fails"),
    ("safe", "unsafe"),
    ("bounded", "unbounded"),
    ("present", "absent"),
    ("open", "closed"),
    ("valid", "invalid"),
)
_CLAIM_FIELDS = (
    "failure_mode",
    "trigger",
    "local_effect",
    "next_higher_effect",
)


def _normalize(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()


def _tokens(value: Any) -> set[str]:
    return {token for token in _normalize(value).split() if len(token) > 1}


def _similarity(left: Any, right: Any) -> float:
    a, b = _tokens(left), _tokens(right)
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _polarity_conflict(left: Any, right: Any) -> str:
    a, b = _tokens(left), _tokens(right)
    for positive, negative in _OPPOSITES:
        if (positive in a and negative in b) or (negative in a and positive in b):
            return f"opposed terms: {positive}/{negative}"
    left_text, right_text = _normalize(left), _normalize(right)
    if left_text.startswith("not ") != right_text.startswith("not "):
        positive = left_text.removeprefix("not ")
        negative = right_text.removeprefix("not ")
        if _similarity(positive, negative) >= 0.7:
            return "one claim explicitly negates the other"
    return ""


def _existing_claims(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for item in analysis.get("items", []):
        if item.get("source_status", "active") != "active":
            continue
        scanner = item.get("scanner", {})
        review = item.get("review", {})
        content = {
            "failure_mode": review.get("failure_mode") or scanner.get("failure_mode", ""),
            "trigger": review.get("trigger", ""),
            "local_effect": review.get("local_effect", ""),
            "next_higher_effect": review.get("next_higher_effect", ""),
        }
        values.append(
            {
                "id": str(item.get("id", "")),
                "kind": "finding",
                "component_id": str(item.get("component_id", "")),
                "component_reference": str(item.get("component_reference", "")),
                "content": content,
                "evidence_ids": [
                    str(value) for value in scanner.get("evidence", []) if value
                ],
            }
        )
    return values


def _suggestion_claims(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "id": str(value.get("id", "")),
            "kind": "suggestion",
            "component_id": str(value.get("component_id", "")),
            "component_reference": str(value.get("component_reference", "")),
            "content": copy.deepcopy(value.get("content", {})),
            "evidence_ids": [str(item) for item in value.get("evidence_ids", [])],
        }
        for value in analysis.get("suggestions", [])
        if value.get("status") == "proposed"
    ]


def suggestion_relationships(analysis: dict[str, Any]) -> dict[str, Any]:
    """Detect bounded duplicates, contradictions, and divergent claims."""

    claims = [*_existing_claims(analysis), *_suggestion_claims(analysis)]
    duplicates: list[dict[str, Any]] = []
    contradictions: list[dict[str, Any]] = []
    divergences: list[dict[str, Any]] = []
    for index, left in enumerate(claims):
        for right in claims[index + 1 :]:
            if left["component_id"] != right["component_id"]:
                continue
            if left["kind"] != "suggestion" and right["kind"] != "suggestion":
                continue
            failure_similarity = _similarity(
                left["content"].get("failure_mode"),
                right["content"].get("failure_mode"),
            )
            if failure_similarity >= 0.84:
                duplicates.append(
                    {
                        "left_id": left["id"],
                        "right_id": right["id"],
                        "component_id": left["component_id"],
                        "similarity": round(failure_similarity, 4),
                        "reason": "high token overlap in the normalized failure-mode claim",
                    }
                )
            if failure_similarity < 0.35:
                continue
            for field in _CLAIM_FIELDS:
                left_value = left["content"].get(field, "")
                right_value = right["content"].get(field, "")
                if not left_value or not right_value:
                    continue
                conflict = _polarity_conflict(left_value, right_value)
                record = {
                    "left_id": left["id"],
                    "right_id": right["id"],
                    "component_id": left["component_id"],
                    "field": field,
                    "left_claim": str(left_value),
                    "right_claim": str(right_value),
                    "evidence_overlap": sorted(
                        set(left["evidence_ids"]) & set(right["evidence_ids"])
                    ),
                }
                if conflict:
                    contradictions.append(
                        {
                            **record,
                            "reason": conflict,
                            "classification": "lexical_contradiction_review_required",
                        }
                    )
                elif field != "failure_mode" and _similarity(left_value, right_value) < 0.2:
                    divergences.append(
                        {
                            **record,
                            "reason": "materially different claims for a related failure mode",
                            "classification": "divergent_claim_review_required",
                        }
                    )
    return {
        "format": "pysfmea-suggestion-relationships-1",
        "duplicates": duplicates[:MAX_SYNTHESIS_ENTRIES],
        "contradictions": contradictions[:MAX_SYNTHESIS_ENTRIES],
        "divergences": divergences[:MAX_SYNTHESIS_ENTRIES],
        "summary": {
            "claims": len(claims),
            "duplicates": len(duplicates),
            "contradictions": len(contradictions),
            "divergences": len(divergences),
            "truncated": any(
                len(value) > MAX_SYNTHESIS_ENTRIES
                for value in (duplicates, contradictions, divergences)
            ),
        },
        "notice": (
            "Relationships are deterministic review leads from bounded lexical comparison; "
            "they are not proof that either claim is correct or semantically equivalent."
        ),
    }


def build_synthesis_workspace(analysis: dict[str, Any]) -> dict[str, Any]:
    relationships = suggestion_relationships(analysis)
    existing = _existing_claims(analysis)
    entries: list[dict[str, Any]] = []
    for suggestion in analysis.get("suggestions", []):
        if suggestion.get("status") != "proposed":
            continue
        related = sorted(
            (
                value
                for value in existing
                if value["component_id"] == suggestion.get("component_id")
            ),
            key=lambda value: -_similarity(
                value["content"].get("failure_mode"),
                suggestion.get("content", {}).get("failure_mode"),
            ),
        )[:5]
        entries.append(
            {
                "suggestion_id": suggestion["id"],
                "component_id": suggestion.get("component_id", ""),
                "component_reference": suggestion.get("component_reference", ""),
                "original_content_sha256": canonical_json_sha256(
                    suggestion.get("content", {})
                ),
                "existing_findings": related,
                "proposed_content": copy.deepcopy(suggestion.get("content", {})),
                "evidence_ids": copy.deepcopy(suggestion.get("evidence_ids", [])),
                "citation_ids": copy.deepcopy(
                    suggestion.get("proposed_citation_ids", [])
                ),
                "uncertainties": copy.deepcopy(suggestion.get("uncertainties", [])),
                "questions": copy.deepcopy(suggestion.get("questions", [])),
                "decision": "defer",
                "reviewer": "",
                "rationale": "",
            }
        )
    workspace = {
        "format": SYNTHESIS_DRAFT_FORMAT,
        "generated_at": utc_now(),
        "binding": {
            "baseline_id": str(
                analysis.get("project", {}).get("baseline", {}).get("id", "")
            ),
            "analysis_state_sha256": canonical_json_sha256(analysis),
        },
        "entries": entries,
        "relationships": relationships,
        "instructions": {
            "editable_fields": [
                "entries[].proposed_content",
                "entries[].decision",
                "entries[].reviewer",
                "entries[].rationale",
            ],
            "decision_values": ["accept", "reject", "defer"],
            "workflow": [
                "Compare the existing findings, proposed content, evidence, and conflicts.",
                "Edit proposal text only where the evidence supports the change.",
                "Record accept or reject with a named reviewer and rationale; otherwise defer.",
                "Seal the edited workspace, verify it, then apply it to the unchanged analysis.",
            ],
        },
        "notice": (
            "No model decision is authoritative. Applying an accepted proposal creates an "
            "unreviewed worksheet item and preserves suggestion provenance."
        ),
    }
    workspace["content_sha256"] = canonical_json_sha256(workspace)
    return workspace


def _validate_content(content: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(content, dict):
        return ["proposed_content must be an object"]
    unknown = set(content) - ALLOWED_CONTENT_FIELDS
    missing = ALLOWED_CONTENT_FIELDS - set(content)
    if unknown:
        errors.append("unsupported content fields: " + ", ".join(sorted(unknown)))
    if missing:
        errors.append("missing content fields: " + ", ".join(sorted(missing)))
    for field in ALLOWED_CONTENT_FIELDS:
        value = content.get(field, [] if field in LIST_CONTENT_FIELDS else "")
        if field in LIST_CONTENT_FIELDS:
            if not isinstance(value, list) or len(value) > MAX_GENERATED_LIST_ITEMS:
                errors.append(f"{field} must be a bounded list")
            elif any(not isinstance(item, str) or not item.strip() for item in value):
                errors.append(f"{field} entries must be non-empty strings")
        elif not isinstance(value, str) or len(value) > MAX_GENERATED_TEXT_CHARS:
            errors.append(f"{field} must be a bounded string")
    if isinstance(content.get("failure_mode"), str) and not content["failure_mode"].strip():
        errors.append("failure_mode is required")
    return errors


def verify_synthesis_workspace(
    workspace: dict[str, Any], analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    errors: list[str] = []
    if set(workspace) != {
        "format",
        "generated_at",
        "binding",
        "entries",
        "relationships",
        "instructions",
        "notice",
        "content_sha256",
    }:
        errors.append("workspace fields do not match the closed format")
    declared = str(workspace.get("content_sha256", ""))
    unsigned = copy.deepcopy(workspace)
    unsigned.pop("content_sha256", None)
    integrity = bool(re.fullmatch(r"[0-9a-f]{64}", declared)) and declared == canonical_json_sha256(unsigned)
    if workspace.get("format") != SYNTHESIS_FORMAT:
        errors.append("workspace must be sealed with synthesis workspace format 1")
    if not isinstance(workspace.get("generated_at"), str) or not workspace.get(
        "generated_at"
    ):
        errors.append("generated_at must be a non-empty string")
    if not isinstance(workspace.get("notice"), str) or not workspace.get("notice"):
        errors.append("notice must be a non-empty string")
    binding = workspace.get("binding")
    if (
        not isinstance(binding, dict)
        or set(binding) != {"baseline_id", "analysis_state_sha256"}
        or not isinstance(binding.get("baseline_id"), str)
        or not re.fullmatch(
            r"[0-9a-f]{64}", str(binding.get("analysis_state_sha256", ""))
        )
    ):
        errors.append("analysis binding does not match the closed format")
        binding = {}
    if not isinstance(workspace.get("relationships"), dict):
        errors.append("relationships must be an object")
    if not isinstance(workspace.get("instructions"), dict):
        errors.append("instructions must be an object")
    entries = workspace.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_SYNTHESIS_ENTRIES:
        errors.append("entries must be a bounded list")
        entries = []
    ids: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"entry {index} must be an object")
            continue
        identifier = str(entry.get("suggestion_id", ""))
        if set(entry) != {
            "suggestion_id",
            "component_id",
            "component_reference",
            "original_content_sha256",
            "existing_findings",
            "proposed_content",
            "evidence_ids",
            "citation_ids",
            "uncertainties",
            "questions",
            "decision",
            "reviewer",
            "rationale",
        }:
            errors.append(f"entry {identifier or index} fields do not match the closed format")
        if not identifier or identifier in ids:
            errors.append(f"entry {index} has a missing or duplicate suggestion_id")
        ids.add(identifier)
        decision = entry.get("decision")
        if decision not in {"accept", "reject", "defer"}:
            errors.append(f"entry {identifier} has an invalid decision")
        if decision in {"accept", "reject"} and (
            not str(entry.get("reviewer", "")).strip()
            or not str(entry.get("rationale", "")).strip()
        ):
            errors.append(f"entry {identifier} requires reviewer and rationale")
        if (
            not isinstance(entry.get("component_id"), str)
            or not isinstance(entry.get("component_reference"), str)
            or not re.fullmatch(
                r"[0-9a-f]{64}", str(entry.get("original_content_sha256", ""))
            )
            or not isinstance(entry.get("existing_findings"), list)
            or len(entry.get("existing_findings", [])) > 5
            or not isinstance(entry.get("reviewer"), str)
            or len(entry.get("reviewer", "")) > 500
            or not isinstance(entry.get("rationale"), str)
            or len(entry.get("rationale", "")) > 20_000
        ):
            errors.append(f"entry {identifier} contains invalid bounded values")
        for field in ("evidence_ids", "citation_ids", "uncertainties", "questions"):
            values = entry.get(field)
            if (
                not isinstance(values, list)
                or len(values) > 100
                or any(not isinstance(value, str) or not value for value in values)
            ):
                errors.append(f"entry {identifier} has invalid {field}")
        errors.extend(
            f"entry {identifier}: {value}"
            for value in _validate_content(entry.get("proposed_content"))
        )
    structure_valid = not errors
    binding_matches: bool | None = None
    if analysis is not None:
        binding_matches = (
            binding.get("baseline_id")
            == analysis.get("project", {}).get("baseline", {}).get("id", "")
            and binding.get("analysis_state_sha256") == canonical_json_sha256(analysis)
        )
        suggestions = {
            str(value.get("id", "")): value
            for value in analysis.get("suggestions", [])
            if value.get("status") == "proposed"
        }
        expected_workspace = build_synthesis_workspace(analysis)
        expected_entries = {
            value["suggestion_id"]: value for value in expected_workspace["entries"]
        }
        immutable_fields = {
            "suggestion_id",
            "component_id",
            "component_reference",
            "original_content_sha256",
            "existing_findings",
            "evidence_ids",
            "citation_ids",
            "uncertainties",
            "questions",
        }
        if workspace.get("relationships") != expected_workspace["relationships"]:
            binding_matches = False
            errors.append("workspace relationships do not regenerate from the analysis")
        if workspace.get("instructions") != expected_workspace["instructions"]:
            binding_matches = False
            errors.append("workspace instructions do not match the supported workflow")
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            suggestion = suggestions.get(str(entry.get("suggestion_id", "")))
            expected_entry = expected_entries.get(str(entry.get("suggestion_id", "")))
            if suggestion is None:
                errors.append(f"suggestion is missing or no longer proposed: {entry.get('suggestion_id', '')}")
            elif entry.get("original_content_sha256") != canonical_json_sha256(
                suggestion.get("content", {})
            ):
                errors.append(f"suggestion content changed: {entry.get('suggestion_id', '')}")
            if expected_entry is None or any(
                entry.get(field) != expected_entry.get(field)
                for field in immutable_fields
            ):
                binding_matches = False
                errors.append(
                    f"immutable suggestion context changed: {entry.get('suggestion_id', '')}"
                )
    valid = integrity and not errors and binding_matches is not False
    return {
        "format": SYNTHESIS_VERIFICATION_FORMAT,
        "valid": valid,
        "checks": {
            "content_integrity": integrity,
            "structure": structure_valid,
            "analysis_binding": binding_matches,
        },
        "entry_count": len(entries),
        "decision_counts": {
            value: sum(
                1
                for entry in entries
                if isinstance(entry, dict) and entry.get("decision") == value
            )
            for value in ("accept", "reject", "defer")
        },
        "errors": errors,
        "notice": "Verification establishes integrity and freshness, not correctness or reviewer authority.",
    }


def export_synthesis_workspace(
    analysis: dict[str, Any], output: str | Path
) -> Path:
    payload = build_synthesis_workspace(analysis)
    return atomic_publish_text(
        output,
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        label="synthesis workspace",
        max_bytes=MAX_SYNTHESIS_BYTES,
    )


def load_synthesis_workspace(source: str | Path) -> dict[str, Any]:
    document = load_bounded_json_document(
        source,
        label="synthesis workspace",
        max_bytes=MAX_SYNTHESIS_BYTES,
        max_depth=MAX_SYNTHESIS_DEPTH,
        max_nodes=MAX_SYNTHESIS_NODES,
    )
    if not isinstance(document.value, dict):
        raise ValueError("synthesis workspace must contain a JSON object")
    return document.value


def seal_synthesis_workspace(source: str | Path) -> Path:
    path = Path(source).expanduser().absolute()
    if path.is_symlink():
        raise ValueError(f"synthesis workspace must not be a symbolic link: {path}")
    workspace = load_synthesis_workspace(path)
    workspace["format"] = SYNTHESIS_FORMAT
    workspace.pop("content_sha256", None)
    workspace["content_sha256"] = canonical_json_sha256(workspace)
    verification = verify_synthesis_workspace(workspace)
    if not verification["valid"]:
        raise ValueError(
            "synthesis workspace cannot be sealed: "
            + "; ".join(verification["errors"])
        )
    return atomic_publish_text(
        path,
        json.dumps(workspace, indent=2, ensure_ascii=False) + "\n",
        label="synthesis workspace",
        max_bytes=MAX_SYNTHESIS_BYTES,
    )


def apply_synthesis_workspace(
    analysis: dict[str, Any], workspace: dict[str, Any]
) -> dict[str, Any]:
    verification = verify_synthesis_workspace(workspace, analysis)
    if not verification["valid"]:
        raise ValueError("invalid or stale synthesis workspace: " + "; ".join(verification["errors"]))
    snapshot = copy.deepcopy(analysis)
    source_analysis_state_sha256 = canonical_json_sha256(analysis)
    applied: list[str] = []
    try:
        suggestions = {
            str(value.get("id", "")): value
            for value in analysis.get("suggestions", [])
        }
        for entry in workspace["entries"]:
            decision = entry["decision"]
            if decision == "defer":
                continue
            suggestion = suggestions[entry["suggestion_id"]]
            edited = copy.deepcopy(entry["proposed_content"])
            if edited != suggestion.get("content", {}):
                changed = sorted(
                    key
                    for key in ALLOWED_CONTENT_FIELDS
                    if edited.get(key) != suggestion.get("content", {}).get(key)
                )
                suggestion["content"] = edited
                suggestion.setdefault("history", []).append(
                    {
                        "event": "human_synthesis_edit",
                        "at": utc_now(),
                        "reviewer": entry["reviewer"].strip(),
                        "changed_fields": changed,
                        "workspace_sha256": workspace["content_sha256"],
                    }
                )
            review_suggestion(
                analysis,
                entry["suggestion_id"],
                decision=decision,
                reviewer=entry["reviewer"],
                rationale=entry["rationale"],
            )
            applied.append(entry["suggestion_id"])
    except Exception:
        analysis.clear()
        analysis.update(snapshot)
        raise
    receipt = {
        "format": SYNTHESIS_APPLY_RECEIPT_FORMAT,
        "workspace_sha256": workspace["content_sha256"],
        "source_analysis_state_sha256": source_analysis_state_sha256,
        "result_analysis_state_sha256": canonical_json_sha256(analysis),
        "applied_suggestion_ids": applied,
        "deferred": verification["decision_counts"]["defer"],
        "applied_at": utc_now(),
        "notice": "Accepted suggestions remain unreviewed worksheet findings until engineering review is completed.",
    }
    receipt["content_sha256"] = canonical_json_sha256(receipt)
    return receipt


def verify_synthesis_workspace_file(
    source: str | Path, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    supplied = Path(source).expanduser().absolute()
    try:
        result = verify_synthesis_workspace(
            load_synthesis_workspace(supplied), analysis
        )
        result["path"] = str(supplied)
        return result
    except (OSError, ValueError) as exc:
        return {
            "format": SYNTHESIS_VERIFICATION_FORMAT,
            "valid": False,
            "checks": {
                "content_integrity": False,
                "structure": False,
                "analysis_binding": False if analysis is not None else None,
            },
            "entry_count": 0,
            "decision_counts": {"accept": 0, "reject": 0, "defer": 0},
            "errors": [f"synthesis workspace could not be verified: {exc}"],
            "notice": (
                "Verification establishes integrity and freshness, not correctness or "
                "reviewer authority."
            ),
            "path": str(supplied),
        }


def export_synthesis_apply_receipt(
    receipt: dict[str, Any], output: str | Path
) -> Path:
    declared = str(receipt.get("content_sha256", ""))
    unsigned = dict(receipt)
    unsigned.pop("content_sha256", None)
    if (
        receipt.get("format") != SYNTHESIS_APPLY_RECEIPT_FORMAT
        or declared != canonical_json_sha256(unsigned)
    ):
        raise ValueError("synthesis apply receipt format or integrity is invalid")
    return atomic_publish_text(
        output,
        json.dumps(receipt, indent=2, ensure_ascii=False) + "\n",
        label="synthesis apply receipt",
        max_bytes=MAX_SYNTHESIS_BYTES,
    )


def load_synthesis_apply_receipt(source: str | Path) -> dict[str, Any]:
    document = load_bounded_json_document(
        source,
        label="synthesis apply receipt",
        max_bytes=MAX_SYNTHESIS_BYTES,
        max_depth=MAX_SYNTHESIS_DEPTH,
        max_nodes=MAX_SYNTHESIS_NODES,
    )
    if not isinstance(document.value, dict):
        raise ValueError("synthesis apply receipt must contain a JSON object")
    return document.value


def verify_synthesis_apply_receipt(
    receipt: dict[str, Any],
    *,
    source_analysis: dict[str, Any] | None = None,
    result_analysis: dict[str, Any] | None = None,
    workspace: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify an apply receipt and any supplied exact source/workspace/result bindings."""

    errors: list[str] = []
    expected_fields = {
        "format",
        "workspace_sha256",
        "source_analysis_state_sha256",
        "result_analysis_state_sha256",
        "applied_suggestion_ids",
        "deferred",
        "applied_at",
        "notice",
        "content_sha256",
    }
    structure = set(receipt) == expected_fields
    if not structure:
        errors.append("receipt fields do not match the closed apply-receipt format")
    unsigned = copy.deepcopy(receipt)
    declared_content_sha256 = str(unsigned.pop("content_sha256", ""))
    actual_content_sha256 = canonical_json_sha256(unsigned)
    content_integrity = bool(
        re.fullmatch(r"[0-9a-f]{64}", declared_content_sha256)
    ) and declared_content_sha256 == actual_content_sha256
    if not content_integrity:
        errors.append("receipt content digest does not match")
    if receipt.get("format") != SYNTHESIS_APPLY_RECEIPT_FORMAT:
        structure = False
        errors.append("receipt format is unsupported")
    for field in (
        "workspace_sha256",
        "source_analysis_state_sha256",
        "result_analysis_state_sha256",
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", str(receipt.get(field, ""))):
            structure = False
            errors.append(f"{field} must be a lowercase SHA-256 digest")
    applied_ids = receipt.get("applied_suggestion_ids")
    if (
        not isinstance(applied_ids, list)
        or len(applied_ids) > MAX_SYNTHESIS_ENTRIES
        or any(not isinstance(value, str) or not value for value in applied_ids)
        or len(set(applied_ids)) != len(applied_ids)
    ):
        structure = False
        errors.append("applied_suggestion_ids must be a bounded unique string list")
        applied_ids = []
    deferred = receipt.get("deferred")
    if (
        not isinstance(deferred, int)
        or isinstance(deferred, bool)
        or deferred < 0
        or deferred > MAX_SYNTHESIS_ENTRIES
    ):
        structure = False
        errors.append("deferred must be a bounded non-negative integer")
        deferred = 0
    for field in ("applied_at", "notice"):
        value = receipt.get(field)
        if not isinstance(value, str) or not value or len(value) > 20_000:
            structure = False
            errors.append(f"{field} must be a bounded non-empty string")

    source_binding: bool | None = None
    if source_analysis is not None:
        source_binding = receipt.get(
            "source_analysis_state_sha256"
        ) == canonical_json_sha256(source_analysis)
        if not source_binding:
            errors.append("receipt does not match the exact source analysis state")

    workspace_integrity: bool | None = None
    workspace_binding: bool | None = None
    workspace_verification: dict[str, Any] | None = None
    if workspace is not None:
        workspace_verification = verify_synthesis_workspace(
            workspace, source_analysis
        )
        workspace_integrity = workspace_verification["valid"]
        workspace_binding = (
            workspace_integrity
            and receipt.get("workspace_sha256") == workspace.get("content_sha256")
        )
        if not workspace_integrity:
            errors.append("sealed workspace is invalid or stale")
        elif not workspace_binding:
            errors.append("receipt does not match the exact sealed workspace")

    result_binding: bool | None = None
    if result_analysis is not None:
        result_binding = receipt.get(
            "result_analysis_state_sha256"
        ) == canonical_json_sha256(result_analysis)
        if not result_binding:
            errors.append("receipt does not match the exact result analysis state")

    decision_reconciliation: bool | None = None
    if workspace is not None:
        entries = workspace.get("entries", [])
        if isinstance(entries, list):
            expected_applied = [
                str(entry.get("suggestion_id", ""))
                for entry in entries
                if isinstance(entry, dict) and entry.get("decision") != "defer"
            ]
            expected_deferred = sum(
                1
                for entry in entries
                if isinstance(entry, dict) and entry.get("decision") == "defer"
            )
            decision_reconciliation = (
                applied_ids == expected_applied and deferred == expected_deferred
            )
            if decision_reconciliation and result_analysis is not None:
                result_suggestions = {
                    str(value.get("id", "")): value
                    for value in result_analysis.get("suggestions", [])
                    if isinstance(value, dict)
                }
                decision_reconciliation = all(
                    result_suggestions.get(str(entry.get("suggestion_id", "")), {}).get(
                        "status"
                    )
                    == ("accepted" if entry.get("decision") == "accept" else "rejected")
                    for entry in entries
                    if isinstance(entry, dict) and entry.get("decision") != "defer"
                )
        else:
            decision_reconciliation = False
        if not decision_reconciliation:
            errors.append("receipt decision accounting does not reconcile")

    bindings_complete = all(
        value is not None
        for value in (source_analysis, result_analysis, workspace)
    )
    checks = {
        "content_integrity": content_integrity,
        "structure": structure,
        "source_analysis_binding": source_binding,
        "workspace_integrity": workspace_integrity,
        "workspace_binding": workspace_binding,
        "result_analysis_binding": result_binding,
        "decision_reconciliation": decision_reconciliation,
    }
    valid = content_integrity and structure and all(
        value is not False for value in checks.values()
    )
    reconciled = valid and bindings_complete and all(
        checks[name] is True
        for name in (
            "source_analysis_binding",
            "workspace_integrity",
            "workspace_binding",
            "result_analysis_binding",
            "decision_reconciliation",
        )
    )
    return {
        "format": SYNTHESIS_APPLY_VERIFICATION_FORMAT,
        "valid": valid,
        "reconciled": reconciled,
        "mode": "complete" if bindings_complete else "integrity_only",
        "checks": checks,
        "applied_suggestion_count": len(applied_ids),
        "deferred": deferred,
        "declared_content_sha256": declared_content_sha256,
        "actual_content_sha256": actual_content_sha256,
        "errors": errors,
        "notice": (
            "Complete reconciliation proves exact source, sealed-workspace, result, and "
            "decision-accounting bindings. It does not approve the suggestions, findings, "
            "risk, citations, or evidence sufficiency."
        ),
    }


def verify_synthesis_apply_receipt_file(
    source: str | Path,
    *,
    source_analysis_path: str | Path | None = None,
    result_analysis_path: str | Path | None = None,
    workspace_path: str | Path | None = None,
) -> dict[str, Any]:
    """Boundedly verify one receipt in integrity-only or complete reconciliation mode."""

    supplied = Path(source).expanduser().absolute()
    binding_paths = (source_analysis_path, result_analysis_path, workspace_path)
    bindings_requested = any(value is not None for value in binding_paths)
    bindings_complete = all(value is not None for value in binding_paths)
    try:
        document = load_bounded_json_document(
            supplied,
            label="synthesis apply receipt",
            max_bytes=MAX_SYNTHESIS_BYTES,
            max_depth=MAX_SYNTHESIS_DEPTH,
            max_nodes=MAX_SYNTHESIS_NODES,
        )
        if not isinstance(document.value, dict):
            raise ValueError("synthesis apply receipt must contain a JSON object")
        receipt = document.value
    except (OSError, ValueError) as exc:
        result = _synthesis_apply_verification_rejection(
            f"synthesis apply receipt could not be verified: {exc}",
            bindings_requested=bindings_requested,
        )
        result.update(
            {
                "path": str(supplied),
                "source_bytes": 0,
                "source_sha256": "",
            }
        )
        return result
    if bindings_requested and not bindings_complete:
        result = verify_synthesis_apply_receipt(receipt)
        result["valid"] = False
        result["reconciled"] = False
        result["mode"] = "incomplete_bindings"
        result["errors"].append(
            "complete reconciliation requires source analysis, sealed workspace, and result analysis"
        )
    else:
        try:
            if bindings_complete:
                from .store import load_analysis

                source_analysis = load_analysis(source_analysis_path)  # type: ignore[arg-type]
                result_analysis = load_analysis(result_analysis_path)  # type: ignore[arg-type]
                workspace = load_synthesis_workspace(workspace_path)  # type: ignore[arg-type]
                result = verify_synthesis_apply_receipt(
                    receipt,
                    source_analysis=source_analysis,
                    result_analysis=result_analysis,
                    workspace=workspace,
                )
            else:
                result = verify_synthesis_apply_receipt(receipt)
        except (OSError, ValueError) as exc:
            result = verify_synthesis_apply_receipt(receipt)
            result["valid"] = False
            result["reconciled"] = False
            result["mode"] = "complete"
            result["errors"].append(f"binding artifact could not be loaded: {exc}")
            for name in (
                "source_analysis_binding",
                "workspace_integrity",
                "workspace_binding",
                "result_analysis_binding",
                "decision_reconciliation",
            ):
                result["checks"][name] = False
    result.update(
        {
            "path": str(document.path),
            "source_bytes": document.size,
            "source_sha256": hashlib.sha256(document.raw).hexdigest(),
        }
    )
    return result


def _synthesis_apply_verification_rejection(
    error: str, *, bindings_requested: bool
) -> dict[str, Any]:
    return {
        "format": SYNTHESIS_APPLY_VERIFICATION_FORMAT,
        "valid": False,
        "reconciled": False,
        "mode": "complete" if bindings_requested else "integrity_only",
        "checks": {
            "content_integrity": False,
            "structure": False,
            "source_analysis_binding": False if bindings_requested else None,
            "workspace_integrity": False if bindings_requested else None,
            "workspace_binding": False if bindings_requested else None,
            "result_analysis_binding": False if bindings_requested else None,
            "decision_reconciliation": False if bindings_requested else None,
        },
        "applied_suggestion_count": 0,
        "deferred": 0,
        "declared_content_sha256": "",
        "actual_content_sha256": "",
        "errors": [error],
        "notice": (
            "Complete reconciliation proves exact source, sealed-workspace, result, and "
            "decision-accounting bindings. It does not approve the suggestions, findings, "
            "risk, citations, or evidence sufficiency."
        ),
    }
