"""Governed authoring, sealing, verification, and application of SFTA inputs."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from .config import validate_fault_tree_definitions
from .file_publication import atomic_publish_text, inspect_artifact_destination
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .model import stable_id, utc_now
from .sfta import build_sfta

SFTA_AUTHORING_DRAFT_FORMAT = "pysfmea-sfta-authoring-draft-1"
SFTA_AUTHORING_FORMAT = "pysfmea-sfta-authoring-1"
SFTA_AUTHORING_VERIFICATION_FORMAT = "pysfmea-sfta-authoring-verification-1"
SFTA_AUTHORING_APPLY_RECEIPT_FORMAT = "pysfmea-sfta-authoring-apply-receipt-1"
MAX_SFTA_AUTHORING_BYTES = 20_000_000
MAX_SFTA_AUTHORING_DEPTH = 100
MAX_SFTA_AUTHORING_NODES = 500_000


def _binding(analysis: dict[str, Any]) -> dict[str, str]:
    baseline = analysis.get("project", {}).get("baseline", {})
    return {
        "baseline_id": str(baseline.get("id", "")),
        "repository_sha256": str(baseline.get("repository_sha256", "")),
        "analysis_state_sha256": canonical_json_sha256(analysis),
    }


def _skeleton(hazard: dict[str, Any]) -> dict[str, Any]:
    hazard_id = str(hazard.get("id", ""))
    tree_id = stable_id("SFTA", hazard_id, "authored")
    top_id = stable_id("SFTA-TOP", hazard_id)
    undeveloped_id = stable_id("SFTA-UNDEV", hazard_id)
    description = str(hazard.get("description", hazard_id))
    return {
        "id": tree_id,
        "hazard": hazard_id,
        "top_event_id": top_id,
        "top_event": description,
        "description": "Preliminary software contribution tree; replace the undeveloped event with reviewed logic where warranted.",
        "assumptions": [],
        "gates": [],
        "events": [
            {
                "id": top_id,
                "type": "top",
                "description": description,
                "inputs": [undeveloped_id],
            },
            {
                "id": undeveloped_id,
                "type": "undeveloped",
                "description": "Software contributors require explicit engineering decomposition.",
                "inputs": [],
                "component_patterns": [],
                "failure_mode_patterns": [],
                "finding_ids": [],
                "evidence": [],
                "assumptions": [],
            },
        ],
    }


def sfta_authoring_draft(analysis: dict[str, Any]) -> dict[str, Any]:
    """Create an editable draft with one explicit action per configured hazard."""

    context = analysis.get("context", {})
    hazards = [value for value in context.get("hazards", []) if isinstance(value, dict)]
    existing = {
        str(value.get("hazard", "")): value
        for value in context.get("fault_trees", [])
        if isinstance(value, dict) and value.get("hazard")
    }
    entries = []
    for hazard in hazards:
        hazard_id = str(hazard.get("id", ""))
        definition = copy.deepcopy(existing.get(hazard_id) or _skeleton(hazard))
        is_existing = hazard_id in existing
        entries.append(
            {
                "hazard_id": hazard_id,
                "hazard_description": str(hazard.get("description", "")),
                "source": "existing_explicit_tree"
                if is_existing
                else "generated_authoring_skeleton",
                "action": "retain" if is_existing else "defer",
                "definition": definition,
                "review": {
                    "status": "not_required" if is_existing else "unreviewed",
                    "reviewer": "",
                    "rationale": "",
                },
            }
        )
    return {
        "format": SFTA_AUTHORING_DRAFT_FORMAT,
        "created_at": utc_now(),
        "analysis_binding": _binding(analysis),
        "entries": entries,
        "instructions": [
            "Use action retain for an unchanged explicit tree, defer to leave the analysis unchanged, or replace to apply the supplied definition.",
            "Every replace action requires review.status approved, a named reviewer, and rationale.",
            "Gate and event logic must be explicit. PySFMEA validates structure and correlation but does not infer causal sufficiency.",
            "Seal this draft against the unchanged analysis before application.",
        ],
        "authority": "editable_engineering_input_not_approved_fault_tree",
    }


def export_sfta_authoring_draft(
    analysis: dict[str, Any], destination: str | Path
) -> Path:
    expected = inspect_artifact_destination(destination, label="SFTA authoring draft")
    draft = sfta_authoring_draft(analysis)
    return atomic_publish_text(
        destination,
        json.dumps(draft, indent=2, ensure_ascii=False) + "\n",
        label="SFTA authoring draft",
        max_bytes=MAX_SFTA_AUTHORING_BYTES,
        expected_destination=expected,
    )


def _validate_entries(
    entries: Any, analysis: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(entries, list) or not all(
        isinstance(value, dict) for value in entries
    ):
        raise ValueError("SFTA authoring entries must be a list of objects")
    context = analysis.get("context", {})
    hazards = [value for value in context.get("hazards", []) if isinstance(value, dict)]
    hazard_ids = {str(value.get("id", "")) for value in hazards if value.get("id")}
    existing = {
        str(value.get("hazard", "")): copy.deepcopy(value)
        for value in context.get("fault_trees", [])
        if isinstance(value, dict) and value.get("hazard")
    }
    seen: set[str] = set()
    replacements: list[dict[str, Any]] = []
    normalized: list[dict[str, Any]] = []
    for index, entry in enumerate(entries, start=1):
        if set(entry) != {
            "hazard_id",
            "hazard_description",
            "source",
            "action",
            "definition",
            "review",
        }:
            raise ValueError(f"SFTA authoring entry {index} has unsupported fields")
        hazard_id = str(entry.get("hazard_id", ""))
        if hazard_id not in hazard_ids:
            raise ValueError(
                f"SFTA authoring entry {index} references an unknown hazard"
            )
        if hazard_id in seen:
            raise ValueError(f"SFTA authoring hazard is duplicated: {hazard_id}")
        seen.add(hazard_id)
        action = str(entry.get("action", ""))
        if action not in {"retain", "defer", "replace"}:
            raise ValueError(f"SFTA authoring entry {index} has an invalid action")
        definition = entry.get("definition")
        if not isinstance(definition, dict) or definition.get("hazard") != hazard_id:
            raise ValueError(
                f"SFTA authoring entry {index} definition must target {hazard_id}"
            )
        review = entry.get("review", {})
        if not isinstance(review, dict) or set(review) != {
            "status",
            "reviewer",
            "rationale",
        }:
            raise ValueError(f"SFTA authoring entry {index} review must be an object")
        if review.get("status") not in {
            "unreviewed",
            "not_required",
            "approved",
            "rework",
        } or not all(
            isinstance(review.get(field), str) for field in ("reviewer", "rationale")
        ):
            raise ValueError(f"SFTA authoring entry {index} review is invalid")
        if action == "retain":
            if hazard_id not in existing or definition != existing[hazard_id]:
                raise ValueError(
                    f"SFTA authoring retain action for {hazard_id} must exactly match the existing definition"
                )
        elif action == "replace":
            if (
                review.get("status") != "approved"
                or not str(review.get("reviewer", "")).strip()
                or not str(review.get("rationale", "")).strip()
            ):
                raise ValueError(
                    f"SFTA replacement for {hazard_id} requires approved review, reviewer, and rationale"
                )
            replacements.append(copy.deepcopy(definition))
        normalized.append(copy.deepcopy(entry))
    if seen != hazard_ids:
        missing = ", ".join(sorted(hazard_ids - seen))
        raise ValueError(
            f"SFTA authoring entries do not account for every hazard: {missing}"
        )
    combined = dict(existing)
    for definition in replacements:
        combined[str(definition["hazard"])] = definition
    validate_fault_tree_definitions(hazards, list(combined.values()))
    return normalized, replacements


def seal_sfta_authoring_draft(
    source: str | Path, analysis: dict[str, Any], destination: str | Path
) -> Path:
    """Validate an edited draft and publish an immutable exact-bound authoring input."""

    source_document = load_bounded_json_document(
        source,
        label="SFTA authoring draft",
        max_bytes=MAX_SFTA_AUTHORING_BYTES,
        max_depth=MAX_SFTA_AUTHORING_DEPTH,
        max_nodes=MAX_SFTA_AUTHORING_NODES,
    )
    draft = source_document.value
    if (
        not isinstance(draft, dict)
        or draft.get("format") != SFTA_AUTHORING_DRAFT_FORMAT
    ):
        raise ValueError("SFTA authoring draft format is missing or unsupported")
    if draft.get("analysis_binding") != _binding(analysis):
        raise ValueError("SFTA authoring draft does not match the exact analysis state")
    entries, replacements = _validate_entries(draft.get("entries"), analysis)
    sealed: dict[str, Any] = {
        "format": SFTA_AUTHORING_FORMAT,
        "sealed_at": utc_now(),
        "analysis_binding": _binding(analysis),
        "source_draft_sha256": hashlib.sha256(source_document.raw).hexdigest(),
        "summary": {
            "hazards": len(entries),
            "replacements": len(replacements),
            "retained": sum(value.get("action") == "retain" for value in entries),
            "deferred": sum(value.get("action") == "defer" for value in entries),
        },
        "entries": entries,
        "authority": "reviewed_structural_input_not_causal_sufficiency_risk_acceptance_or_compliance",
    }
    sealed["content_sha256"] = canonical_json_sha256(sealed)
    expected = inspect_artifact_destination(
        destination, label="sealed SFTA authoring input"
    )
    return atomic_publish_text(
        destination,
        json.dumps(sealed, indent=2, ensure_ascii=False) + "\n",
        label="sealed SFTA authoring input",
        max_bytes=MAX_SFTA_AUTHORING_BYTES,
        expected_destination=expected,
        staged_verifier=lambda path: (
            verify_sfta_authoring_file(path, analysis=analysis)["valid"] is True
        ),
    )


def _verify_value(value: Any, analysis: dict[str, Any] | None) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    findings: list[dict[str, str]] = []

    def check(name: str, passed: bool, code: str, message: str) -> None:
        checks[name] = passed
        if not passed:
            findings.append({"code": code, "message": message})

    shape = isinstance(value, dict)
    check(
        "object_shape", shape, "sfta_authoring.invalid_shape", "Root must be an object."
    )
    if not shape:
        return {
            "format": SFTA_AUTHORING_VERIFICATION_FORMAT,
            "valid": False,
            "status": "invalid",
            "analysis_checked": analysis is not None,
            "checks": checks,
            "counts": {"error": len(findings)},
            "findings": findings,
            "notice": "The authoring input was rejected before semantic processing.",
        }
    check(
        "format",
        value.get("format") == SFTA_AUTHORING_FORMAT,
        "sfta_authoring.unsupported_format",
        "Sealed SFTA authoring format is unsupported.",
    )
    supplied = value.get("content_sha256")
    canonical = dict(value)
    canonical.pop("content_sha256", None)
    check(
        "content_integrity",
        isinstance(supplied, str) and supplied == canonical_json_sha256(canonical),
        "sfta_authoring.content_mismatch",
        "Sealed content differs from its declared digest.",
    )
    check(
        "sealed_structure",
        isinstance(value.get("analysis_binding"), dict)
        and isinstance(value.get("summary"), dict)
        and isinstance(value.get("entries"), list)
        and isinstance(value.get("source_draft_sha256"), str)
        and len(str(value.get("source_draft_sha256", ""))) == 64,
        "sfta_authoring.invalid_structure",
        "Sealed SFTA authoring metadata or entries are malformed.",
    )
    if analysis is not None:
        check(
            "analysis_binding",
            value.get("analysis_binding") == _binding(analysis),
            "sfta_authoring.analysis_mismatch",
            "Sealed input does not match the exact supplied analysis.",
        )
        try:
            _validate_entries(value.get("entries"), analysis)
            semantic_valid = True
        except ValueError as exc:
            semantic_valid = False
            semantic_message = str(exc)
        check(
            "fault_tree_semantics",
            semantic_valid,
            "sfta_authoring.invalid_semantics",
            semantic_message if not semantic_valid else "",
        )
    valid = all(checks.values())
    return {
        "format": SFTA_AUTHORING_VERIFICATION_FORMAT,
        "valid": valid,
        "status": "matched"
        if valid and analysis is not None
        else "internally_valid"
        if valid
        else "invalid",
        "analysis_checked": analysis is not None,
        "checks": checks,
        "counts": {"error": len(findings)},
        "findings": findings,
        "notice": "Verification establishes integrity, structure, and optional exact binding; it does not establish fault-tree completeness or causal sufficiency.",
    }


def verify_sfta_authoring_file(
    source: str | Path, *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    try:
        document = load_bounded_json_document(
            source,
            label="sealed SFTA authoring input",
            max_bytes=MAX_SFTA_AUTHORING_BYTES,
            max_depth=MAX_SFTA_AUTHORING_DEPTH,
            max_nodes=MAX_SFTA_AUTHORING_NODES,
        )
    except ValueError as exc:
        return {
            "format": SFTA_AUTHORING_VERIFICATION_FORMAT,
            "valid": False,
            "status": "invalid",
            "analysis_checked": analysis is not None,
            "source": str(Path(source).absolute()),
            "source_bytes": 0,
            "source_sha256": "",
            "checks": {"bounded_ingestion": False},
            "counts": {"error": 1},
            "findings": [
                {"code": "sfta_authoring.ingestion_failed", "message": str(exc)}
            ],
            "notice": "The authoring input was rejected before semantic processing.",
        }
    result = _verify_value(document.value, analysis)
    result["source"] = str(document.path)
    result["source_bytes"] = document.size
    result["source_sha256"] = hashlib.sha256(document.raw).hexdigest()
    return result


def load_sfta_authoring(source: str | Path) -> dict[str, Any]:
    document = load_bounded_json_document(
        source,
        label="sealed SFTA authoring input",
        max_bytes=MAX_SFTA_AUTHORING_BYTES,
        max_depth=MAX_SFTA_AUTHORING_DEPTH,
        max_nodes=MAX_SFTA_AUTHORING_NODES,
    )
    if not isinstance(document.value, dict):
        raise ValueError("sealed SFTA authoring input root must be an object")
    return document.value


def apply_sfta_authoring(
    analysis: dict[str, Any], sealed: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    verification = _verify_value(sealed, analysis)
    if not verification["valid"]:
        codes = ", ".join(value["code"] for value in verification["findings"])
        raise ValueError(f"sealed SFTA authoring input cannot be applied: {codes}")
    replacements = {
        str(entry["hazard_id"]): copy.deepcopy(entry["definition"])
        for entry in sealed.get("entries", [])
        if entry.get("action") == "replace"
    }
    if not replacements:
        raise ValueError("sealed SFTA authoring input contains no approved replacement")
    updated = copy.deepcopy(analysis)
    context = updated.setdefault("context", {})
    definitions = {
        str(value.get("hazard", "")): copy.deepcopy(value)
        for value in context.get("fault_trees", [])
        if isinstance(value, dict) and value.get("hazard")
    }
    definitions.update(replacements)
    context["fault_trees"] = [definitions[key] for key in sorted(definitions)]
    applied_at = utc_now()
    updated.setdefault("sfta_authoring", {}).setdefault("history", []).append(
        {
            "sealed_input_sha256": str(sealed.get("content_sha256", "")),
            "applied_at": applied_at,
            "replacement_hazards": sorted(replacements),
            "reviews": [
                {
                    "hazard_id": str(entry["hazard_id"]),
                    "definition_sha256": canonical_json_sha256(entry["definition"]),
                    **copy.deepcopy(entry["review"]),
                }
                for entry in sealed.get("entries", [])
                if entry.get("action") == "replace"
            ],
        }
    )
    updated["sfta"] = build_sfta(updated)
    receipt: dict[str, Any] = {
        "format": SFTA_AUTHORING_APPLY_RECEIPT_FORMAT,
        "status": "applied",
        "source_analysis_state_sha256": _binding(analysis)["analysis_state_sha256"],
        "sealed_input_sha256": str(sealed.get("content_sha256", "")),
        "result_analysis_state_sha256": canonical_json_sha256(updated),
        "replacement_hazards": sorted(replacements),
        "explicit_trees": int(
            updated.get("sfta", {})
            .get("reconciliation", {})
            .get("summary", {})
            .get("explicit_trees", 0)
        ),
        "placeholder_trees": int(
            updated.get("sfta", {})
            .get("reconciliation", {})
            .get("summary", {})
            .get("placeholder_trees", 0)
        ),
        "qualitative_cut_sets": int(
            updated.get("sfta", {})
            .get("reconciliation", {})
            .get("summary", {})
            .get("qualitative_cut_sets", 0)
        ),
        "notice": "Applied fault-tree definitions remain subject to engineering completeness, independence, and risk-acceptance review.",
    }
    receipt["content_sha256"] = canonical_json_sha256(receipt)
    return updated, receipt
