"""SLSA 1.2 trust-policy assessment for PySFMEA provenance.

Cryptographic verification is deliberately performed by an external verifier.  This
module consumes its attributable observation, applies a closed local trust policy,
and records why a Build or Source track level was (or was not) satisfied.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .model import utc_now
from .slsa import load_slsa_provenance, verify_slsa_provenance

SLSA_POLICY_FORMAT = "pysfmea-slsa-1.2-trust-policy-1"
SLSA_OBSERVATION_FORMAT = "pysfmea-slsa-1.2-verification-observation-1"
SLSA_ASSESSMENT_FORMAT = "pysfmea-slsa-1.2-policy-assessment-1"
SLSA_POLICY_VERIFICATION_FORMAT = "pysfmea-slsa-1.2-policy-verification-1"
LEVELS = {0, 1, 2, 3}


def _load_object(source: str | Path, label: str) -> tuple[dict[str, Any], Path]:
    document = load_bounded_json_document(
        source, label=label, max_bytes=20_000_000, max_depth=100, max_nodes=500_000
    )
    if not isinstance(document.value, dict):
        raise ValueError(f"{label} must contain an object")
    return copy.deepcopy(document.value), document.path


def _digest_valid(value: dict[str, Any]) -> bool:
    unsigned = copy.deepcopy(value)
    claimed = unsigned.pop("content_sha256", "")
    return bool(
        isinstance(claimed, str)
        and re.fullmatch(r"[0-9a-f]{64}", claimed)
        and canonical_json_sha256(unsigned) == claimed
    )


def slsa_trust_policy_template(*, authority: str, generated_at: str | None = None) -> dict[str, Any]:
    """Create a deny-by-default SLSA 1.2 Build/Source policy template."""

    result: dict[str, Any] = {
        "format": SLSA_POLICY_FORMAT,
        "generated_at": generated_at or utc_now(),
        "authority": authority.strip(),
        "minimum_build_track_level": 2,
        "minimum_source_track_level": 2,
        "trusted_builders": [],
        "trusted_signer_identities": [],
        "allowed_build_types": [],
        "allowed_source_repositories": [],
        "require_authenticated_provenance": True,
        "require_two_party_source_review": True,
        "policy_evidence_refs": [],
        "notice": (
            "Deny-by-default template. Populate identities and constraints from an approved "
            "threat model; policy evaluation is not cryptographic signature verification."
        ),
    }
    if not result["authority"]:
        raise ValueError("SLSA policy authority must not be empty")
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def slsa_verification_observation_template(
    *, verifier: str, generated_at: str | None = None
) -> dict[str, Any]:
    """Create an explicit evidence intake record for an external SLSA verifier."""

    result: dict[str, Any] = {
        "format": SLSA_OBSERVATION_FORMAT,
        "observed_at": generated_at or utc_now(),
        "verifier": verifier.strip(),
        "verification_tool": "",
        "verification_tool_version": "",
        "signature_verified": False,
        "signer_identity": "",
        "verification_evidence_ref": "",
        "hosted_build": False,
        "isolated_builds": False,
        "ephemeral_environment": False,
        "parameterless_rebuild": False,
        "source_repository": "",
        "source_two_party_reviewed": False,
        "source_provenance_verified": False,
        "source_history_retained": False,
        "evidence_refs": [],
    }
    if not result["verifier"]:
        raise ValueError("SLSA observation verifier must not be empty")
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def seal_slsa_verification_observation(source: str | Path, destination: str | Path) -> Path:
    value, _ = _load_object(source, "SLSA verification observation")
    value.pop("content_sha256", None)
    value["content_sha256"] = canonical_json_sha256(value)
    _validate_observation(value)
    return export_slsa_verification_observation(value, destination)


def seal_slsa_trust_policy(source: str | Path, destination: str | Path) -> Path:
    value, _ = _load_object(source, "SLSA trust policy")
    value.pop("content_sha256", None)
    value["content_sha256"] = canonical_json_sha256(value)
    _validate_policy(value)
    return export_slsa_trust_policy(value, destination)


def _text_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 10_000 or any(
        not isinstance(item, str) or not item.strip() or len(item) > 20_000 for item in value
    ) or len(value) != len(set(value)):
        raise ValueError(f"{label} must be a bounded unique text list")
    return [item.strip() for item in value]


def _validate_policy(value: dict[str, Any]) -> dict[str, Any]:
    fields = {
        "format", "generated_at", "authority", "minimum_build_track_level",
        "minimum_source_track_level", "trusted_builders", "trusted_signer_identities",
        "allowed_build_types", "allowed_source_repositories",
        "require_authenticated_provenance", "require_two_party_source_review",
        "policy_evidence_refs", "notice", "content_sha256",
    }
    if set(value) != fields or value.get("format") != SLSA_POLICY_FORMAT or not _digest_valid(value):
        raise ValueError("SLSA trust policy structure, format, or digest is invalid")
    if not isinstance(value["authority"], str) or not value["authority"].strip():
        raise ValueError("SLSA trust policy authority is required")
    if value["minimum_build_track_level"] not in LEVELS or value["minimum_source_track_level"] not in LEVELS:
        raise ValueError("SLSA track levels must be integers from 0 through 3")
    for name in (
        "trusted_builders", "trusted_signer_identities", "allowed_build_types",
        "allowed_source_repositories", "policy_evidence_refs",
    ):
        _text_list(value[name], name)
    if not isinstance(value["require_authenticated_provenance"], bool) or not isinstance(value["require_two_party_source_review"], bool):
        raise ValueError("SLSA policy requirement flags must be booleans")
    return value


def _validate_observation(value: dict[str, Any]) -> dict[str, Any]:
    fields = {
        "format", "observed_at", "verifier", "verification_tool", "verification_tool_version",
        "signature_verified", "signer_identity", "verification_evidence_ref", "hosted_build",
        "isolated_builds", "ephemeral_environment", "parameterless_rebuild", "source_repository",
        "source_two_party_reviewed", "source_provenance_verified", "source_history_retained",
        "evidence_refs", "content_sha256",
    }
    if set(value) != fields or value.get("format") != SLSA_OBSERVATION_FORMAT or not _digest_valid(value):
        raise ValueError("SLSA verification observation structure, format, or digest is invalid")
    for name in (
        "signature_verified", "hosted_build", "isolated_builds", "ephemeral_environment",
        "parameterless_rebuild", "source_two_party_reviewed", "source_provenance_verified",
        "source_history_retained",
    ):
        if not isinstance(value[name], bool):
            raise ValueError(f"SLSA observation {name} must be boolean")
    for name in ("verifier", "verification_tool", "verification_tool_version", "verification_evidence_ref"):
        if not isinstance(value[name], str) or not value[name].strip():
            raise ValueError(f"SLSA observation {name} is required")
    _text_list(value["evidence_refs"], "SLSA observation evidence")
    return value


def slsa_policy_assessment(
    provenance_source: str | Path,
    policy_source: str | Path,
    observation_source: str | Path,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Evaluate verified provenance observations against a SLSA 1.2 trust policy."""

    provenance = load_slsa_provenance(provenance_source)
    structural = verify_slsa_provenance(provenance)
    policy, policy_path = _load_object(policy_source, "SLSA trust policy")
    observation, observation_path = _load_object(observation_source, "SLSA verification observation")
    _validate_policy(policy)
    _validate_observation(observation)
    predicate = provenance.get("predicate", {})
    build_definition = predicate.get("buildDefinition", {}) if isinstance(predicate, dict) else {}
    run_details = predicate.get("runDetails", {}) if isinstance(predicate, dict) else {}
    builder = run_details.get("builder", {}) if isinstance(run_details, dict) else {}
    builder_id = str(builder.get("id", "")) if isinstance(builder, dict) else ""
    build_type = str(build_definition.get("buildType", "")) if isinstance(build_definition, dict) else ""
    builder_trusted = builder_id in policy["trusted_builders"]
    build_type_allowed = build_type in policy["allowed_build_types"]
    signer_trusted = observation["signer_identity"] in policy["trusted_signer_identities"]
    repository_allowed = observation["source_repository"] in policy["allowed_source_repositories"]
    authenticated = bool(observation["signature_verified"] and signer_trusted)

    build_level = 0
    if structural.get("valid"):
        build_level = 1
    if build_level >= 1 and builder_trusted and build_type_allowed and observation["hosted_build"] and authenticated:
        build_level = 2
    if build_level >= 2 and observation["isolated_builds"] and observation["ephemeral_environment"] and observation["parameterless_rebuild"]:
        build_level = 3

    source_level = 0
    if repository_allowed and observation["source_history_retained"]:
        source_level = 1
    if source_level >= 1 and observation["source_provenance_verified"] and observation["source_two_party_reviewed"]:
        source_level = 2
    # Source L3 requires stronger controls than this observation claims. Keep it unavailable
    # until a future closed format captures technical enforcement and administrator controls.

    checks = {
        "provenance_structurally_valid": bool(structural.get("valid")),
        "builder_trusted": builder_trusted,
        "build_type_allowed": build_type_allowed,
        "provenance_authenticated": authenticated if policy["require_authenticated_provenance"] else True,
        "source_repository_allowed": repository_allowed,
        "source_two_party_reviewed": bool(observation["source_two_party_reviewed"]) if policy["require_two_party_source_review"] else True,
        "minimum_build_track_level_met": build_level >= policy["minimum_build_track_level"],
        "minimum_source_track_level_met": source_level >= policy["minimum_source_track_level"],
    }
    passed = all(checks.values())
    result: dict[str, Any] = {
        "format": SLSA_ASSESSMENT_FORMAT,
        "generated_at": generated_at or utc_now(),
        "bindings": {
            "provenance_content_sha256": canonical_json_sha256(provenance),
            "policy_reference": policy_path.name,
            "policy_content_sha256": policy["content_sha256"],
            "observation_reference": observation_path.name,
            "observation_content_sha256": observation["content_sha256"],
        },
        "authority": policy["authority"],
        "identities": {"builder_id": builder_id, "build_type": build_type, "signer_identity": observation["signer_identity"], "source_repository": observation["source_repository"]},
        "levels": {
            "build_track_achieved": build_level,
            "build_track_required": policy["minimum_build_track_level"],
            "source_track_achieved": source_level,
            "source_track_required": policy["minimum_source_track_level"],
        },
        "checks": checks,
        "summary": {"passed": passed, "status": "policy_satisfied" if passed else "policy_not_satisfied", "failed_checks": sorted(name for name, state in checks.items() if not state)},
        "notice": (
            "This evaluates recorded evidence against local policy. Signature validity, builder "
            "operation, source controls, and SLSA conformance remain claims of their named evidence providers."
        ),
    }
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def verify_slsa_policy_assessment(value: dict[str, Any]) -> dict[str, Any]:
    expected = {"format", "generated_at", "bindings", "authority", "identities", "levels", "checks", "summary", "notice", "content_sha256"}
    errors: list[str] = []
    structure = bool(set(value) == expected and value.get("format") == SLSA_ASSESSMENT_FORMAT and isinstance(value.get("checks"), dict))
    semantic = False
    try:
        passed = all(state is True for state in value["checks"].values())
        semantic = value["summary"] == {"passed": passed, "status": "policy_satisfied" if passed else "policy_not_satisfied", "failed_checks": sorted(name for name, state in value["checks"].items() if not state)}
    except (KeyError, TypeError):
        semantic = False
    integrity = _digest_valid(value)
    if not structure:
        errors.append("SLSA policy assessment fields do not match format 1")
    if not semantic:
        errors.append("SLSA policy assessment summary does not reconcile")
    if not integrity:
        errors.append("SLSA policy assessment content digest does not match")
    return {
        "format": SLSA_POLICY_VERIFICATION_FORMAT, "valid": bool(structure and semantic and integrity),
        "passed": bool(structure and semantic and integrity and value.get("summary", {}).get("passed")),
        "checks": {"closed_structure": structure, "content_integrity": integrity, "semantic_reconciliation": semantic, "source_regeneration": None},
        "errors": errors, "content_sha256": str(value.get("content_sha256", "")),
        "notice": "Verification proves policy accounting, not cryptographic authenticity or SLSA certification.",
    }


def verify_slsa_policy_assessment_file(
    source: str | Path, *, provenance_source: str | Path | None = None,
    policy_source: str | Path | None = None, observation_source: str | Path | None = None,
) -> dict[str, Any]:
    try:
        value, path = _load_object(source, "SLSA policy assessment")
        result = verify_slsa_policy_assessment(value)
        result["path"] = str(path)
        if (
            provenance_source is not None
            and policy_source is not None
            and observation_source is not None
            and result["valid"]
        ):
            regenerated = slsa_policy_assessment(
                provenance_source, policy_source, observation_source,
                generated_at=str(value.get("generated_at", "")),
            )
            exact = regenerated == value
            result["checks"]["source_regeneration"] = exact
            result["valid"] = bool(result["valid"] and exact)
            result["passed"] = bool(result["passed"] and exact)
            if not exact:
                result["errors"].append("assessment does not exactly regenerate from supplied sources")
        return result
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "path": str(Path(source).expanduser().absolute()), "format": SLSA_POLICY_VERIFICATION_FORMAT,
            "valid": False, "passed": False,
            "checks": {"closed_structure": False, "content_integrity": False, "semantic_reconciliation": False, "source_regeneration": None},
            "errors": [str(exc)], "content_sha256": "",
            "notice": "The SLSA policy assessment could not be safely verified.",
        }


def export_slsa_trust_policy(value: dict[str, Any], destination: str | Path) -> Path:
    return atomic_publish_text(destination, json.dumps(value, indent=2, ensure_ascii=False) + "\n", label="SLSA trust policy")


def export_slsa_verification_observation(value: dict[str, Any], destination: str | Path) -> Path:
    return atomic_publish_text(destination, json.dumps(value, indent=2, ensure_ascii=False) + "\n", label="SLSA verification observation")


def export_slsa_policy_assessment(value: dict[str, Any], destination: str | Path) -> Path:
    return atomic_publish_text(destination, json.dumps(value, indent=2, ensure_ascii=False) + "\n", label="SLSA policy assessment")
