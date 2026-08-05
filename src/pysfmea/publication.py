"""Stable package-publication failure taxonomy and remediation metadata."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .file_publication import atomic_publish_text, inspect_artifact_destination
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_file

PUBLICATION_FAILURE_CATALOG_FORMAT = "pysfmea-publication-failure-catalog-1"
PUBLICATION_FAILURE_CATALOG_ALGORITHM = "sha256"
PUBLICATION_FAILURE_CATALOG_CANONICALIZATION = "json-sort-keys-compact-utf8"
PUBLICATION_FAILURE_CATALOG_VERIFICATION_FORMAT = (
    "pysfmea-publication-failure-catalog-verification-1"
)
MAX_PUBLICATION_FAILURE_CATALOG_BYTES = 1_000_000
MAX_PUBLICATION_FAILURE_CATALOG_DEPTH = 50
MAX_PUBLICATION_FAILURE_CATALOG_NODES = 100_000
PUBLICATION_FAILURE_CATALOG_NOTICE = (
    "Failure categories and next actions support automation and remediation; "
    "they do not prove package safety, approval, or successful recovery."
)


@dataclass(frozen=True, slots=True)
class PublicationFailure:
    """One public, schema-bound package-publication failure category."""

    code: str
    rule_id: str
    phases: tuple[str, ...]
    next_action: str
    retry_policy: str
    message: str


_FAILURES = (
    PublicationFailure(
        code="analysis_missing",
        rule_id="package.publication.analysis_missing",
        phases=("analysis_load",),
        next_action="provide_analysis",
        retry_policy="after_remediation",
        message="The requested analysis input was not found or is unavailable.",
    ),
    PublicationFailure(
        code="analysis_unreadable",
        rule_id="package.publication.analysis_unreadable",
        phases=("analysis_load",),
        next_action="restore_analysis_access",
        retry_policy="after_remediation",
        message="The requested analysis input could not be read from local storage.",
    ),
    PublicationFailure(
        code="analysis_invalid",
        rule_id="package.publication.analysis_invalid",
        phases=("analysis_load",),
        next_action="repair_analysis",
        retry_policy="after_remediation",
        message="The analysis input is not valid supported PySFMEA JSON.",
    ),
    PublicationFailure(
        code="destination_unavailable",
        rule_id="package.publication.destination_unavailable",
        phases=("generation",),
        next_action="choose_writable_destination",
        retry_policy="after_remediation",
        message="The review package destination could not be written safely.",
    ),
    PublicationFailure(
        code="generation_rejected",
        rule_id="package.publication.generation_rejected",
        phases=("generation",),
        next_action="resolve_generation_rejection",
        retry_policy="after_remediation",
        message=(
            "Review package generation was rejected by an input, destination, "
            "or internal verification check."
        ),
    ),
    PublicationFailure(
        code="internal_failure",
        rule_id="package.publication.internal_failure",
        phases=("analysis_load", "generation"),
        next_action="collect_diagnostics",
        retry_policy="manual_diagnostics",
        message=(
            "Review package publication stopped after an internal failure; "
            "retry with diagnostic logging in an approved environment."
        ),
    ),
)


def _validate_catalog() -> None:
    codes = [failure.code for failure in _FAILURES]
    rule_ids = [failure.rule_id for failure in _FAILURES]
    next_actions = [failure.next_action for failure in _FAILURES]
    if len(codes) != len(set(codes)):
        raise RuntimeError("publication failure codes must be unique")
    if len(rule_ids) != len(set(rule_ids)):
        raise RuntimeError("publication failure rule IDs must be unique")
    if len(next_actions) != len(set(next_actions)):
        raise RuntimeError("publication failure next actions must be unique")
    for failure in _FAILURES:
        if failure.rule_id != f"package.publication.{failure.code}":
            raise RuntimeError("publication failure rule ID must match its code")
        if not failure.phases or set(failure.phases) - {
            "analysis_load",
            "generation",
        }:
            raise RuntimeError("publication failure phases are invalid")
        if not failure.next_action or not failure.message:
            raise RuntimeError("publication failure remediation metadata is incomplete")
        if failure.retry_policy not in {"after_remediation", "manual_diagnostics"}:
            raise RuntimeError("publication failure retry policy is invalid")


_validate_catalog()

PUBLICATION_FAILURES: Mapping[str, PublicationFailure] = MappingProxyType(
    {failure.code: failure for failure in _FAILURES}
)


def classify_publication_failure(
    error: Exception, *, phase: str
) -> PublicationFailure:
    """Classify an exception without exposing exception text or host paths."""

    if phase not in {"analysis_load", "generation"}:
        raise ValueError(f"unsupported package publication phase: {phase}")
    if isinstance(error, RuntimeError):
        return PUBLICATION_FAILURES["internal_failure"]
    if phase == "analysis_load":
        if isinstance(error, FileNotFoundError):
            return PUBLICATION_FAILURES["analysis_missing"]
        if isinstance(error, (PermissionError, OSError)):
            return PUBLICATION_FAILURES["analysis_unreadable"]
        if isinstance(error, (json.JSONDecodeError, UnicodeError, ValueError)):
            return PUBLICATION_FAILURES["analysis_invalid"]
        return PUBLICATION_FAILURES["internal_failure"]
    if isinstance(error, (PermissionError, OSError)):
        return PUBLICATION_FAILURES["destination_unavailable"]
    if isinstance(error, ValueError):
        return PUBLICATION_FAILURES["generation_rejected"]
    return PUBLICATION_FAILURES["internal_failure"]


def _publication_failure_catalog_content() -> dict[str, object]:
    return {
        "format": PUBLICATION_FAILURE_CATALOG_FORMAT,
        "algorithm": PUBLICATION_FAILURE_CATALOG_ALGORITHM,
        "canonicalization": PUBLICATION_FAILURE_CATALOG_CANONICALIZATION,
        "failures": [
            {
                "code": failure.code,
                "rule_id": failure.rule_id,
                "phases": list(failure.phases),
                "next_action": failure.next_action,
                "retry_policy": failure.retry_policy,
                "message": failure.message,
            }
            for failure in sorted(PUBLICATION_FAILURES.values(), key=lambda item: item.code)
        ],
        "notice": PUBLICATION_FAILURE_CATALOG_NOTICE,
    }


PUBLICATION_FAILURE_CATALOG_SHA256 = canonical_json_sha256(
    _publication_failure_catalog_content()
)


def publication_failure_catalog() -> dict[str, object]:
    """Return the deterministic, content-addressed remediation catalog."""

    return {
        **_publication_failure_catalog_content(),
        "content_sha256": PUBLICATION_FAILURE_CATALOG_SHA256,
    }


def export_publication_failure_catalog(
    destination: str | Path, *, overwrite: bool = False
) -> Path:
    """Atomically publish deterministic catalog JSON without replacing unknown files."""

    destination_state = inspect_artifact_destination(
        destination, label="publication catalog"
    )
    path = destination_state.path
    if destination_state.snapshot is not None:
        if not overwrite:
            raise ValueError(
                "publication catalog destination already exists; use --force to replace it"
            )
        existing = verify_publication_failure_catalog_file(path)
        existing_checks = existing.get("checks", {})
        if not (
            isinstance(existing_checks, dict)
            and existing_checks.get("format")
            and existing_checks.get("integrity_metadata")
            and existing_checks.get("structure")
        ):
            raise ValueError(
                "publication catalog destination is not a recognized catalog envelope; "
                "refusing replacement"
            )
    document = (
        json.dumps(publication_failure_catalog(), indent=2, ensure_ascii=False) + "\n"
    )
    return atomic_publish_text(
        destination,
        document,
        max_bytes=MAX_PUBLICATION_FAILURE_CATALOG_BYTES,
        label="publication catalog",
        expected_destination=destination_state,
    )


def verify_publication_failure_catalog(value: Any) -> dict[str, object]:
    """Return a bounded, stable verdict for a decoded catalog candidate."""

    expected = publication_failure_catalog()
    is_object = isinstance(value, dict)
    candidate = value if is_object else {}
    declared_digest = str(candidate.get("content_sha256", ""))
    content = dict(candidate)
    content.pop("content_sha256", None)
    actual_digest = canonical_json_sha256(content) if is_object else ""
    expected_keys = set(expected)
    failures = candidate.get("failures")
    failure_keys = {
        "code",
        "rule_id",
        "phases",
        "next_action",
        "retry_policy",
        "message",
    }
    failure_structure_valid = bool(
        isinstance(failures, list)
        and len(failures) == len(PUBLICATION_FAILURES)
        and all(
            isinstance(entry, dict)
            and set(entry) == failure_keys
            and all(
                isinstance(entry.get(field), str) and bool(entry.get(field))
                for field in (
                    "code",
                    "rule_id",
                    "next_action",
                    "retry_policy",
                    "message",
                )
            )
            and isinstance(entry.get("phases"), list)
            and bool(entry["phases"])
            and all(isinstance(phase, str) for phase in entry["phases"])
            and len(entry["phases"]) == len(set(entry["phases"]))
            and not set(entry["phases"]) - {"analysis_load", "generation"}
            for entry in failures
        )
    )
    checks = {
        "json_object": is_object,
        "format": candidate.get("format") == PUBLICATION_FAILURE_CATALOG_FORMAT,
        "integrity_metadata": (
            candidate.get("algorithm") == PUBLICATION_FAILURE_CATALOG_ALGORITHM
            and candidate.get("canonicalization")
            == PUBLICATION_FAILURE_CATALOG_CANONICALIZATION
            and len(declared_digest) == 64
            and all(character in "0123456789abcdef" for character in declared_digest)
        ),
        "structure": (
            is_object
            and set(candidate) == expected_keys
            and failure_structure_valid
            and isinstance(candidate.get("notice"), str)
            and bool(candidate.get("notice"))
        ),
        "content_integrity": bool(
            is_object and declared_digest and declared_digest == actual_digest
        ),
        "canonical_catalog": candidate == expected,
    }
    messages = {
        "json_object": "Catalog root must be a JSON object.",
        "format": "Catalog format is missing or unsupported.",
        "integrity_metadata": (
            "Catalog integrity algorithm, canonicalization, or digest encoding is invalid."
        ),
        "structure": "Catalog fields or failure-entry structure are incomplete or unexpected.",
        "content_integrity": "Catalog content does not match its declared SHA-256 digest.",
        "canonical_catalog": "Catalog does not match the taxonomy shipped by this verifier.",
    }
    errors = [
        {
            "code": f"publication_catalog.{name}",
            "message": messages[name],
            "path": "",
        }
        for name, passed in checks.items()
        if not passed
    ]
    result: dict[str, object] = {
        "format": PUBLICATION_FAILURE_CATALOG_VERIFICATION_FORMAT,
        "source": "<memory>",
        "valid": all(checks.values()),
        "checks": checks,
        "errors": errors,
        "catalog_format": str(candidate.get("format", "")),
        "declared_content_sha256": declared_digest,
        "failure_count": len(failures) if isinstance(failures, list) else 0,
        "notice": (
            "Catalog verification establishes exact taxonomy and content integrity; "
            "it does not authorize remediation, retry, approval, or risk acceptance."
        ),
    }
    if actual_digest:
        result["actual_content_sha256"] = actual_digest
    return result


def verify_publication_failure_catalog_file(source: str | Path) -> dict[str, object]:
    """Load and verify one strict, bounded, identity-stable catalog JSON file."""

    path = Path(source).expanduser().absolute()
    input_error = ""
    candidate: Any = None
    try:
        path, candidate, _size = load_bounded_json_file(
            path,
            label="publication catalog input",
            max_bytes=MAX_PUBLICATION_FAILURE_CATALOG_BYTES,
            max_depth=MAX_PUBLICATION_FAILURE_CATALOG_DEPTH,
            max_nodes=MAX_PUBLICATION_FAILURE_CATALOG_NODES,
        )
    except ValueError as exc:
        input_error = str(exc)
    result = verify_publication_failure_catalog(candidate)
    result["source"] = str(path)
    if input_error:
        result["errors"] = [
            {
                "code": "publication_catalog.input",
                "message": input_error,
                "path": "",
            },
            *result["errors"],
        ]
        result["valid"] = False
    return result
