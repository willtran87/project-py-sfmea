"""Normative-schema and independent receiving-tool interoperability evidence.

PySFMEA's internal projection checks prove source binding and population
reconciliation.  This module deliberately keeps a second boundary: validation
against a supplied normative schema and a separately recorded receiving-tool
round trip.  Neither receipt authenticates the schema publisher or operator;
those are project assurance responsibilities made explicit in the artifacts.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.metadata
import json
import re
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import (
    BoundedFileSnapshot,
    load_bounded_file_snapshot,
    load_bounded_json_document,
    parse_bounded_json_bytes,
)
from .model import utc_now

NORMATIVE_VALIDATION_FORMAT = "pysfmea-normative-schema-validation-1"
NORMATIVE_VALIDATION_VERIFICATION_FORMAT = (
    "pysfmea-normative-schema-validation-verification-1"
)
ROUNDTRIP_EVIDENCE_FORMAT = "pysfmea-independent-roundtrip-evidence-1"
ROUNDTRIP_VERIFICATION_FORMAT = "pysfmea-independent-roundtrip-verification-1"
SCHEMA_KINDS = frozenset({"json-schema", "xml-schema"})
MAX_ARTIFACT_BYTES = 100_000_000
MAX_SCHEMA_BYTES = 20_000_000
MAX_ERRORS = 1_000
MAX_TEXT = 20_000


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT:
        raise ValueError(f"{label} must be non-empty bounded text")
    return value.strip()


def _sha256(snapshot: BoundedFileSnapshot) -> str:
    return hashlib.sha256(snapshot.raw).hexdigest()


def _file_binding(snapshot: BoundedFileSnapshot) -> dict[str, Any]:
    return {
        "reference": snapshot.path.name,
        "bytes": snapshot.size,
        "sha256": _sha256(snapshot),
    }


def _json_schema_validate(
    artifact: BoundedFileSnapshot, schema: BoundedFileSnapshot
) -> tuple[str, str, list[str]]:
    try:
        from jsonschema.validators import validator_for  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - exercised in minimal installs
        raise RuntimeError(
            "JSON Schema validation requires the 'interop' or 'dev' optional dependency"
        ) from exc

    artifact_value = parse_bounded_json_bytes(
        artifact.raw,
        label="exchange artifact",
        max_bytes=MAX_ARTIFACT_BYTES,
        max_depth=150,
        max_nodes=2_000_000,
    )
    schema_value = parse_bounded_json_bytes(
        schema.raw,
        label="normative JSON Schema",
        max_bytes=MAX_SCHEMA_BYTES,
        max_depth=150,
        max_nodes=1_000_000,
    )
    if not isinstance(schema_value, dict):
        raise ValueError("normative JSON Schema root must be an object")
    validator_type = validator_for(schema_value)
    validator_type.check_schema(schema_value)
    validator = validator_type(schema_value, format_checker=validator_type.FORMAT_CHECKER)
    errors = sorted(
        validator.iter_errors(artifact_value),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    rendered = [
        f"/{'/'.join(str(part) for part in error.absolute_path)}: {error.message}"
        for error in errors[:MAX_ERRORS]
    ]
    if len(errors) > MAX_ERRORS:
        rendered.append(f"validation produced {len(errors) - MAX_ERRORS} additional errors")
    return (
        f"jsonschema-{validator_type.__name__}",
        importlib.metadata.version("jsonschema"),
        rendered,
    )


def _xml_schema_validate(
    artifact: BoundedFileSnapshot, schema: BoundedFileSnapshot
) -> tuple[str, str, list[str]]:
    try:
        from lxml import etree  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - depends on optional wheel
        raise RuntimeError(
            "XML Schema validation requires the 'interop' optional dependency"
        ) from exc

    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        huge_tree=False,
        remove_comments=False,
    )
    schema_root = etree.fromstring(schema.raw, parser=parser)
    validator = etree.XMLSchema(schema_root)
    artifact_root = etree.fromstring(artifact.raw, parser=parser)
    valid = validator.validate(artifact_root)
    errors = [] if valid else [str(entry) for entry in validator.error_log[:MAX_ERRORS]]
    return "lxml-etree-XMLSchema", importlib.metadata.version("lxml"), errors


def normative_schema_validation(
    artifact_source: str | Path,
    schema_source: str | Path,
    *,
    schema_kind: str,
    standard_name: str,
    standard_edition: str,
    normative_schema_uri: str,
    schema_publisher_sha256: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Validate exact bytes against a supplied schema and seal the result."""

    if schema_kind not in SCHEMA_KINDS:
        raise ValueError("schema kind must be json-schema or xml-schema")
    standard = {
        "name": _text(standard_name, "standard name"),
        "edition": _text(standard_edition, "standard edition"),
        "normative_schema_uri": _text(
            normative_schema_uri, "normative schema URI"
        ),
        "publisher_schema_sha256": schema_publisher_sha256,
    }
    if schema_publisher_sha256 is not None and not re.fullmatch(
        r"[0-9a-f]{64}", schema_publisher_sha256
    ):
        raise ValueError("publisher schema SHA-256 must be lowercase hexadecimal")
    artifact = load_bounded_file_snapshot(
        artifact_source,
        label="exchange artifact",
        max_bytes=MAX_ARTIFACT_BYTES,
    )
    schema = load_bounded_file_snapshot(
        schema_source,
        label="normative schema",
        max_bytes=MAX_SCHEMA_BYTES,
    )
    if schema_publisher_sha256 is not None and _sha256(schema) != schema_publisher_sha256:
        raise ValueError("supplied schema does not match the publisher-controlled digest")
    if schema_kind == "json-schema":
        engine, version, errors = _json_schema_validate(artifact, schema)
        schema_value = parse_bounded_json_bytes(
            schema.raw,
            label="normative JSON Schema",
            max_bytes=MAX_SCHEMA_BYTES,
            max_depth=150,
            max_nodes=1_000_000,
        )
        identifier = str(schema_value.get("$id", "")) if isinstance(schema_value, dict) else ""
    else:
        engine, version, errors = _xml_schema_validate(artifact, schema)
        identifier = normative_schema_uri
    valid = not errors
    receipt: dict[str, Any] = {
        "format": NORMATIVE_VALIDATION_FORMAT,
        "generated_at": generated_at or utc_now(),
        "schema_kind": schema_kind,
        "standard": standard,
        "validator": {"engine": engine, "version": version},
        "artifact": _file_binding(artifact),
        "schema": {**_file_binding(schema), "identifier": identifier},
        "outcome": {
            "valid": valid,
            "error_count": len(errors),
            "errors": errors,
        },
        "claim": (
            "The exact artifact bytes passed validation against the exact supplied "
            "schema bytes. Schema provenance and standard conformance beyond that schema "
            "remain subject to authorized review."
            if valid
            else "The exact artifact bytes did not pass the supplied normative schema."
        ),
    }
    receipt["content_sha256"] = canonical_json_sha256(receipt)
    return receipt


def _validation_structure(receipt: dict[str, Any]) -> bool:
    expected = {
        "format",
        "generated_at",
        "schema_kind",
        "standard",
        "validator",
        "artifact",
        "schema",
        "outcome",
        "claim",
        "content_sha256",
    }
    try:
        standard = receipt["standard"]
        validator = receipt["validator"]
        artifact = receipt["artifact"]
        schema = receipt["schema"]
        outcome = receipt["outcome"]
        return bool(
            set(receipt) == expected
            and receipt["format"] == NORMATIVE_VALIDATION_FORMAT
            and receipt["schema_kind"] in SCHEMA_KINDS
            and isinstance(standard, dict)
            and set(standard)
            == {
                "name",
                "edition",
                "normative_schema_uri",
                "publisher_schema_sha256",
            }
            and isinstance(validator, dict)
            and set(validator) == {"engine", "version"}
            and isinstance(artifact, dict)
            and set(artifact) == {"reference", "bytes", "sha256"}
            and isinstance(schema, dict)
            and set(schema) == {"reference", "bytes", "sha256", "identifier"}
            and isinstance(outcome, dict)
            and set(outcome) == {"valid", "error_count", "errors"}
            and isinstance(outcome["valid"], bool)
            and isinstance(outcome["error_count"], int)
            and outcome["error_count"] >= 0
            and isinstance(outcome["errors"], list)
            and outcome["error_count"] == len(outcome["errors"])
            and all(isinstance(error, str) and error for error in outcome["errors"])
            and outcome["valid"] == (not outcome["errors"])
            and all(
                isinstance(binding["bytes"], int)
                and binding["bytes"] >= 1
                and re.fullmatch(r"[0-9a-f]{64}", str(binding["sha256"]))
                for binding in (artifact, schema)
            )
            and (
                standard["publisher_schema_sha256"] is None
                or re.fullmatch(
                    r"[0-9a-f]{64}", standard["publisher_schema_sha256"]
                )
            )
            and (
                standard["publisher_schema_sha256"] is None
                or standard["publisher_schema_sha256"] == schema["sha256"]
            )
        )
    except (KeyError, TypeError):
        return False


def verify_normative_schema_validation(
    receipt: dict[str, Any],
    *,
    artifact: BoundedFileSnapshot | None = None,
    schema: BoundedFileSnapshot | None = None,
) -> dict[str, Any]:
    """Verify receipt structure, integrity, semantics, and optional exact files."""

    errors: list[str] = []
    structure = _validation_structure(receipt)
    if not structure:
        errors.append("validation receipt fields or semantics are invalid")
    unsigned = copy.deepcopy(receipt)
    claimed = str(unsigned.pop("content_sha256", ""))
    integrity = bool(
        re.fullmatch(r"[0-9a-f]{64}", claimed)
        and canonical_json_sha256(unsigned) == claimed
    )
    if not integrity:
        errors.append("validation receipt content digest does not match")
    artifact_binding: bool | None = None
    schema_binding: bool | None = None
    if artifact is not None:
        artifact_binding = bool(
            structure and receipt["artifact"] == _file_binding(artifact)
        )
        if not artifact_binding:
            errors.append("validation receipt does not bind the supplied artifact")
    if schema is not None:
        expected = _file_binding(schema)
        schema_binding = bool(
            structure
            and all(receipt["schema"].get(key) == value for key, value in expected.items())
        )
        if not schema_binding:
            errors.append("validation receipt does not bind the supplied schema")
    valid = bool(
        structure
        and integrity
        and artifact_binding is not False
        and schema_binding is not False
    )
    return {
        "format": NORMATIVE_VALIDATION_VERIFICATION_FORMAT,
        "valid": valid,
        "schema_valid": bool(valid and receipt.get("outcome", {}).get("valid")),
        "checks": {
            "closed_structure": structure,
            "content_integrity": integrity,
            "artifact_binding": artifact_binding,
            "schema_binding": schema_binding,
        },
        "errors": errors,
        "content_sha256": claimed,
        "notice": (
            "Receipt verification proves exact-byte validation accounting. It does not "
            "authenticate the schema publisher or grant standard conformance."
        ),
    }


def verify_normative_schema_validation_file(
    receipt_source: str | Path,
    *,
    artifact_source: str | Path | None = None,
    schema_source: str | Path | None = None,
) -> dict[str, Any]:
    try:
        document = load_bounded_json_document(
            receipt_source,
            label="normative validation receipt",
            max_bytes=5_000_000,
            max_depth=50,
            max_nodes=200_000,
        )
        if not isinstance(document.value, dict):
            raise ValueError("normative validation receipt must contain an object")
        artifact = (
            load_bounded_file_snapshot(
                artifact_source,
                label="exchange artifact",
                max_bytes=MAX_ARTIFACT_BYTES,
            )
            if artifact_source is not None
            else None
        )
        schema = (
            load_bounded_file_snapshot(
                schema_source,
                label="normative schema",
                max_bytes=MAX_SCHEMA_BYTES,
            )
            if schema_source is not None
            else None
        )
        return {
            "path": str(document.path),
            **verify_normative_schema_validation(
                document.value, artifact=artifact, schema=schema
            ),
        }
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "path": str(Path(receipt_source).expanduser().absolute()),
            "format": NORMATIVE_VALIDATION_VERIFICATION_FORMAT,
            "valid": False,
            "schema_valid": False,
            "checks": {
                "closed_structure": False,
                "content_integrity": False,
                "artifact_binding": False if artifact_source is not None else None,
                "schema_binding": False if schema_source is not None else None,
            },
            "errors": [str(exc)],
            "content_sha256": "",
            "notice": "The normative validation receipt could not be safely verified.",
        }


def export_normative_schema_validation(
    receipt: dict[str, Any], destination: str | Path
) -> Path:
    verdict = verify_normative_schema_validation(receipt)
    if not verdict["valid"]:
        raise ValueError("normative validation receipt is internally invalid")
    return atomic_publish_text(
        destination,
        json.dumps(receipt, indent=2, ensure_ascii=False) + "\n",
        label="normative schema validation receipt",
    )


def independent_roundtrip_evidence(
    validation_receipt_source: str | Path,
    evidence_source: str | Path,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Seal independent receiving-tool evidence to one validation receipt."""

    receipt_document = load_bounded_json_document(
        validation_receipt_source,
        label="normative validation receipt",
        max_bytes=5_000_000,
        max_depth=50,
        max_nodes=200_000,
    )
    if not isinstance(receipt_document.value, dict):
        raise ValueError("normative validation receipt must contain an object")
    receipt_verdict = verify_normative_schema_validation(receipt_document.value)
    if not receipt_verdict["valid"] or not receipt_verdict["schema_valid"]:
        raise ValueError("round-trip evidence requires a valid passing schema receipt")
    evidence_document = load_bounded_json_document(
        evidence_source,
        label="independent round-trip observation",
        max_bytes=5_000_000,
        max_depth=30,
        max_nodes=100_000,
    )
    evidence = evidence_document.value
    expected = {
        "receiver_name",
        "receiver_version",
        "receiver_vendor",
        "operator",
        "independence_basis",
        "import_succeeded",
        "import_evidence_ref",
        "reexport_artifact",
        "identity_preserved",
        "relationships_preserved",
        "extensions_preserved",
        "differences",
        "comparison_evidence_ref",
    }
    if not isinstance(evidence, dict) or set(evidence) != expected:
        raise ValueError("round-trip observation fields do not match format 1")
    for field in (
        "receiver_name",
        "receiver_version",
        "receiver_vendor",
        "operator",
        "independence_basis",
        "import_evidence_ref",
        "comparison_evidence_ref",
    ):
        _text(evidence[field], f"round-trip {field}")
    if str(evidence["receiver_name"]).casefold() == "pysfmea":
        raise ValueError("round-trip receiver must be independent of PySFMEA")
    for field in (
        "import_succeeded",
        "identity_preserved",
        "relationships_preserved",
        "extensions_preserved",
    ):
        if not isinstance(evidence[field], bool):
            raise ValueError(f"round-trip {field} must be boolean")
    differences = evidence["differences"]
    if (
        not isinstance(differences, list)
        or len(differences) > 1_000
        or any(not isinstance(value, str) or not value for value in differences)
    ):
        raise ValueError("round-trip differences must be a bounded text array")
    reexport = load_bounded_file_snapshot(
        evidence["reexport_artifact"],
        label="receiving-tool re-export",
        max_bytes=MAX_ARTIFACT_BYTES,
    )
    passed = bool(
        evidence["import_succeeded"]
        and evidence["identity_preserved"]
        and evidence["relationships_preserved"]
        and evidence["extensions_preserved"]
        and not differences
    )
    result: dict[str, Any] = {
        "format": ROUNDTRIP_EVIDENCE_FORMAT,
        "generated_at": generated_at or utc_now(),
        "validation_receipt": {
            "reference": receipt_document.path.name,
            "bytes": receipt_document.size,
            "sha256": hashlib.sha256(receipt_document.raw).hexdigest(),
            "content_sha256": receipt_document.value["content_sha256"],
        },
        "observation": {
            "reference": evidence_document.path.name,
            "bytes": evidence_document.size,
            "sha256": hashlib.sha256(evidence_document.raw).hexdigest(),
        },
        "receiver": {
            "name": evidence["receiver_name"],
            "version": evidence["receiver_version"],
            "vendor": evidence["receiver_vendor"],
        },
        "operator": evidence["operator"],
        "independence_basis": evidence["independence_basis"],
        "import": {
            "succeeded": evidence["import_succeeded"],
            "evidence_ref": evidence["import_evidence_ref"],
        },
        "reexport": _file_binding(reexport),
        "preservation": {
            "identity": evidence["identity_preserved"],
            "relationships": evidence["relationships_preserved"],
            "extensions": evidence["extensions_preserved"],
            "differences": differences,
            "comparison_evidence_ref": evidence["comparison_evidence_ref"],
        },
        "passed": passed,
        "claim": (
            "Independent receiving-tool round trip preserved the declared identity, "
            "relationships, and extensions."
            if passed
            else "Independent receiving-tool round trip has unresolved failures or differences."
        ),
    }
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def verify_independent_roundtrip_evidence(
    value: dict[str, Any],
    *,
    validation_receipt: BoundedFileSnapshot | None = None,
    observation: BoundedFileSnapshot | None = None,
    reexport: BoundedFileSnapshot | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    expected = {
        "format",
        "generated_at",
        "validation_receipt",
        "observation",
        "receiver",
        "operator",
        "independence_basis",
        "import",
        "reexport",
        "preservation",
        "passed",
        "claim",
        "content_sha256",
    }
    structure = False
    semantics = False
    try:
        structure = bool(
            set(value) == expected
            and value["format"] == ROUNDTRIP_EVIDENCE_FORMAT
            and set(value["validation_receipt"])
            == {"reference", "bytes", "sha256", "content_sha256"}
            and set(value["observation"]) == {"reference", "bytes", "sha256"}
            and set(value["receiver"]) == {"name", "version", "vendor"}
            and set(value["import"]) == {"succeeded", "evidence_ref"}
            and set(value["reexport"]) == {"reference", "bytes", "sha256"}
            and set(value["preservation"])
            == {
                "identity",
                "relationships",
                "extensions",
                "differences",
                "comparison_evidence_ref",
            }
        )
        preservation = value["preservation"]
        expected_passed = bool(
            value["import"]["succeeded"]
            and preservation["identity"]
            and preservation["relationships"]
            and preservation["extensions"]
            and not preservation["differences"]
        )
        semantics = bool(
            structure
            and isinstance(value["passed"], bool)
            and value["passed"] == expected_passed
            and str(value["receiver"]["name"]).casefold() != "pysfmea"
        )
    except (KeyError, TypeError):
        structure = False
        semantics = False
    if not structure:
        errors.append("round-trip evidence fields do not match format 1")
    if not semantics:
        errors.append("round-trip outcome does not reconcile")
    unsigned = copy.deepcopy(value)
    claimed = str(unsigned.pop("content_sha256", ""))
    integrity = bool(
        re.fullmatch(r"[0-9a-f]{64}", claimed)
        and canonical_json_sha256(unsigned) == claimed
    )
    if not integrity:
        errors.append("round-trip evidence content digest does not match")

    def matches(snapshot: BoundedFileSnapshot | None, binding: Any) -> bool | None:
        if snapshot is None:
            return None
        return bool(
            isinstance(binding, dict)
            and binding.get("bytes") == snapshot.size
            and binding.get("sha256") == _sha256(snapshot)
        )

    receipt_binding = matches(validation_receipt, value.get("validation_receipt"))
    observation_binding = matches(observation, value.get("observation"))
    reexport_binding = matches(reexport, value.get("reexport"))
    for label, state in (
        ("validation receipt", receipt_binding),
        ("observation", observation_binding),
        ("re-export", reexport_binding),
    ):
        if state is False:
            errors.append(f"round-trip evidence does not bind the supplied {label}")
    valid = bool(
        structure
        and semantics
        and integrity
        and all(
            state is not False
            for state in (receipt_binding, observation_binding, reexport_binding)
        )
    )
    return {
        "format": ROUNDTRIP_VERIFICATION_FORMAT,
        "valid": valid,
        "passed": bool(valid and value.get("passed")),
        "checks": {
            "closed_structure": structure,
            "content_integrity": integrity,
            "semantic_reconciliation": semantics,
            "validation_receipt_binding": receipt_binding,
            "observation_binding": observation_binding,
            "reexport_binding": reexport_binding,
        },
        "errors": errors,
        "content_sha256": claimed,
        "notice": (
            "Verification proves exact evidence accounting, not operator identity, "
            "organizational independence, or universal receiving-tool compatibility."
        ),
    }


def export_independent_roundtrip_evidence(
    value: dict[str, Any], destination: str | Path
) -> Path:
    verdict = verify_independent_roundtrip_evidence(value)
    if not verdict["valid"]:
        raise ValueError("independent round-trip evidence is internally invalid")
    return atomic_publish_text(
        destination,
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        label="independent round-trip evidence",
    )


def verify_independent_roundtrip_evidence_file(
    source: str | Path,
    *,
    validation_receipt_source: str | Path | None = None,
    observation_source: str | Path | None = None,
    reexport_source: str | Path | None = None,
) -> dict[str, Any]:
    """Safely verify a round-trip receipt and optional exact source files."""

    try:
        document = load_bounded_json_document(
            source,
            label="independent round-trip evidence",
            max_bytes=5_000_000,
            max_depth=60,
            max_nodes=250_000,
        )
        if not isinstance(document.value, dict):
            raise ValueError("independent round-trip evidence must contain an object")

        def snapshot(
            candidate: str | Path | None, label: str, limit: int
        ) -> BoundedFileSnapshot | None:
            return (
                load_bounded_file_snapshot(candidate, label=label, max_bytes=limit)
                if candidate is not None
                else None
            )

        return {
            "path": str(document.path),
            **verify_independent_roundtrip_evidence(
                document.value,
                validation_receipt=snapshot(
                    validation_receipt_source,
                    "normative validation receipt",
                    5_000_000,
                ),
                observation=snapshot(
                    observation_source,
                    "independent round-trip observation",
                    5_000_000,
                ),
                reexport=snapshot(
                    reexport_source,
                    "receiving-tool re-export",
                    MAX_ARTIFACT_BYTES,
                ),
            ),
        }
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {
            "path": str(Path(source).expanduser().absolute()),
            "format": ROUNDTRIP_VERIFICATION_FORMAT,
            "valid": False,
            "passed": False,
            "checks": {
                "closed_structure": False,
                "content_integrity": False,
                "semantic_reconciliation": False,
                "validation_receipt_binding": False
                if validation_receipt_source is not None
                else None,
                "observation_binding": False
                if observation_source is not None
                else None,
                "reexport_binding": False if reexport_source is not None else None,
            },
            "errors": [str(exc)],
            "content_sha256": "",
            "notice": "The independent round-trip evidence could not be safely verified.",
        }
