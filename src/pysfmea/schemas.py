"""Discoverable JSON Schema contracts for public PySFMEA interchange formats."""

from __future__ import annotations

import copy
import json
import os
import shutil
import uuid
from pathlib import Path
from typing import Any

from .assurance import (
    ASSURANCE_REGISTER_VERIFICATION_FORMAT,
    ASSURANCE_WORK_NEXT_ACTIONS,
    ASSURANCE_WORK_QUEUE_FORMAT,
    ASSURANCE_WORK_QUEUE_VERIFICATION_FORMAT,
    ASSURANCE_WORK_STATES,
)
from .diagrams import (
    DIAGRAM_BUNDLE_SCHEMA,
    DIAGRAM_BUNDLE_VERIFICATION_FORMAT,
    DIAGRAM_SCHEMA,
    DIAGRAM_TYPES,
    MAX_DIAGRAM_EDGES,
    MAX_DIAGRAM_NODES,
    MAX_DIAGRAMS,
    MAX_TEXT_LENGTH,
)
from .file_publication import atomic_publish_text
from .html_report import HTML_REPORT_VERIFICATION_FORMAT
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_file
from .publication import (
    PUBLICATION_FAILURE_CATALOG_ALGORITHM,
    PUBLICATION_FAILURE_CATALOG_CANONICALIZATION,
    PUBLICATION_FAILURE_CATALOG_FORMAT,
    PUBLICATION_FAILURE_CATALOG_NOTICE,
    PUBLICATION_FAILURE_CATALOG_SHA256,
    PUBLICATION_FAILURE_CATALOG_VERIFICATION_FORMAT,
    PUBLICATION_FAILURES,
    publication_failure_catalog,
)
from .signing import SIGNATURE_FORMAT, STATEMENT_FORMAT
from .workflow import WORKFLOW_STATUS_FORMAT

JSON_SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_CATALOG_FORMAT = "pysfmea-schema-catalog-1"
SCHEMA_BUNDLE_VERIFICATION_FORMAT = "pysfmea-schema-bundle-verification-1"
MAX_SCHEMA_BUNDLE_FILE_BYTES = 2_000_000
MAX_SCHEMA_BUNDLE_JSON_DEPTH = 100
MAX_SCHEMA_BUNDLE_JSON_NODES = 250_000
REVIEW_PACKAGE_FORMAT = "pysfmea-review-package-1"
REVIEW_PACKAGE_VERIFICATION_FORMAT = "pysfmea-review-package-verification-1"
ANALYSIS_STRUCTURE_VERIFICATION_FORMAT = (
    "pysfmea-analysis-structure-verification-1"
)
ANALYSIS_DIAGNOSTICS_VERIFICATION_FORMAT = (
    "pysfmea-analysis-diagnostics-verification-1"
)
GUIDANCE_TRACEABILITY_VERIFICATION_FORMAT = (
    "pysfmea-guidance-traceability-verification-1"
)
SFTA_PROJECTION_VERIFICATION_FORMAT = "pysfmea-sfta-projection-verification-1"
EVIDENCE_CATALOG_VERIFICATION_FORMAT = (
    "pysfmea-evidence-catalog-verification-1"
)
INTERCHANGE_ARTIFACTS_VERIFICATION_FORMAT = (
    "pysfmea-interchange-artifacts-verification-1"
)
REVIEW_VIEWS_VERIFICATION_FORMAT = "pysfmea-review-views-verification-1"
PACKAGE_PROVENANCE_VERIFICATION_FORMAT = (
    "pysfmea-package-provenance-verification-1"
)
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"


def _schema_id(name: str) -> str:
    return f"urn:pysfmea:schema:{name}:1"


def _scalar_schema() -> dict[str, Any]:
    return {"type": ["string", "number", "boolean", "null"]}


def _metadata_schema() -> dict[str, Any]:
    scalar = _scalar_schema()
    return {
        "type": "object",
        "additionalProperties": {
            "oneOf": [
                scalar,
                {
                    "type": "array",
                    "maxItems": 100,
                    "items": scalar,
                },
            ]
        },
    }


def _identifier_schema() -> dict[str, Any]:
    return {
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_TEXT_LENGTH,
        "pattern": _IDENTIFIER_PATTERN,
    }


def _text_schema(*, required: bool = False) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string", "maxLength": MAX_TEXT_LENGTH}
    if required:
        schema["minLength"] = 1
    return schema


def _diagram_definition() -> dict[str, Any]:
    identifier = _identifier_schema()
    text = _text_schema()
    required_text = _text_schema(required=True)
    node = {
        "type": "object",
        "required": ["id", "label", "kind"],
        "properties": {
            "id": identifier,
            "label": required_text,
            "kind": required_text,
            "group": text,
            "description": text,
            "source": text,
            "tags": {
                "type": "array",
                "maxItems": 100,
                "items": required_text,
            },
            "metrics": _metadata_schema(),
            "layer": {"type": ["integer", "null"], "minimum": 0, "maximum": 100},
            "order": {
                "type": ["integer", "null"],
                "minimum": 0,
                "maximum": 100_000,
            },
        },
        "additionalProperties": False,
    }
    edge = {
        "type": "object",
        "required": ["source", "target"],
        "properties": {
            "id": identifier,
            "source": identifier,
            "target": identifier,
            "label": text,
            "kind": required_text,
            "evidence": text,
            "description": text,
            "order": {
                "type": ["integer", "null"],
                "minimum": 0,
                "maximum": 100_000,
            },
            "cycle": {"type": "boolean"},
        },
        "additionalProperties": False,
    }
    return {
        "type": "object",
        "required": ["schema_version", "id", "title", "type", "nodes", "edges"],
        "properties": {
            "schema_version": {"const": DIAGRAM_SCHEMA},
            "id": identifier,
            "title": required_text,
            "type": {"enum": list(DIAGRAM_TYPES)},
            "description": text,
            "notice": text,
            "nodes": {
                "type": "array",
                "maxItems": MAX_DIAGRAM_NODES,
                "items": node,
            },
            "edges": {
                "type": "array",
                "maxItems": MAX_DIAGRAM_EDGES,
                "items": edge,
            },
            "metadata": _metadata_schema(),
        },
        "additionalProperties": False,
    }


def _diagram_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("diagram"),
        "title": "PySFMEA canonical diagram",
        "description": (
            "Structural contract for renderer-neutral diagrams. Uniqueness and edge "
            "reference checks require the PySFMEA semantic verifier."
        ),
        **_diagram_definition(),
    }


def _detached_signature_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("detached-signature"),
        "title": "PySFMEA detached Ed25519 package signature",
        "description": (
            "Closed structural contract for the detached signature envelope. "
            "Authenticity and subject reconciliation require verify-package with a "
            "separately trusted public key."
        ),
        "type": "object",
        "required": ["format", "statement", "key_fingerprint", "signature"],
        "properties": {
            "format": {"const": SIGNATURE_FORMAT},
            "statement": {
                "type": "object",
                "required": [
                    "format",
                    "algorithm",
                    "signed_at",
                    "signer",
                    "subject",
                ],
                "properties": {
                    "format": {"const": STATEMENT_FORMAT},
                    "algorithm": {"const": "Ed25519"},
                    "signed_at": {"type": "string", "minLength": 1},
                    "signer": {"type": "string", "minLength": 1, "maxLength": 4096},
                    "subject": {
                        "type": "object",
                        "required": [
                            "container",
                            "digest_scope",
                            "sha256",
                            "package_format",
                            "project",
                            "baseline_id",
                            "analysis_schema_version",
                            "package_generated_at",
                        ],
                        "properties": {
                            "container": {"enum": ["directory", "zip"]},
                            "digest_scope": {"enum": ["manifest_bytes", "zip_bytes"]},
                            "sha256": digest,
                            "package_format": {"const": REVIEW_PACKAGE_FORMAT},
                            "project": {"type": "string", "maxLength": 4096},
                            "baseline_id": {"type": "string", "maxLength": 4096},
                            "analysis_schema_version": {
                                "type": "string",
                                "maxLength": 256,
                            },
                            "package_generated_at": {
                                "type": "string",
                                "minLength": 1,
                            },
                        },
                        "additionalProperties": False,
                    },
                },
                "additionalProperties": False,
            },
            "key_fingerprint": {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
            },
            "signature": {
                "type": "string",
                "pattern": "^[A-Za-z0-9+/]{86}==$",
            },
        },
        "additionalProperties": False,
    }


def _assurance_work_queue_schema() -> dict[str, Any]:
    states = ASSURANCE_WORK_STATES
    next_actions = ASSURANCE_WORK_NEXT_ACTIONS
    count = {"type": "integer", "minimum": 0}
    text = {"type": "string", "maxLength": MAX_TEXT_LENGTH}
    item = {
        "type": "object",
        "required": [
            "finding_id",
            "obligation_id",
            "priority",
            "component",
            "state",
            "actionable",
            "automation_eligible",
            "next_action_id",
            "blockers",
            "latest_execution_id",
            "latest_execution_status",
        ],
        "properties": {
            "finding_id": _identifier_schema(),
            "obligation_id": text,
            "priority": text,
            "component": text,
            "state": {"enum": list(states)},
            "actionable": {"type": "boolean"},
            "automation_eligible": {"type": "boolean"},
            "next_action_id": {"enum": list(next_actions)},
            "blockers": {
                "type": "array",
                "maxItems": 100,
                "items": _text_schema(required=True),
            },
            "latest_execution_id": text,
            "latest_execution_status": text,
        },
        "additionalProperties": False,
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("assurance-work-queue"),
        "title": "PySFMEA assurance engineering work queue",
        "description": (
            "Closed structural contract for the accepted-finding hardening queue. "
            "Count reconciliation, lifecycle derivation, actionability, and automation "
            "eligibility require PySFMEA semantic validation."
        ),
        "type": "object",
        "required": [
            "format",
            "generator",
            "binding",
            "summary",
            "items",
            "notice",
            "integrity",
        ],
        "properties": {
            "format": {"const": ASSURANCE_WORK_QUEUE_FORMAT},
            "generator": {
                "type": "object",
                "required": ["name", "version"],
                "properties": {
                    "name": {"const": "PySFMEA"},
                    "version": {"type": "string", "minLength": 1},
                },
                "additionalProperties": False,
            },
            "binding": {
                "type": "object",
                "required": [
                    "format",
                    "baseline_id",
                    "analysis_schema_version",
                    "analysis_state_sha256",
                ],
                "properties": {
                    "format": {"const": ASSURANCE_WORK_QUEUE_FORMAT},
                    "baseline_id": {"type": "string", "minLength": 1},
                    "analysis_schema_version": {"type": "string", "minLength": 1},
                    "analysis_state_sha256": {
                        "type": "string",
                        "pattern": "^[0-9a-f]{64}$",
                    },
                },
                "additionalProperties": False,
            },
            "summary": {
                "type": "object",
                "required": [
                    "total",
                    "actionable",
                    "automation_eligible",
                    "implementation_ready",
                    "execution_ready",
                    "by_state",
                ],
                "properties": {
                    "total": count,
                    "actionable": count,
                    "automation_eligible": count,
                    "implementation_ready": count,
                    "execution_ready": count,
                    "by_state": {
                        "type": "object",
                        "properties": {state: count for state in states},
                        "additionalProperties": False,
                    },
                },
                "additionalProperties": False,
            },
            "items": {
                "type": "array",
                "maxItems": 1_000_000,
                "items": item,
            },
            "notice": _text_schema(required=True),
            "integrity": {
                "type": "object",
                "required": ["algorithm", "canonicalization", "content_sha256"],
                "properties": {
                    "algorithm": {"const": "sha256"},
                    "canonicalization": {"const": "json-sort-keys-compact-utf8"},
                    "content_sha256": {
                        "type": "string",
                        "pattern": "^[0-9a-f]{64}$",
                    },
                },
                "additionalProperties": False,
            },
        },
        "additionalProperties": False,
    }


def _diagram_bundle_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("diagram-bundle"),
        "title": "PySFMEA generated diagram bundle",
        "description": (
            "Structural contract for generated, integrity-declaring bundles. Digest, "
            "diagram identity, and analysis-state semantics require diagram-verify."
        ),
        "type": "object",
        "required": [
            "schema_version",
            "generator",
            "generated_at",
            "project",
            "generation",
            "binding",
            "diagrams",
            "integrity",
        ],
        "properties": {
            "schema_version": {"const": DIAGRAM_BUNDLE_SCHEMA},
            "generator": {
                "type": "object",
                "required": ["name", "version"],
                "properties": {
                    "name": {"const": "PySFMEA"},
                    "version": {"type": "string", "minLength": 1},
                },
                "additionalProperties": False,
            },
            "generated_at": {"type": "string", "minLength": 1},
            "project": {
                "type": "object",
                "required": ["name", "baseline_id"],
                "properties": {
                    "name": {"type": "string"},
                    "baseline_id": {"type": "string", "minLength": 1},
                },
                "additionalProperties": False,
            },
            "generation": {"type": "object"},
            "binding": {
                "type": "object",
                "required": [
                    "format",
                    "baseline_id",
                    "analysis_schema_version",
                    "analysis_state_sha256",
                ],
                "properties": {
                    "format": {"const": DIAGRAM_BUNDLE_SCHEMA},
                    "baseline_id": {"type": "string", "minLength": 1},
                    "analysis_schema_version": {"type": "string", "minLength": 1},
                    "analysis_state_sha256": digest,
                },
                "additionalProperties": False,
            },
            "diagrams": {
                "type": "array",
                "maxItems": MAX_DIAGRAMS,
                "items": {"$ref": "#/$defs/diagram"},
            },
            "integrity": {
                "type": "object",
                "required": ["algorithm", "canonicalization", "content_sha256"],
                "properties": {
                    "algorithm": {"const": "sha256"},
                    "canonicalization": {"const": "json-sort-keys-compact-utf8"},
                    "content_sha256": digest,
                },
                "additionalProperties": False,
            },
        },
        "$defs": {"diagram": _diagram_definition()},
        "additionalProperties": False,
    }


def _error_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "required": ["code", "message"],
        "properties": {
            "code": {"type": "string", "minLength": 1},
            "message": {"type": "string"},
            "path": {"type": "string"},
        },
        "additionalProperties": False,
    }


def _verification_schema(
    *,
    name: str,
    format_name: str,
    title: str,
    check_names: tuple[str, ...],
) -> dict[str, Any]:
    check_value = {"type": ["boolean", "null"]}
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id(name),
        "title": title,
        "description": (
            "Stable verdict envelope. Format-specific successful results may add "
            "diagnostic and provenance properties."
        ),
        "type": "object",
        "required": [
            "format",
            "path",
            "valid",
            "status",
            "binding_requested",
            "binding_checked",
            "checks",
            "failed_checks",
            "unchecked_checks",
            "errors",
            "notice",
        ],
        "properties": {
            "format": {"const": format_name},
            "verifier": {
                "type": "object",
                "required": ["name", "version"],
                "properties": {
                    "name": {"const": "PySFMEA"},
                    "version": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 128,
                    },
                },
                "additionalProperties": False,
            },
            "path": {"type": "string", "minLength": 1},
            "valid": {"type": "boolean"},
            "status": {
                "enum": [
                    "invalid",
                    "mismatched",
                    "matched",
                    "valid_binding_not_checked",
                ]
            },
            "binding_requested": {"type": "boolean"},
            "binding_checked": {"type": "boolean"},
            "checks": {
                "type": "object",
                "required": list(check_names),
                "properties": {name: check_value for name in check_names},
                "additionalProperties": False,
            },
            "failed_checks": {
                "type": "array",
                "uniqueItems": True,
                "items": {"enum": list(check_names)},
            },
            "unchecked_checks": {
                "type": "array",
                "uniqueItems": True,
                "items": {"enum": list(check_names)},
            },
            "errors": {"type": "array", "items": _error_schema()},
            "notice": {"type": "string", "minLength": 1},
        },
        "additionalProperties": True,
    }


def _html_report_verification_schema() -> dict[str, Any]:
    schema = _verification_schema(
        name="html-report-verification",
        format_name=HTML_REPORT_VERIFICATION_FORMAT,
        title="PySFMEA HTML report verification verdict",
        check_names=(
            "metadata_complete",
            "report_format",
            "payload_present",
            "payload_json",
            "payload_integrity",
            "payload_binding",
            "document_integrity",
            "baseline",
            "schema",
            "analysis_state",
        ),
    )
    schema["properties"]["publication"] = {
        "type": "object",
        "required": [
            "status",
            "phase",
            "destination_existed",
            "prior_destination_preserved",
        ],
        "properties": {
            "status": {"enum": ["published", "not_published"]},
            "phase": {
                "enum": [
                    "input_validation",
                    "analysis_load",
                    "generation",
                    "verification",
                    "publication",
                    "complete",
                ]
            },
            "destination_existed": {"type": "boolean"},
            "prior_destination_preserved": {"type": "boolean"},
        },
        "allOf": [
            {
                "if": {
                    "properties": {"status": {"const": "published"}},
                    "required": ["status"],
                },
                "then": {
                    "properties": {
                        "phase": {"const": "complete"},
                        "prior_destination_preserved": {"const": False},
                    }
                },
            },
            {
                "if": {
                    "properties": {"status": {"const": "not_published"}},
                    "required": ["status"],
                },
                "then": {
                    "properties": {
                        "phase": {
                            "enum": [
                                "input_validation",
                                "analysis_load",
                                "generation",
                                "verification",
                                "publication",
                            ]
                        }
                    }
                },
            },
        ],
        "additionalProperties": False,
    }
    schema["allOf"] = [
        {
            "if": {
                "required": ["publication"],
                "properties": {
                    "publication": {
                        "properties": {"status": {"const": "published"}},
                        "required": ["status"],
                    }
                },
            },
            "then": {
                "properties": {
                    "valid": {"const": True},
                    "status": {"const": "matched"},
                    "binding_requested": {"const": True},
                    "binding_checked": {"const": True},
                }
            },
        },
        {
            "if": {
                "required": ["publication"],
                "properties": {
                    "publication": {
                        "properties": {
                            "status": {"const": "not_published"}
                        },
                        "required": ["status"],
                    }
                },
            },
            "then": {"properties": {"valid": {"const": False}}},
        },
    ]
    return schema


def _diagram_bundle_verification_schema() -> dict[str, Any]:
    return _verification_schema(
        name="diagram-bundle-verification",
        format_name=DIAGRAM_BUNDLE_VERIFICATION_FORMAT,
        title="PySFMEA diagram bundle verification verdict",
        check_names=("content_integrity", "diagram_schema", "analysis_binding"),
    )


def _assurance_work_queue_verification_schema() -> dict[str, Any]:
    return _verification_schema(
        name="assurance-work-queue-verification",
        format_name=ASSURANCE_WORK_QUEUE_VERIFICATION_FORMAT,
        title="PySFMEA assurance work-queue verification verdict",
        check_names=(
            "format",
            "structure",
            "content_integrity",
            "baseline",
            "schema",
            "analysis_state",
            "semantic_projection",
        ),
    )


def _schema_catalog_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("schema-catalog"),
        "title": "PySFMEA public schema catalog",
        "description": (
            "Discovery contract for the complete content-addressed public schema set. "
            "Name uniqueness and digest reconciliation require semantic verification."
        ),
        "type": "object",
        "required": ["format", "schemas"],
        "properties": {
            "format": {"const": SCHEMA_CATALOG_FORMAT},
            "schemas": {
                "type": "array",
                "minItems": 1,
                "maxItems": 100,
                "items": {
                    "type": "object",
                    "required": [
                        "name",
                        "schema_id",
                        "draft",
                        "filename",
                        "description",
                        "sha256",
                    ],
                    "properties": {
                        "name": {"enum": sorted(_SCHEMA_BUILDERS)},
                        "schema_id": {"type": "string", "minLength": 1},
                        "draft": {"const": JSON_SCHEMA_DRAFT},
                        "filename": {
                            "type": "string",
                            "minLength": 1,
                            "pattern": r"^[^/\\]+$",
                        },
                        "description": {"type": "string", "minLength": 1},
                        "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    },
                    "additionalProperties": False,
                },
            },
        },
        "additionalProperties": False,
    }


def _schema_bundle_verification_schema() -> dict[str, Any]:
    check_names = (
        "file_set",
        "catalog_format",
        "catalog_completeness",
        "schema_identity",
        "content_integrity",
    )
    digest_or_empty = {
        "oneOf": [
            {"const": ""},
            {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        ]
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("schema-bundle-verification"),
        "title": "PySFMEA schema-bundle verification verdict",
        "description": (
            "Stable success and rejection verdict for the offline public-schema bundle."
        ),
        "type": "object",
        "required": [
            "format",
            "valid",
            "checks",
            "schema_count",
            "schemas",
            "errors",
            "notice",
        ],
        "properties": {
            "format": {"const": SCHEMA_BUNDLE_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "checks": {
                "type": "object",
                "required": list(check_names),
                "properties": {
                    name: {"type": "boolean"} for name in check_names
                },
                "additionalProperties": False,
            },
            "schema_count": {"type": "integer", "minimum": 0, "maximum": 100},
            "schemas": {
                "type": "array",
                "maxItems": 100,
                "items": {
                    "type": "object",
                    "required": [
                        "name",
                        "filename",
                        "schema_id",
                        "sha256",
                        "identity_valid",
                        "digest_valid",
                    ],
                    "properties": {
                        "name": {"enum": sorted(_SCHEMA_BUILDERS)},
                        "filename": {"type": "string", "minLength": 1},
                        "schema_id": {"type": "string"},
                        "sha256": digest_or_empty,
                        "identity_valid": {"type": "boolean"},
                        "digest_valid": {"type": "boolean"},
                    },
                    "additionalProperties": False,
                },
            },
            "errors": {"type": "array", "items": _error_schema()},
            "notice": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }


def _review_package_manifest_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    nonempty = {"type": "string", "minLength": 1, "maxLength": 4096}
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("review-package-manifest"),
        "title": "PySFMEA review-package manifest",
        "description": (
            "Structural contract for checksum-manifested review packages. File-set, "
            "digest, provenance, and governed-state semantics require verify-package."
        ),
        "type": "object",
        "required": [
            "format",
            "generated_at",
            "exporter",
            "analysis_generator",
            "analysis_schema_version",
            "project",
            "baseline_id",
            "analysis_state_sha256",
            "portable",
            "source_analysis",
            "files",
        ],
        "properties": {
            "format": {"const": REVIEW_PACKAGE_FORMAT},
            "generated_at": nonempty,
            "exporter": {
                "type": "object",
                "required": ["name", "version"],
                "properties": {
                    "name": {"const": "PySFMEA"},
                    "version": nonempty,
                },
                "additionalProperties": False,
            },
            "analysis_generator": {"type": "object"},
            "analysis_schema_version": {"type": "string", "maxLength": 256},
            "project": {"type": "string", "maxLength": 4096},
            "baseline_id": {"type": "string", "maxLength": 4096},
            "analysis_state_sha256": digest,
            "capabilities": {
                "type": "array",
                "uniqueItems": True,
                "items": {
                    "enum": [
                        "analysis_diagnostics_projection_v1",
                        "assurance_register_projection",
                        "assurance_work_queue_projection",
                        "evidence_catalog_projection_v1",
                        "guidance_traceability_projection_v1",
                        "interchange_artifacts_projection_v1",
                        "package_provenance_projection_v1",
                        "review_views_projection_v1",
                        "sfta_projection_v1",
                    ]
                },
            },
            "schema_catalog": {
                "type": "object",
                "required": [
                    "format",
                    "path",
                    "canonical_sha256",
                    "schema_count",
                ],
                "properties": {
                    "format": {"const": SCHEMA_CATALOG_FORMAT},
                    "path": {"const": SCHEMA_CATALOG_FILENAME},
                    "canonical_sha256": digest,
                    "schema_count": {"type": "integer", "minimum": 1},
                },
                "additionalProperties": False,
            },
            "portable": {"type": "boolean"},
            "source_analysis": {"type": "string", "maxLength": 32768},
            "files": {
                "type": "array",
                "minItems": 1,
                "maxItems": 100,
                "items": {
                    "type": "object",
                    "required": ["path", "bytes", "sha256"],
                    "properties": {
                        "path": nonempty,
                        "bytes": {"type": "integer", "minimum": 0},
                        "sha256": digest,
                    },
                    "additionalProperties": False,
                },
            },
        },
        "additionalProperties": True,
    }


def _publication_failure_catalog_schema() -> dict[str, Any]:
    failure = {
        "type": "object",
        "required": [
            "code",
            "rule_id",
            "phases",
            "next_action",
            "retry_policy",
            "message",
        ],
        "properties": {
            "code": {"enum": sorted(PUBLICATION_FAILURES)},
            "rule_id": {"type": "string", "minLength": 1},
            "phases": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {"enum": ["analysis_load", "generation"]},
            },
            "next_action": {"type": "string", "minLength": 1},
            "retry_policy": {
                "enum": ["after_remediation", "manual_diagnostics"]
            },
            "message": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("publication-failure-catalog"),
        "title": "PySFMEA package-publication failure and remediation catalog",
        "description": (
            "Deterministic discovery contract for package-publication failure codes, "
            "valid phases, stable findings, and next actions."
        ),
        "type": "object",
        "required": [
            "format",
            "algorithm",
            "canonicalization",
            "failures",
            "notice",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": PUBLICATION_FAILURE_CATALOG_FORMAT},
            "algorithm": {"const": PUBLICATION_FAILURE_CATALOG_ALGORITHM},
            "canonicalization": {
                "const": PUBLICATION_FAILURE_CATALOG_CANONICALIZATION,
            },
            "content_sha256": {
                "const": PUBLICATION_FAILURE_CATALOG_SHA256,
            },
            "failures": {
                "type": "array",
                "minItems": len(PUBLICATION_FAILURES),
                "maxItems": len(PUBLICATION_FAILURES),
                "uniqueItems": True,
                "items": failure,
                "allOf": [
                    {
                        "contains": {
                            "properties": {
                                "code": {"const": item.code},
                                "rule_id": {"const": item.rule_id},
                                "phases": {"const": list(item.phases)},
                                "next_action": {"const": item.next_action},
                                "retry_policy": {"const": item.retry_policy},
                                "message": {"const": item.message},
                            },
                            "required": [
                                "code",
                                "rule_id",
                                "phases",
                                "next_action",
                                "retry_policy",
                                "message",
                            ],
                        },
                        "minContains": 1,
                        "maxContains": 1,
                    }
                    for item in PUBLICATION_FAILURES.values()
                ],
            },
            "notice": {"const": PUBLICATION_FAILURE_CATALOG_NOTICE},
        },
        "additionalProperties": False,
    }


def _publication_failure_catalog_verification_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    check_names = (
        "json_object",
        "format",
        "integrity_metadata",
        "structure",
        "content_integrity",
        "canonical_catalog",
    )
    checks = {
        "type": "object",
        "required": list(check_names),
        "properties": {name: {"type": "boolean"} for name in check_names},
        "additionalProperties": False,
    }
    error = {
        "type": "object",
        "required": ["code", "message", "path"],
        "properties": {
            "code": {
                "enum": [
                    "publication_catalog.input",
                    *[f"publication_catalog.{name}" for name in check_names],
                ]
            },
            "message": {"type": "string", "minLength": 1},
            "path": {"type": "string"},
        },
        "additionalProperties": False,
    }
    passing_checks = {
        "required": list(check_names),
        "properties": {name: {"const": True} for name in check_names},
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("publication-failure-catalog-verification"),
        "title": "PySFMEA publication failure catalog verification verdict",
        "description": (
            "Bounded exact-taxonomy and canonical-content verification for received "
            "publication failure catalogs."
        ),
        "type": "object",
        "required": [
            "format",
            "source",
            "valid",
            "checks",
            "errors",
            "catalog_format",
            "declared_content_sha256",
            "failure_count",
            "notice",
        ],
        "properties": {
            "format": {
                "const": PUBLICATION_FAILURE_CATALOG_VERIFICATION_FORMAT
            },
            "source": {"type": "string", "minLength": 1},
            "valid": {"type": "boolean"},
            "checks": checks,
            "errors": {"type": "array", "items": error, "maxItems": 10},
            "catalog_format": {"type": "string", "maxLength": 256},
            "declared_content_sha256": {
                "type": "string",
                "maxLength": 256,
            },
            "actual_content_sha256": digest,
            "failure_count": {"type": "integer", "minimum": 0, "maximum": 10_000},
            "notice": {"type": "string", "minLength": 1},
        },
        "allOf": [
            {
                "if": {"properties": {"valid": {"const": True}}},
                "then": {
                    "required": ["actual_content_sha256"],
                    "properties": {
                        "checks": passing_checks,
                        "errors": {"maxItems": 0},
                        "catalog_format": {
                            "const": PUBLICATION_FAILURE_CATALOG_FORMAT
                        },
                        "declared_content_sha256": {
                            "const": PUBLICATION_FAILURE_CATALOG_SHA256
                        },
                        "actual_content_sha256": {
                            "const": PUBLICATION_FAILURE_CATALOG_SHA256
                        },
                        "failure_count": {"const": len(PUBLICATION_FAILURES)},
                    },
                },
                "else": {"properties": {"errors": {"minItems": 1}}},
            },
            {
                "if": {"properties": {"checks": passing_checks}},
                "then": {"properties": {"valid": {"const": True}}},
                "else": {"properties": {"valid": {"const": False}}},
            },
        ],
        "additionalProperties": False,
    }


def _review_package_verification_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    queue_verdict = _assurance_work_queue_verification_schema()
    for metadata_field in ("$schema", "$id", "title", "description"):
        queue_verdict.pop(metadata_field, None)
    finding = {
        "type": "object",
        "required": ["rule_id", "level", "message", "path"],
        "properties": {
            "rule_id": {"type": "string", "minLength": 1},
            "level": {"enum": ["error", "warning"]},
            "message": {"type": "string"},
            "path": {"type": "string"},
        },
        "additionalProperties": False,
    }
    analysis_structure_check_names = (
        "json_object",
        "depth_limit",
        "node_limit",
        "core_contract",
    )
    analysis_structure_verdict = {
        "type": "object",
        "required": [
            "format",
            "valid",
            "checks",
            "errors",
            "node_count",
            "max_depth",
            "limits",
            "notice",
        ],
        "properties": {
            "format": {"const": ANALYSIS_STRUCTURE_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "checks": {
                "type": "object",
                "required": list(analysis_structure_check_names),
                "properties": {
                    name: {"type": "boolean"}
                    for name in analysis_structure_check_names
                },
                "additionalProperties": False,
            },
            "errors": {"type": "array", "items": _error_schema()},
            "node_count": {"type": "integer", "minimum": 0},
            "max_depth": {"type": "integer", "minimum": 0},
            "limits": {
                "type": "object",
                "required": ["max_nodes", "max_depth"],
                "properties": {
                    "max_nodes": {"type": "integer", "minimum": 1},
                    "max_depth": {"type": "integer", "minimum": 1},
                },
                "additionalProperties": False,
            },
            "notice": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }
    register_check_names = (
        "structure",
        "semantic_projection",
        "embedded_work_queue",
        "standalone_work_queue_consistency",
    )
    register_verdict = {
        "type": "object",
        "required": [
            "format",
            "valid",
            "checks",
            "errors",
            "obligation_count",
            "notice",
        ],
        "properties": {
            "format": {"const": ASSURANCE_REGISTER_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "checks": {
                "type": "object",
                "required": list(register_check_names),
                "properties": {
                    name: {"type": "boolean"} for name in register_check_names
                },
                "additionalProperties": False,
            },
            "errors": {"type": "array", "items": _error_schema()},
            "obligation_count": {"type": "integer", "minimum": 0},
            "notice": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }
    diagnostic_check_names = (
        "summary",
        "validation",
        "system_context",
        "repository_inventory",
        "adapter_runs",
    )
    diagnostics_verdict = {
        "type": "object",
        "required": [
            "format",
            "valid",
            "checks",
            "errors",
            "artifact_count",
            "notice",
        ],
        "properties": {
            "format": {"const": ANALYSIS_DIAGNOSTICS_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "checks": {
                "type": "object",
                "required": list(diagnostic_check_names),
                "properties": {
                    name: {"type": "boolean"} for name in diagnostic_check_names
                },
                "additionalProperties": False,
            },
            "errors": {"type": "array", "items": _error_schema()},
            "artifact_count": {"const": len(diagnostic_check_names)},
            "notice": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }
    guidance_check_names = (
        "traceability_projection",
        "citation_catalog_projection",
        "cross_artifact_consistency",
    )
    guidance_verdict = {
        "type": "object",
        "required": [
            "format",
            "valid",
            "checks",
            "errors",
            "artifact_count",
            "citation_count",
            "finding_link_count",
            "notice",
        ],
        "properties": {
            "format": {"const": GUIDANCE_TRACEABILITY_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "checks": {
                "type": "object",
                "required": list(guidance_check_names),
                "properties": {
                    name: {"type": "boolean"} for name in guidance_check_names
                },
                "additionalProperties": False,
            },
            "errors": {"type": "array", "items": _error_schema()},
            "artifact_count": {"const": 2},
            "citation_count": {"type": "integer", "minimum": 0},
            "finding_link_count": {"type": "integer", "minimum": 0},
            "notice": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }
    sfta_check_names = (
        "model_projection",
        "gap_register_projection",
        "gap_count_consistency",
    )
    sfta_verdict = {
        "type": "object",
        "required": [
            "format",
            "valid",
            "checks",
            "errors",
            "artifact_count",
            "tree_count",
            "gap_count",
            "notice",
        ],
        "properties": {
            "format": {"const": SFTA_PROJECTION_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "checks": {
                "type": "object",
                "required": list(sfta_check_names),
                "properties": {
                    name: {"type": "boolean"} for name in sfta_check_names
                },
                "additionalProperties": False,
            },
            "errors": {"type": "array", "items": _error_schema()},
            "artifact_count": {"const": 2},
            "tree_count": {"type": "integer", "minimum": 0},
            "gap_count": {"type": "integer", "minimum": 0},
            "notice": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }
    evidence_check_names = (
        "semantic_projection",
        "baseline_binding",
        "execution_inventory",
        "evidence_artifact_inventory",
    )
    evidence_verdict = {
        "type": "object",
        "required": [
            "format",
            "valid",
            "checks",
            "errors",
            "artifact_count",
            "execution_count",
            "evidence_artifact_count",
            "notice",
        ],
        "properties": {
            "format": {"const": EVIDENCE_CATALOG_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "checks": {
                "type": "object",
                "required": list(evidence_check_names),
                "properties": {
                    name: {"type": "boolean"} for name in evidence_check_names
                },
                "additionalProperties": False,
            },
            "errors": {"type": "array", "items": _error_schema()},
            "artifact_count": {"const": 1},
            "execution_count": {"type": "integer", "minimum": 0},
            "evidence_artifact_count": {"type": "integer", "minimum": 0},
            "notice": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }
    interchange_check_names = (
        "sarif_projection",
        "cyclonedx_projection",
        "baseline_consistency",
    )
    interchange_verdict = {
        "type": "object",
        "required": [
            "format",
            "valid",
            "checks",
            "errors",
            "artifact_count",
            "sarif_result_count",
            "cyclonedx_component_count",
            "notice",
        ],
        "properties": {
            "format": {"const": INTERCHANGE_ARTIFACTS_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "checks": {
                "type": "object",
                "required": list(interchange_check_names),
                "properties": {
                    name: {"type": "boolean"} for name in interchange_check_names
                },
                "additionalProperties": False,
            },
            "errors": {"type": "array", "items": _error_schema()},
            "artifact_count": {"const": 2},
            "sarif_result_count": {"type": "integer", "minimum": 0},
            "cyclonedx_component_count": {"type": "integer", "minimum": 0},
            "notice": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }
    review_view_check_names = (
        "worksheet_projection",
        "system_views_projection",
        "audit_projection",
        "guidance_csv_projection",
        "assurance_views_projection",
    )
    review_views_verdict = {
        "type": "object",
        "required": [
            "format",
            "valid",
            "checks",
            "errors",
            "artifact_count",
            "finding_count",
            "component_count",
            "notice",
        ],
        "properties": {
            "format": {"const": REVIEW_VIEWS_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "checks": {
                "type": "object",
                "required": list(review_view_check_names),
                "properties": {
                    name: {"type": "boolean"} for name in review_view_check_names
                },
                "additionalProperties": False,
            },
            "errors": {"type": "array", "items": _error_schema()},
            "artifact_count": {"const": 10},
            "finding_count": {"type": "integer", "minimum": 0},
            "component_count": {"type": "integer", "minimum": 0},
            "notice": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }
    provenance_check_names = (
        "run_manifest_projection",
        "readme_projection",
        "timestamp_consistency",
        "baseline_consistency",
    )
    provenance_verdict = {
        "type": "object",
        "required": [
            "format",
            "valid",
            "checks",
            "errors",
            "artifact_count",
            "review_decision_count",
            "execution_count",
            "notice",
        ],
        "properties": {
            "format": {"const": PACKAGE_PROVENANCE_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "checks": {
                "type": "object",
                "required": list(provenance_check_names),
                "properties": {
                    name: {"type": "boolean"} for name in provenance_check_names
                },
                "additionalProperties": False,
            },
            "errors": {"type": "array", "items": _error_schema()},
            "artifact_count": {"const": 2},
            "review_decision_count": {"type": "integer", "minimum": 0},
            "execution_count": {"type": "integer", "minimum": 0},
            "notice": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("review-package-verification"),
        "title": "PySFMEA review-package verification verdict",
        "description": (
            "Stable verdict envelope for success and rejection results. Successful "
            "results may add binding, schema-catalog, archive, and signature details."
        ),
        "x-pysfmea-publication-failure-catalog": publication_failure_catalog(),
        "type": "object",
        "required": [
            "verification_format",
            "verifier",
            "package",
            "container",
            "format",
            "valid",
            "checked_files",
            "counts",
            "findings",
            "notice",
        ],
        "properties": {
            "verification_format": {"const": REVIEW_PACKAGE_VERIFICATION_FORMAT},
            "verifier": {
                "type": "object",
                "required": ["name", "version"],
                "properties": {
                    "name": {"const": "PySFMEA"},
                    "version": {"type": "string", "minLength": 1, "maxLength": 128},
                },
                "additionalProperties": False,
            },
            "package": {"type": "string", "minLength": 1},
            "container": {"enum": ["directory", "zip"]},
            "format": {"type": "string"},
            "valid": {"type": "boolean"},
            "checked_files": {"type": "integer", "minimum": 0},
            "manifest_sha256": digest,
            "archive_sha256": digest,
            "publication": {
                "type": "object",
                "required": ["status", "phase"],
                "properties": {
                    "status": {"enum": ["published", "not_published"]},
                    "phase": {
                        "enum": [
                            "analysis_load",
                            "generation",
                            "complete",
                            "post_publication_verification",
                        ]
                    },
                    "catalog_format": {
                        "const": PUBLICATION_FAILURE_CATALOG_FORMAT,
                    },
                    "catalog_algorithm": {
                        "const": PUBLICATION_FAILURE_CATALOG_ALGORITHM,
                    },
                    "catalog_canonicalization": {
                        "const": PUBLICATION_FAILURE_CATALOG_CANONICALIZATION,
                    },
                    "catalog_sha256": {
                        "const": PUBLICATION_FAILURE_CATALOG_SHA256,
                    },
                    "failure_code": {
                        "enum": sorted(PUBLICATION_FAILURES),
                    },
                    "failure_rule_id": {
                        "enum": sorted(
                            failure.rule_id
                            for failure in PUBLICATION_FAILURES.values()
                        )
                    },
                    "next_action": {
                        "enum": sorted(
                            failure.next_action
                            for failure in PUBLICATION_FAILURES.values()
                        )
                    },
                    "retry_policy": {
                        "enum": ["after_remediation", "manual_diagnostics"]
                    },
                },
                "additionalProperties": False,
            },
            "capabilities": {
                "type": "array",
                "uniqueItems": True,
                "items": {
                    "enum": [
                        "analysis_diagnostics_projection_v1",
                        "assurance_register_projection",
                        "assurance_work_queue_projection",
                        "evidence_catalog_projection_v1",
                        "guidance_traceability_projection_v1",
                        "interchange_artifacts_projection_v1",
                        "package_provenance_projection_v1",
                        "review_views_projection_v1",
                        "sfta_projection_v1",
                    ]
                },
            },
            "assurance_register": {
                "oneOf": [
                    {"type": "object", "maxProperties": 0},
                    register_verdict,
                ]
            },
            "analysis_diagnostics": {
                "oneOf": [
                    {"type": "object", "maxProperties": 0},
                    diagnostics_verdict,
                ]
            },
            "analysis_structure": {
                "oneOf": [
                    {"type": "object", "maxProperties": 0},
                    analysis_structure_verdict,
                ]
            },
            "guidance_traceability": {
                "oneOf": [
                    {"type": "object", "maxProperties": 0},
                    guidance_verdict,
                ]
            },
            "sfta_projection": {
                "oneOf": [
                    {"type": "object", "maxProperties": 0},
                    sfta_verdict,
                ]
            },
            "evidence_catalog": {
                "oneOf": [
                    {"type": "object", "maxProperties": 0},
                    evidence_verdict,
                ]
            },
            "interchange_artifacts": {
                "oneOf": [
                    {"type": "object", "maxProperties": 0},
                    interchange_verdict,
                ]
            },
            "review_views": {
                "oneOf": [
                    {"type": "object", "maxProperties": 0},
                    review_views_verdict,
                ]
            },
            "package_provenance": {
                "oneOf": [
                    {"type": "object", "maxProperties": 0},
                    provenance_verdict,
                ]
            },
            "assurance_work_queue": {
                "oneOf": [
                    {"type": "object", "maxProperties": 0},
                    queue_verdict,
                ]
            },
            "counts": {
                "type": "object",
                "required": ["error", "warning"],
                "properties": {
                    "error": {"type": "integer", "minimum": 0},
                    "warning": {"type": "integer", "minimum": 0},
                },
                "additionalProperties": False,
            },
            "findings": {"type": "array", "items": finding},
            "notice": {"type": "string", "minLength": 1},
        },
        "allOf": [
            {
                "if": {"properties": {"valid": {"const": True}}},
                "then": {
                    "required": ["manifest_sha256"],
                    "properties": {
                        "checked_files": {"minimum": 1},
                        "counts": {
                            "properties": {"error": {"const": 0}}
                        },
                        "findings": {
                            "not": {
                                "contains": {
                                    "required": ["level"],
                                    "properties": {"level": {"const": "error"}},
                                }
                            }
                        },
                    }
                },
                "else": {
                    "properties": {
                        "counts": {
                            "properties": {"error": {"minimum": 1}}
                        },
                        "findings": {
                            "contains": {
                                "required": ["level"],
                                "properties": {"level": {"const": "error"}},
                            },
                            "minContains": 1,
                        },
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "counts": {
                            "properties": {"warning": {"const": 0}}
                        }
                    }
                },
                "then": {
                    "properties": {
                        "findings": {
                            "not": {
                                "contains": {
                                    "required": ["level"],
                                    "properties": {"level": {"const": "warning"}},
                                }
                            }
                        }
                    }
                },
                "else": {
                    "properties": {
                        "findings": {
                            "contains": {
                                "required": ["level"],
                                "properties": {"level": {"const": "warning"}},
                            },
                            "minContains": 1,
                        }
                    }
                },
            },
            {
                "if": {
                    "required": ["valid", "container"],
                    "properties": {
                        "valid": {"const": True},
                        "container": {"const": "zip"},
                    },
                },
                "then": {"required": ["archive_sha256"]},
            },
            {
                "if": {"required": ["publication"]},
                "then": {
                    "oneOf": [
                        {
                            "properties": {
                                "valid": {"const": True},
                                "publication": {
                                    "not": {
                                        "anyOf": [
                                            {"required": ["failure_code"]},
                                            {"required": ["failure_rule_id"]},
                                            {"required": ["catalog_format"]},
                                            {"required": ["catalog_algorithm"]},
                                            {
                                                "required": [
                                                    "catalog_canonicalization"
                                                ]
                                            },
                                            {"required": ["catalog_sha256"]},
                                            {"required": ["next_action"]},
                                            {"required": ["retry_policy"]},
                                        ]
                                    },
                                    "properties": {
                                        "status": {"const": "published"},
                                        "phase": {"const": "complete"},
                                    }
                                },
                            }
                        },
                        {
                            "properties": {
                                "valid": {"const": False},
                                "checked_files": {"const": 0},
                                "publication": {
                                    "required": [
                                        "failure_code",
                                        "failure_rule_id",
                                        "catalog_format",
                                        "catalog_algorithm",
                                        "catalog_canonicalization",
                                        "catalog_sha256",
                                        "next_action",
                                        "retry_policy",
                                    ],
                                    "properties": {
                                        "status": {"const": "not_published"},
                                    },
                                },
                            }
                        },
                        {
                            "properties": {
                                "valid": {"const": False},
                                "publication": {
                                    "not": {
                                        "anyOf": [
                                            {"required": ["failure_code"]},
                                            {"required": ["failure_rule_id"]},
                                            {"required": ["catalog_format"]},
                                            {"required": ["catalog_algorithm"]},
                                            {
                                                "required": [
                                                    "catalog_canonicalization"
                                                ]
                                            },
                                            {"required": ["catalog_sha256"]},
                                            {"required": ["next_action"]},
                                            {"required": ["retry_policy"]},
                                        ]
                                    },
                                    "properties": {
                                        "status": {"const": "published"},
                                        "phase": {
                                            "const": "post_publication_verification"
                                        },
                                    }
                                },
                            }
                        },
                    ]
                },
            },
            *[
                {
                    "if": {
                        "required": ["publication"],
                        "properties": {
                            "publication": {
                                "required": ["failure_code"],
                                "properties": {
                                    "failure_code": {"const": failure.code}
                                },
                            }
                        },
                    },
                    "then": {
                        "properties": {
                            "findings": {
                                "contains": {
                                    "required": ["rule_id", "level"],
                                    "properties": {
                                        "rule_id": {"const": failure.rule_id},
                                        "level": {"const": "error"},
                                    },
                                },
                                "minContains": 1,
                            },
                            "publication": {
                                "properties": {
                                    "phase": {"enum": list(failure.phases)},
                                    "catalog_format": {
                                        "const": PUBLICATION_FAILURE_CATALOG_FORMAT
                                    },
                                    "catalog_algorithm": {
                                        "const": PUBLICATION_FAILURE_CATALOG_ALGORITHM
                                    },
                                    "catalog_canonicalization": {
                                        "const": PUBLICATION_FAILURE_CATALOG_CANONICALIZATION
                                    },
                                    "catalog_sha256": {
                                        "const": PUBLICATION_FAILURE_CATALOG_SHA256
                                    },
                                    "failure_rule_id": {
                                        "const": failure.rule_id
                                    },
                                    "next_action": {
                                        "const": failure.next_action
                                    },
                                    "retry_policy": {
                                        "const": failure.retry_policy
                                    },
                                }
                            },
                        }
                    },
                }
                for failure in PUBLICATION_FAILURES.values()
            ],
        ],
        "additionalProperties": True,
    }


def _workflow_status_schema() -> dict[str, Any]:
    nonempty = {"type": "string", "minLength": 1, "maxLength": 16_384}
    count = {"type": "integer", "minimum": 0}
    gate = {
        "type": "object",
        "required": [
            "id",
            "label",
            "required",
            "passed",
            "status",
            "detail",
            "remediation_action_id",
            "evidence",
        ],
        "properties": {
            "id": _identifier_schema(),
            "label": nonempty,
            "required": {"const": True},
            "passed": {"type": "boolean"},
            "status": {"enum": ["passed", "blocked"]},
            "detail": nonempty,
            "remediation_action_id": _identifier_schema(),
            "evidence": {"type": "object", "maxProperties": 100},
        },
        "allOf": [
            {
                "if": {"properties": {"passed": {"const": True}}},
                "then": {"properties": {"status": {"const": "passed"}}},
                "else": {"properties": {"status": {"const": "blocked"}}},
            }
        ],
        "additionalProperties": False,
    }
    action = {
        "type": "object",
        "required": ["id", "command", "reason"],
        "properties": {
            "id": _identifier_schema(),
            "command": nonempty,
            "reason": nonempty,
        },
        "additionalProperties": False,
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("workflow-status"),
        "title": "PySFMEA workflow status",
        "description": (
            "Stable read-only lifecycle and handoff-gate contract. Cross-field count, "
            "readiness, and remediation-action consistency require semantic validation "
            "by PySFMEA."
        ),
        "type": "object",
        "required": [
            "format",
            "generated_at",
            "repository",
            "stage",
            "ready_for_handoff",
            "handoff_gates",
            "handoff_gate_summary",
            "paths",
            "readiness",
            "analysis",
            "artifacts",
            "assurance_scaffolds",
            "assurance_scaffold_portfolio",
            "next_actions",
            "notice",
        ],
        "properties": {
            "format": {"const": WORKFLOW_STATUS_FORMAT},
            "generated_at": nonempty,
            "repository": nonempty,
            "stage": {
                "enum": [
                    "configuration_required",
                    "ready_to_scan",
                    "inputs_need_attention",
                    "revalidation_required",
                    "engineering_review",
                    "assurance_planning",
                    "report_invalid",
                    "report_binding_required",
                    "package_invalid",
                    "package_binding_required",
                    "handoff_preparation",
                    "handoff_ready",
                ]
            },
            "ready_for_handoff": {"type": "boolean"},
            "handoff_gates": {
                "type": "array",
                "minItems": 1,
                "maxItems": 100,
                "items": gate,
            },
            "handoff_gate_summary": {
                "type": "object",
                "required": ["total", "passed", "blocked"],
                "properties": {
                    "total": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                    },
                    "passed": count,
                    "blocked": count,
                },
                "additionalProperties": False,
            },
            "paths": {"type": "object"},
            "readiness": {"type": "object"},
            "analysis": {"type": "object"},
            "artifacts": {"type": "object"},
            "assurance_scaffolds": {"type": "array", "maxItems": 10_000},
            "assurance_scaffold_portfolio": {"type": "object"},
            "next_actions": {
                "type": "array",
                "maxItems": 1_000,
                "items": action,
            },
            "notice": nonempty,
        },
        "additionalProperties": False,
    }


_SCHEMA_BUILDERS = {
    "assurance-work-queue": _assurance_work_queue_schema,
    "assurance-work-queue-verification": _assurance_work_queue_verification_schema,
    "detached-signature": _detached_signature_schema,
    "diagram": _diagram_schema,
    "diagram-bundle": _diagram_bundle_schema,
    "diagram-bundle-verification": _diagram_bundle_verification_schema,
    "html-report-verification": _html_report_verification_schema,
    "publication-failure-catalog": _publication_failure_catalog_schema,
    "publication-failure-catalog-verification": (
        _publication_failure_catalog_verification_schema
    ),
    "schema-bundle-verification": _schema_bundle_verification_schema,
    "schema-catalog": _schema_catalog_schema,
    "review-package-manifest": _review_package_manifest_schema,
    "review-package-verification": _review_package_verification_schema,
    "workflow-status": _workflow_status_schema,
}
_SCHEMA_DESCRIPTIONS = {
    "assurance-work-queue": "Accepted-finding hardening states, blockers, eligibility, and next actions.",
    "assurance-work-queue-verification": "Work-queue integrity, analysis binding, and semantic-projection verdicts.",
    "detached-signature": "Detached Ed25519 package-signature envelope and subject binding.",
    "diagram": "Canonical renderer-neutral diagram model.",
    "diagram-bundle": "Generated, state-bound and digest-declaring diagram bundle.",
    "diagram-bundle-verification": "Diagram verification success and rejection verdicts.",
    "html-report-verification": "HTML report verification success and rejection verdicts.",
    "publication-failure-catalog": "Package-publication failure phases, findings, and remediation actions.",
    "publication-failure-catalog-verification": "Publication catalog integrity and exact-taxonomy verdicts.",
    "schema-bundle-verification": "Offline schema-set verification success and rejection verdicts.",
    "schema-catalog": "Content-addressed discovery catalog for public contracts.",
    "review-package-manifest": "Checksum, provenance, binding, and file inventory declaration.",
    "review-package-verification": "Package verification success and rejection verdicts.",
    "workflow-status": "Read-only lifecycle, handoff-gate, evidence, and remediation status.",
}
SCHEMA_FILENAMES = {
    "assurance-work-queue": "pysfmea-assurance-work-queue.schema.json",
    "assurance-work-queue-verification": "pysfmea-assurance-work-queue-verification.schema.json",
    "detached-signature": "pysfmea-detached-signature.schema.json",
    "diagram": "pysfmea-diagram.schema.json",
    "diagram-bundle": "pysfmea-diagram-bundle.schema.json",
    "diagram-bundle-verification": "pysfmea-diagram-bundle-verification.schema.json",
    "html-report-verification": "pysfmea-html-report-verification.schema.json",
    "publication-failure-catalog": "pysfmea-publication-failure-catalog.schema.json",
    "publication-failure-catalog-verification": "pysfmea-publication-failure-catalog-verification.schema.json",
    "schema-bundle-verification": "pysfmea-schema-bundle-verification.schema.json",
    "schema-catalog": "pysfmea-schema-catalog.schema.json",
    "review-package-manifest": "pysfmea-review-package-manifest.schema.json",
    "review-package-verification": "pysfmea-review-package-verification.schema.json",
    "workflow-status": "pysfmea-workflow-status.schema.json",
}
SCHEMA_CATALOG_FILENAME = "schema-catalog.json"


def schema_document(name: str) -> dict[str, Any]:
    """Return an isolated JSON Schema document by stable catalog name."""

    builder = _SCHEMA_BUILDERS.get(name)
    if builder is None:
        available = ", ".join(sorted(_SCHEMA_BUILDERS))
        raise ValueError(f"unknown schema {name!r}; choose one of: {available}")
    return copy.deepcopy(builder())


def schema_catalog() -> dict[str, Any]:
    """Return deterministic discovery metadata and schema content digests."""

    entries = []
    for name in sorted(_SCHEMA_BUILDERS):
        document = schema_document(name)
        entries.append(
            {
                "name": name,
                "schema_id": document["$id"],
                "draft": document["$schema"],
                "filename": SCHEMA_FILENAMES[name],
                "description": _SCHEMA_DESCRIPTIONS[name],
                "sha256": canonical_json_sha256(document),
            }
        )
    return {"format": SCHEMA_CATALOG_FORMAT, "schemas": entries}


def schema_bundle_documents() -> dict[str, dict[str, Any]]:
    """Return the complete offline catalog and its self-contained schema documents."""

    documents = {
        SCHEMA_FILENAMES[name]: schema_document(name) for name in sorted(_SCHEMA_BUILDERS)
    }
    return {SCHEMA_CATALOG_FILENAME: schema_catalog(), **documents}


def verify_schema_bundle_documents(
    documents: dict[str, Any],
) -> dict[str, Any]:
    """Verify offline catalog completeness, identities, and canonical content digests."""

    errors: list[dict[str, str]] = []

    def add(code: str, message: str, path: str = "") -> None:
        errors.append({"code": code, "message": message, "path": path})

    catalog = documents.get(SCHEMA_CATALOG_FILENAME)
    catalog_format_valid = (
        isinstance(catalog, dict) and catalog.get("format") == SCHEMA_CATALOG_FORMAT
    )
    if not catalog_format_valid:
        add(
            "schema.catalog_format",
            "Schema catalog format is missing or unsupported.",
            SCHEMA_CATALOG_FILENAME,
        )
    entries = catalog.get("schemas") if isinstance(catalog, dict) else None
    if not isinstance(entries, list):
        entries = []
        add(
            "schema.catalog_entries",
            "Schema catalog entries must be an array.",
            SCHEMA_CATALOG_FILENAME,
        )
    by_name = {
        str(entry.get("name", "")): entry
        for entry in entries
        if isinstance(entry, dict) and entry.get("name")
    }
    base_names = frozenset(
        {
            "diagram",
            "diagram-bundle",
            "diagram-bundle-verification",
            "html-report-verification",
        }
    )
    package_names = base_names | {
        "review-package-manifest",
        "review-package-verification",
    }
    self_describing_names = package_names | {
        "schema-bundle-verification",
        "schema-catalog",
    }
    signed_names = self_describing_names | {"detached-signature"}
    workflow_names = signed_names | {"workflow-status"}
    work_queue_names = workflow_names | {"assurance-work-queue"}
    work_queue_verification_names = work_queue_names | {
        "assurance-work-queue-verification"
    }
    publication_catalog_names = work_queue_verification_names | {
        "publication-failure-catalog"
    }
    supported_name_sets = {
        base_names,
        frozenset(package_names),
        frozenset(self_describing_names),
        frozenset(signed_names),
        frozenset(workflow_names),
        frozenset(work_queue_names),
        frozenset(work_queue_verification_names),
        frozenset(publication_catalog_names),
        frozenset(_SCHEMA_BUILDERS),
    }
    catalog_names = frozenset(by_name)
    catalog_complete = len(by_name) == len(entries) and catalog_names in supported_name_sets
    if not catalog_complete:
        add(
            "schema.catalog_completeness",
            "Schema catalog names are partial, mixed-version, duplicated, or unexpected.",
            SCHEMA_CATALOG_FILENAME,
        )

    expected_names = catalog_names if catalog_complete else frozenset(_SCHEMA_BUILDERS)
    expected_files = {
        SCHEMA_CATALOG_FILENAME,
        *(SCHEMA_FILENAMES[name] for name in expected_names),
    }
    supplied_files = set(documents)
    if supplied_files != expected_files:
        for filename in sorted(expected_files - supplied_files):
            add("schema.file_missing", "Required schema-bundle file is missing.", filename)
        for filename in sorted(supplied_files - expected_files):
            add("schema.file_unexpected", "Unexpected schema-bundle file.", filename)

    verified = []
    for name in sorted(expected_names):
        filename = SCHEMA_FILENAMES[name]
        document = documents.get(filename)
        entry = by_name.get(name)
        identity_valid = bool(
            isinstance(document, dict)
            and isinstance(entry, dict)
            and entry.get("schema_id") == document.get("$id") == _schema_id(name)
            and entry.get("draft") == document.get("$schema") == JSON_SCHEMA_DRAFT
            and entry.get("filename") == filename
        )
        if not identity_valid:
            add(
                "schema.identity",
                "Catalog metadata does not match the schema identity or filename.",
                filename,
            )
        actual_digest = (
            canonical_json_sha256(document) if isinstance(document, dict) else ""
        )
        expected_digest = str(entry.get("sha256", "")) if isinstance(entry, dict) else ""
        digest_valid = bool(actual_digest and actual_digest == expected_digest)
        if not digest_valid:
            add(
                "schema.digest",
                "Schema canonical SHA-256 does not match the catalog.",
                filename,
            )
        verified.append(
            {
                "name": name,
                "filename": filename,
                "schema_id": document.get("$id", "") if isinstance(document, dict) else "",
                "sha256": actual_digest,
                "identity_valid": identity_valid,
                "digest_valid": digest_valid,
            }
        )
    return {
        "format": SCHEMA_BUNDLE_VERIFICATION_FORMAT,
        "valid": not errors,
        "checks": {
            "file_set": supplied_files == expected_files,
            "catalog_format": catalog_format_valid,
            "catalog_completeness": catalog_complete,
            "schema_identity": all(value["identity_valid"] for value in verified),
            "content_integrity": all(value["digest_valid"] for value in verified),
        },
        "schema_count": len(verified),
        "schemas": verified,
        "errors": errors,
        "notice": (
            "Schema-bundle integrity establishes catalog consistency, not artifact "
            "authorship, semantic analysis validity, approval, or risk acceptance."
        ),
    }


def export_schema(name: str, destination: str | Path) -> Path:
    """Publish a schema atomically using deterministic UTF-8 JSON."""

    document = json.dumps(schema_document(name), indent=2, ensure_ascii=False) + "\n"
    return atomic_publish_text(
        destination,
        document,
        label=f"{name} JSON Schema export",
    )


def verify_schema_bundle_path(source: str | Path) -> dict[str, Any]:
    """Safely load and verify a standalone, root-level schema-bundle directory."""

    supplied = Path(source).expanduser().absolute()
    path = supplied.resolve()
    input_errors: list[dict[str, str]] = []

    def add(code: str, message: str, location: str = "") -> None:
        input_errors.append({"code": code, "message": message, "path": location})

    if supplied.is_symlink() or not path.is_dir():
        add("schema.bundle_directory", "Schema bundle must be a regular directory.", str(path))
        result = verify_schema_bundle_documents({})
        result["errors"] = input_errors + result["errors"]
        result["valid"] = False
        return result

    allowed = {SCHEMA_CATALOG_FILENAME, *SCHEMA_FILENAMES.values()}
    documents: dict[str, Any] = {}
    try:
        entries = list(path.iterdir())
    except OSError as exc:
        add("schema.bundle_unreadable", f"Schema bundle cannot be enumerated: {exc}")
        entries = []
    if len(entries) > 100:
        add("schema.bundle_entry_limit", "Schema bundle contains more than 100 entries.")
    for entry in entries[:101]:
        name = entry.name
        if name not in allowed:
            documents[name] = None
            continue
        if entry.is_symlink() or not entry.is_file():
            add("schema.file_type", "Schema-bundle entries must be regular files.", name)
            continue
        try:
            _path, document, _size = load_bounded_json_file(
                entry,
                label="schema-bundle file",
                max_bytes=MAX_SCHEMA_BUNDLE_FILE_BYTES,
                max_depth=MAX_SCHEMA_BUNDLE_JSON_DEPTH,
                max_nodes=MAX_SCHEMA_BUNDLE_JSON_NODES,
            )
            if not isinstance(document, dict):
                raise ValueError("JSON root is not an object")
            documents[name] = document
        except ValueError as exc:
            documents[name] = None
            add("schema.file_invalid", f"Schema-bundle file cannot be read: {exc}", name)

    result = verify_schema_bundle_documents(documents)
    if input_errors:
        result["errors"] = input_errors + result["errors"]
        result["valid"] = False
        if any(error["code"].startswith("schema.bundle") for error in input_errors):
            result["checks"]["file_set"] = False
    return result


def export_schema_bundle(
    destination: str | Path, *, overwrite: bool = False
) -> Path:
    """Atomically publish the complete offline public-schema bundle."""

    supplied = Path(destination).expanduser().absolute()
    path = supplied.resolve()
    documents = schema_bundle_documents()
    expected = set(documents)
    if supplied.is_symlink():
        raise ValueError(f"schema-bundle destination must not be a symbolic link: {supplied}")
    if path.exists():
        if not path.is_dir():
            raise ValueError(f"schema-bundle destination must be a regular directory: {path}")
        entries = list(path.iterdir())
        if entries and not overwrite:
            raise ValueError(f"schema-bundle destination is not empty: {path}; use --force")
        unrecognized = {entry.name for entry in entries} - expected
        invalid_types = {
            entry.name
            for entry in entries
            if entry.name in expected and (entry.is_symlink() or not entry.is_file())
        }
        if unrecognized or invalid_types:
            names = ", ".join(sorted(unrecognized | invalid_types))
            raise ValueError(
                "schema-bundle destination contains unrecognized or non-file entries: "
                + names
            )

    path.parent.mkdir(parents=True, exist_ok=True)
    staging = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    backup: Path | None = None
    try:
        staging.mkdir()
        for filename, document in documents.items():
            (staging / filename).write_text(
                json.dumps(document, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        verification = verify_schema_bundle_path(staging)
        if not verification["valid"]:
            raise RuntimeError("generated schema bundle failed internal verification")
        if path.exists():
            backup = path.with_name(f".{path.name}.previous-{uuid.uuid4().hex}")
            os.replace(path, backup)
        try:
            os.replace(staging, path)
        except Exception:
            if backup and backup.exists() and not path.exists():
                os.replace(backup, path)
                backup = None
            raise
        if backup and backup.exists():
            shutil.rmtree(backup)
            backup = None
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        if backup and backup.exists() and not path.exists():
            os.replace(backup, path)
    return path
