"""Discoverable JSON Schema contracts for public PySFMEA interchange formats."""

from __future__ import annotations

import copy
import json
import os
import shutil
import uuid
from pathlib import Path
from typing import Any

from .accessibility import (
    ACCESSIBILITY_DRAFT_FORMAT,
    ACCESSIBILITY_FORMAT,
    ACCESSIBILITY_VERIFICATION_FORMAT,
    REQUIRED_ACCESSIBILITY_SCENARIOS,
)
from .assurance import (
    ASSURANCE_REGISTER_VERIFICATION_FORMAT,
    ASSURANCE_SCAFFOLD_FORMAT,
    ASSURANCE_SCAFFOLD_VERIFICATION_FORMAT,
    ASSURANCE_WORK_NEXT_ACTIONS,
    ASSURANCE_WORK_QUEUE_FORMAT,
    ASSURANCE_WORK_QUEUE_VERIFICATION_FORMAT,
    ASSURANCE_WORK_STATES,
)
from .assurance_synthesis import (
    ASSURANCE_SCAFFOLD_GENERATED_FILE_ROLES,
    ASSURANCE_TEST_DESIGNS_FORMAT,
)
from .browser_quality import (
    BROWSER_QUALITY_CHECKS,
    BROWSER_QUALITY_FORMAT,
    BROWSER_QUALITY_VERIFICATION_FORMAT,
)
from .cross_reference import (
    ANALYSIS_PROJECTION_STATUSES,
    ANALYSIS_RECORD_PROJECTION_STATUSES,
    ANALYSIS_SECTION_RECORD_COVERAGE_STATUSES,
    CROSS_REFERENCE_FORMAT,
    CROSS_REFERENCE_VERIFICATION_CHECKS,
    CROSS_REFERENCE_VERIFICATION_FORMAT,
    LIFECYCLE_SCOPE_PARENT_RELATIONS,
    MAX_ANALYSIS_PROJECTION_RECORDS,
    MAX_ANALYSIS_RECORD_IDENTITY_TOKENS,
    MAX_CHAINS,
    MAX_ENTITIES,
    MAX_FUSIONS,
    MAX_RELATIONSHIPS,
    MAX_REVIEW_LEADS,
    REVIEW_GOVERNANCE_STATES,
    SEMANTIC_EXPOSURE_DIMENSIONS,
    VERIFICATION_EVIDENCE_POSTURES,
    VERIFICATION_EVIDENCE_SIGNAL_NAMES,
    VERIFICATION_READINESS_STATE_ACTIONS,
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
from .discovery import (
    EVALUATION_CORPUS_FORMAT,
    MAX_EVALUATION_CASES,
    MAX_EVALUATION_METADATA_CHARS,
    MAX_EVALUATION_SCOPES,
    MAX_EVALUATION_VALUE_CHARS,
    MAX_GENERATED_LIST_ITEMS,
    SEMANTIC_SEQUENCE_FIELDS,
    SEMANTIC_SET_FIELDS,
    SEMANTIC_TEXT_FIELDS,
)
from .enhancements import (
    ENHANCEMENT_WORKBENCH_FORMAT,
    ENHANCEMENT_WORKBENCH_VERIFICATION_FORMAT,
)
from .fault_injection import (
    FAULT_INJECTION_PLAN_FORMAT,
    FAULT_INJECTION_PLAN_VERIFICATION_FORMAT,
)
from .file_publication import atomic_publish_text
from .html_report import HTML_REPORT_VERIFICATION_FORMAT
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_file
from .program import (
    PROGRAM_REPORT_FORMAT,
    PROGRAM_REPORT_VERIFICATION_FORMAT,
    PROGRAM_VERIFICATION_CHECKS,
)
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
from .pull_request import (
    PULL_REQUEST_ANALYSIS_FORMAT,
    PULL_REQUEST_ANALYSIS_VERIFICATION_FORMAT,
)
from .qualification import (
    MAX_QUALIFICATION_REPOSITORIES,
    QUALIFICATION_CAMPAIGN_MANIFEST_FORMAT,
    QUALIFICATION_CAMPAIGN_RESULT_FORMAT,
    QUALIFICATION_CAMPAIGN_VERIFICATION_FORMAT,
    QUALIFICATION_CHECKS,
)
from .qualification_report import (
    QUALIFICATION_REPORT_CHECKS,
    QUALIFICATION_REPORT_VERIFICATION_FORMAT,
)
from .review_package_schema import _review_package_manifest_schema
from .schema_registry import SCHEMA_CATALOG_FILENAME, SCHEMA_FILENAMES
from .sdk import (
    PLUGIN_MANIFEST_FORMAT,
    PLUGIN_REQUEST_FORMAT,
    PLUGIN_RESPONSE_FORMAT,
    PLUGIN_RUN_FORMAT,
    PLUGIN_RUN_VERIFICATION_FORMAT,
    SUPPORTED_CAPABILITIES,
)
from .signing import SIGNATURE_FORMAT, STATEMENT_FORMAT
from .synthesis import (
    SYNTHESIS_APPLY_RECEIPT_FORMAT,
    SYNTHESIS_APPLY_VERIFICATION_FORMAT,
    SYNTHESIS_DRAFT_FORMAT,
    SYNTHESIS_FORMAT,
    SYNTHESIS_VERIFICATION_FORMAT,
)
from .test_generation_quality_schemas import (
    _assurance_test_generation_quality_corpus_schema,
    _assurance_test_generation_quality_result_schema,
)
from .test_generation_schemas import (
    _assurance_test_generation_readiness_schema,
    _assurance_test_proposal_apply_receipt_schema,
    _assurance_test_proposal_apply_receipt_verification_schema,
    _assurance_test_proposal_schema,
    _assurance_test_proposal_stage_schema,
    _assurance_test_proposal_stage_verification_schema,
    _assurance_test_proposal_verification_schema,
)
from .workflow import MAX_TIMESTAMPED_ANALYSIS_CANDIDATES, WORKFLOW_STATUS_FORMAT

JSON_SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_CATALOG_FORMAT = "pysfmea-schema-catalog-1"
SCHEMA_BUNDLE_VERIFICATION_FORMAT = "pysfmea-schema-bundle-verification-1"
MAX_SCHEMA_BUNDLE_FILE_BYTES = 2_000_000
MAX_SCHEMA_BUNDLE_JSON_DEPTH = 100
MAX_SCHEMA_BUNDLE_JSON_NODES = 250_000
REVIEW_PACKAGE_FORMAT = "pysfmea-review-package-1"
REVIEW_PACKAGE_VERIFICATION_FORMAT = "pysfmea-review-package-verification-1"
ANALYSIS_STRUCTURE_VERIFICATION_FORMAT = "pysfmea-analysis-structure-verification-1"
ANALYSIS_DIAGNOSTICS_VERIFICATION_FORMAT = "pysfmea-analysis-diagnostics-verification-1"
GUIDANCE_TRACEABILITY_VERIFICATION_FORMAT = (
    "pysfmea-guidance-traceability-verification-1"
)
SFTA_PROJECTION_VERIFICATION_FORMAT = "pysfmea-sfta-projection-verification-1"
EVIDENCE_CATALOG_VERIFICATION_FORMAT = "pysfmea-evidence-catalog-verification-1"
INTERCHANGE_ARTIFACTS_VERIFICATION_FORMAT = (
    "pysfmea-interchange-artifacts-verification-1"
)
REVIEW_VIEWS_VERIFICATION_FORMAT = "pysfmea-review-views-verification-1"
PACKAGE_PROVENANCE_VERIFICATION_FORMAT = "pysfmea-package-provenance-verification-1"
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
                        "properties": {"status": {"const": "not_published"}},
                        "required": ["status"],
                    }
                },
            },
            "then": {"properties": {"valid": {"const": False}}},
        },
    ]
    return schema


def _assurance_program_report_verification_schema() -> dict[str, Any]:
    schema = _verification_schema(
        name="assurance-program-report-verification",
        format_name=PROGRAM_REPORT_VERIFICATION_FORMAT,
        title="PySFMEA assurance-program HTML report verification verdict",
        check_names=(
            "metadata_complete",
            "metadata_unique",
            "report_format",
            "payload_present",
            "payload_json",
            "payload_contract",
            "payload_integrity",
            "verification_result_integrity",
            "payload_binding",
            "document_integrity",
            "artifact_identity",
            "program_content",
            "program_verification",
        ),
    )
    digest = {"type": "string", "pattern": "^(?:[0-9a-f]{64})?$"}
    schema["required"].extend(
        [
            "verifier",
            "bytes",
            "artifact_sha256",
            "expected_artifact_sha256",
            "artifact_binding_requested",
            "artifact_binding_checked",
            "assurance_valid",
            "declared",
            "current",
        ]
    )
    schema["properties"].update(
        {
            "bytes": {"type": "integer", "minimum": 0},
            "artifact_sha256": digest,
            "expected_artifact_sha256": digest,
            "artifact_binding_requested": {"type": "boolean"},
            "artifact_binding_checked": {"type": "boolean"},
            "assurance_valid": {"type": ["boolean", "null"]},
            "declared": {
                "type": "object",
                "properties": {
                    "format": {"enum": ["", PROGRAM_REPORT_FORMAT]},
                    "program_sha256": digest,
                    "verification_result_sha256": digest,
                    "payload_sha256": digest,
                    "document_sha256": digest,
                },
                "additionalProperties": False,
            },
            "current": {
                "type": "object",
                "properties": {
                    "program_path": {"type": "string"},
                    "program_sha256": digest,
                    "verification_result_sha256": digest,
                    "verifier": {
                        "type": "object",
                        "required": ["name", "version"],
                        "properties": {
                            "name": {"const": "PySFMEA"},
                            "version": {"type": "string", "minLength": 1},
                        },
                        "additionalProperties": False,
                    },
                    "assurance_valid": {"type": "boolean"},
                },
                "additionalProperties": False,
            },
            "publication": {
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
                            "program_verification",
                            "generation",
                            "publication",
                            "post_publication_verification",
                            "complete",
                        ]
                    },
                    "destination_existed": {"type": "boolean"},
                    "prior_destination_preserved": {"type": "boolean"},
                },
                "allOf": [
                    {
                        "if": {
                            "required": ["status"],
                            "properties": {"status": {"const": "published"}},
                        },
                        "then": {
                            "properties": {
                                "phase": {
                                    "enum": [
                                        "complete",
                                        "post_publication_verification",
                                    ]
                                },
                                "prior_destination_preserved": {"const": False},
                            }
                        },
                    },
                    {
                        "if": {
                            "required": ["status"],
                            "properties": {"status": {"const": "not_published"}},
                        },
                        "then": {
                            "properties": {
                                "phase": {
                                    "enum": [
                                        "input_validation",
                                        "program_verification",
                                        "generation",
                                        "publication",
                                    ]
                                }
                            }
                        },
                    },
                    {
                        "if": {
                            "required": ["destination_existed"],
                            "properties": {
                                "status": {"const": "not_published"},
                                "destination_existed": {"const": True},
                            },
                        },
                        "then": {
                            "properties": {
                                "prior_destination_preserved": {"const": True}
                            }
                        },
                    },
                    {
                        "if": {
                            "required": ["destination_existed"],
                            "properties": {"destination_existed": {"const": False}},
                        },
                        "then": {
                            "properties": {
                                "prior_destination_preserved": {"const": False}
                            }
                        },
                    },
                ],
                "additionalProperties": False,
            },
        }
    )
    schema["allOf"] = [
        {
            "if": {"properties": {"artifact_binding_requested": {"const": False}}},
            "then": {
                "properties": {
                    "expected_artifact_sha256": {"const": ""},
                    "artifact_binding_checked": {"const": False},
                    "checks": {"properties": {"artifact_identity": {"type": "null"}}},
                }
            },
        },
        {
            "if": {"properties": {"artifact_binding_checked": {"const": True}}},
            "then": {
                "properties": {
                    "artifact_binding_requested": {"const": True},
                    "expected_artifact_sha256": {"pattern": "^[0-9a-f]{64}$"},
                    "checks": {
                        "properties": {"artifact_identity": {"type": "boolean"}}
                    },
                }
            },
        },
        {
            "if": {"properties": {"artifact_binding_checked": {"const": False}}},
            "then": {
                "properties": {
                    "checks": {"properties": {"artifact_identity": {"type": "null"}}}
                }
            },
        },
        {
            "if": {
                "properties": {
                    "checks": {"properties": {"artifact_identity": {"const": False}}}
                }
            },
            "then": {
                "properties": {
                    "valid": {"const": False},
                    "status": {"const": "invalid"},
                    "artifact_binding_requested": {"const": True},
                    "artifact_binding_checked": {"const": True},
                }
            },
        },
        {
            "if": {"properties": {"binding_checked": {"const": True}}},
            "then": {
                "properties": {
                    "binding_requested": {"const": True},
                    "current": {
                        "required": [
                            "program_path",
                            "program_sha256",
                            "verification_result_sha256",
                            "verifier",
                            "assurance_valid",
                        ]
                    },
                },
            },
        },
        {
            "if": {"properties": {"binding_checked": {"const": False}}},
            "then": {"properties": {"current": {"maxProperties": 0}}},
        },
        {
            "if": {"properties": {"status": {"const": "matched"}}},
            "then": {
                "properties": {
                    "valid": {"const": True},
                    "binding_requested": {"const": True},
                    "binding_checked": {"const": True},
                }
            },
        },
        {
            "if": {"properties": {"status": {"const": "mismatched"}}},
            "then": {
                "properties": {
                    "valid": {"const": False},
                    "binding_requested": {"const": True},
                    "binding_checked": {"const": True},
                }
            },
        },
        {
            "if": {"properties": {"status": {"const": "valid_binding_not_checked"}}},
            "then": {
                "properties": {
                    "valid": {"const": True},
                    "binding_requested": {"const": False},
                    "binding_checked": {"const": False},
                }
            },
        },
        {
            "if": {"properties": {"status": {"const": "invalid"}}},
            "then": {"properties": {"valid": {"const": False}}},
        },
        {
            "if": {"properties": {"bytes": {"minimum": 1}}},
            "then": {
                "properties": {
                    "artifact_sha256": {
                        "type": "string",
                        "pattern": "^[0-9a-f]{64}$",
                    }
                }
            },
        },
        {
            "if": {
                "required": ["publication"],
                "properties": {
                    "publication": {
                        "required": ["status", "phase"],
                        "properties": {
                            "status": {"const": "published"},
                            "phase": {"const": "complete"},
                        },
                    }
                },
            },
            "then": {
                "properties": {
                    "valid": {"const": True},
                    "status": {"const": "matched"},
                    "binding_requested": {"const": True},
                    "binding_checked": {"const": True},
                    "publication": {
                        "properties": {"prior_destination_preserved": {"const": False}}
                    },
                }
            },
        },
        {
            "if": {
                "required": ["publication"],
                "properties": {
                    "publication": {
                        "required": ["status"],
                        "properties": {"status": {"const": "not_published"}},
                    }
                },
            },
            "then": {"properties": {"valid": {"const": False}}},
        },
        {
            "if": {
                "required": ["publication"],
                "properties": {
                    "publication": {
                        "required": ["status"],
                        "properties": {"status": {"const": "not_published"}},
                    }
                },
            },
            "then": {
                "properties": {
                    "bytes": {"const": 0},
                    "artifact_sha256": {"const": ""},
                }
            },
        },
        {
            "if": {
                "required": ["publication"],
                "properties": {
                    "publication": {
                        "required": ["status", "phase"],
                        "properties": {
                            "status": {"const": "published"},
                            "phase": {"const": "post_publication_verification"},
                        },
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


def _cross_reference_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": r"^[0-9a-f]{64}$"}
    identifier = _identifier_schema()
    text = {"type": "string", "maxLength": 20_000}
    entity_reference = {
        "type": "string",
        "minLength": 1,
        "maxLength": 20_000,
    }
    string_list = {
        "type": "array",
        "maxItems": 100_000,
        "uniqueItems": True,
        "items": entity_reference,
    }
    text_list = {
        "type": "array",
        "maxItems": 100_000,
        "uniqueItems": True,
        "items": text,
    }
    metadata = {
        "type": "object",
        "maxProperties": 100,
        "additionalProperties": {
            "oneOf": [
                _scalar_schema(),
                {
                    "type": "array",
                    "maxItems": 1_000,
                    "items": _scalar_schema(),
                },
            ]
        },
    }
    entity_properties = {
        "id": entity_reference,
        "raw_id": text,
        "kind": identifier,
        "label": text,
        "authority": text,
        "metadata": metadata,
    }
    relationship_properties = {
        "id": identifier,
        "source": entity_reference,
        "target": entity_reference,
        "kind": identifier,
        "channel": identifier,
        "authority": text,
        "evidence_ids": string_list,
        "metadata": metadata,
    }
    fusion_properties = {
        "id": identifier,
        "source_component_id": identifier,
        "target_component_id": identifier,
        "channels": string_list,
        "classification": {
            "enum": [
                "observed_multi_source",
                "observed_native",
                "observed_graphify_gap",
                "multi_static",
                "runtime_only_review_lead",
                "graphify_only_review_lead",
                "native_static_only",
            ]
        },
        "corroboration_count": {"type": "integer", "minimum": 1, "maximum": 3},
        "runtime_observed": {"type": "boolean"},
        "relationship_ids": string_list,
        "notice": text,
    }
    dimensions = {
        "type": "object",
        "required": [
            "component",
            "source_provenance",
            "requirements",
            "hazards",
            "guidance",
            "guidance_provenance",
            "verification",
            "evidence",
            "sfta",
            "interfaces",
            "component_relationships",
            "cascade_analysis",
            "timing_and_resilience",
            "semantic_exposure",
            "verification_readiness",
            "quality_governance",
            "tool_provenance",
            "machine_assistance",
            "system_context",
            "lifecycle_history",
        ],
        "properties": {
            name: {"type": "boolean"}
            for name in (
                "component",
                "source_provenance",
                "requirements",
                "hazards",
                "guidance",
                "guidance_provenance",
                "verification",
                "evidence",
                "sfta",
                "interfaces",
                "component_relationships",
                "cascade_analysis",
                "timing_and_resilience",
                "semantic_exposure",
                "verification_readiness",
                "quality_governance",
                "tool_provenance",
                "machine_assistance",
                "system_context",
                "lifecycle_history",
            )
        },
        "additionalProperties": False,
    }
    semantic_dimensions = {
        "type": "object",
        "required": list(SEMANTIC_EXPOSURE_DIMENSIONS),
        "properties": {
            name: {"type": "boolean"} for name in SEMANTIC_EXPOSURE_DIMENSIONS
        },
        "additionalProperties": False,
    }
    semantic_profile_properties = {
        "id": identifier,
        "component_id": identifier,
        "dimensions": semantic_dimensions,
        "entity_ids": string_list,
        "relationship_ids": string_list,
        "populated_dimension_count": {
            "type": "integer",
            "minimum": 0,
            "maximum": len(SEMANTIC_EXPOSURE_DIMENSIONS),
        },
        "notice": text,
    }
    evidence_signals = {
        "type": "object",
        "required": list(VERIFICATION_EVIDENCE_SIGNAL_NAMES),
        "properties": {
            name: {"type": "boolean"} for name in VERIFICATION_EVIDENCE_SIGNAL_NAMES
        },
        "additionalProperties": False,
    }
    readiness_profile_properties = {
        "id": identifier,
        "finding_id": identifier,
        "component_id": identifier,
        "source_status": text,
        "finding_disposition": text,
        "lifecycle_state": {"enum": list(VERIFICATION_READINESS_STATE_ACTIONS)},
        "next_action_id": {
            "enum": sorted(set(VERIFICATION_READINESS_STATE_ACTIONS.values()))
        },
        "blockers": {
            "type": "array",
            "maxItems": 1_000,
            "items": text,
        },
        "evidence_posture": {"enum": list(VERIFICATION_EVIDENCE_POSTURES)},
        "evidence_signals": evidence_signals,
        "readiness_gaps": string_list,
        "test_candidate_entity_ids": string_list,
        "coverage_entity_ids": string_list,
        "implemented_test_entity_ids": string_list,
        "assignment_entity_ids": string_list,
        "obligation_ids": string_list,
        "execution_ids": string_list,
        "evidence_artifact_ids": string_list,
        "relationship_ids": string_list,
        "latest_execution_id": text,
        "latest_execution_status": text,
        "notice": text,
    }
    diagnostic_count_map = {
        "type": "object",
        "maxProperties": 10,
        "additionalProperties": {"type": "integer", "minimum": 0},
    }
    governance_profile_properties = {
        "id": identifier,
        "finding_id": identifier,
        "component_id": identifier,
        "source_status": text,
        "source_change": text,
        "screening_priority": text,
        "finding_disposition": text,
        "workflow_status": text,
        "revalidation_required": {"type": "boolean"},
        "state": {"enum": list(REVIEW_GOVERNANCE_STATES)},
        "next_action_id": identifier,
        "readiness_profile_id": identifier,
        "diagnostic_entity_ids": string_list,
        "blocking_diagnostic_entity_ids": string_list,
        "diagnostic_counts": diagnostic_count_map,
        "relationship_ids": string_list,
        "notice": text,
    }
    quality_gate_projection_properties = {
        "analysis_scope_entity_id": identifier,
        "global_diagnostic_entity_ids": string_list,
        "global_relationship_ids": string_list,
        "global_diagnostic_counts": diagnostic_count_map,
        "analysis_gate_state": {"enum": ["blocked", "review_required", "clear"]},
        "notice": text,
    }
    adapter_status_map = {
        "type": "object",
        "maxProperties": 1_000,
        "additionalProperties": text,
    }
    adapter_provenance_profile_properties = {
        "id": identifier,
        "adapter_id": identifier,
        "status": text,
        "contribution_entity_ids": string_list,
        "linked_contribution_entity_ids": string_list,
        "unlinked_contribution_entity_ids": string_list,
        "relationship_ids": string_list,
        "notice": text,
    }
    adapter_provenance_properties = {
        "run_manifest_entity_id": identifier,
        "adapter_ledger_entity_id": identifier,
        "adapter_run_profiles": {
            "type": "array",
            "maxItems": MAX_ENTITIES,
            "items": {
                "type": "object",
                "required": list(adapter_provenance_profile_properties),
                "properties": adapter_provenance_profile_properties,
                "additionalProperties": False,
            },
        },
        "relationship_ids": string_list,
        "notice": text,
    }
    repository_provenance_properties = {
        "repository_inventory_entity_id": identifier,
        "configuration_input_entity_id": {
            "type": "string",
            "maxLength": 20_000,
        },
        "repository_artifact_entity_ids": string_list,
        "repository_region_entity_ids": string_list,
        "dependency_entity_ids": string_list,
        "contract_entity_ids": string_list,
        "opaque_repository_artifact_entity_ids": string_list,
        "unaccounted_component_ids": string_list,
        "unaccounted_finding_ids": string_list,
        "configured_component_ids": string_list,
        "configured_finding_ids": string_list,
        "relationship_ids": string_list,
        "inventory_truncated": {"type": "boolean"},
        "notice": text,
    }
    analysis_projection_profile_properties = {
        "section": identifier,
        "section_entity_id": identifier,
        "section_relationship_id": identifier,
        "source_sha256": digest,
        "source_type": identifier,
        "source_record_count": {"type": "integer", "minimum": 0},
        "registered": {"type": "boolean"},
        "projection_mode": {"enum": ["semantic", "provenance_only", "unmapped"]},
        "coverage_status": {"enum": list(ANALYSIS_PROJECTION_STATUSES)},
        "entity_kinds": string_list,
        "relationship_channels": string_list,
        "projected_entity_count": {"type": "integer", "minimum": 0},
        "projected_entity_ids_sha256": digest,
        "projected_entity_id_sample": {
            "type": "array",
            "maxItems": 25,
            "items": text,
        },
        "projected_relationship_count": {"type": "integer", "minimum": 0},
        "projected_relationship_ids_sha256": digest,
        "projected_relationship_id_sample": {
            "type": "array",
            "maxItems": 25,
            "items": text,
        },
        "record_coverage_status": {
            "enum": list(ANALYSIS_SECTION_RECORD_COVERAGE_STATUSES)
        },
        "semantically_projected_record_count": {
            "type": "integer",
            "minimum": 0,
        },
        "unresolved_record_count": {"type": "integer", "minimum": 0},
        "record_profiles_omitted_by_bound": {
            "type": "integer",
            "minimum": 0,
        },
        "rationale": text,
    }
    analysis_record_projection_profile_properties = {
        "section": identifier,
        "path": text,
        "locator": text,
        "record_entity_id": identifier,
        "source_record_sha256": digest,
        "identity_tokens": {
            "type": "array",
            "maxItems": MAX_ANALYSIS_RECORD_IDENTITY_TOKENS,
            "items": {"type": "string", "maxLength": 8_192},
        },
        "identity_tokens_sha256": digest,
        "coverage_status": {"enum": list(ANALYSIS_RECORD_PROJECTION_STATUSES)},
        "projected_entity_count": {"type": "integer", "minimum": 0},
        "projected_entity_ids_sha256": digest,
        "projected_entity_id_sample": {
            "type": "array",
            "maxItems": 25,
            "items": text,
        },
        "projected_relationship_count": {"type": "integer", "minimum": 0},
        "projected_relationship_ids_sha256": digest,
        "projected_relationship_id_sample": {
            "type": "array",
            "maxItems": 25,
            "items": text,
        },
        "projection_relationship_ids": string_list,
    }
    analysis_projection_coverage_properties = {
        "analysis_scope_entity_id": identifier,
        "section_profiles": {
            "type": "array",
            "maxItems": 1_000,
            "items": {
                "type": "object",
                "required": list(analysis_projection_profile_properties),
                "properties": analysis_projection_profile_properties,
                "additionalProperties": False,
            },
        },
        "record_profiles": {
            "type": "array",
            "maxItems": MAX_ANALYSIS_PROJECTION_RECORDS,
            "items": {
                "type": "object",
                "required": list(analysis_record_projection_profile_properties),
                "properties": analysis_record_projection_profile_properties,
                "additionalProperties": False,
            },
        },
        "registered_section_names": string_list,
        "semantically_projected_section_names": string_list,
        "registered_without_projection_section_names": string_list,
        "provenance_only_section_names": string_list,
        "empty_section_names": string_list,
        "unmapped_section_names": string_list,
        "relationship_ids": string_list,
        "record_relationship_ids": string_list,
        "semantic_record_count": {"type": "integer", "minimum": 0},
        "semantically_projected_record_count": {
            "type": "integer",
            "minimum": 0,
        },
        "unresolved_record_count": {"type": "integer", "minimum": 0},
        "record_profiles_omitted_by_bound": {
            "type": "integer",
            "minimum": 0,
        },
        "record_coverage_percent": {
            "type": "number",
            "minimum": 0,
            "maximum": 100,
        },
        "coverage_percent": {"type": "number", "minimum": 0, "maximum": 100},
        "material_coverage_percent": {
            "type": "number",
            "minimum": 0,
            "maximum": 100,
        },
        "notice": text,
    }
    machine_suggestion_profile_properties = {
        "id": identifier,
        "suggestion_id": identifier,
        "component_id": identifier,
        "status": identifier,
        "confidence": identifier,
        "evidence_entity_ids": string_list,
        "citation_entity_ids": string_list,
        "materialized_finding_entity_id": {"type": "string", "maxLength": 20_000},
        "claim_relationship_ids": string_list,
        "relationship_ids": string_list,
        "unresolved_evidence_ids": text_list,
        "unresolved_citation_ids": text_list,
        "notice": text,
    }
    machine_summary_profile_properties = {
        "id": identifier,
        "summary_id": identifier,
        "group_by": {"enum": ["project", "subsystem", "hazard", "component"]},
        "key": text,
        "stale": {"type": "boolean"},
        "scope_entity_id": {"type": "string", "maxLength": 20_000},
        "evidence_entity_ids": string_list,
        "unresolved_evidence_ids": text_list,
        "relationship_ids": string_list,
        "notice": text,
    }
    machine_assistance_properties = {
        "suggestion_profiles": {
            "type": "array",
            "maxItems": MAX_ENTITIES,
            "items": {
                "type": "object",
                "required": list(machine_suggestion_profile_properties),
                "properties": machine_suggestion_profile_properties,
                "additionalProperties": False,
            },
        },
        "summary_profiles": {
            "type": "array",
            "maxItems": MAX_ENTITIES,
            "items": {
                "type": "object",
                "required": list(machine_summary_profile_properties),
                "properties": machine_summary_profile_properties,
                "additionalProperties": False,
            },
        },
        "claim_relationship_ids": string_list,
        "relationship_ids": string_list,
        "unresolved_evidence_references": text_list,
        "unresolved_citation_references": text_list,
        "stale_summary_entity_ids": string_list,
        "lexical_analysis": {
            "type": "object",
            "required": ["format", "summary", "notice"],
            "properties": {
                "format": {"const": "pysfmea-suggestion-relationships-1"},
                "summary": {
                    "type": "object",
                    "required": [
                        "claims",
                        "duplicates",
                        "contradictions",
                        "divergences",
                        "truncated",
                    ],
                    "properties": {
                        "claims": {"type": "integer", "minimum": 0},
                        "duplicates": {"type": "integer", "minimum": 0},
                        "contradictions": {"type": "integer", "minimum": 0},
                        "divergences": {"type": "integer", "minimum": 0},
                        "truncated": {"type": "boolean"},
                    },
                    "additionalProperties": False,
                },
                "notice": text,
            },
            "additionalProperties": False,
        },
        "notice": text,
    }
    guidance_source_profile_properties = {
        "id": identifier,
        "source_id": identifier,
        "source_record": {"type": "object", "maxProperties": 100},
        "source_record_sha256": digest,
        "catalog_record_sha256": {"type": "string", "maxLength": 64},
        "methodology_basis": {"type": "boolean"},
        "citation_entity_ids": string_list,
        "relationship_ids": string_list,
    }
    guidance_citation_profile_properties = {
        "id": identifier,
        "citation_id": identifier,
        "citation_record": {"type": "object", "maxProperties": 100},
        "citation_record_sha256": digest,
        "source_id": text,
        "source_entity_id": {"type": "string", "maxLength": 20_000},
        "finding_entity_ids": string_list,
        "relationship_ids": string_list,
    }
    methodology_review_check_profile_properties = {
        "id": identifier,
        "sequence": {"type": "integer", "minimum": 1},
        "text": text,
        "text_sha256": digest,
        "relationship_ids": string_list,
    }
    guidance_provenance_properties = {
        "methodology_entity_id": identifier,
        "methodology_record": {"type": "object", "maxProperties": 100},
        "methodology_sha256": digest,
        "source_profiles": {
            "type": "array",
            "maxItems": MAX_ENTITIES,
            "items": {
                "type": "object",
                "required": list(guidance_source_profile_properties),
                "properties": guidance_source_profile_properties,
                "additionalProperties": False,
            },
        },
        "citation_profiles": {
            "type": "array",
            "maxItems": MAX_ENTITIES,
            "items": {
                "type": "object",
                "required": list(guidance_citation_profile_properties),
                "properties": guidance_citation_profile_properties,
                "additionalProperties": False,
            },
        },
        "review_check_profiles": {
            "type": "array",
            "maxItems": MAX_ENTITIES,
            "items": {
                "type": "object",
                "required": list(methodology_review_check_profile_properties),
                "properties": methodology_review_check_profile_properties,
                "additionalProperties": False,
            },
        },
        "unresolved_methodology_source_ids": string_list,
        "mismatched_methodology_source_ids": string_list,
        "unresolved_citation_source_ids": string_list,
        "relationship_ids": string_list,
        "notice": text,
    }
    system_context_field_profile_properties = {
        "id": identifier,
        "field": identifier,
        "label": text,
        "required": {"type": "boolean"},
        "status": text,
        "provenance": text,
        "value_entity_ids": string_list,
        "relationship_ids": string_list,
    }
    finding_context_claim_profile_properties = {
        "id": identifier,
        "finding_id": identifier,
        "review_field": identifier,
        "context_field": {"type": "string", "maxLength": 20_000},
        "value": text,
        "normalized_value": text,
        "alignment_status": {
            "enum": [
                "matched",
                "outside_catalog",
                "catalog_unresolved",
                "not_cataloged",
            ]
        },
        "field_entity_id": {"type": "string", "maxLength": 20_000},
        "matched_value_entity_id": {"type": "string", "maxLength": 20_000},
        "relationship_ids": string_list,
    }
    system_context_provenance_properties = {
        "system_context_entity_id": identifier,
        "configuration_input_entity_id": {"type": "string", "maxLength": 20_000},
        "status": text,
        "completeness_percent": {"type": "number", "minimum": 0, "maximum": 100},
        "context_sha256": {"type": "string", "maxLength": 64},
        "field_profiles": {
            "type": "array",
            "maxItems": MAX_ENTITIES,
            "items": {
                "type": "object",
                "required": list(system_context_field_profile_properties),
                "properties": system_context_field_profile_properties,
                "additionalProperties": False,
            },
        },
        "value_entity_ids": string_list,
        "finding_claim_profiles": {
            "type": "array",
            "maxItems": MAX_ENTITIES,
            "items": {
                "type": "object",
                "required": list(finding_context_claim_profile_properties),
                "properties": finding_context_claim_profile_properties,
                "additionalProperties": False,
            },
        },
        "outside_catalog_claim_entity_ids": string_list,
        "unresolved_catalog_claim_entity_ids": string_list,
        "uncataloged_claim_entity_ids": string_list,
        "missing_required_fields": string_list,
        "missing_recommended_fields": string_list,
        "relationship_ids": string_list,
        "notice": text,
    }
    lifecycle_event_profile_properties = {
        "id": identifier,
        "scope": {"enum": list(LIFECYCLE_SCOPE_PARENT_RELATIONS)},
        "parent_entity_id": identifier,
        "finding_id": {"type": "string", "maxLength": 20_000},
        "sequence": {"type": "integer", "minimum": 1},
        "event": text,
        "at": {"type": "string", "maxLength": 20_000},
        "reviewer": {"type": "string", "maxLength": 20_000},
        "event_sha256": digest,
        "event_record": {"type": "object", "maxProperties": 100},
        "changed_fields": string_list,
        "subject_entity_ids": string_list,
        "unresolved_subject_references": text_list,
        "relationship_ids": string_list,
    }
    lifecycle_provenance_properties = {
        "analysis_event_profiles": {
            "type": "array",
            "maxItems": MAX_ENTITIES,
            "items": {
                "type": "object",
                "required": list(lifecycle_event_profile_properties),
                "properties": lifecycle_event_profile_properties,
                "additionalProperties": False,
            },
        },
        "finding_review_event_profiles": {
            "type": "array",
            "maxItems": MAX_ENTITIES,
            "items": {
                "type": "object",
                "required": list(lifecycle_event_profile_properties),
                "properties": lifecycle_event_profile_properties,
                "additionalProperties": False,
            },
        },
        "subject_event_profiles": {
            "type": "array",
            "maxItems": MAX_ENTITIES,
            "items": {
                "type": "object",
                "required": list(lifecycle_event_profile_properties),
                "properties": lifecycle_event_profile_properties,
                "additionalProperties": False,
            },
        },
        "unresolved_subject_references": text_list,
        "relationship_ids": string_list,
        "notice": text,
    }
    chain_properties = {
        "finding_id": identifier,
        "component_id": identifier,
        "source_status": text,
        "source_repository_artifact_entity_id": {
            "type": "string",
            "maxLength": 20_000,
        },
        "source_repository_artifact_entity_ids": string_list,
        "source_configuration_input_entity_id": {
            "type": "string",
            "maxLength": 20_000,
        },
        "source_repository_path": text,
        "source_repository_status": text,
        "source_analysis_depth": text,
        "source_snapshot_sha256": {"type": "string", "maxLength": 64},
        "source_adapter_ids": string_list,
        "source_provenance_relationship_ids": string_list,
        "requirement_ids": string_list,
        "hazard_ids": string_list,
        "citation_ids": string_list,
        "guidance_source_entity_ids": string_list,
        "guidance_provenance_relationship_ids": string_list,
        "guidance_lineage_status": {
            "enum": ["complete", "unresolved", "not_applicable"]
        },
        "obligation_ids": string_list,
        "evidence_artifact_ids": string_list,
        "execution_ids": string_list,
        "sfta_event_ids": string_list,
        "cascade_component_ids": string_list,
        "cascade_paths": {
            "type": "array",
            "maxItems": 25,
            "items": string_list,
        },
        "cascade_path_analysis": metadata,
        "resilience_entity_ids": string_list,
        "timing_relationship_ids": string_list,
        "semantic_profile_id": {"type": "string", "maxLength": 20_000},
        "semantic_dimensions": semantic_dimensions,
        "semantic_entity_ids": string_list,
        "semantic_relationship_ids": string_list,
        "compound_exposure_kinds": string_list,
        "verification_readiness_profile_id": identifier,
        "test_candidate_entity_ids": string_list,
        "coverage_entity_ids": string_list,
        "implemented_test_entity_ids": string_list,
        "assignment_entity_ids": string_list,
        "readiness_relationship_ids": string_list,
        "verification_lifecycle_state": identifier,
        "verification_evidence_posture": {"enum": list(VERIFICATION_EVIDENCE_POSTURES)},
        "verification_next_action_id": identifier,
        "verification_readiness_gaps": string_list,
        "review_governance_profile_id": identifier,
        "quality_diagnostic_entity_ids": string_list,
        "blocking_quality_diagnostic_entity_ids": string_list,
        "review_governance_relationship_ids": string_list,
        "review_governance_state": {"enum": list(REVIEW_GOVERNANCE_STATES)},
        "review_next_action_id": identifier,
        "quality_diagnostic_counts": diagnostic_count_map,
        "source_change": text,
        "revalidation_required": {"type": "boolean"},
        "adapter_run_entity_ids": string_list,
        "adapter_provenance_relationship_ids": string_list,
        "adapter_statuses": adapter_status_map,
        "machine_assistance_entity_ids": string_list,
        "machine_assistance_relationship_ids": string_list,
        "system_context_claim_entity_ids": string_list,
        "system_context_value_entity_ids": string_list,
        "system_context_relationship_ids": string_list,
        "system_context_alignment_statuses": string_list,
        "lifecycle_event_entity_ids": string_list,
        "lifecycle_relationship_ids": string_list,
        "dimensions": dimensions,
        "linkage_completeness_percent": {
            "type": "number",
            "minimum": 0,
            "maximum": 100,
        },
        "notice": text,
        "interface_entity_ids": string_list,
        "inbound_fusion_ids": string_list,
        "outbound_fusion_ids": string_list,
    }
    lead_properties = {
        "id": identifier,
        "kind": identifier,
        "priority": {"enum": ["high", "medium", "low"]},
        "subject_ids": string_list,
        "description": text,
        "affected_count": {"type": "integer", "minimum": 0},
        "subject_ids_omitted": {"type": "integer", "minimum": 0},
    }
    integer_map = {
        "type": "object",
        "maxProperties": 1_000,
        "additionalProperties": {"type": "integer", "minimum": 0},
    }
    summary_properties = {
        "entities": {"type": "integer", "minimum": 0},
        "relationships": {"type": "integer", "minimum": 0},
        "component_relationship_fusions": {"type": "integer", "minimum": 0},
        "semantic_profiles": {"type": "integer", "minimum": 0},
        "semantic_profiles_with_records": {"type": "integer", "minimum": 0},
        "verification_readiness_profiles": {"type": "integer", "minimum": 0},
        "verification_profiles_with_signals": {
            "type": "integer",
            "minimum": 0,
        },
        "review_governance_profiles": {"type": "integer", "minimum": 0},
        "analysis_sections": {"type": "integer", "minimum": 0},
        "populated_analysis_sections": {"type": "integer", "minimum": 0},
        "semantically_projected_analysis_sections": {
            "type": "integer",
            "minimum": 0,
        },
        "registered_without_projection_analysis_sections": {
            "type": "integer",
            "minimum": 0,
        },
        "provenance_only_analysis_sections": {
            "type": "integer",
            "minimum": 0,
        },
        "empty_analysis_sections": {"type": "integer", "minimum": 0},
        "unmapped_analysis_sections": {"type": "integer", "minimum": 0},
        "analysis_projection_relationships": {
            "type": "integer",
            "minimum": 0,
        },
        "analysis_records": {"type": "integer", "minimum": 0},
        "semantically_projected_analysis_records": {
            "type": "integer",
            "minimum": 0,
        },
        "unresolved_analysis_records": {"type": "integer", "minimum": 0},
        "analysis_record_projection_relationships": {
            "type": "integer",
            "minimum": 0,
        },
        "analysis_record_projection_coverage_percent": {
            "type": "number",
            "minimum": 0,
            "maximum": 100,
        },
        "analysis_projection_coverage_percent": {
            "type": "number",
            "minimum": 0,
            "maximum": 100,
        },
        "analysis_material_projection_coverage_percent": {
            "type": "number",
            "minimum": 0,
            "maximum": 100,
        },
        "quality_gate_diagnostics": {"type": "integer", "minimum": 0},
        "global_quality_gate_diagnostics": {"type": "integer", "minimum": 0},
        "profiles_with_blocking_quality_diagnostics": {
            "type": "integer",
            "minimum": 0,
        },
        "adapter_runs": {"type": "integer", "minimum": 0},
        "findings_with_tool_provenance": {"type": "integer", "minimum": 0},
        "adapter_contribution_relationships": {"type": "integer", "minimum": 0},
        "unlinked_adapter_contributions": {"type": "integer", "minimum": 0},
        "repository_artifacts": {"type": "integer", "minimum": 0},
        "semantically_analyzed_repository_artifacts": {
            "type": "integer",
            "minimum": 0,
        },
        "opaque_repository_artifacts": {"type": "integer", "minimum": 0},
        "excluded_repository_regions": {"type": "integer", "minimum": 0},
        "dependency_entities": {"type": "integer", "minimum": 0},
        "contract_entities": {"type": "integer", "minimum": 0},
        "components_with_repository_provenance": {
            "type": "integer",
            "minimum": 0,
        },
        "findings_with_repository_provenance": {
            "type": "integer",
            "minimum": 0,
        },
        "configured_source_components": {"type": "integer", "minimum": 0},
        "configured_source_findings": {"type": "integer", "minimum": 0},
        "components_with_source_provenance": {
            "type": "integer",
            "minimum": 0,
        },
        "findings_with_source_provenance": {
            "type": "integer",
            "minimum": 0,
        },
        "repository_provenance_relationships": {
            "type": "integer",
            "minimum": 0,
        },
        "machine_suggestions": {"type": "integer", "minimum": 0},
        "proposed_machine_suggestions": {"type": "integer", "minimum": 0},
        "machine_summaries": {"type": "integer", "minimum": 0},
        "stale_machine_summaries": {"type": "integer", "minimum": 0},
        "machine_claim_relationships": {"type": "integer", "minimum": 0},
        "machine_assistance_relationships": {"type": "integer", "minimum": 0},
        "machine_assistance_unresolved_evidence_references": {
            "type": "integer",
            "minimum": 0,
        },
        "machine_assistance_unresolved_citation_references": {
            "type": "integer",
            "minimum": 0,
        },
        "findings_with_machine_assistance": {"type": "integer", "minimum": 0},
        "guidance_sources": {"type": "integer", "minimum": 0},
        "methodology_basis_sources": {"type": "integer", "minimum": 0},
        "methodology_review_checks": {"type": "integer", "minimum": 0},
        "guidance_citations": {"type": "integer", "minimum": 0},
        "guidance_citations_with_source_lineage": {
            "type": "integer",
            "minimum": 0,
        },
        "findings_with_guidance_citations": {"type": "integer", "minimum": 0},
        "findings_with_complete_guidance_lineage": {
            "type": "integer",
            "minimum": 0,
        },
        "guidance_provenance_relationships": {
            "type": "integer",
            "minimum": 0,
        },
        "unresolved_guidance_source_references": {
            "type": "integer",
            "minimum": 0,
        },
        "system_context_fields": {"type": "integer", "minimum": 0},
        "system_context_values": {"type": "integer", "minimum": 0},
        "finding_context_claims": {"type": "integer", "minimum": 0},
        "matched_finding_context_claims": {"type": "integer", "minimum": 0},
        "unmatched_finding_context_claims": {"type": "integer", "minimum": 0},
        "findings_with_explicit_system_context": {"type": "integer", "minimum": 0},
        "system_context_relationships": {"type": "integer", "minimum": 0},
        "analysis_lifecycle_events": {"type": "integer", "minimum": 0},
        "finding_review_events": {"type": "integer", "minimum": 0},
        "subject_lifecycle_events": {"type": "integer", "minimum": 0},
        "lifecycle_relationships": {"type": "integer", "minimum": 0},
        "unresolved_lifecycle_subject_references": {
            "type": "integer",
            "minimum": 0,
        },
        "findings_with_review_history": {"type": "integer", "minimum": 0},
        "compound_exposure_chains": {"type": "integer", "minimum": 0},
        "finding_chains": {"type": "integer", "minimum": 0},
        "active_finding_chains": {"type": "integer", "minimum": 0},
        "historical_finding_chains": {"type": "integer", "minimum": 0},
        "review_leads": {"type": "integer", "minimum": 0},
        "runtime_observed_fusions": {"type": "integer", "minimum": 0},
        "multi_source_fusions": {"type": "integer", "minimum": 0},
        "classifications": integer_map,
        "review_leads_by_kind": integer_map,
        "semantic_dimensions": integer_map,
        "compound_exposures_by_kind": integer_map,
        "verification_lifecycle_states": integer_map,
        "verification_evidence_postures": integer_map,
        "verification_readiness_gaps": integer_map,
        "quality_diagnostics_by_level": integer_map,
        "global_quality_diagnostics_by_level": integer_map,
        "review_governance_states": integer_map,
        "source_change_states": integer_map,
        "adapter_run_statuses": integer_map,
        "repository_artifact_statuses": integer_map,
        "machine_suggestion_statuses": integer_map,
        "machine_claim_relationship_types": integer_map,
        "finding_context_alignment_statuses": integer_map,
        "lifecycle_event_types": integer_map,
        "omitted_by_bound": integer_map,
    }
    properties = {
        "format": {"const": CROSS_REFERENCE_FORMAT},
        "analysis_state_sha256": digest,
        "baseline_id": {"type": "string", "maxLength": 512},
        "authority": {"type": "string", "minLength": 1, "maxLength": 20_000},
        "summary": {
            "type": "object",
            "required": list(summary_properties),
            "properties": summary_properties,
            "additionalProperties": False,
        },
        "entities": {
            "type": "array",
            "maxItems": MAX_ENTITIES,
            "items": {
                "type": "object",
                "required": list(entity_properties),
                "properties": entity_properties,
                "additionalProperties": False,
            },
        },
        "relationships": {
            "type": "array",
            "maxItems": MAX_RELATIONSHIPS,
            "items": {
                "type": "object",
                "required": list(relationship_properties),
                "properties": relationship_properties,
                "additionalProperties": False,
            },
        },
        "component_relationship_fusions": {
            "type": "array",
            "maxItems": MAX_FUSIONS,
            "items": {
                "type": "object",
                "required": list(fusion_properties),
                "properties": fusion_properties,
                "additionalProperties": False,
            },
        },
        "semantic_profiles": {
            "type": "array",
            "maxItems": MAX_ENTITIES,
            "items": {
                "type": "object",
                "required": list(semantic_profile_properties),
                "properties": semantic_profile_properties,
                "additionalProperties": False,
            },
        },
        "verification_readiness_profiles": {
            "type": "array",
            "maxItems": MAX_CHAINS,
            "items": {
                "type": "object",
                "required": list(readiness_profile_properties),
                "properties": readiness_profile_properties,
                "additionalProperties": False,
            },
        },
        "quality_gate_projection": {
            "type": "object",
            "required": list(quality_gate_projection_properties),
            "properties": quality_gate_projection_properties,
            "additionalProperties": False,
        },
        "review_governance_profiles": {
            "type": "array",
            "maxItems": MAX_CHAINS,
            "items": {
                "type": "object",
                "required": list(governance_profile_properties),
                "properties": governance_profile_properties,
                "additionalProperties": False,
            },
        },
        "analysis_projection_coverage": {
            "type": "object",
            "required": list(analysis_projection_coverage_properties),
            "properties": analysis_projection_coverage_properties,
            "additionalProperties": False,
        },
        "adapter_provenance": {
            "type": "object",
            "required": list(adapter_provenance_properties),
            "properties": adapter_provenance_properties,
            "additionalProperties": False,
        },
        "repository_provenance": {
            "type": "object",
            "required": list(repository_provenance_properties),
            "properties": repository_provenance_properties,
            "additionalProperties": False,
        },
        "machine_assistance_provenance": {
            "type": "object",
            "required": list(machine_assistance_properties),
            "properties": machine_assistance_properties,
            "additionalProperties": False,
        },
        "guidance_provenance": {
            "type": "object",
            "required": list(guidance_provenance_properties),
            "properties": guidance_provenance_properties,
            "additionalProperties": False,
        },
        "system_context_provenance": {
            "type": "object",
            "required": list(system_context_provenance_properties),
            "properties": system_context_provenance_properties,
            "additionalProperties": False,
        },
        "lifecycle_provenance": {
            "type": "object",
            "required": list(lifecycle_provenance_properties),
            "properties": lifecycle_provenance_properties,
            "additionalProperties": False,
        },
        "finding_chains": {
            "type": "array",
            "maxItems": MAX_CHAINS,
            "items": {
                "type": "object",
                "required": list(chain_properties),
                "properties": chain_properties,
                "additionalProperties": False,
            },
        },
        "review_leads": {
            "type": "array",
            "maxItems": MAX_REVIEW_LEADS,
            "items": {
                "type": "object",
                "required": ["id", "kind", "priority", "subject_ids", "description"],
                "properties": lead_properties,
                "additionalProperties": False,
            },
        },
        "limitations": {
            "type": "array",
            "minItems": 1,
            "maxItems": 100,
            "items": {"type": "string", "minLength": 1, "maxLength": 20_000},
        },
        "content_sha256": digest,
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("cross-reference"),
        "title": "PySFMEA cross-reference evidence fabric",
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }


def _cross_reference_verification_schema() -> dict[str, Any]:
    return _verification_schema(
        name="cross-reference-verification",
        format_name=CROSS_REFERENCE_VERIFICATION_FORMAT,
        title="PySFMEA cross-reference evidence-fabric verification verdict",
        check_names=CROSS_REFERENCE_VERIFICATION_CHECKS,
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


def _assurance_scaffold_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    required_text = {"type": "string", "minLength": 1, "maxLength": 20_000}
    source = {
        "type": "object",
        "required": ["path", "line", "end_line"],
        "properties": {
            "path": {"type": "string", "maxLength": 4_096},
            "line": {"type": "integer", "minimum": 0},
            "end_line": {"type": "integer", "minimum": 0},
        },
        "additionalProperties": False,
    }
    observation_item = {
        "type": "object",
        "required": ["id", "text"],
        "properties": {"id": _identifier_schema(), "text": required_text},
        "additionalProperties": False,
    }
    common_design_properties: dict[str, Any] = {
        "id": _identifier_schema(),
        "obligation_id": _identifier_schema(),
        "finding_id": _identifier_schema(),
        "component_id": _identifier_schema(),
        "component": required_text,
        "source": source,
        "contract_sha256": digest,
        "failure_condition": required_text,
        "oracles": {
            "type": "array",
            "minItems": 1,
            "maxItems": 100,
            "items": observation_item,
        },
        "acceptance_criteria": {
            "type": "array",
            "minItems": 1,
            "maxItems": 100,
            "items": observation_item,
        },
        "adapter_status": {"const": "project_implementation_required"},
        "method": {"enum": ["property_test", "contract_test"]},
        "adapter_function": {"enum": ["exercise_property", "exercise_contract"]},
        "limitations": {
            "type": "array",
            "minItems": 1,
            "maxItems": 20,
            "items": required_text,
        },
    }
    common_required = list(common_design_properties)
    property_design = {
        "type": "object",
        "required": common_required
        + ["parameters", "scenarios", "generation", "strategy_strength"],
        "properties": {
            **common_design_properties,
            "method": {"const": "property_test"},
            "adapter_function": {"const": "exercise_property"},
            "parameters": {
                "type": "array",
                "maxItems": 32,
                "items": {
                    "type": "object",
                    "required": ["name", "annotation", "strategy"],
                    "properties": {
                        "name": required_text,
                        "annotation": {"type": "string", "maxLength": 2_000},
                        "strategy": {"type": "object", "minProperties": 1},
                    },
                    "additionalProperties": False,
                },
            },
            "scenarios": {
                "type": "array",
                "minItems": 1,
                "maxItems": 20,
                "items": required_text,
            },
            "generation": {
                "type": "object",
                "required": ["engine", "max_examples", "derandomize", "deadline"],
                "properties": {
                    "engine": {"const": "hypothesis"},
                    "max_examples": {"type": "integer", "minimum": 1, "maximum": 1_000},
                    "derandomize": {"const": True},
                    "deadline": {"type": "null"},
                },
                "additionalProperties": False,
            },
            "strategy_strength": {
                "enum": ["annotation_and_name_based", "bounded_heuristic"]
            },
        },
        "additionalProperties": False,
    }
    contract_reference = {
        "type": "object",
        "required": ["id", "path", "kind", "sha256", "operations", "data_types"],
        "properties": {
            "id": _identifier_schema(),
            "path": {"type": "string", "maxLength": 4_096},
            "kind": required_text,
            "sha256": digest,
            "operations": {
                "type": "array",
                "maxItems": 20,
                "items": required_text,
            },
            "data_types": {
                "type": "array",
                "maxItems": 100,
                "items": required_text,
            },
        },
        "additionalProperties": False,
    }
    contract_case: dict[str, Any] = {
        "type": "object",
        "required": [
            "id",
            "kind",
            "contract_id",
            "contract_sha256",
            "operation",
            "expected_behavior",
            "binding_status",
        ],
        "properties": {
            "id": _identifier_schema(),
            "kind": {
                "enum": [
                    "conforming_exchange",
                    "missing_required_input",
                    "malformed_input",
                    "incompatible_response",
                    "declared_error_exchange",
                    "establish_contract_binding",
                ]
            },
            "contract_id": {"type": "string", "maxLength": 20_000},
            "contract_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"},
            "operation": {"type": "string", "maxLength": 20_000},
            "expected_behavior": required_text,
            "binding_status": {
                "enum": [
                    "static_candidate_match_requires_review",
                    "single_inventory_candidate_requires_review",
                    "unresolved",
                ]
            },
        },
        "additionalProperties": False,
    }
    contract_design = {
        "type": "object",
        "required": common_required + ["binding_status", "contracts", "cases"],
        "properties": {
            **common_design_properties,
            "method": {"const": "contract_test"},
            "adapter_function": {"const": "exercise_contract"},
            "binding_status": contract_case["properties"]["binding_status"],
            "contracts": {
                "type": "array",
                "maxItems": 20,
                "items": contract_reference,
            },
            "cases": {
                "type": "array",
                "minItems": 1,
                "maxItems": 40,
                "items": contract_case,
            },
        },
        "additionalProperties": False,
    }
    generated_file_properties = {
        name: {
            "type": "object",
            "required": ["role", "sha256"],
            "properties": {"role": {"const": role}, "sha256": digest},
            "additionalProperties": False,
        }
        for name, role in ASSURANCE_SCAFFOLD_GENERATED_FILE_ROLES.items()
    }
    schema: dict[str, Any] = {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("assurance-scaffold"),
        "title": "PySFMEA executable assurance scaffold manifest",
        "description": (
            "Closed structural contract for analysis-bound pytest starting points, "
            "property strategies, contract cases, and generated-file identities. Exact "
            "semantic regeneration requires assurance-scaffold-verify."
        ),
        "type": "object",
        "required": [
            "format",
            "generated_at",
            "baseline_id",
            "queue",
            "binding",
            "selection",
            "notice",
            "contract_snapshot",
            "obligations",
            "test_designs",
            "generated_files",
            "manifest_sha256",
        ],
        "properties": {
            "format": {"const": ASSURANCE_SCAFFOLD_FORMAT},
            "generated_at": required_text,
            "baseline_id": required_text,
            "queue": {
                "type": "object",
                "required": ["id", "owner", "purpose"],
                "properties": {
                    "id": _identifier_schema(),
                    "owner": {"type": "string", "maxLength": 200},
                    "purpose": {"type": "string", "maxLength": 500},
                },
                "additionalProperties": False,
            },
            "binding": {
                "type": "object",
                "required": [
                    "baseline_id",
                    "analysis_schema_version",
                    "analysis_state_sha256",
                    "scaffold_contracts_sha256",
                    "test_designs_sha256",
                ],
                "properties": {
                    "baseline_id": required_text,
                    "analysis_schema_version": required_text,
                    "analysis_state_sha256": digest,
                    "scaffold_contracts_sha256": digest,
                    "test_designs_sha256": digest,
                },
                "additionalProperties": False,
            },
            "selection": {
                "type": "object",
                "required": ["disposition", "scope", "limit", "include_implemented"],
                "properties": {
                    "disposition": {
                        "enum": ["accepted", "rejected", "unreviewed", "all"]
                    },
                    "scope": required_text,
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1_000},
                    "include_implemented": {"type": "boolean"},
                },
                "additionalProperties": False,
            },
            "notice": required_text,
            "contract_snapshot": {
                "type": "array",
                "minItems": 1,
                "maxItems": 1_000,
                "items": {
                    "type": "object",
                    "required": [
                        "id",
                        "finding_id",
                        "contract_sha256",
                        "disposition",
                        "source_status",
                        "implementation_status",
                    ],
                    "properties": {
                        "id": _identifier_schema(),
                        "finding_id": _identifier_schema(),
                        "contract_sha256": digest,
                        "disposition": {"enum": ["accepted", "rejected", "unreviewed"]},
                        "source_status": required_text,
                        "implementation_status": required_text,
                    },
                    "additionalProperties": False,
                },
            },
            "obligations": {
                "type": "array",
                "minItems": 1,
                "maxItems": 1_000,
                "items": {
                    "type": "object",
                    "required": ["id", "finding_id", "verification_method"],
                    "properties": {
                        "id": _identifier_schema(),
                        "finding_id": _identifier_schema(),
                        "verification_method": required_text,
                    },
                    "additionalProperties": True,
                },
            },
            "test_designs": {
                "type": "object",
                "required": [
                    "format",
                    "property_tests",
                    "contract_tests",
                    "summary",
                    "notice",
                    "authority",
                    "content_sha256",
                ],
                "properties": {
                    "format": {"const": ASSURANCE_TEST_DESIGNS_FORMAT},
                    "property_tests": {
                        "type": "array",
                        "maxItems": 1_000,
                        "items": property_design,
                    },
                    "contract_tests": {
                        "type": "array",
                        "maxItems": 1_000,
                        "items": contract_design,
                    },
                    "summary": {
                        "type": "object",
                        "required": [
                            "property_designs",
                            "property_parameters",
                            "contract_designs",
                            "contract_cases",
                            "unresolved_contract_bindings",
                        ],
                        "additionalProperties": {
                            "type": "integer",
                            "minimum": 0,
                        },
                    },
                    "notice": required_text,
                    "authority": {
                        "const": "deterministic_test_design_not_project_oracle_or_assurance_evidence"
                    },
                    "content_sha256": digest,
                },
                "additionalProperties": False,
            },
            "generated_files": {
                "type": "object",
                "required": sorted(generated_file_properties),
                "properties": generated_file_properties,
                "additionalProperties": False,
            },
            "manifest_sha256": digest,
        },
        "additionalProperties": False,
    }
    return schema


def _assurance_scaffold_verification_schema() -> dict[str, Any]:
    required_text = {"type": "string", "minLength": 1, "maxLength": 20_000}
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("assurance-scaffold-verification"),
        "title": "PySFMEA executable assurance scaffold verification verdict",
        "type": "object",
        "required": [
            "format",
            "path",
            "valid",
            "status",
            "checks",
            "binding",
            "obligation_count",
            "obligation_ids",
            "current_selection",
            "lifecycle",
            "retirement",
            "queue",
            "contract_change_summary",
            "contract_changes",
            "generated_files",
            "test_design_summary",
            "findings",
            "notice",
        ],
        "properties": {
            "format": {"const": ASSURANCE_SCAFFOLD_VERIFICATION_FORMAT},
            "path": {"type": "string"},
            "valid": {"type": "boolean"},
            "status": {
                "enum": ["matched", "contracts_current", "mismatched", "invalid"]
            },
            "checks": {"type": "object", "minProperties": 1},
            "binding": {"type": "object", "minProperties": 1},
            "obligation_count": {"type": "integer", "minimum": 0},
            "obligation_ids": {
                "type": "array",
                "maxItems": 1_000,
                "items": _identifier_schema(),
            },
            "current_selection": {"type": "object", "minProperties": 1},
            "lifecycle": {"enum": ["active", "retirement_candidate", "archived"]},
            "retirement": {"type": "object", "minProperties": 1},
            "queue": {"type": "object", "minProperties": 1},
            "contract_change_summary": {"type": "object", "minProperties": 1},
            "contract_changes": {"type": "array", "maxItems": 2_000},
            "generated_files": {
                "type": "array",
                "maxItems": len(ASSURANCE_SCAFFOLD_GENERATED_FILE_ROLES),
            },
            "test_design_summary": {"type": "object"},
            "findings": {"type": "array", "maxItems": 10_000},
            "notice": required_text,
        },
        "additionalProperties": False,
    }


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
                "properties": {name: {"type": "boolean"} for name in check_names},
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
            "retry_policy": {"enum": ["after_remediation", "manual_diagnostics"]},
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
            "format": {"const": PUBLICATION_FAILURE_CATALOG_VERIFICATION_FORMAT},
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
                        "catalog_format": {"const": PUBLICATION_FAILURE_CATALOG_FORMAT},
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
                    name: {"type": "boolean"} for name in analysis_structure_check_names
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
    cross_reference_verdict = copy.deepcopy(_cross_reference_verification_schema())
    for metadata_key in ("$schema", "$id", "title", "description"):
        cross_reference_verdict.pop(metadata_key, None)
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
                "properties": {name: {"type": "boolean"} for name in sfta_check_names},
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
                            failure.rule_id for failure in PUBLICATION_FAILURES.values()
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
                        "cross_reference_projection_v1",
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
            "cross_reference": {
                "oneOf": [
                    {"type": "object", "maxProperties": 0},
                    cross_reference_verdict,
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
                        "counts": {"properties": {"error": {"const": 0}}},
                        "findings": {
                            "not": {
                                "contains": {
                                    "required": ["level"],
                                    "properties": {"level": {"const": "error"}},
                                }
                            }
                        },
                    },
                },
                "else": {
                    "properties": {
                        "counts": {"properties": {"error": {"minimum": 1}}},
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
                    "properties": {"counts": {"properties": {"warning": {"const": 0}}}}
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
                                            {"required": ["catalog_canonicalization"]},
                                            {"required": ["catalog_sha256"]},
                                            {"required": ["next_action"]},
                                            {"required": ["retry_policy"]},
                                        ]
                                    },
                                    "properties": {
                                        "status": {"const": "published"},
                                        "phase": {"const": "complete"},
                                    },
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
                                            {"required": ["catalog_canonicalization"]},
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
                                    },
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
                                "properties": {"failure_code": {"const": failure.code}},
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
                                    "failure_rule_id": {"const": failure.rule_id},
                                    "next_action": {"const": failure.next_action},
                                    "retry_policy": {"const": failure.retry_policy},
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
    analysis_selection = {
        "type": "object",
        "required": [
            "method",
            "timestamped_candidate_count",
            "timestamped_candidates_truncated",
        ],
        "properties": {
            "method": {
                "enum": [
                    "explicit",
                    "unsafe_explicit",
                    "standard_location",
                    "unsafe_standard_location",
                    "latest_timestamped_artifact",
                    "bounded_timestamped_artifact",
                    "default_missing_location",
                ]
            },
            "timestamped_candidate_count": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_TIMESTAMPED_ANALYSIS_CANDIDATES,
            },
            "timestamped_candidates_truncated": {"type": "boolean"},
        },
        "additionalProperties": False,
    }
    paths = {
        "type": "object",
        "required": [
            "configuration",
            "analysis",
            "analysis_selection",
            "assurance_scaffold",
            "assurance_scaffolds",
        ],
        "properties": {
            "configuration": nonempty,
            "analysis": nonempty,
            "analysis_selection": analysis_selection,
            "artifact_selection": {
                "type": "object",
                "required": ["html_report", "pdf_report", "review_package"],
                "properties": {
                    "html_report": {"enum": ["auto_discovered", "explicit"]},
                    "pdf_report": {"enum": ["auto_discovered", "explicit"]},
                    "review_package": {"enum": ["auto_discovered", "explicit"]},
                },
                "additionalProperties": False,
            },
            "assurance_scaffold": {"type": "string", "maxLength": 16_384},
            "assurance_scaffolds": {
                "type": "array",
                "maxItems": 10_000,
                "items": {"type": "string", "minLength": 1, "maxLength": 16_384},
                "uniqueItems": True,
            },
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
                    "analysis_invalid",
                    "analysis_unsafe",
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
            "paths": paths,
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


def _assurance_program_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    nonempty = {"type": "string", "minLength": 1, "maxLength": 2_000}
    identifier = {
        "type": "string",
        "minLength": 1,
        "maxLength": 200,
        "pattern": "^\\S+$",
    }
    string_ids = {
        "type": "array",
        "maxItems": 10_000,
        "items": identifier,
        "uniqueItems": True,
    }
    endpoint = {
        "type": "object",
        "required": ["repository_id", "component_id"],
        "properties": {"repository_id": identifier, "component_id": identifier},
        "additionalProperties": False,
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("assurance-program"),
        "title": "PySFMEA system assurance program",
        "type": "object",
        "required": [
            "format",
            "name",
            "purpose",
            "created_at",
            "repositories",
            "relationships",
            "requirements_sources",
            "external_evidence",
            "validation_cohorts",
            "llm_evaluations",
            "governance",
            "quality_gates",
            "integrity",
        ],
        "properties": {
            "format": {"const": "pysfmea-assurance-program-1"},
            "name": {"type": "string", "minLength": 1, "maxLength": 500},
            "purpose": nonempty,
            "created_at": nonempty,
            "repositories": {
                "type": "array",
                "minItems": 1,
                "maxItems": 100,
                "items": {
                    "type": "object",
                    "required": [
                        "id",
                        "analysis",
                        "analysis_state_sha256",
                        "baseline_id",
                        "role",
                    ],
                    "properties": {
                        "id": identifier,
                        "analysis": nonempty,
                        "analysis_state_sha256": digest,
                        "baseline_id": nonempty,
                        "role": nonempty,
                    },
                    "additionalProperties": False,
                },
            },
            "relationships": {
                "type": "array",
                "maxItems": 10_000,
                "items": {
                    "type": "object",
                    "required": ["id", "kind", "source", "target"],
                    "properties": {
                        "id": identifier,
                        "kind": {
                            "enum": [
                                "calls",
                                "publishes",
                                "subscribes",
                                "data_flow",
                                "depends_on",
                                "controls",
                                "fallback",
                            ]
                        },
                        "source": endpoint,
                        "target": endpoint,
                        "temporal": {
                            "type": "object",
                            "properties": {
                                "deadline_ms": {
                                    "type": "number",
                                    "exclusiveMinimum": 0,
                                },
                                "timeout_ms": {"type": "number", "exclusiveMinimum": 0},
                                "retry_limit": {"type": "integer", "minimum": 0},
                                "backoff_ms": {"type": "number", "minimum": 0},
                                "max_in_flight": {"type": "integer", "minimum": 1},
                                "ordering": nonempty,
                                "clock": nonempty,
                            },
                            "additionalProperties": False,
                        },
                        "circuit_breaker": {
                            "type": "object",
                            "required": [
                                "failure_threshold",
                                "open_state_timeout_ms",
                                "half_open_max_calls",
                                "recovery_deadline_ms",
                            ],
                            "properties": {
                                "failure_threshold": {"type": "integer", "minimum": 1},
                                "open_state_timeout_ms": {
                                    "type": "number",
                                    "exclusiveMinimum": 0,
                                },
                                "half_open_max_calls": {
                                    "type": "integer",
                                    "minimum": 1,
                                },
                                "recovery_deadline_ms": {
                                    "type": "number",
                                    "exclusiveMinimum": 0,
                                },
                            },
                            "additionalProperties": False,
                        },
                    },
                    "additionalProperties": False,
                },
            },
            "requirements_sources": {
                "type": "array",
                "maxItems": 50_000,
                "items": {
                    "type": "object",
                    "required": [
                        "id",
                        "provider",
                        "revision",
                        "retrieved_at",
                        "source_uri",
                        "content_sha256",
                        "requirements",
                    ],
                    "properties": {
                        "id": identifier,
                        "provider": nonempty,
                        "revision": nonempty,
                        "retrieved_at": {
                            "type": "string",
                            "format": "date-time",
                            "minLength": 1,
                        },
                        "source_uri": nonempty,
                        "content_sha256": digest,
                        "requirements": {
                            "type": "array",
                            "maxItems": 50_000,
                            "items": {
                                "type": "object",
                                "required": [
                                    "id",
                                    "text",
                                    "repository_ids",
                                    "hazard_ids",
                                    "finding_ids",
                                ],
                                "properties": {
                                    "id": identifier,
                                    "text": nonempty,
                                    "repository_ids": string_ids,
                                    "hazard_ids": string_ids,
                                    "finding_ids": string_ids,
                                },
                                "additionalProperties": False,
                            },
                        },
                    },
                    "additionalProperties": False,
                },
            },
            "external_evidence": {
                "type": "array",
                "maxItems": 50_000,
                "items": {
                    "type": "object",
                    "required": [
                        "id",
                        "technique",
                        "status",
                        "repository_ids",
                        "relationship_ids",
                        "finding_ids",
                        "producer",
                        "reviewer",
                        "metrics",
                        "artifact",
                    ],
                    "properties": {
                        "id": identifier,
                        "technique": {
                            "enum": [
                                "coverage",
                                "mutation",
                                "property_based",
                                "fault_injection",
                                "concurrency",
                                "load",
                                "chaos",
                                "sast",
                                "dast",
                                "runtime_trace",
                                "formal_analysis",
                                "manual_inspection",
                            ]
                        },
                        "status": {
                            "enum": ["passed", "failed", "inconclusive", "not_run"]
                        },
                        "repository_ids": string_ids,
                        "relationship_ids": string_ids,
                        "finding_ids": string_ids,
                        "producer": {"type": "string", "maxLength": 500},
                        "reviewer": {"type": "string", "maxLength": 500},
                        "metrics": {
                            "type": "object",
                            "maxProperties": 100,
                            "additionalProperties": {
                                "type": [
                                    "number",
                                    "integer",
                                    "string",
                                    "boolean",
                                    "null",
                                ]
                            },
                        },
                        "artifact": {
                            "type": "object",
                            "properties": {"path": nonempty, "sha256": digest},
                            "additionalProperties": False,
                        },
                    },
                    "additionalProperties": False,
                    "allOf": [
                        {
                            "if": {
                                "properties": {"status": {"enum": ["passed", "failed"]}}
                            },
                            "then": {
                                "properties": {
                                    "artifact": {"required": ["path", "sha256"]}
                                }
                            },
                        }
                    ],
                },
            },
            "validation_cohorts": {
                "type": "array",
                "maxItems": 2_000,
                "items": {
                    "type": "object",
                    "required": [
                        "id",
                        "repository",
                        "framework",
                        "corpus_sha256",
                        "case_count",
                        "recall",
                        "precision",
                        "independent_reviewed",
                        "producer",
                        "reviewer",
                    ],
                    "properties": {
                        "id": identifier,
                        "repository": nonempty,
                        "framework": nonempty,
                        "corpus_sha256": digest,
                        "case_count": {"type": "integer", "minimum": 1},
                        "recall": {"type": "number", "minimum": 0, "maximum": 1},
                        "precision": {"type": "number", "minimum": 0, "maximum": 1},
                        "matched_count": {"type": "integer", "minimum": 0},
                        "actual_matched_count": {"type": "integer", "minimum": 0},
                        "actual_count": {"type": "integer", "minimum": 1},
                        "evaluation_result_format": {
                            "const": "pysfmea-evaluation-result-1"
                        },
                        "evaluation_result_sha256": digest,
                        "evaluation_verifier_version": nonempty,
                        "evaluation_result_artifact": {
                            "type": "object",
                            "required": ["path", "sha256"],
                            "properties": {"path": nonempty, "sha256": digest},
                            "additionalProperties": False,
                        },
                        "call_case_count": {"type": "integer", "minimum": 0},
                        "call_resolution_recall": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 1,
                        },
                        "call_resolution_precision": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 1,
                        },
                        "call_matched_count": {"type": "integer", "minimum": 0},
                        "call_actual_matched_count": {
                            "type": "integer",
                            "minimum": 0,
                        },
                        "call_actual_count": {"type": "integer", "minimum": 1},
                        "semantic_case_count": {"type": "integer", "minimum": 0},
                        "semantic_output_recall": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 1,
                        },
                        "semantic_output_precision": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 1,
                        },
                        "semantic_matched_count": {"type": "integer", "minimum": 0},
                        "semantic_actual_matched_count": {
                            "type": "integer",
                            "minimum": 0,
                        },
                        "semantic_actual_count": {"type": "integer", "minimum": 1},
                        "independent_reviewed": {"type": "boolean"},
                        "producer": nonempty,
                        "reviewer": nonempty,
                    },
                    "allOf": [
                        {
                            "if": {
                                "required": ["call_case_count"],
                                "properties": {"call_case_count": {"minimum": 1}},
                            },
                            "then": {
                                "required": [
                                    "call_resolution_recall",
                                    "call_resolution_precision",
                                ]
                            },
                        },
                        {
                            "if": {
                                "anyOf": [
                                    {"required": ["matched_count"]},
                                    {"required": ["actual_matched_count"]},
                                    {"required": ["actual_count"]},
                                    {"required": ["evaluation_result_format"]},
                                    {"required": ["evaluation_result_sha256"]},
                                    {"required": ["evaluation_verifier_version"]},
                                    {"required": ["evaluation_result_artifact"]},
                                ]
                            },
                            "then": {
                                "required": [
                                    "matched_count",
                                    "actual_matched_count",
                                    "actual_count",
                                    "evaluation_result_format",
                                    "evaluation_result_sha256",
                                    "evaluation_verifier_version",
                                ]
                            },
                        },
                        {
                            "if": {
                                "anyOf": [
                                    {"required": ["call_matched_count"]},
                                    {"required": ["call_actual_matched_count"]},
                                    {"required": ["call_actual_count"]},
                                ]
                            },
                            "then": {
                                "required": [
                                    "call_case_count",
                                    "call_resolution_recall",
                                    "call_resolution_precision",
                                    "call_matched_count",
                                    "call_actual_matched_count",
                                    "call_actual_count",
                                    "matched_count",
                                    "actual_matched_count",
                                    "actual_count",
                                    "evaluation_result_format",
                                    "evaluation_result_sha256",
                                    "evaluation_verifier_version",
                                ],
                                "properties": {"call_case_count": {"minimum": 1}},
                            },
                        },
                        {
                            "if": {
                                "anyOf": [
                                    {"required": ["call_resolution_recall"]},
                                    {"required": ["call_resolution_precision"]},
                                ]
                            },
                            "then": {
                                "required": ["call_case_count"],
                                "properties": {"call_case_count": {"minimum": 1}},
                            },
                        },
                    ],
                    "additionalProperties": False,
                },
            },
            "llm_evaluations": {
                "type": "array",
                "maxItems": 10_000,
                "items": {
                    "type": "object",
                    "required": [
                        "id",
                        "provider",
                        "model",
                        "prompt_version",
                        "sample_count",
                        "grounding",
                        "citation_accuracy",
                        "unsupported_claim_rate",
                        "corpus_sha256",
                        "independent_reviewed",
                        "producer",
                        "reviewer",
                    ],
                    "properties": {
                        "id": identifier,
                        "provider": nonempty,
                        "model": nonempty,
                        "prompt_version": nonempty,
                        "sample_count": {"type": "integer", "minimum": 1},
                        "grounding": {"type": "number", "minimum": 0, "maximum": 1},
                        "citation_accuracy": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 1,
                        },
                        "unsupported_claim_rate": {
                            "type": "number",
                            "minimum": 0,
                            "maximum": 1,
                        },
                        "grounded_sample_count": {"type": "integer", "minimum": 0},
                        "citation_correct_sample_count": {
                            "type": "integer",
                            "minimum": 0,
                        },
                        "claim_count": {"type": "integer", "minimum": 1},
                        "unsupported_claim_count": {
                            "type": "integer",
                            "minimum": 0,
                        },
                        "corpus_sha256": digest,
                        "evidence_fingerprint_sha256": digest,
                        "corpus_format": {
                            "enum": [
                                "pysfmea-llm-quality-corpus-1",
                                "pysfmea-llm-quality-corpus-2",
                                "pysfmea-llm-quality-corpus-3",
                            ]
                        },
                        "subject_bound": {"type": "boolean"},
                        "corpus_artifact": {
                            "type": "object",
                            "required": ["path", "sha256"],
                            "properties": {"path": nonempty, "sha256": digest},
                            "additionalProperties": False,
                        },
                        "independent_reviewed": {"type": "boolean"},
                        "producer": nonempty,
                        "reviewer": nonempty,
                    },
                    "allOf": [
                        {
                            "if": {
                                "anyOf": [
                                    {"required": ["corpus_format"]},
                                    {"required": ["subject_bound"]},
                                ]
                            },
                            "then": {"required": ["corpus_format", "subject_bound"]},
                        },
                        {
                            "if": {
                                "anyOf": [
                                    {"required": ["grounded_sample_count"]},
                                    {"required": ["citation_correct_sample_count"]},
                                    {"required": ["claim_count"]},
                                    {"required": ["unsupported_claim_count"]},
                                    {"required": ["corpus_artifact"]},
                                ]
                            },
                            "then": {
                                "required": [
                                    "grounded_sample_count",
                                    "citation_correct_sample_count",
                                    "claim_count",
                                    "unsupported_claim_count",
                                ]
                            },
                        },
                    ],
                    "additionalProperties": False,
                },
            },
            "governance": {
                "type": "object",
                "required": [
                    "required_roles",
                    "independent_evidence_review",
                    "require_program_approval",
                    "approvals",
                ],
                "properties": {
                    "required_roles": string_ids,
                    "independent_evidence_review": {"type": "boolean"},
                    "require_program_approval": {"type": "boolean"},
                    "approvals": {
                        "type": "array",
                        "maxItems": 50_000,
                        "items": {
                            "type": "object",
                            "required": [
                                "subject_kind",
                                "subject_id",
                                "reviewer",
                                "role",
                                "decision",
                                "at",
                            ],
                            "properties": {
                                "subject_kind": {
                                    "enum": [
                                        "program",
                                        "repository",
                                        "requirement",
                                        "relationship",
                                        "evidence",
                                    ]
                                },
                                "subject_id": nonempty,
                                "reviewer": nonempty,
                                "role": identifier,
                                "decision": {"enum": ["approved", "rejected"]},
                                "at": {
                                    "type": "string",
                                    "format": "date-time",
                                    "minLength": 1,
                                },
                            },
                            "additionalProperties": False,
                        },
                    },
                },
                "additionalProperties": False,
            },
            "quality_gates": {
                "type": "object",
                "required": [
                    "min_validation_repositories",
                    "require_independent_validation",
                    "min_recall",
                    "min_precision",
                    "require_temporal_evidence",
                    "require_resilience_evidence",
                    "min_llm_samples",
                    "require_independent_llm_evaluation",
                    "min_llm_grounding",
                    "min_llm_citation_accuracy",
                    "max_llm_unsupported_claim_rate",
                ],
                "properties": {
                    "min_validation_repositories": {"type": "integer", "minimum": 0},
                    "require_independent_validation": {"type": "boolean"},
                    "min_recall": {"type": "number", "minimum": 0, "maximum": 1},
                    "min_precision": {"type": "number", "minimum": 0, "maximum": 1},
                    "require_count_backed_validation": {"type": "boolean"},
                    "require_evaluation_result_artifacts": {"type": "boolean"},
                    "min_micro_recall": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                    "min_micro_precision": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                    "min_call_resolution_recall": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                    "min_call_resolution_precision": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                    "min_micro_call_resolution_recall": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                    "min_micro_call_resolution_precision": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                    "min_semantic_output_recall": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                    "min_semantic_output_precision": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                    "min_micro_semantic_output_recall": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                    "min_micro_semantic_output_precision": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                    "require_temporal_evidence": {"type": "boolean"},
                    "require_resilience_evidence": {"type": "boolean"},
                    "min_llm_samples": {"type": "integer", "minimum": 0},
                    "require_independent_llm_evaluation": {"type": "boolean"},
                    "require_llm_count_backing": {"type": "boolean"},
                    "require_llm_corpus_artifacts": {"type": "boolean"},
                    "require_llm_subject_binding": {"type": "boolean"},
                    "min_llm_grounding": {"type": "number", "minimum": 0, "maximum": 1},
                    "min_llm_citation_accuracy": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                    "max_llm_unsupported_claim_rate": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                },
                "additionalProperties": False,
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
        "additionalProperties": False,
    }


def _assurance_program_verification_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^([0-9a-f]{64})?$"}
    nonempty = {"type": "string", "minLength": 1, "maxLength": 4_096}
    count = {"type": "integer", "minimum": 0}
    ratio = {"type": ["number", "null"], "minimum": 0, "maximum": 1}
    string_array = {
        "type": "array",
        "maxItems": 50_000,
        "uniqueItems": True,
        "items": nonempty,
    }
    role_array = {
        "type": "array",
        "maxItems": 10_000,
        "uniqueItems": True,
        "items": {
            "type": "string",
            "minLength": 1,
            "maxLength": 200,
            "pattern": "^\\S+$",
        },
    }
    check_names = PROGRAM_VERIFICATION_CHECKS
    full_checks = {
        "type": "object",
        "required": list(check_names),
        "properties": {name: {"type": "boolean"} for name in check_names},
        "additionalProperties": False,
    }
    checks = {
        "oneOf": [
            {
                "type": "object",
                "required": ["input"],
                "properties": {"input": {"const": False}},
                "additionalProperties": False,
            },
            {
                "type": "object",
                "required": ["input", "format"],
                "properties": {
                    "input": {"const": True},
                    "format": {"const": False},
                },
                "additionalProperties": False,
            },
            full_checks,
        ]
    }
    summary = {
        "type": "object",
        "required": [
            "name",
            "purpose",
            "repositories",
            "repository_ids",
            "bound_repositories",
            "relationships",
            "requirements",
            "external_evidence",
            "verified_evidence",
            "trusted_evidence",
            "duplicate_evidence",
            "evidence_bytes",
            "evidence_statuses",
            "approvals",
            "validated_approvals",
            "credited_program_approvals",
            "conflicting_program_roles",
            "required_roles",
            "approved_roles",
            "program_approval",
        ],
        "properties": {
            "name": {"type": "string", "maxLength": 4_096},
            "purpose": {"type": "string", "maxLength": 16_384},
            "repositories": count,
            "repository_ids": string_array,
            "bound_repositories": count,
            "relationships": count,
            "requirements": count,
            "external_evidence": count,
            "verified_evidence": count,
            "trusted_evidence": count,
            "duplicate_evidence": count,
            "evidence_bytes": count,
            "evidence_statuses": {
                "type": "object",
                "maxProperties": 100,
                "propertyNames": {"minLength": 1, "maxLength": 500},
                "additionalProperties": count,
            },
            "approvals": count,
            "validated_approvals": count,
            "credited_program_approvals": count,
            "conflicting_program_roles": role_array,
            "required_roles": role_array,
            "approved_roles": role_array,
            "program_approval": {"type": "boolean"},
        },
        "additionalProperties": False,
        "allOf": [
            {
                "if": {"properties": {"program_approval": {"const": True}}},
                "then": {"properties": {"credited_program_approvals": {"minimum": 1}}},
                "else": {"properties": {"credited_program_approvals": {"const": 0}}},
            }
        ],
    }
    relationship = {
        "type": "object",
        "required": [
            "id",
            "kind",
            "source",
            "source_repository",
            "target",
            "target_repository",
            "endpoints_valid",
            "temporal_status",
            "resilience_status",
            "deadline_ms",
            "observed_max_ms",
            "recovery_deadline_ms",
            "observed_recovery_ms",
            "evidence_ids",
        ],
        "properties": {
            "id": nonempty,
            "kind": {"type": "string", "maxLength": 500},
            "source": {"type": "string", "maxLength": 4_096},
            "source_repository": {"type": "string", "maxLength": 2_000},
            "target": {"type": "string", "maxLength": 4_096},
            "target_repository": {"type": "string", "maxLength": 2_000},
            "endpoints_valid": {"type": "boolean"},
            "temporal_status": {
                "enum": ["not_configured", "unverified", "supported", "violated"]
            },
            "resilience_status": {
                "enum": ["not_configured", "unverified", "supported", "violated"]
            },
            "deadline_ms": {"type": ["number", "null"], "minimum": 0},
            "observed_max_ms": {"type": ["number", "null"], "minimum": 0},
            "recovery_deadline_ms": {
                "type": ["number", "null"],
                "minimum": 0,
            },
            "observed_recovery_ms": {
                "type": ["number", "null"],
                "minimum": 0,
            },
            "evidence_ids": string_array,
        },
        "additionalProperties": False,
        "allOf": [
            {
                "if": {"properties": {"temporal_status": {"const": "not_configured"}}},
                "then": {"properties": {"deadline_ms": {"type": "null"}}},
                "else": {"properties": {"deadline_ms": {"type": "number"}}},
            },
            {
                "if": {
                    "properties": {
                        "temporal_status": {"enum": ["supported", "violated"]}
                    }
                },
                "then": {
                    "properties": {
                        "observed_max_ms": {"type": "number", "minimum": 0},
                        "evidence_ids": {"minItems": 1},
                    }
                },
            },
            {
                "if": {
                    "properties": {"resilience_status": {"const": "not_configured"}}
                },
                "then": {
                    "properties": {
                        "recovery_deadline_ms": {"type": "null"},
                        "observed_recovery_ms": {"type": "null"},
                    }
                },
                "else": {"properties": {"recovery_deadline_ms": {"type": "number"}}},
            },
            {
                "if": {
                    "properties": {
                        "resilience_status": {"enum": ["supported", "violated"]}
                    }
                },
                "then": {"properties": {"evidence_ids": {"minItems": 1}}},
            },
            {
                "if": {"properties": {"resilience_status": {"const": "supported"}}},
                "then": {
                    "properties": {
                        "observed_recovery_ms": {"type": "number", "minimum": 0}
                    }
                },
            },
        ],
    }
    validation_count_names = (
        "cohorts",
        "credited_cohorts",
        "duplicate_evidence",
        "repositories",
        "independently_reviewed",
        "cases",
        "count_backed_cohorts",
        "count_backed_cases",
        "evaluation_artifacts",
        "verified_evaluation_artifacts",
        "evaluation_artifact_bytes",
        "call_cases",
        "call_resolution_cohorts",
        "call_count_backed_cohorts",
        "call_count_backed_cases",
        "semantic_cases",
        "semantic_output_cohorts",
        "semantic_count_backed_cohorts",
        "semantic_count_backed_cases",
    )
    validation_ratio_names = (
        "macro_recall",
        "macro_precision",
        "micro_recall",
        "micro_precision",
        "macro_call_resolution_recall",
        "macro_call_resolution_precision",
        "micro_call_resolution_recall",
        "micro_call_resolution_precision",
        "macro_semantic_output_recall",
        "macro_semantic_output_precision",
        "micro_semantic_output_recall",
        "micro_semantic_output_precision",
    )
    validation = {
        "type": "object",
        "required": [*validation_count_names, *validation_ratio_names],
        "properties": {
            **{name: count for name in validation_count_names},
            **{name: ratio for name in validation_ratio_names},
        },
        "additionalProperties": False,
        "allOf": [
            {
                "if": {"properties": {"credited_cohorts": {"const": 0}}},
                "then": {
                    "properties": {
                        "macro_recall": {"type": "null"},
                        "macro_precision": {"type": "null"},
                    }
                },
                "else": {
                    "properties": {
                        "macro_recall": {"type": "number"},
                        "macro_precision": {"type": "number"},
                    }
                },
            },
            {
                "if": {"properties": {"count_backed_cohorts": {"const": 0}}},
                "then": {
                    "properties": {
                        "micro_recall": {"type": "null"},
                        "micro_precision": {"type": "null"},
                    }
                },
                "else": {
                    "properties": {
                        "micro_recall": {"type": "number"},
                        "micro_precision": {"type": "number"},
                    }
                },
            },
            {
                "if": {"properties": {"call_resolution_cohorts": {"const": 0}}},
                "then": {
                    "properties": {
                        "macro_call_resolution_recall": {"type": "null"},
                        "macro_call_resolution_precision": {"type": "null"},
                    }
                },
                "else": {
                    "properties": {
                        "macro_call_resolution_recall": {"type": "number"},
                        "macro_call_resolution_precision": {"type": "number"},
                    }
                },
            },
            {
                "if": {"properties": {"call_count_backed_cohorts": {"const": 0}}},
                "then": {
                    "properties": {
                        "micro_call_resolution_recall": {"type": "null"},
                        "micro_call_resolution_precision": {"type": "null"},
                    }
                },
                "else": {
                    "properties": {
                        "micro_call_resolution_recall": {"type": "number"},
                        "micro_call_resolution_precision": {"type": "number"},
                    }
                },
            },
            {
                "if": {"properties": {"semantic_output_cohorts": {"const": 0}}},
                "then": {
                    "properties": {
                        "macro_semantic_output_recall": {"type": "null"},
                        "macro_semantic_output_precision": {"type": "null"},
                    }
                },
                "else": {
                    "properties": {
                        "macro_semantic_output_recall": {"type": "number"},
                        "macro_semantic_output_precision": {"type": "number"},
                    }
                },
            },
            {
                "if": {"properties": {"semantic_count_backed_cohorts": {"const": 0}}},
                "then": {
                    "properties": {
                        "micro_semantic_output_recall": {"type": "null"},
                        "micro_semantic_output_precision": {"type": "null"},
                    }
                },
                "else": {
                    "properties": {
                        "micro_semantic_output_recall": {"type": "number"},
                        "micro_semantic_output_precision": {"type": "number"},
                    }
                },
            },
        ],
    }
    llm_count_names = (
        "evaluations",
        "credited_evaluations",
        "duplicate_evidence",
        "samples",
        "independently_reviewed",
        "count_backed_evaluations",
        "verified_corpus_artifacts",
        "subject_bound_evaluations",
        "semantic_fingerprinted_evaluations",
        "corpus_artifacts",
        "corpus_artifact_bytes",
    )
    llm_quality = {
        "type": "object",
        "required": [
            *llm_count_names,
            "claim_count",
            "unsupported_claim_count",
            "aggregation_method",
            "grounding",
            "citation_accuracy",
            "unsupported_claim_rate",
        ],
        "properties": {
            **{name: count for name in llm_count_names},
            "claim_count": {"type": ["integer", "null"], "minimum": 0},
            "unsupported_claim_count": {
                "type": ["integer", "null"],
                "minimum": 0,
            },
            "aggregation_method": {
                "enum": [
                    "count-backed",
                    "legacy-sample-weighted",
                    "unavailable",
                ]
            },
            "grounding": ratio,
            "citation_accuracy": ratio,
            "unsupported_claim_rate": ratio,
        },
        "additionalProperties": False,
        "allOf": [
            {
                "if": {"properties": {"aggregation_method": {"const": "unavailable"}}},
                "then": {
                    "properties": {
                        "credited_evaluations": {"const": 0},
                        "count_backed_evaluations": {"const": 0},
                        "samples": {"const": 0},
                        "claim_count": {"type": "null"},
                        "unsupported_claim_count": {"type": "null"},
                        "grounding": {"type": "null"},
                        "citation_accuracy": {"type": "null"},
                        "unsupported_claim_rate": {"type": "null"},
                    }
                },
            },
            {
                "if": {"properties": {"aggregation_method": {"const": "count-backed"}}},
                "then": {
                    "properties": {
                        "credited_evaluations": {"minimum": 1},
                        "claim_count": {"type": "integer", "minimum": 1},
                        "unsupported_claim_count": {
                            "type": "integer",
                            "minimum": 0,
                        },
                        "grounding": {"type": "number"},
                        "citation_accuracy": {"type": "number"},
                        "unsupported_claim_rate": {"type": "number"},
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "aggregation_method": {"const": "legacy-sample-weighted"}
                    }
                },
                "then": {
                    "properties": {
                        "credited_evaluations": {"minimum": 1},
                        "claim_count": {"type": "null"},
                        "unsupported_claim_count": {"type": "null"},
                        "grounding": {"type": "number"},
                        "citation_accuracy": {"type": "number"},
                        "unsupported_claim_rate": {"type": "number"},
                    }
                },
            },
        ],
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("assurance-program-verification"),
        "title": "PySFMEA system assurance program verification",
        "type": "object",
        "required": [
            "format",
            "verifier",
            "program",
            "valid",
            "checks",
            "counts",
            "summary",
            "relationships",
            "validation",
            "llm_quality",
            "findings",
            "notice",
        ],
        "properties": {
            "format": {"const": "pysfmea-assurance-program-verification-1"},
            "verifier": {
                "type": "object",
                "required": ["name", "version"],
                "properties": {
                    "name": {"const": "PySFMEA"},
                    "version": {"type": "string", "minLength": 1},
                },
                "additionalProperties": False,
            },
            "program": {
                "type": "object",
                "required": ["path", "content_sha256"],
                "properties": {"path": {"type": "string"}, "content_sha256": digest},
                "additionalProperties": False,
            },
            "valid": {"type": "boolean"},
            "checks": checks,
            "counts": {
                "type": "object",
                "required": ["errors", "warnings", "information"],
                "properties": {
                    "errors": {"type": "integer", "minimum": 0},
                    "warnings": {"type": "integer", "minimum": 0},
                    "information": {"type": "integer", "minimum": 0},
                },
                "additionalProperties": False,
            },
            "summary": {"oneOf": [{"type": "object", "maxProperties": 0}, summary]},
            "relationships": {
                "type": "array",
                "maxItems": 10_000,
                "items": relationship,
            },
            "validation": {
                "oneOf": [{"type": "object", "maxProperties": 0}, validation]
            },
            "llm_quality": {
                "oneOf": [{"type": "object", "maxProperties": 0}, llm_quality]
            },
            "findings": {
                "type": "array",
                "maxItems": 200_000,
                "items": {
                    "type": "object",
                    "required": ["code", "level", "message", "location"],
                    "properties": {
                        "code": {
                            "type": "string",
                            "pattern": "^(program|repository|relationship|requirements|evidence|validation|llm|governance)\\.[a-z0-9_]+$",
                        },
                        "level": {"enum": ["error", "warning", "information"]},
                        "message": {"type": "string", "minLength": 1},
                        "location": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
            },
            "notice": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }


def _fault_injection_plan_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    nonempty = {"type": "string", "minLength": 1, "maxLength": 4_096}
    plugin_ids = [
        "builtin.raise-exception.v1",
        "builtin.return-value.v1",
        "builtin.sequence.v1",
    ]
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("fault-injection-plan"),
        "title": "PySFMEA governed fault-injection plan",
        "description": (
            "Closed structural contract for an obligation-bound built-in fault-injection "
            "plan. Integrity, readiness, plugin-specific case semantics, and exact "
            "obligation binding require the PySFMEA semantic verifier."
        ),
        "type": "object",
        "required": [
            "format",
            "id",
            "status",
            "generated_at",
            "generator",
            "binding",
            "plugin",
            "case",
            "execution",
            "notice",
            "integrity",
        ],
        "properties": {
            "format": {"const": FAULT_INJECTION_PLAN_FORMAT},
            "id": nonempty,
            "status": {"enum": ["binding_required", "ready"]},
            "generated_at": nonempty,
            "completed_at": nonempty,
            "generator": {
                "type": "object",
                "required": ["name", "version"],
                "properties": {"name": {"const": "PySFMEA"}, "version": nonempty},
                "additionalProperties": False,
            },
            "binding": {
                "type": "object",
                "required": [
                    "obligation_id",
                    "finding_id",
                    "baseline_id",
                    "contract_sha256",
                ],
                "properties": {
                    "obligation_id": nonempty,
                    "finding_id": nonempty,
                    "baseline_id": nonempty,
                    "contract_sha256": digest,
                },
                "additionalProperties": False,
            },
            "plugin": {
                "type": "object",
                "required": ["id", "recommended_plugin_ids"],
                "properties": {
                    "id": {"enum": plugin_ids},
                    "recommended_plugin_ids": {
                        "type": "array",
                        "maxItems": 3,
                        "uniqueItems": True,
                        "items": {"enum": plugin_ids},
                    },
                },
                "additionalProperties": False,
            },
            "case": {
                "type": "object",
                "required": [
                    "subject",
                    "patch_target",
                    "args",
                    "kwargs",
                    "fault",
                    "expected",
                ],
                "properties": {
                    "subject": {"type": "string", "maxLength": 1_000},
                    "patch_target": {"type": "string", "maxLength": 1_000},
                    "args": {"type": "array", "maxItems": 10_000},
                    "kwargs": {"type": "object", "maxProperties": 10_000},
                    "fault": {"type": "object", "maxProperties": 100},
                    "expected": {
                        "type": "object",
                        "required": ["outcomes"],
                        "properties": {
                            "outcomes": {
                                "type": "array",
                                "minItems": 1,
                                "maxItems": 32,
                                "items": {
                                    "type": "object",
                                    "required": ["outcome"],
                                    "properties": {
                                        "outcome": {"enum": ["returns", "raises"]},
                                        "value": {},
                                        "exception_type": {
                                            "enum": [
                                                "ConnectionError",
                                                "OSError",
                                                "RuntimeError",
                                                "TimeoutError",
                                                "ValueError",
                                            ]
                                        },
                                        "min_duration_ms": {
                                            "type": "number",
                                            "minimum": 0,
                                        },
                                        "max_duration_ms": {
                                            "type": "number",
                                            "minimum": 0,
                                        },
                                    },
                                    "additionalProperties": False,
                                },
                            }
                        },
                        "additionalProperties": False,
                    },
                },
                "additionalProperties": False,
            },
            "execution": {
                "type": "object",
                "required": ["policy", "network", "scanner_execution"],
                "properties": {
                    "policy": {"const": "approved_sandbox_required"},
                    "network": {"const": "deny_by_default"},
                    "scanner_execution": {"const": False},
                },
                "additionalProperties": False,
            },
            "notice": nonempty,
            "integrity": {
                "type": "object",
                "required": ["algorithm", "content_sha256"],
                "properties": {
                    "algorithm": {"const": "sha256"},
                    "content_sha256": digest,
                },
                "additionalProperties": False,
            },
        },
        "additionalProperties": False,
        "allOf": [
            {
                "if": {"properties": {"status": {"const": "ready"}}},
                "then": {"required": ["completed_at"]},
                "else": {"not": {"required": ["completed_at"]}},
            }
        ],
    }


def _fault_injection_plan_verification_schema() -> dict[str, Any]:
    check = {"type": ["boolean", "null"]}
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("fault-injection-plan-verification"),
        "title": "PySFMEA fault-injection plan verification verdict",
        "description": "Closed success and rejection verdict for a governed fault-injection plan.",
        "type": "object",
        "required": [
            "format",
            "valid",
            "status",
            "checks",
            "findings",
            "plugin_id",
            "verified_at",
            "verifier",
        ],
        "properties": {
            "format": {"const": FAULT_INJECTION_PLAN_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "status": {"enum": ["ready", "binding_required", "invalid"]},
            "checks": {
                "type": "object",
                "required": [
                    "format",
                    "contract",
                    "content_integrity",
                    "plugin",
                    "case",
                    "execution_policy",
                    "binding",
                    "ready",
                ],
                "properties": {
                    name: check
                    for name in (
                        "format",
                        "contract",
                        "content_integrity",
                        "plugin",
                        "case",
                        "execution_policy",
                        "binding",
                        "ready",
                    )
                },
                "additionalProperties": False,
            },
            "findings": {
                "type": "array",
                "maxItems": 100,
                "items": {
                    "type": "object",
                    "required": ["code", "message"],
                    "properties": {
                        "code": {"type": "string", "minLength": 1, "maxLength": 200},
                        "message": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 4_096,
                        },
                    },
                    "additionalProperties": False,
                },
            },
            "plugin_id": {"type": "string", "maxLength": 200},
            "verified_at": {"type": "string", "minLength": 1},
            "verifier": {
                "type": "object",
                "required": ["name", "version"],
                "properties": {
                    "name": {"const": "PySFMEA"},
                    "version": {"type": "string", "minLength": 1},
                },
                "additionalProperties": False,
            },
        },
        "additionalProperties": False,
    }


def _enhancement_workbench_schema() -> dict[str, Any]:
    bounded_object: dict[str, Any] = {
        "type": "object",
        "maxProperties": 10_000,
        "additionalProperties": True,
    }
    capability = {
        "type": "object",
        "required": [
            "id",
            "domain",
            "title",
            "authority",
            "product_resolution",
            "projection",
            "status",
            "adapter_context",
        ],
        "properties": {
            "id": {"type": "string", "pattern": "^P[0-3]-[0-9]{2}$"},
            "domain": _text_schema(required=True),
            "title": _text_schema(required=True),
            "authority": {"enum": ["product", "project_evidence", "human_authority"]},
            "product_resolution": _text_schema(required=True),
            "projection": _text_schema(required=True),
            "status": {
                "enum": [
                    "available_product_capability",
                    "awaiting_project_evidence",
                    "awaiting_human_authority",
                ]
            },
            "adapter_context": {"type": ["object", "null"]},
        },
        "additionalProperties": False,
    }
    hardening = {
        "type": "object",
        "required": [
            "id",
            "priority",
            "domain",
            "title",
            "authority",
            "product_resolution",
            "acceptance_criterion",
            "projection",
            "resolution_state",
        ],
        "properties": {
            "id": {"type": "string", "pattern": "^H[0-9]{2}$"},
            "priority": {"enum": ["P0", "P1", "P2", "P3"]},
            "domain": _text_schema(required=True),
            "title": _text_schema(required=True),
            "authority": {"enum": ["product", "project_evidence", "human_authority"]},
            "product_resolution": _text_schema(required=True),
            "acceptance_criterion": _text_schema(required=True),
            "projection": _text_schema(required=True),
            "resolution_state": {
                "enum": [
                    "resolved_product_capability",
                    "project_evidence_required",
                    "project_evidence_available_for_review",
                    "human_decision_required",
                ]
            },
        },
        "additionalProperties": False,
    }

    post_hardening = {
        "type": "object",
        "required": [
            "id",
            "priority",
            "title",
            "authority",
            "projection",
            "product_resolution",
            "acceptance_criterion",
            "resolution_state",
        ],
        "properties": {
            "id": {"type": "string", "pattern": "^N[0-9]{2}$"},
            "priority": {"enum": ["P0", "P1", "P2", "P3"]},
            "title": _text_schema(required=True),
            "authority": {"enum": ["product", "project_evidence", "human_authority"]},
            "projection": _text_schema(required=True),
            "product_resolution": _text_schema(required=True),
            "acceptance_criterion": _text_schema(required=True),
            "resolution_state": {
                "enum": [
                    "resolved_product_projection",
                    "project_evidence_required",
                    "human_decision_required",
                ]
            },
        },
        "additionalProperties": False,
    }
    next_generation: dict[str, Any] = {
        "type": "object",
        "required": [
            "id",
            "priority",
            "title",
            "authority",
            "projection",
            "product_resolution",
            "acceptance_criterion",
            "resolution_state",
        ],
        "properties": {
            "id": {"type": "string", "pattern": "^R[0-9]{3}$"},
            "priority": {"enum": ["P0", "P1", "P2"]},
            "title": _text_schema(required=True),
            "authority": {"enum": ["product", "project_evidence", "human_authority"]},
            "projection": _text_schema(required=True),
            "product_resolution": _text_schema(required=True),
            "acceptance_criterion": _text_schema(required=True),
            "resolution_state": {
                "enum": [
                    "resolved_product_capability",
                    "project_evidence_required",
                    "human_decision_required",
                ]
            },
        },
        "additionalProperties": False,
    }
    product_outcome: dict[str, Any] = {
        **next_generation,
        "required": [
            *next_generation["required"],
            "product_maturity",
            "maturity_basis",
            "implementation_evidence",
            "test_evidence",
            "representative_validation_evidence",
            "related_evidence",
            "known_limitations",
            "next_action",
        ],
        "properties": {
            **next_generation["properties"],
            "id": {"type": "string", "pattern": "^E[0-9]{3}$"},
            "product_maturity": {
                "enum": ["planned", "partial", "implemented", "validated"]
            },
            "maturity_basis": _text_schema(required=True),
            "implementation_evidence": {
                "type": "array",
                "maxItems": 20,
                "uniqueItems": True,
                "items": _text_schema(required=True),
            },
            "test_evidence": {
                "type": "array",
                "maxItems": 20,
                "uniqueItems": True,
                "items": _text_schema(required=True),
            },
            "representative_validation_evidence": {
                "type": "array",
                "maxItems": 20,
                "uniqueItems": True,
                "items": _text_schema(required=True),
            },
            "related_evidence": {
                "type": "array",
                "minItems": 1,
                "maxItems": 40,
                "uniqueItems": True,
                "items": _text_schema(required=True),
            },
            "known_limitations": {
                "type": "array",
                "minItems": 1,
                "maxItems": 20,
                "items": _text_schema(required=True),
            },
            "next_action": _text_schema(required=True),
            "resolution_state": {
                "enum": [
                    "planned_product_capability",
                    "partial_product_capability",
                    "implemented_product_capability",
                    "validated_product_capability",
                    "project_evidence_required",
                    "human_decision_required",
                ]
            },
        },
        "allOf": [
            {
                "if": {
                    "properties": {"product_maturity": {"const": "planned"}},
                    "required": ["product_maturity"],
                },
                "then": {
                    "properties": {
                        "implementation_evidence": {"maxItems": 0},
                        "test_evidence": {"maxItems": 0},
                        "representative_validation_evidence": {"maxItems": 0},
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "product_maturity": {"enum": ["partial", "implemented"]}
                    },
                    "required": ["product_maturity"],
                },
                "then": {
                    "properties": {
                        "implementation_evidence": {"minItems": 1},
                        "test_evidence": {"minItems": 1},
                        "representative_validation_evidence": {"maxItems": 0},
                    }
                },
            },
            {
                "if": {
                    "properties": {"product_maturity": {"const": "validated"}},
                    "required": ["product_maturity"],
                },
                "then": {
                    "properties": {
                        "implementation_evidence": {"minItems": 1},
                        "test_evidence": {"minItems": 1},
                        "representative_validation_evidence": {"minItems": 1},
                    }
                },
            },
            {
                "if": {
                    "properties": {"authority": {"const": "project_evidence"}},
                    "required": ["authority"],
                },
                "then": {
                    "properties": {
                        "resolution_state": {"const": "project_evidence_required"}
                    }
                },
            },
            {
                "if": {
                    "properties": {"authority": {"const": "human_authority"}},
                    "required": ["authority"],
                },
                "then": {
                    "properties": {
                        "resolution_state": {"const": "human_decision_required"}
                    }
                },
            },
            *[
                {
                    "if": {
                        "properties": {
                            "authority": {"const": "product"},
                            "product_maturity": {"const": maturity},
                        },
                        "required": ["authority", "product_maturity"],
                    },
                    "then": {
                        "properties": {
                            "resolution_state": {
                                "const": f"{maturity}_product_capability"
                            }
                        }
                    },
                }
                for maturity in ("planned", "partial", "implemented", "validated")
            ],
        ],
    }
    required = [
        "format",
        "analysis_binding",
        "summary",
        "capability_register",
        "hardening_register",
        "post_hardening_register",
        "next_generation_register",
        "product_outcome_register",
        "capability_attestations",
        "resolution_attestations",
        "product_outcome_attestations",
        "artifact_freshness",
        "artifact_health",
        "scope_patch",
        "scope_preview",
        "evidence_preflight",
        "calibration_campaign",
        "review_campaign",
        "finding_consolidation_program",
        "evidence_onboarding",
        "precision_program",
        "architecture_program",
        "interface_program",
        "temporal_resilience_program",
        "guidance_specificity_program",
        "performance_ratchet",
        "report_delivery_program",
        "llm_governance_program",
        "qualification_program",
        "analysis_fidelity_program",
        "sequence_sfta_program",
        "assurance_automation_program",
        "architecture_interface_program",
        "product_outcome_scorecard",
        "activation_progress",
        "metric_provenance",
        "report_scale",
        "precision_risks",
        "acceptance_targets",
        "evidence_acquisition",
        "review_clusters",
        "review_clusters_omitted",
        "evidence_portfolio",
        "architecture_mapping_queue",
        "interface_disposition_queue",
        "surface_models",
        "evidence_quality",
        "sfta_queue",
        "guidance_queue",
        "change_review",
        "review_analytics",
        "performance_plan",
        "qualification_plan",
        "budgets",
        "guardrails",
        "content_sha256",
    ]
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("enhancement-workbench"),
        "title": "PySFMEA enhancement and evidence activation workbench",
        "description": (
            "Bounded product capability, project evidence, and human-authority "
            "activation plan. Semantic reconciliation and digest verification require "
            "PySFMEA."
        ),
        "type": "object",
        "required": required,
        "properties": {
            "format": {"const": ENHANCEMENT_WORKBENCH_FORMAT},
            "analysis_binding": bounded_object,
            "summary": bounded_object,
            "capability_register": {
                "type": "array",
                "minItems": 1,
                "maxItems": 100,
                "items": capability,
            },
            "hardening_register": {
                "type": "array",
                "minItems": 76,
                "maxItems": 100,
                "items": hardening,
            },
            "post_hardening_register": {
                "type": "array",
                "minItems": 82,
                "maxItems": 100,
                "items": post_hardening,
            },
            "next_generation_register": {
                "type": "array",
                "minItems": 102,
                "maxItems": 150,
                "items": next_generation,
            },
            "product_outcome_register": {
                "type": "array",
                "minItems": 95,
                "maxItems": 95,
                "items": product_outcome,
            },
            "capability_attestations": bounded_object,
            "resolution_attestations": bounded_object,
            "product_outcome_attestations": bounded_object,
            "artifact_freshness": bounded_object,
            "artifact_health": bounded_object,
            "scope_patch": bounded_object,
            "scope_preview": bounded_object,
            "evidence_preflight": bounded_object,
            "calibration_campaign": bounded_object,
            "review_campaign": bounded_object,
            "finding_consolidation_program": bounded_object,
            "evidence_onboarding": bounded_object,
            "precision_program": bounded_object,
            "architecture_program": bounded_object,
            "interface_program": bounded_object,
            "temporal_resilience_program": bounded_object,
            "guidance_specificity_program": bounded_object,
            "performance_ratchet": bounded_object,
            "report_delivery_program": bounded_object,
            "llm_governance_program": bounded_object,
            "qualification_program": bounded_object,
            "analysis_fidelity_program": bounded_object,
            "sequence_sfta_program": bounded_object,
            "assurance_automation_program": bounded_object,
            "architecture_interface_program": bounded_object,
            "product_outcome_scorecard": bounded_object,
            "activation_progress": bounded_object,
            "metric_provenance": bounded_object,
            "report_scale": bounded_object,
            "precision_risks": bounded_object,
            "acceptance_targets": bounded_object,
            "evidence_acquisition": bounded_object,
            "review_clusters": {
                "type": "array",
                "maxItems": 1_000,
                "items": bounded_object,
            },
            "review_clusters_omitted": {"type": "integer", "minimum": 0},
            "evidence_portfolio": {
                "type": "array",
                "maxItems": 500,
                "items": bounded_object,
            },
            "architecture_mapping_queue": bounded_object,
            "interface_disposition_queue": bounded_object,
            "surface_models": bounded_object,
            "evidence_quality": bounded_object,
            "sfta_queue": bounded_object,
            "guidance_queue": bounded_object,
            "change_review": bounded_object,
            "review_analytics": bounded_object,
            "performance_plan": bounded_object,
            "qualification_plan": bounded_object,
            "budgets": bounded_object,
            "guardrails": {
                "type": "array",
                "maxItems": 100,
                "items": _text_schema(required=True),
            },
            "content_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
        "additionalProperties": False,
    }


def _enhancement_workbench_verification_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("enhancement-workbench-verification"),
        "title": "PySFMEA enhancement-workbench verification verdict",
        "type": "object",
        "required": [
            "format",
            "valid",
            "status",
            "source",
            "source_bytes",
            "source_sha256",
            "analysis_checked",
            "checks",
            "findings",
        ],
        "properties": {
            "format": {"const": ENHANCEMENT_WORKBENCH_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "status": {"enum": ["invalid", "internally_valid", "matched"]},
            "source": {"type": "string", "minLength": 1},
            "source_bytes": {"type": "integer", "minimum": 0},
            "source_sha256": {
                "type": "string",
                "pattern": "^$|^[0-9a-f]{64}$",
            },
            "analysis_checked": {"type": "boolean"},
            "checks": {
                "type": "object",
                "maxProperties": 20,
                "additionalProperties": {"type": "boolean"},
            },
            "findings": {
                "type": "array",
                "maxItems": 100,
                "items": {
                    "type": "object",
                    "required": ["code", "message"],
                    "properties": {
                        "code": {"type": "string", "minLength": 1},
                        "message": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
            },
        },
        "additionalProperties": False,
    }


def _enhancement_scope_preview_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("enhancement-scope-preview"),
        "title": "PySFMEA evidence-only scope metadata preview",
        "type": "object",
        "required": [
            "format",
            "analysis_binding",
            "repository",
            "proposed_changes",
            "summary",
            "files",
            "authority",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": "pysfmea-enhancement-scope-preview-1"},
            "analysis_binding": {"type": "object", "additionalProperties": True},
            "repository": {"type": "string", "minLength": 1},
            "proposed_changes": {"type": "object", "additionalProperties": True},
            "summary": {"type": "object", "additionalProperties": True},
            "files": {
                "type": "array",
                "maxItems": 10_000,
                "items": {
                    "type": "object",
                    "required": ["path", "size", "matches", "classification"],
                    "properties": {
                        "path": {"type": "string", "minLength": 1},
                        "size": {"type": "integer", "minimum": 0},
                        "matches": {"type": "array", "maxItems": 100},
                        "classification": {
                            "enum": [
                                "test_evidence_candidate",
                                "web_boundary_candidate",
                            ]
                        },
                    },
                    "additionalProperties": False,
                },
            },
            "authority": {"type": "string", "minLength": 1},
            "content_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
        "additionalProperties": False,
    }


def _evidence_preflight_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("evidence-preflight"),
        "title": "PySFMEA read-only evidence readiness preflight",
        "type": "object",
        "required": [
            "format",
            "analysis_binding",
            "repository",
            "summary",
            "discovery",
            "ordered_actions",
            "authority",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": "pysfmea-evidence-preflight-1"},
            "analysis_binding": {"type": "object", "additionalProperties": True},
            "repository": {"type": "string", "minLength": 1},
            "summary": {"type": "object", "additionalProperties": True},
            "discovery": {"type": "object", "additionalProperties": True},
            "ordered_actions": {
                "type": "array",
                "maxItems": 20,
                "items": {"type": "object", "additionalProperties": True},
            },
            "authority": {"type": "string", "minLength": 1},
            "content_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
        "additionalProperties": False,
    }


def _evidence_onboarding_receipt_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    binding = {
        "type": "object",
        "required": ["baseline_id", "analysis_state_sha256"],
        "properties": {
            "baseline_id": {"type": "string", "minLength": 1},
            "analysis_state_sha256": digest,
            "run_manifest_sha256": digest,
            "assurance_work_queue_sha256": digest,
        },
        "additionalProperties": False,
    }
    result_binding = copy.deepcopy(binding)
    result_binding["required"] = [
        "baseline_id",
        "analysis_state_sha256",
        "run_manifest_sha256",
        "assurance_work_queue_sha256",
    ]
    selected = {
        "type": "object",
        "required": [
            "kind",
            "subject_id",
            "label",
            "path",
            "bytes",
            "sha256",
            "status",
            "record_id",
            "result",
        ],
        "properties": {
            "kind": {"enum": ["coverage", "runtime_trace", "execution_manifest"]},
            "subject_id": {"type": "string"},
            "label": {"type": "string", "maxLength": 500},
            "path": {"type": "string", "minLength": 1},
            "bytes": {"type": "integer", "minimum": 0},
            "sha256": digest,
            "status": {"enum": ["validated", "imported", "duplicate"]},
            "record_id": {"type": "string", "minLength": 1},
            "result": {"type": "object", "additionalProperties": True},
        },
        "additionalProperties": False,
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("evidence-onboarding-receipt"),
        "title": "PySFMEA evidence-onboarding receipt",
        "type": "object",
        "required": [
            "format",
            "id",
            "mode",
            "created_at",
            "generator",
            "repository",
            "source_binding",
            "result_binding",
            "preflight",
            "selection_sha256",
            "selected_evidence",
            "summary",
            "queue_verification",
            "authority",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": "pysfmea-evidence-onboarding-receipt-1"},
            "id": {"type": "string", "pattern": "^ONBOARD-[A-F0-9]+$"},
            "mode": {"enum": ["validated_plan", "applied"]},
            "created_at": {"type": "string", "minLength": 1},
            "generator": {"type": "object", "additionalProperties": True},
            "repository": {"type": "string", "minLength": 1},
            "source_binding": binding,
            "result_binding": result_binding,
            "preflight": {"type": "object", "additionalProperties": True},
            "selection_sha256": digest,
            "selected_evidence": {
                "type": "array",
                "maxItems": 100,
                "items": selected,
            },
            "summary": {"type": "object", "additionalProperties": True},
            "queue_verification": {"type": "object", "additionalProperties": True},
            "authority": {"type": "string", "minLength": 1},
            "content_sha256": digest,
        },
        "additionalProperties": False,
    }


def _evidence_onboarding_receipt_verification_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("evidence-onboarding-receipt-verification"),
        "title": "PySFMEA evidence-onboarding receipt verification",
        "type": "object",
        "required": [
            "format",
            "path",
            "valid",
            "status",
            "checks",
            "failed_checks",
            "unchecked_checks",
            "receipt_id",
            "content_sha256",
            "notice",
        ],
        "properties": {
            "format": {"const": "pysfmea-evidence-onboarding-receipt-verification-1"},
            "path": {"type": "string", "minLength": 1},
            "valid": {"type": "boolean"},
            "status": {"enum": ["matched", "valid_binding_not_checked", "invalid"]},
            "checks": {"type": "object", "additionalProperties": True},
            "failed_checks": {
                "type": "array",
                "items": {"type": "string", "minLength": 1},
            },
            "unchecked_checks": {
                "type": "array",
                "items": {"type": "string", "minLength": 1},
            },
            "receipt_id": {"type": "string", "minLength": 1},
            "content_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "notice": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }


def _activation_workspace_schema() -> dict[str, Any]:
    decision = {
        "type": "object",
        "required": [
            "id",
            "kind",
            "subject_id",
            "decision",
            "reviewer",
            "rationale",
            "recorded_at",
        ],
        "properties": {
            "id": {"type": "string", "minLength": 1},
            "kind": {
                "enum": [
                    "finding",
                    "consolidation",
                    "guidance",
                    "sfta",
                    "architecture",
                    "interface",
                ]
            },
            "subject_id": {"type": "string", "minLength": 1},
            "decision": {"type": "string", "minLength": 1},
            "reviewer": {"type": "string", "minLength": 1},
            "rationale": {"type": "string", "minLength": 1},
            "recorded_at": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("activation-workspace"),
        "title": "PySFMEA governed activation workspace",
        "type": "object",
        "required": [
            "format",
            "created_at",
            "analysis_binding",
            "repository",
            "summary",
            "evidence_onboarding",
            "queues",
            "decisions",
            "assignments",
            "workflow",
            "guardrails",
            "authority",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": "pysfmea-activation-workspace-1"},
            "created_at": {"type": "string", "minLength": 1},
            "analysis_binding": {
                "type": "object",
                "required": [
                    "baseline_id",
                    "repository_sha256",
                    "analysis_state_sha256",
                ],
                "properties": {
                    "baseline_id": {"type": "string"},
                    "repository_sha256": {"type": "string"},
                    "analysis_state_sha256": {
                        "type": "string",
                        "pattern": "^[0-9a-f]{64}$",
                    },
                },
                "additionalProperties": False,
            },
            "repository": {"type": "string", "minLength": 1},
            "summary": {"type": "object", "additionalProperties": True},
            "evidence_onboarding": {"type": "object", "additionalProperties": True},
            "queues": {"type": "object", "additionalProperties": True},
            "decisions": {"type": "array", "maxItems": 50_000, "items": decision},
            "assignments": {
                "type": "array",
                "maxItems": 50_000,
                "items": {
                    "type": "object",
                    "required": [
                        "id",
                        "kind",
                        "subject_id",
                        "assignee",
                        "due_date",
                        "assigned_at",
                    ],
                    "properties": {
                        "id": {"type": "string", "minLength": 1},
                        "kind": {
                            "enum": [
                                "finding",
                                "consolidation",
                                "guidance",
                                "sfta",
                                "architecture",
                                "interface",
                            ]
                        },
                        "subject_id": {"type": "string", "minLength": 1},
                        "assignee": {"type": "string", "minLength": 1},
                        "due_date": {
                            "type": "string",
                            "pattern": "^$|^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
                        },
                        "assigned_at": {"type": "string", "minLength": 1},
                    },
                    "additionalProperties": False,
                },
            },
            "workflow": {"type": "array", "maxItems": 20},
            "guardrails": {
                "type": "array",
                "maxItems": 50,
                "items": {"type": "string"},
            },
            "authority": {"type": "string", "minLength": 1},
            "content_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
        "additionalProperties": False,
    }


def _activation_workspace_verification_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("activation-workspace-verification"),
        "title": "PySFMEA activation workspace verification",
        "type": "object",
        "required": [
            "format",
            "valid",
            "status",
            "analysis_checked",
            "checks",
            "decision_count",
            "assignment_count",
            "findings",
            "notice",
        ],
        "properties": {
            "format": {"const": "pysfmea-activation-workspace-verification-1"},
            "valid": {"type": "boolean"},
            "status": {"enum": ["invalid", "internally_valid", "matched"]},
            "source": {"type": "string"},
            "source_bytes": {"type": "integer", "minimum": 0},
            "source_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "analysis_checked": {"type": "boolean"},
            "checks": {
                "type": "object",
                "maxProperties": 20,
                "additionalProperties": {"type": "boolean"},
            },
            "decision_count": {"type": "integer", "minimum": 0},
            "assignment_count": {"type": "integer", "minimum": 0},
            "findings": {
                "type": "array",
                "maxItems": 100,
                "items": {
                    "type": "object",
                    "required": ["code", "message"],
                    "properties": {
                        "code": {"type": "string", "minLength": 1},
                        "message": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
            },
            "notice": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }


def _activation_apply_receipt_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("activation-apply-receipt"),
        "title": "PySFMEA activation application receipt",
        "type": "object",
        "required": [
            "format",
            "status",
            "source_analysis_state_sha256",
            "workspace_sha256",
            "result_analysis_state_sha256",
            "finding_reviews_applied",
            "finding_consolidations_applied",
            "governance_decisions_recorded",
            "applied_records",
            "notice",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": "pysfmea-activation-apply-receipt-1"},
            "status": {"const": "applied"},
            "source_analysis_state_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "workspace_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "result_analysis_state_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "finding_reviews_applied": {"type": "integer", "minimum": 0},
            "finding_consolidations_applied": {
                "type": "integer",
                "minimum": 0,
            },
            "governance_decisions_recorded": {"type": "integer", "minimum": 0},
            "applied_records": {
                "type": "array",
                "maxItems": 50_000,
                "items": {
                    "type": "object",
                    "required": ["decision_id", "kind", "subject_id"],
                    "properties": {
                        "decision_id": {"type": "string", "minLength": 1},
                        "kind": {"type": "string", "minLength": 1},
                        "subject_id": {"type": "string", "minLength": 1},
                    },
                    "additionalProperties": False,
                },
            },
            "notice": {"type": "string", "minLength": 1},
            "content_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
        "additionalProperties": False,
    }


def _activation_records_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("activation-records"),
        "title": "PySFMEA bulk activation records",
        "type": "object",
        "required": [
            "format",
            "workspace_binding",
            "decision_choices",
            "assignments",
            "decisions",
            "instructions",
            "authority",
        ],
        "properties": {
            "format": {"const": "pysfmea-activation-records-1"},
            "workspace_binding": {
                "type": "object",
                "required": ["content_sha256", "analysis_state_sha256"],
                "properties": {
                    "content_sha256": {
                        "type": "string",
                        "pattern": "^[0-9a-f]{64}$",
                    },
                    "analysis_state_sha256": {
                        "type": "string",
                        "pattern": "^[0-9a-f]{64}$",
                    },
                },
                "additionalProperties": False,
            },
            "decision_choices": {"type": "object", "additionalProperties": True},
            "assignments": {
                "type": "array",
                "maxItems": 50_000,
                "items": {
                    "type": "object",
                    "required": ["kind", "subject_id", "assignee"],
                    "properties": {
                        "kind": {"type": "string", "minLength": 1},
                        "subject_id": {"type": "string", "minLength": 1},
                        "assignee": {"type": "string", "minLength": 1},
                        "due_date": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
            },
            "decisions": {
                "type": "array",
                "maxItems": 50_000,
                "items": {
                    "type": "object",
                    "required": [
                        "kind",
                        "subject_id",
                        "decision",
                        "reviewer",
                        "rationale",
                    ],
                    "properties": {
                        "kind": {"type": "string", "minLength": 1},
                        "subject_id": {"type": "string", "minLength": 1},
                        "decision": {"type": "string", "minLength": 1},
                        "reviewer": {"type": "string", "minLength": 1},
                        "rationale": {"type": "string", "minLength": 1},
                    },
                    "additionalProperties": False,
                },
            },
            "instructions": {
                "type": "array",
                "maxItems": 20,
                "items": {"type": "string"},
            },
            "authority": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }


def _activation_records_import_receipt_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("activation-records-import-receipt"),
        "title": "PySFMEA bulk activation-record import receipt",
        "type": "object",
        "required": [
            "format",
            "status",
            "workspace",
            "records_sha256",
            "assignments_imported",
            "decisions_imported",
            "result_workspace_sha256",
            "authority",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": "pysfmea-activation-records-import-receipt-1"},
            "status": {"const": "imported"},
            "workspace": {"type": "string", "minLength": 1},
            "records_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "assignments_imported": {"type": "integer", "minimum": 0},
            "decisions_imported": {"type": "integer", "minimum": 0},
            "result_workspace_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "authority": {"type": "string", "minLength": 1},
            "content_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
        "additionalProperties": False,
    }


def _sfta_authoring_entry_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "required": [
            "hazard_id",
            "hazard_description",
            "source",
            "action",
            "definition",
            "review",
        ],
        "properties": {
            "hazard_id": {"type": "string", "minLength": 1},
            "hazard_description": {"type": "string"},
            "source": {
                "enum": ["existing_explicit_tree", "generated_authoring_skeleton"]
            },
            "action": {"enum": ["retain", "defer", "replace"]},
            "definition": {"type": "object", "additionalProperties": True},
            "review": {
                "type": "object",
                "required": ["status", "reviewer", "rationale"],
                "properties": {
                    "status": {
                        "enum": ["unreviewed", "not_required", "approved", "rework"]
                    },
                    "reviewer": {"type": "string"},
                    "rationale": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
        "additionalProperties": False,
    }


def _configuration_authoring_entry_schema() -> dict[str, Any]:
    string_array = {
        "type": "array",
        "maxItems": 10_000,
        "items": {"type": "string", "minLength": 1},
        "uniqueItems": True,
    }
    schema: dict[str, Any] = {
        "type": "object",
        "required": ["kind", "subject_id", "action", "proposal", "review"],
        "properties": {
            "kind": {"enum": ["guidance", "architecture", "interface"]},
            "subject_id": {"type": "string", "minLength": 1},
            "action": {"enum": ["defer", "apply"]},
            "proposal": {"type": "object", "additionalProperties": True},
            "review": {
                "type": "object",
                "required": ["status", "reviewer", "rationale", "reviewed_at"],
                "properties": {
                    "status": {
                        "enum": ["unreviewed", "approved", "rejected", "rework"]
                    },
                    "reviewer": {"type": "string"},
                    "rationale": {"type": "string"},
                    "reviewed_at": {"type": "string"},
                },
                "additionalProperties": False,
            },
        },
        "additionalProperties": False,
    }
    schema["allOf"] = [
        {
            "if": {"properties": {"kind": {"const": "guidance"}}},
            "then": {
                "properties": {
                    "proposal": {
                        "type": "object",
                        "required": [
                            "rule_selector",
                            "citation_id",
                            "relationship",
                            "strength",
                        ],
                        "properties": {
                            "rule_selector": {"type": "string", "minLength": 1},
                            "citation_id": {"type": "string"},
                            "relationship": {"type": "string", "minLength": 1},
                            "strength": {
                                "enum": ["direct", "supporting", "contextual"]
                            },
                        },
                        "additionalProperties": False,
                    }
                }
            },
        },
        {
            "if": {"properties": {"kind": {"const": "architecture"}}},
            "then": {
                "properties": {
                    "proposal": {
                        "type": "object",
                        "required": [
                            "component_id",
                            "pattern",
                            "subsystem",
                            "requirements",
                            "hazards",
                            "interfaces",
                            "confidence",
                            "supporting_component_ids",
                        ],
                        "properties": {
                            "component_id": {"type": "string", "minLength": 1},
                            "pattern": {"type": "string", "minLength": 1},
                            "subsystem": {"type": "string"},
                            "requirements": string_array,
                            "hazards": string_array,
                            "interfaces": string_array,
                            "confidence": {"type": "string", "minLength": 1},
                            "supporting_component_ids": string_array,
                        },
                        "additionalProperties": False,
                    }
                }
            },
        },
        {
            "if": {"properties": {"kind": {"const": "interface"}}},
            "then": {
                "properties": {
                    "proposal": {
                        "type": "object",
                        "required": ["endpoint_id", "side", "decision"],
                        "properties": {
                            "endpoint_id": {"type": "string", "minLength": 1},
                            "side": {"enum": ["server", "client"]},
                            "decision": {"type": "string", "minLength": 1},
                        },
                        "additionalProperties": False,
                    }
                }
            },
        },
        {
            "if": {"properties": {"action": {"const": "apply"}}},
            "then": {
                "properties": {
                    "review": {
                        "properties": {
                            "status": {"const": "approved"},
                            "reviewer": {"minLength": 1},
                            "rationale": {"minLength": 1},
                            "reviewed_at": {
                                "type": "string",
                                "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
                            },
                        }
                    }
                }
            },
        },
    ]
    return schema


def _configuration_authoring_draft_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("configuration-authoring-draft"),
        "title": "PySFMEA editable configuration authoring draft",
        "type": "object",
        "required": [
            "format",
            "created_at",
            "analysis_binding",
            "configuration_binding",
            "summary",
            "entries",
            "instructions",
            "authority",
        ],
        "properties": {
            "format": {"const": "pysfmea-configuration-authoring-draft-1"},
            "created_at": {"type": "string", "minLength": 1},
            "analysis_binding": {"type": "object", "additionalProperties": True},
            "configuration_binding": {
                "type": "object",
                "additionalProperties": True,
            },
            "summary": {"type": "object", "additionalProperties": True},
            "entries": {
                "type": "array",
                "maxItems": 50_000,
                "items": _configuration_authoring_entry_schema(),
            },
            "instructions": {
                "type": "array",
                "maxItems": 20,
                "items": {"type": "string"},
            },
            "authority": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }


def _configuration_authoring_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("configuration-authoring"),
        "title": "PySFMEA sealed configuration authoring input",
        "type": "object",
        "required": [
            "format",
            "sealed_at",
            "analysis_binding",
            "configuration_binding",
            "source_draft_sha256",
            "summary",
            "entries",
            "authority",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": "pysfmea-configuration-authoring-1"},
            "sealed_at": {"type": "string", "minLength": 1},
            "analysis_binding": {"type": "object", "additionalProperties": True},
            "configuration_binding": {
                "type": "object",
                "additionalProperties": True,
            },
            "source_draft_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "summary": {"type": "object", "additionalProperties": True},
            "entries": {
                "type": "array",
                "maxItems": 50_000,
                "items": _configuration_authoring_entry_schema(),
            },
            "authority": {"type": "string", "minLength": 1},
            "content_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
        "additionalProperties": False,
    }


def _configuration_authoring_verification_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("configuration-authoring-verification"),
        "title": "PySFMEA configuration authoring verification",
        "type": "object",
        "required": [
            "format",
            "valid",
            "status",
            "analysis_checked",
            "configuration_checked",
            "checks",
            "counts",
            "findings",
            "notice",
        ],
        "properties": {
            "format": {"const": "pysfmea-configuration-authoring-verification-1"},
            "valid": {"type": "boolean"},
            "status": {"enum": ["invalid", "internally_valid", "matched"]},
            "analysis_checked": {"type": "boolean"},
            "configuration_checked": {"type": "boolean"},
            "source": {"type": "string"},
            "source_bytes": {"type": "integer", "minimum": 0},
            "source_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"},
            "checks": {
                "type": "object",
                "maxProperties": 20,
                "additionalProperties": {"type": "boolean"},
            },
            "counts": {
                "type": "object",
                "required": ["error"],
                "properties": {"error": {"type": "integer", "minimum": 0}},
                "additionalProperties": False,
            },
            "findings": {
                "type": "array",
                "maxItems": 100,
                "items": {
                    "type": "object",
                    "required": ["code", "message"],
                    "properties": {
                        "code": {"type": "string", "minLength": 1},
                        "message": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
            },
            "notice": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }


def _configuration_authoring_apply_receipt_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("configuration-authoring-apply-receipt"),
        "title": "PySFMEA configuration authoring apply receipt",
        "type": "object",
        "required": [
            "format",
            "status",
            "analysis_state_sha256",
            "source_configuration_sha256",
            "sealed_input_sha256",
            "result_configuration_sha256",
            "output",
            "guidance_mappings",
            "component_mappings",
            "interface_dispositions",
            "notice",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": "pysfmea-configuration-authoring-apply-receipt-1"},
            "status": {"const": "applied"},
            "analysis_state_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "source_configuration_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "sealed_input_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "result_configuration_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "output": {"type": "string", "minLength": 1},
            "guidance_mappings": {"type": "integer", "minimum": 0},
            "component_mappings": {"type": "integer", "minimum": 0},
            "interface_dispositions": {"type": "integer", "minimum": 0},
            "notice": {"type": "string", "minLength": 1},
            "content_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
        "additionalProperties": False,
    }


def _sfta_authoring_draft_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("sfta-authoring-draft"),
        "title": "PySFMEA editable SFTA authoring draft",
        "type": "object",
        "required": [
            "format",
            "created_at",
            "analysis_binding",
            "entries",
            "instructions",
            "authority",
        ],
        "properties": {
            "format": {"const": "pysfmea-sfta-authoring-draft-1"},
            "created_at": {"type": "string", "minLength": 1},
            "analysis_binding": {"type": "object", "additionalProperties": True},
            "entries": {
                "type": "array",
                "maxItems": 10_000,
                "items": _sfta_authoring_entry_schema(),
            },
            "instructions": {
                "type": "array",
                "maxItems": 20,
                "items": {"type": "string"},
            },
            "authority": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }


def _sfta_authoring_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("sfta-authoring"),
        "title": "PySFMEA sealed SFTA authoring input",
        "type": "object",
        "required": [
            "format",
            "sealed_at",
            "analysis_binding",
            "source_draft_sha256",
            "summary",
            "entries",
            "authority",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": "pysfmea-sfta-authoring-1"},
            "sealed_at": {"type": "string", "minLength": 1},
            "analysis_binding": {"type": "object", "additionalProperties": True},
            "source_draft_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "summary": {"type": "object", "additionalProperties": True},
            "entries": {
                "type": "array",
                "maxItems": 10_000,
                "items": _sfta_authoring_entry_schema(),
            },
            "authority": {"type": "string", "minLength": 1},
            "content_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
        "additionalProperties": False,
    }


def _sfta_authoring_verification_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("sfta-authoring-verification"),
        "title": "PySFMEA SFTA authoring verification",
        "type": "object",
        "required": [
            "format",
            "valid",
            "status",
            "analysis_checked",
            "checks",
            "counts",
            "findings",
            "notice",
        ],
        "properties": {
            "format": {"const": "pysfmea-sfta-authoring-verification-1"},
            "valid": {"type": "boolean"},
            "status": {"enum": ["invalid", "internally_valid", "matched"]},
            "analysis_checked": {"type": "boolean"},
            "source": {"type": "string"},
            "source_bytes": {"type": "integer", "minimum": 0},
            "source_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"},
            "checks": {
                "type": "object",
                "maxProperties": 20,
                "additionalProperties": {"type": "boolean"},
            },
            "counts": {
                "type": "object",
                "required": ["error"],
                "properties": {"error": {"type": "integer", "minimum": 0}},
                "additionalProperties": False,
            },
            "findings": {
                "type": "array",
                "maxItems": 100,
                "items": {
                    "type": "object",
                    "required": ["code", "message"],
                    "properties": {
                        "code": {"type": "string", "minLength": 1},
                        "message": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
            },
            "notice": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }


def _sfta_authoring_apply_receipt_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("sfta-authoring-apply-receipt"),
        "title": "PySFMEA SFTA authoring apply receipt",
        "type": "object",
        "required": [
            "format",
            "status",
            "source_analysis_state_sha256",
            "sealed_input_sha256",
            "result_analysis_state_sha256",
            "replacement_hazards",
            "explicit_trees",
            "placeholder_trees",
            "qualitative_cut_sets",
            "notice",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": "pysfmea-sfta-authoring-apply-receipt-1"},
            "status": {"const": "applied"},
            "source_analysis_state_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "sealed_input_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "result_analysis_state_sha256": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "replacement_hazards": {
                "type": "array",
                "maxItems": 10_000,
                "items": {"type": "string", "minLength": 1},
            },
            "explicit_trees": {"type": "integer", "minimum": 0},
            "placeholder_trees": {"type": "integer", "minimum": 0},
            "qualitative_cut_sets": {"type": "integer", "minimum": 0},
            "notice": {"type": "string", "minLength": 1},
            "content_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
        "additionalProperties": False,
    }


def _sha256_schema() -> dict[str, Any]:
    return {"type": "string", "pattern": "^[0-9a-f]{64}$"}


def _accessibility_evidence_schema(*, draft: bool) -> dict[str, Any]:
    name = "accessibility-evidence-draft" if draft else "accessibility-evidence"
    format_name = ACCESSIBILITY_DRAFT_FORMAT if draft else ACCESSIBILITY_FORMAT
    scenario_ids = [value[0] for value in REQUIRED_ACCESSIBILITY_SCENARIOS]
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id(name),
        "title": "PySFMEA accessibility qualification evidence",
        "type": "object",
        "required": [
            "format",
            "generated_at",
            "report",
            "standard",
            "evaluator",
            "reviewed_at",
            "scenarios",
            "exceptions",
            "notice",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": format_name},
            "generated_at": {"type": "string", "minLength": 1},
            "report": {
                "type": "object",
                "required": [
                    "filename",
                    "bytes",
                    "sha256",
                    "analysis_baseline",
                    "analysis_state_sha256",
                ],
                "properties": {
                    "filename": {"type": "string", "minLength": 1, "maxLength": 500},
                    "bytes": {"type": "integer", "minimum": 0},
                    "sha256": _sha256_schema(),
                    "analysis_baseline": {"type": "string"},
                    "analysis_state_sha256": _sha256_schema(),
                },
                "additionalProperties": False,
            },
            "standard": {
                "type": "object",
                "required": ["target", "scope", "claim"],
                "properties": {
                    "target": {"const": "WCAG 2.2 Level AA"},
                    "scope": {"type": "string", "minLength": 1},
                    "claim": {"type": "string", "minLength": 1},
                },
                "additionalProperties": False,
            },
            "evaluator": {
                "type": "object",
                "required": ["name", "organization"],
                "properties": {
                    "name": {"type": "string", "maxLength": 500},
                    "organization": {"type": "string", "maxLength": 500},
                },
                "additionalProperties": False,
            },
            "reviewed_at": {"type": "string", "maxLength": 100},
            "scenarios": {
                "type": "array",
                "minItems": len(scenario_ids),
                "maxItems": len(scenario_ids),
                "items": {
                    "type": "object",
                    "required": [
                        "id",
                        "procedure",
                        "status",
                        "environment",
                        "evidence_refs",
                        "notes",
                    ],
                    "properties": {
                        "id": {"enum": scenario_ids},
                        "procedure": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 5_000,
                        },
                        "status": {
                            "enum": ["pass", "fail", "not_applicable", "not_run"]
                        },
                        "environment": {"type": "string", "maxLength": 10_000},
                        "evidence_refs": {
                            "type": "array",
                            "maxItems": 100,
                            "uniqueItems": True,
                            "items": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 2_000,
                            },
                        },
                        "notes": {"type": "string", "maxLength": 20_000},
                    },
                    "additionalProperties": False,
                },
            },
            "exceptions": {"type": "array", "maxItems": 1_000, "items": {}},
            "notice": {"type": "string", "minLength": 1},
            "content_sha256": _sha256_schema(),
        },
        "additionalProperties": False,
    }


def _accessibility_evidence_draft_schema() -> dict[str, Any]:
    return _accessibility_evidence_schema(draft=True)


def _accessibility_evidence_sealed_schema() -> dict[str, Any]:
    return _accessibility_evidence_schema(draft=False)


def _accessibility_evidence_verification_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("accessibility-evidence-verification"),
        "title": "PySFMEA accessibility evidence verification",
        "type": "object",
        "required": [
            "format",
            "valid",
            "qualified",
            "checks",
            "scenario_statuses",
            "errors",
            "notice",
        ],
        "properties": {
            "format": {"const": ACCESSIBILITY_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "qualified": {"type": "boolean"},
            "checks": {
                "type": "object",
                "required": [
                    "content_integrity",
                    "structure",
                    "report_binding",
                    "manual_scenarios_complete",
                    "no_failed_scenarios",
                    "all_required_scenarios_passed",
                ],
                "additionalProperties": {"type": ["boolean", "null"]},
            },
            "scenario_statuses": {
                "type": "object",
                "additionalProperties": {
                    "enum": ["pass", "fail", "not_applicable", "not_run"]
                },
            },
            "errors": {"type": "array", "items": {"type": "string"}},
            "notice": {"type": "string", "minLength": 1},
            "path": {"type": "string"},
        },
        "additionalProperties": False,
    }


def _synthesis_content_schema() -> dict[str, Any]:
    list_fields = {
        "causes",
        "possible_end_effects",
        "prevention_controls",
        "detection_controls",
        "recommended_actions",
    }
    fields = {
        "failure_class",
        "guideword",
        "failure_mode",
        "trigger",
        "local_effect",
        "next_higher_effect",
        *list_fields,
    }
    return {
        "type": "object",
        "required": sorted(fields),
        "properties": {
            field: (
                {
                    "type": "array",
                    "maxItems": 100,
                    "items": {"type": "string", "minLength": 1, "maxLength": 20_000},
                }
                if field in list_fields
                else {"type": "string", "maxLength": 20_000}
            )
            for field in sorted(fields)
        },
        "additionalProperties": False,
    }


def _synthesis_workspace_schema(*, draft: bool) -> dict[str, Any]:
    name = "synthesis-workspace-draft" if draft else "synthesis-workspace"
    format_name = SYNTHESIS_DRAFT_FORMAT if draft else SYNTHESIS_FORMAT
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id(name),
        "title": "PySFMEA human suggestion synthesis workspace",
        "type": "object",
        "required": [
            "format",
            "generated_at",
            "binding",
            "entries",
            "relationships",
            "instructions",
            "notice",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": format_name},
            "generated_at": {"type": "string", "minLength": 1},
            "binding": {
                "type": "object",
                "required": ["baseline_id", "analysis_state_sha256"],
                "properties": {
                    "baseline_id": {"type": "string"},
                    "analysis_state_sha256": _sha256_schema(),
                },
                "additionalProperties": False,
            },
            "entries": {
                "type": "array",
                "maxItems": 5_000,
                "items": {
                    "type": "object",
                    "required": [
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
                    ],
                    "properties": {
                        "suggestion_id": {"type": "string", "minLength": 1},
                        "component_id": {"type": "string"},
                        "component_reference": {"type": "string"},
                        "original_content_sha256": _sha256_schema(),
                        "existing_findings": {
                            "type": "array",
                            "maxItems": 5,
                            "items": {"type": "object"},
                        },
                        "proposed_content": _synthesis_content_schema(),
                        "evidence_ids": {
                            "type": "array",
                            "maxItems": 100,
                            "items": {"type": "string", "minLength": 1},
                        },
                        "citation_ids": {
                            "type": "array",
                            "maxItems": 100,
                            "items": {"type": "string", "minLength": 1},
                        },
                        "uncertainties": {
                            "type": "array",
                            "maxItems": 100,
                            "items": {"type": "string", "minLength": 1},
                        },
                        "questions": {
                            "type": "array",
                            "maxItems": 100,
                            "items": {"type": "string", "minLength": 1},
                        },
                        "decision": {"enum": ["accept", "reject", "defer"]},
                        "reviewer": {"type": "string", "maxLength": 500},
                        "rationale": {"type": "string", "maxLength": 20_000},
                    },
                    "additionalProperties": False,
                },
            },
            "relationships": {"type": "object"},
            "instructions": {"type": "object"},
            "notice": {"type": "string", "minLength": 1},
            "content_sha256": _sha256_schema(),
        },
        "additionalProperties": False,
    }


def _synthesis_workspace_draft_schema() -> dict[str, Any]:
    return _synthesis_workspace_schema(draft=True)


def _synthesis_workspace_sealed_schema() -> dict[str, Any]:
    return _synthesis_workspace_schema(draft=False)


def _synthesis_workspace_verification_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("synthesis-workspace-verification"),
        "title": "PySFMEA synthesis workspace verification",
        "type": "object",
        "required": [
            "format",
            "valid",
            "checks",
            "entry_count",
            "decision_counts",
            "errors",
            "notice",
        ],
        "properties": {
            "format": {"const": SYNTHESIS_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "checks": {
                "type": "object",
                "required": ["content_integrity", "structure", "analysis_binding"],
                "additionalProperties": {"type": ["boolean", "null"]},
            },
            "entry_count": {"type": "integer", "minimum": 0},
            "decision_counts": {
                "type": "object",
                "required": ["accept", "reject", "defer"],
                "additionalProperties": {"type": "integer", "minimum": 0},
            },
            "errors": {"type": "array", "items": {"type": "string"}},
            "notice": {"type": "string", "minLength": 1},
            "path": {"type": "string"},
        },
        "additionalProperties": False,
    }


def _synthesis_apply_receipt_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("synthesis-apply-receipt"),
        "title": "PySFMEA synthesis application receipt",
        "type": "object",
        "required": [
            "format",
            "workspace_sha256",
            "source_analysis_state_sha256",
            "result_analysis_state_sha256",
            "applied_suggestion_ids",
            "deferred",
            "applied_at",
            "notice",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": SYNTHESIS_APPLY_RECEIPT_FORMAT},
            "workspace_sha256": _sha256_schema(),
            "source_analysis_state_sha256": _sha256_schema(),
            "result_analysis_state_sha256": _sha256_schema(),
            "applied_suggestion_ids": {
                "type": "array",
                "maxItems": 5_000,
                "uniqueItems": True,
                "items": {"type": "string", "minLength": 1},
            },
            "deferred": {"type": "integer", "minimum": 0},
            "applied_at": {"type": "string", "minLength": 1},
            "notice": {"type": "string", "minLength": 1},
            "content_sha256": _sha256_schema(),
        },
        "additionalProperties": False,
    }


def _synthesis_apply_receipt_verification_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("synthesis-apply-receipt-verification"),
        "title": "PySFMEA synthesis application receipt verification",
        "type": "object",
        "required": [
            "format",
            "valid",
            "reconciled",
            "mode",
            "checks",
            "applied_suggestion_count",
            "deferred",
            "declared_content_sha256",
            "actual_content_sha256",
            "errors",
            "notice",
            "path",
            "source_bytes",
            "source_sha256",
        ],
        "properties": {
            "format": {"const": SYNTHESIS_APPLY_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "reconciled": {"type": "boolean"},
            "mode": {"enum": ["integrity_only", "complete", "incomplete_bindings"]},
            "checks": {
                "type": "object",
                "required": [
                    "content_integrity",
                    "structure",
                    "source_analysis_binding",
                    "workspace_integrity",
                    "workspace_binding",
                    "result_analysis_binding",
                    "decision_reconciliation",
                ],
                "properties": {
                    "content_integrity": {"type": "boolean"},
                    "structure": {"type": "boolean"},
                    "source_analysis_binding": {"type": ["boolean", "null"]},
                    "workspace_integrity": {"type": ["boolean", "null"]},
                    "workspace_binding": {"type": ["boolean", "null"]},
                    "result_analysis_binding": {"type": ["boolean", "null"]},
                    "decision_reconciliation": {"type": ["boolean", "null"]},
                },
                "additionalProperties": False,
            },
            "applied_suggestion_count": {"type": "integer", "minimum": 0},
            "deferred": {"type": "integer", "minimum": 0},
            "declared_content_sha256": {"type": "string", "maxLength": 64},
            "actual_content_sha256": {"type": "string", "maxLength": 64},
            "errors": {
                "type": "array",
                "maxItems": 100,
                "items": {"type": "string", "maxLength": 4_000},
            },
            "notice": {"type": "string", "minLength": 1, "maxLength": 2_000},
            "path": {"type": "string", "minLength": 1, "maxLength": 4_096},
            "source_bytes": {"type": "integer", "minimum": 0},
            "source_sha256": {"type": "string", "maxLength": 64},
        },
        "additionalProperties": False,
    }


def _pull_request_analysis_schema() -> dict[str, Any]:
    artifact_names = (
        "base-analysis.json",
        "head-analysis.json",
        "differential-analysis.json",
        "base-report.html",
        "head-report.html",
    )
    artifact = {
        "type": "object",
        "required": ["bytes", "sha256"],
        "properties": {
            "bytes": {"type": "integer", "minimum": 0},
            "sha256": _sha256_schema(),
        },
        "additionalProperties": False,
    }
    revision = {
        "type": "object",
        "required": ["requested_ref", "commit", "analysis_state_sha256"],
        "properties": {
            "requested_ref": {"type": "string", "minLength": 1, "maxLength": 256},
            "commit": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
            "analysis_state_sha256": _sha256_schema(),
        },
        "additionalProperties": False,
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("pull-request-analysis"),
        "title": "PySFMEA pull-request differential bundle receipt",
        "type": "object",
        "required": [
            "format",
            "generated_at",
            "tool",
            "repository",
            "base",
            "head",
            "configuration_changed",
            "artifacts",
            "security",
            "notice",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": PULL_REQUEST_ANALYSIS_FORMAT},
            "generated_at": {"type": "string", "minLength": 1},
            "tool": {"type": "object"},
            "repository": {"type": "string", "minLength": 1},
            "base": revision,
            "head": revision,
            "configuration_changed": {"type": "boolean"},
            "artifacts": {
                "type": "object",
                "required": list(artifact_names),
                "properties": {name: artifact for name in artifact_names},
                "additionalProperties": False,
            },
            "security": {
                "type": "object",
                "required": [
                    "checkout_method",
                    "repository_code_executed",
                    "working_tree_mutated",
                ],
                "properties": {
                    "checkout_method": {
                        "const": "git_archive_with_bounded_safe_extraction"
                    },
                    "repository_code_executed": {"const": False},
                    "working_tree_mutated": {"const": False},
                },
                "additionalProperties": False,
            },
            "notice": {"type": "string", "minLength": 1},
            "content_sha256": _sha256_schema(),
        },
        "additionalProperties": False,
    }


def _pull_request_analysis_verification_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("pull-request-analysis-verification"),
        "title": "PySFMEA pull-request bundle verification",
        "type": "object",
        "required": [
            "format",
            "path",
            "valid",
            "checks",
            "base_commit",
            "head_commit",
            "errors",
            "notice",
        ],
        "properties": {
            "format": {"const": PULL_REQUEST_ANALYSIS_VERIFICATION_FORMAT},
            "path": {"type": "string"},
            "valid": {"type": "boolean"},
            "checks": {
                "type": "object",
                "minProperties": 9,
                "maxProperties": 9,
                "additionalProperties": {"type": "boolean"},
            },
            "base_commit": {"type": "string"},
            "head_commit": {"type": "string"},
            "errors": {"type": "array", "items": {"type": "string"}},
            "notice": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }


def _plugin_manifest_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("plugin-manifest"),
        "title": "PySFMEA process-plugin manifest",
        "type": "object",
        "required": [
            "format",
            "id",
            "name",
            "version",
            "sdk_api",
            "command",
            "capabilities",
            "deterministic",
            "timeout_seconds",
            "trust",
        ],
        "properties": {
            "format": {"const": PLUGIN_MANIFEST_FORMAT},
            "id": {
                "type": "string",
                "pattern": "^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+$",
                "maxLength": 120,
            },
            "name": {"type": "string", "minLength": 1, "maxLength": 120},
            "version": {
                "type": "string",
                "pattern": "^(?:0|[1-9][0-9]*)(?:\\.(?:0|[1-9][0-9]*)){2}(?:[-+][0-9A-Za-z.-]+)?$",
            },
            "sdk_api": {"const": "1.0"},
            "command": {
                "type": "array",
                "minItems": 1,
                "maxItems": 20,
                "items": {"type": "string", "minLength": 1, "maxLength": 1_000},
            },
            "capabilities": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {"enum": sorted(SUPPORTED_CAPABILITIES)},
            },
            "deterministic": {"type": "boolean"},
            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 300},
            "trust": {"enum": ["project", "organization", "third_party"]},
        },
        "additionalProperties": False,
    }


def _plugin_observation_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "required": [
            "id",
            "kind",
            "subject_id",
            "message",
            "evidence_ids",
            "confidence",
            "properties",
        ],
        "properties": {
            "id": {"type": "string", "minLength": 1, "maxLength": 160},
            "kind": {"type": "string", "maxLength": 20_000},
            "subject_id": {"type": "string", "maxLength": 20_000},
            "message": {"type": "string", "maxLength": 20_000},
            "evidence_ids": {
                "type": "array",
                "maxItems": 100,
                "items": {"type": "string", "maxLength": 500},
            },
            "confidence": {"enum": ["low", "medium", "high"]},
            "properties": {"type": "object"},
        },
        "additionalProperties": False,
    }


def _plugin_request_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("plugin-request"),
        "title": "PySFMEA process-plugin request",
        "type": "object",
        "required": [
            "format",
            "sdk_api",
            "plugin_id",
            "capability",
            "analysis_binding",
            "analysis",
            "authority",
        ],
        "properties": {
            "format": {"const": PLUGIN_REQUEST_FORMAT},
            "sdk_api": {"const": "1.0"},
            "plugin_id": {"type": "string", "minLength": 1},
            "capability": {"enum": sorted(SUPPORTED_CAPABILITIES)},
            "analysis_binding": {"type": "object"},
            "analysis": {"type": "object"},
            "authority": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }


def _plugin_response_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("plugin-response"),
        "title": "PySFMEA process-plugin response",
        "type": "object",
        "required": ["format", "plugin_id", "observations"],
        "properties": {
            "format": {"const": PLUGIN_RESPONSE_FORMAT},
            "plugin_id": {"type": "string", "minLength": 1},
            "observations": {
                "type": "array",
                "maxItems": 5_000,
                "items": _plugin_observation_schema(),
            },
        },
        "additionalProperties": False,
    }


def _plugin_run_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("plugin-run"),
        "title": "PySFMEA process-plugin run receipt",
        "type": "object",
        "required": [
            "format",
            "generated_at",
            "host",
            "plugin",
            "analysis_binding",
            "observations",
            "execution",
            "notice",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": PLUGIN_RUN_FORMAT},
            "generated_at": {"type": "string", "minLength": 1},
            "host": {"type": "object"},
            "plugin": {"type": "object"},
            "analysis_binding": {"type": "object"},
            "observations": {
                "type": "array",
                "maxItems": 5_000,
                "items": _plugin_observation_schema(),
            },
            "execution": {"type": "object"},
            "notice": {"type": "string", "minLength": 1},
            "content_sha256": _sha256_schema(),
        },
        "additionalProperties": False,
    }


def _plugin_run_verification_schema() -> dict[str, Any]:
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("plugin-run-verification"),
        "title": "PySFMEA plugin-run verification",
        "type": "object",
        "required": [
            "format",
            "valid",
            "checks",
            "plugin_id",
            "observation_count",
            "errors",
            "notice",
        ],
        "properties": {
            "format": {"const": PLUGIN_RUN_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "checks": {
                "type": "object",
                "additionalProperties": {"type": ["boolean", "null"]},
            },
            "plugin_id": {"type": "string"},
            "observation_count": {"type": "integer", "minimum": 0},
            "errors": {"type": "array", "items": {"type": "string"}},
            "notice": {"type": "string", "minLength": 1},
            "path": {"type": "string"},
        },
        "additionalProperties": False,
    }


def _report_browser_quality_schema() -> dict[str, Any]:
    nullable_number = {"type": ["number", "null"], "minimum": 0}
    nullable_integer = {"type": ["integer", "null"], "minimum": 1}
    check_properties = {
        name: {"type": ["boolean", "null"]} for name in BROWSER_QUALITY_CHECKS
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("report-browser-quality"),
        "title": "PySFMEA report browser-quality receipt",
        "type": "object",
        "required": [
            "format",
            "tool",
            "report",
            "bytes",
            "report_sha256",
            "load_seconds",
            "budgets",
            "browser_memory",
            "rendering",
            "checks",
            "views",
            "responsive",
            "saved_views",
            "accessibility",
            "console_errors",
            "page_errors",
            "browser_execution_error",
            "passed",
            "notice",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": BROWSER_QUALITY_FORMAT},
            "tool": {
                "type": "object",
                "required": ["name", "version"],
                "properties": {
                    "name": {"const": "PySFMEA"},
                    "version": {"type": "string", "minLength": 1, "maxLength": 100},
                },
                "additionalProperties": False,
            },
            "report": {"type": "string", "minLength": 1, "maxLength": 4_096},
            "bytes": {"type": "integer", "minimum": 0},
            "report_sha256": _sha256_schema(),
            "load_seconds": nullable_number,
            "budgets": {
                "type": "object",
                "required": [
                    "max_bytes",
                    "max_load_seconds",
                    "max_js_heap_bytes",
                    "authority",
                ],
                "properties": {
                    "max_bytes": nullable_integer,
                    "max_load_seconds": nullable_number,
                    "max_js_heap_bytes": nullable_integer,
                    "authority": {"type": "string", "minLength": 1, "maxLength": 500},
                },
                "additionalProperties": False,
            },
            "browser_memory": {
                "type": "object",
                "required": [
                    "maximum_used_js_heap_bytes",
                    "samples",
                    "measurement",
                    "limitations",
                ],
                "properties": {
                    "maximum_used_js_heap_bytes": nullable_integer,
                    "samples": {
                        "type": "array",
                        "maxItems": 100,
                        "items": {"type": "object"},
                    },
                    "measurement": {"type": "string", "minLength": 1, "maxLength": 500},
                    "limitations": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 1_000,
                    },
                },
                "additionalProperties": False,
            },
            "rendering": {
                "type": "object",
                "required": [
                    "mode",
                    "initial_view",
                    "initial_ready",
                    "boot_seconds",
                    "initial_render_seconds",
                    "rendered_view_count",
                    "total_view_count",
                    "all_views_ready",
                    "maximum_view_render_seconds",
                    "samples",
                    "limitations",
                ],
                "properties": {
                    "mode": {"const": "progressive_on_demand"},
                    "initial_view": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 100,
                    },
                    "initial_ready": {"type": "boolean"},
                    "boot_seconds": nullable_number,
                    "initial_render_seconds": nullable_number,
                    "rendered_view_count": {"type": "integer", "minimum": 0},
                    "total_view_count": {"type": "integer", "minimum": 1},
                    "all_views_ready": {"type": "boolean"},
                    "maximum_view_render_seconds": nullable_number,
                    "samples": {
                        "type": "array",
                        "maxItems": 100,
                        "items": {
                            "type": "object",
                            "required": ["view", "state", "render_seconds"],
                            "properties": {
                                "view": {
                                    "type": "string",
                                    "minLength": 1,
                                    "maxLength": 100,
                                },
                                "state": {"enum": ["ready", "error"]},
                                "render_seconds": nullable_number,
                            },
                            "additionalProperties": False,
                        },
                    },
                    "limitations": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 2_000,
                    },
                },
                "additionalProperties": False,
            },
            "checks": {
                "type": "object",
                "required": list(BROWSER_QUALITY_CHECKS),
                "properties": check_properties,
                "additionalProperties": False,
            },
            "views": {
                "type": "array",
                "maxItems": 100,
                "items": {
                    "type": "object",
                    "required": [
                        "view",
                        "visible",
                        "navigation_active",
                        "render_state",
                    ],
                    "properties": {
                        "view": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 100,
                        },
                        "visible": {"type": "boolean"},
                        "navigation_active": {"type": "boolean"},
                        "render_state": {"enum": ["ready", "error"]},
                    },
                    "additionalProperties": False,
                },
            },
            "responsive": {
                "type": "array",
                "maxItems": 20,
                "items": {"type": "object"},
            },
            "saved_views": {"type": "object", "maxProperties": 20},
            "accessibility": {"type": "object", "maxProperties": 20},
            "console_errors": {
                "type": "array",
                "maxItems": 1_000,
                "items": {"type": "string", "maxLength": 4_000},
            },
            "page_errors": {
                "type": "array",
                "maxItems": 1_000,
                "items": {"type": "string", "maxLength": 4_000},
            },
            "browser_execution_error": {"type": "string", "maxLength": 500},
            "passed": {"type": "boolean"},
            "notice": {"type": "string", "minLength": 1, "maxLength": 2_000},
            "content_sha256": _sha256_schema(),
        },
        "additionalProperties": False,
    }


def _report_browser_quality_verification_schema() -> dict[str, Any]:
    nullable_bytes = {"type": ["integer", "null"], "minimum": 0}
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("report-browser-quality-verification"),
        "title": "PySFMEA report browser-quality receipt verification",
        "type": "object",
        "required": [
            "format",
            "valid",
            "quality_passed",
            "checks",
            "declared_content_sha256",
            "actual_content_sha256",
            "declared_report_sha256",
            "actual_report_sha256",
            "declared_report_bytes",
            "actual_report_bytes",
            "errors",
            "notice",
            "path",
            "source_bytes",
            "source_sha256",
        ],
        "properties": {
            "format": {"const": BROWSER_QUALITY_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "quality_passed": {"type": "boolean"},
            "checks": {
                "type": "object",
                "required": [
                    "content_integrity",
                    "structure",
                    "semantic_consistency",
                    "report_binding",
                ],
                "properties": {
                    "content_integrity": {"type": "boolean"},
                    "structure": {"type": "boolean"},
                    "semantic_consistency": {"type": "boolean"},
                    "report_binding": {"type": ["boolean", "null"]},
                },
                "additionalProperties": False,
            },
            "declared_content_sha256": {"type": "string", "maxLength": 64},
            "actual_content_sha256": {"type": "string", "maxLength": 64},
            "declared_report_sha256": {"type": "string", "maxLength": 64},
            "actual_report_sha256": {"type": "string", "maxLength": 64},
            "declared_report_bytes": nullable_bytes,
            "actual_report_bytes": nullable_bytes,
            "errors": {
                "type": "array",
                "maxItems": 100,
                "items": {"type": "string", "maxLength": 4_000},
            },
            "notice": {"type": "string", "minLength": 1, "maxLength": 2_000},
            "path": {"type": "string", "minLength": 1, "maxLength": 4_096},
            "source_bytes": {"type": "integer", "minimum": 0},
            "source_sha256": {"type": "string", "maxLength": 64},
        },
        "additionalProperties": False,
    }


def _evaluation_metric_schema() -> dict[str, Any]:
    ratio = {"type": ["number", "null"], "minimum": 0, "maximum": 1}
    return {
        "type": "object",
        "required": ["expected", "actual", "matched", "recall", "precision"],
        "properties": {
            "expected": {"type": "integer", "minimum": 0},
            "actual": {"type": "integer", "minimum": 0},
            "matched": {"type": "integer", "minimum": 0},
            "recall": ratio,
            "precision": ratio,
        },
        "additionalProperties": False,
    }


def _golden_corpus_schema() -> dict[str, Any]:
    text = {"type": "string", "maxLength": MAX_EVALUATION_VALUE_CHARS}
    required_text = {
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_EVALUATION_VALUE_CHARS,
    }
    metadata = {"type": "string", "maxLength": MAX_EVALUATION_METADATA_CHARS}
    finding_case = {
        "type": "object",
        "required": ["source", "component", "rule_id"],
        "properties": {
            "source": text,
            "component": required_text,
            "rule_id": required_text,
        },
        "additionalProperties": False,
    }
    call_case = {
        "type": "object",
        "required": [
            "source",
            "component",
            "raw_reference",
            "reference",
            "resolution",
            "candidate_confidence",
            "line",
            "order",
            "awaited",
            "control_context",
        ],
        "properties": {
            "source": required_text,
            "component": required_text,
            "raw_reference": required_text,
            "reference": required_text,
            "resolution": required_text,
            "candidate_confidence": {"enum": ["", "low", "medium", "high"]},
            "line": {"type": "integer", "minimum": 0},
            "order": {"type": "integer", "minimum": 0},
            "awaited": {"type": "boolean"},
            "control_context": {
                "type": "array",
                "maxItems": MAX_GENERATED_LIST_ITEMS,
                "items": required_text,
                "uniqueItems": True,
            },
        },
        "additionalProperties": False,
    }
    control_case = {
        "type": "object",
        "required": ["source", "component", "kind", "roles"],
        "properties": {
            "source": required_text,
            "component": required_text,
            "kind": required_text,
            "roles": {
                "type": "array",
                "maxItems": MAX_GENERATED_LIST_ITEMS,
                "items": required_text,
                "uniqueItems": True,
            },
        },
        "additionalProperties": False,
    }
    semantic_properties: dict[str, Any] = {
        field: {
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_EVALUATION_METADATA_CHARS,
        }
        for field in SEMANTIC_TEXT_FIELDS
    }
    semantic_properties.update(
        {
            field: {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_GENERATED_LIST_ITEMS,
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_EVALUATION_METADATA_CHARS,
                },
                "uniqueItems": True,
            }
            for field in SEMANTIC_SEQUENCE_FIELDS
        }
    )
    semantic_properties.update(
        {
            field: {
                "type": "array",
                "maxItems": MAX_GENERATED_LIST_ITEMS,
                "items": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_EVALUATION_METADATA_CHARS,
                },
                "uniqueItems": True,
            }
            for field in SEMANTIC_SET_FIELDS
        }
    )
    semantic_case = {
        "type": "object",
        "required": ["source", "component", "rule_id", "expect"],
        "properties": {
            "source": required_text,
            "component": required_text,
            "rule_id": required_text,
            "expect": {
                "type": "object",
                "minProperties": 1,
                "properties": semantic_properties,
                "additionalProperties": False,
            },
        },
        "additionalProperties": False,
    }
    governance = {
        "type": "object",
        "properties": {
            "independent": {"type": "boolean"},
            "repositories": {
                "type": "array",
                "maxItems": MAX_EVALUATION_CASES,
                "items": required_text,
                "uniqueItems": True,
            },
            "labeled_by": text,
            "approved_by": text,
            "approval_date": text,
        },
        "additionalProperties": False,
    }
    scope = {
        "type": "array",
        "maxItems": MAX_EVALUATION_SCOPES,
        "items": required_text,
        "uniqueItems": True,
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("golden-corpus"),
        "title": "PySFMEA golden evaluation corpus",
        "type": "object",
        "required": ["schema_version", "cases"],
        "properties": {
            "schema_version": {"const": EVALUATION_CORPUS_FORMAT},
            "name": metadata,
            "purpose": metadata,
            "scope": scope,
            "cases": {
                "type": "array",
                "maxItems": MAX_EVALUATION_CASES,
                "items": finding_case,
                "uniqueItems": True,
            },
            "call_cases": {
                "type": "array",
                "maxItems": MAX_EVALUATION_CASES,
                "items": call_case,
                "uniqueItems": True,
            },
            "control_cases": {
                "type": "array",
                "maxItems": MAX_EVALUATION_CASES,
                "items": control_case,
                "uniqueItems": True,
            },
            "control_scope": scope,
            "semantic_cases": {
                "type": "array",
                "maxItems": MAX_EVALUATION_CASES,
                "items": semantic_case,
                "uniqueItems": True,
            },
            "governance": governance,
        },
        "additionalProperties": False,
    }


def _evaluation_result_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    text = {"type": "string", "maxLength": MAX_EVALUATION_METADATA_CHARS}
    required_text = {
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_EVALUATION_METADATA_CHARS,
    }
    ratio = {"type": ["number", "null"], "minimum": 0, "maximum": 1}
    count = {"type": "integer", "minimum": 0}
    metric = _evaluation_metric_schema()
    finding = {
        "type": "object",
        "required": ["source", "component", "rule_id"],
        "properties": {
            "source": text,
            "component": required_text,
            "rule_id": required_text,
        },
        "additionalProperties": False,
    }
    call = {
        "type": "object",
        "required": [
            "source",
            "component",
            "raw_reference",
            "reference",
            "resolution",
            "candidate_confidence",
            "line",
            "order",
            "awaited",
            "control_context",
        ],
        "properties": {
            "source": required_text,
            "component": required_text,
            "raw_reference": required_text,
            "reference": required_text,
            "resolution": required_text,
            "candidate_confidence": {"type": "string", "maxLength": 20},
            "line": count,
            "order": count,
            "awaited": {"type": "boolean"},
            "control_context": {
                "type": "array",
                "maxItems": MAX_GENERATED_LIST_ITEMS,
                "items": required_text,
                "uniqueItems": True,
            },
        },
        "additionalProperties": False,
    }
    control = {
        "type": "object",
        "required": ["source", "component", "kind", "roles"],
        "properties": {
            "source": required_text,
            "component": required_text,
            "kind": required_text,
            "roles": {
                "type": "array",
                "maxItems": MAX_GENERATED_LIST_ITEMS,
                "items": required_text,
                "uniqueItems": True,
            },
        },
        "additionalProperties": False,
    }
    semantic_identity = {
        "source": required_text,
        "component": required_text,
        "rule_id": required_text,
    }
    semantic_value = {
        "oneOf": [
            text,
            {
                "type": "array",
                "maxItems": MAX_GENERATED_LIST_ITEMS,
                "items": text,
                "uniqueItems": True,
            },
        ]
    }
    semantic_missing = {
        "type": "object",
        "required": list(semantic_identity),
        "properties": semantic_identity,
        "additionalProperties": False,
    }
    semantic_mismatch = {
        "type": "object",
        "required": [*semantic_identity, "field", "expected", "actual"],
        "properties": {
            **semantic_identity,
            "field": required_text,
            "expected": semantic_value,
            "actual": semantic_value,
        },
        "additionalProperties": False,
    }
    governance = {
        "type": "object",
        "required": [
            "independent",
            "repositories",
            "labeled_by",
            "approved_by",
            "approval_date",
            "qualification_ready",
            "authority",
        ],
        "properties": {
            "independent": {"type": "boolean"},
            "repositories": {
                "type": "array",
                "maxItems": MAX_EVALUATION_CASES,
                "items": required_text,
                "uniqueItems": True,
            },
            "labeled_by": text,
            "approved_by": text,
            "approval_date": text,
            "qualification_ready": {"type": "boolean"},
            "authority": required_text,
        },
        "additionalProperties": False,
    }
    quality_properties = {
        "duplicate_count": count,
        "duplicate_rate": ratio,
        "source_localization_accuracy": ratio,
        "citation_link_accuracy": ratio,
        "traceability_integrity": ratio,
        "adapter_provenance_coverage": ratio,
        "repository_source_accounting": ratio,
        "unsupported_verification_claims": {
            "type": "array",
            "maxItems": MAX_EVALUATION_CASES,
            "items": finding,
        },
    }
    corpus_properties = {
        "format": {"const": EVALUATION_CORPUS_FORMAT},
        "content_sha256": digest,
        "case_count": count,
        "call_case_count": count,
        "control_case_count": count,
        "control_scope_count": count,
        "semantic_case_count": count,
        "semantic_claim_count": count,
        "scope_count": count,
        "governance": governance,
    }
    call_properties = {
        "enabled": {"type": "boolean"},
        "expected": count,
        "actual": count,
        "matched": count,
        "recall": ratio,
        "precision": ratio,
        "missing": {"type": "array", "maxItems": MAX_EVALUATION_CASES, "items": call},
        "unexpected": {
            "type": "array",
            "maxItems": MAX_EVALUATION_CASES,
            "items": call,
        },
        "by_resolution": {
            "type": "object",
            "maxProperties": MAX_EVALUATION_CASES,
            "additionalProperties": metric,
        },
        "notice": required_text,
    }
    control_properties = {
        "enabled": {"type": "boolean"},
        "expected": count,
        "actual": count,
        "matched": count,
        "recall": ratio,
        "precision": ratio,
        "missing": {
            "type": "array",
            "maxItems": MAX_EVALUATION_CASES,
            "items": control,
        },
        "unexpected": {
            "type": "array",
            "maxItems": MAX_EVALUATION_CASES,
            "items": control,
        },
        "by_kind": {
            "type": "object",
            "maxProperties": MAX_EVALUATION_CASES,
            "additionalProperties": metric,
        },
        "population": {
            "type": "object",
            "required": [
                "scope_basis",
                "scope_patterns",
                "evaluated_components",
                "positive_components",
                "negative_components",
            ],
            "properties": {
                "scope_basis": required_text,
                "scope_patterns": {
                    "type": "array",
                    "maxItems": MAX_EVALUATION_SCOPES,
                    "items": required_text,
                    "uniqueItems": True,
                },
                "evaluated_components": count,
                "positive_components": count,
                "negative_components": count,
            },
            "additionalProperties": False,
        },
        "qualification_ready_corpus": {"type": "boolean"},
        "notice": required_text,
    }
    semantic_properties = {
        "enabled": {"type": "boolean"},
        "expected": count,
        "actual": count,
        "matched": count,
        "recall": ratio,
        "precision": ratio,
        "claim_expected": count,
        "claim_actual": count,
        "claim_matched": count,
        "claim_recall": ratio,
        "claim_precision": ratio,
        "missing": {
            "type": "array",
            "maxItems": MAX_EVALUATION_CASES,
            "items": semantic_missing,
        },
        "mismatches": {
            "type": "array",
            "maxItems": MAX_EVALUATION_CASES,
            "items": semantic_mismatch,
        },
        "by_field": {
            "type": "object",
            "maxProperties": 20,
            "additionalProperties": metric,
        },
        "by_rule": {
            "type": "object",
            "maxProperties": MAX_EVALUATION_CASES,
            "additionalProperties": metric,
        },
        "qualification_ready_corpus": {"type": "boolean"},
        "authority": required_text,
        "notice": required_text,
    }
    confidence_bin = {
        "type": "object",
        "properties": {
            "actual": count,
            "matched": count,
            "false_positive": count,
            "empirical_precision": ratio,
        },
        "additionalProperties": False,
    }
    properties = {
        "format": {"const": "pysfmea-evaluation-result-1"},
        "verifier": {
            "type": "object",
            "required": ["name", "version"],
            "properties": {"name": {"const": "PySFMEA"}, "version": required_text},
            "additionalProperties": False,
        },
        "corpus": {
            "type": "object",
            "required": list(corpus_properties),
            "properties": corpus_properties,
            "additionalProperties": False,
        },
        "scope": {
            "type": "array",
            "maxItems": MAX_EVALUATION_SCOPES,
            "items": required_text,
            "uniqueItems": True,
        },
        "expected": count,
        "actual": count,
        "matched": count,
        "recall": ratio,
        "precision": ratio,
        "missing": {
            "type": "array",
            "maxItems": MAX_EVALUATION_CASES,
            "items": finding,
        },
        "unexpected": {
            "type": "array",
            "maxItems": MAX_EVALUATION_CASES,
            "items": finding,
        },
        "by_rule": {
            "type": "object",
            "maxProperties": MAX_EVALUATION_CASES,
            "additionalProperties": metric,
        },
        "metrics": {
            "type": "object",
            "required": list(quality_properties),
            "properties": quality_properties,
            "additionalProperties": False,
        },
        "call_resolution": {
            "type": "object",
            "required": list(call_properties),
            "properties": call_properties,
            "additionalProperties": False,
        },
        "confidence_calibration": {
            "type": "object",
            "required": [
                "enabled",
                "bins",
                "ranked_labels",
                "monotonic_empirical_precision",
                "population",
                "qualification_ready_corpus",
                "authority",
            ],
            "properties": {
                "enabled": {"type": "boolean"},
                "bins": {
                    "type": "object",
                    "maxProperties": 20,
                    "additionalProperties": confidence_bin,
                },
                "ranked_labels": {
                    "type": "array",
                    "maxItems": 20,
                    "items": required_text,
                    "uniqueItems": True,
                },
                "monotonic_empirical_precision": {"type": "boolean"},
                "population": count,
                "qualification_ready_corpus": {"type": "boolean"},
                "authority": required_text,
            },
            "additionalProperties": False,
        },
        "control_detection": {
            "type": "object",
            "required": list(control_properties),
            "properties": control_properties,
            "additionalProperties": False,
        },
        "semantic_output": {
            "type": "object",
            "required": list(semantic_properties),
            "properties": semantic_properties,
            "additionalProperties": False,
        },
        "notice": required_text,
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("evaluation-result"),
        "title": "PySFMEA evaluation result",
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }


def _calibration_comparison_schema() -> dict[str, Any]:
    ratio = {"type": ["number", "null"], "minimum": -1, "maximum": 1}
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("calibration-comparison"),
        "title": "PySFMEA governed calibration comparison",
        "type": "object",
        "required": [
            "format",
            "corpus_sha256",
            "change",
            "global",
            "rules",
            "gates",
            "eligible_for_product_change_review",
            "decision",
            "authority",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": "pysfmea-calibration-comparison-1"},
            "corpus_sha256": digest,
            "change": {"type": "object", "maxProperties": 20},
            "global": {
                "type": "object",
                "properties": {
                    "before": {"type": "object"},
                    "after": {"type": "object"},
                    "recall_delta": ratio,
                    "precision_delta": ratio,
                    "control_recall_delta": ratio,
                    "semantic_enabled": {"type": "boolean"},
                    "semantic_recall_delta": ratio,
                    "semantic_precision_delta": ratio,
                    "semantic_claim_recall_delta": ratio,
                    "semantic_claim_precision_delta": ratio,
                },
                "additionalProperties": False,
            },
            "rules": {
                "type": "array",
                "maxItems": MAX_EVALUATION_CASES,
                "items": {"type": "object"},
            },
            "gates": {"type": "object", "additionalProperties": {"type": "boolean"}},
            "eligible_for_product_change_review": {"type": "boolean"},
            "decision": {"enum": ["eligible_for_review", "blocked"]},
            "authority": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_EVALUATION_METADATA_CHARS,
            },
            "content_sha256": digest,
        },
        "additionalProperties": False,
    }


def _qualification_threshold_schema() -> dict[str, Any]:
    count = {"type": "integer", "minimum": 0}
    ratio = {"type": "number", "minimum": 0, "maximum": 1}
    properties = {
        "minimum_repositories": {"type": "integer", "minimum": 1},
        "minimum_frameworks": count,
        "minimum_domains": count,
        "minimum_expected_findings": {"type": "integer", "minimum": 1},
        "minimum_finding_recall": ratio,
        "minimum_finding_precision": ratio,
        "require_call_cases": {"type": "boolean"},
        "minimum_call_recall": ratio,
        "minimum_call_precision": ratio,
        "require_control_cases": {"type": "boolean"},
        "minimum_control_negative_components_per_repository": count,
        "minimum_control_recall": ratio,
        "minimum_control_precision": ratio,
        "require_semantic_cases": {"type": "boolean"},
        "minimum_semantic_recall": ratio,
        "minimum_semantic_precision": ratio,
    }
    return {
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }


def _qualification_manifest_schema() -> dict[str, Any]:
    required_text = {"type": "string", "minLength": 1, "maxLength": 20_000}
    identifier = {
        "type": "string",
        "minLength": 1,
        "maxLength": 100,
        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$",
    }
    labels = {
        "type": "array",
        "maxItems": 100,
        "uniqueItems": True,
        "items": identifier,
    }
    governance_properties = {
        "independent": {"type": "boolean"},
        "labeled_by": required_text,
        "approved_by": required_text,
        "approval_date": {
            "type": "string",
            "format": "date",
            "maxLength": 20_000,
        },
        "selection_method": required_text,
        "representativeness_rationale": required_text,
    }
    repository_properties = {
        "id": identifier,
        "analysis": required_text,
        "corpus": required_text,
        "evaluation": required_text,
        "frameworks": labels,
        "domains": labels,
        "selection_rationale": required_text,
    }
    properties = {
        "format": {"const": QUALIFICATION_CAMPAIGN_MANIFEST_FORMAT},
        "id": identifier,
        "title": required_text,
        "purpose": required_text,
        "governance": {
            "type": "object",
            "required": list(governance_properties),
            "properties": governance_properties,
            "additionalProperties": False,
        },
        "thresholds": _qualification_threshold_schema(),
        "repositories": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_QUALIFICATION_REPOSITORIES,
            "items": {
                "type": "object",
                "required": list(repository_properties),
                "properties": repository_properties,
                "additionalProperties": False,
            },
        },
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("qualification-campaign-manifest"),
        "title": "PySFMEA qualification campaign manifest",
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }


def _qualification_metric_schema(
    *, repository_count: bool, control_population: bool = False
) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "expected": {"type": "integer", "minimum": 0},
        "actual": {"type": "integer", "minimum": 0},
        "matched": {"type": "integer", "minimum": 0},
        "recall": {"type": ["number", "null"], "minimum": 0, "maximum": 1},
        "precision": {"type": ["number", "null"], "minimum": 0, "maximum": 1},
    }
    if repository_count:
        properties["repositories"] = {"type": "integer", "minimum": 0}
    if control_population:
        properties.update(
            {
                "evaluated_components": {"type": "integer", "minimum": 0},
                "positive_components": {"type": "integer", "minimum": 0},
                "negative_components": {"type": "integer", "minimum": 0},
            }
        )
    return {
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }


def _qualification_features_schema(*, repository_count: bool) -> dict[str, Any]:
    properties = {
        name: _qualification_metric_schema(
            repository_count=repository_count,
            control_population=name == "control_detection",
        )
        for name in (
            "finding_detection",
            "call_resolution",
            "control_detection",
            "semantic_output",
        )
    }
    return {
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }


def _qualification_named_metrics_schema(*, repository_count: bool) -> dict[str, Any]:
    return {
        "type": "object",
        "maxProperties": 20_000,
        "additionalProperties": _qualification_metric_schema(
            repository_count=repository_count
        ),
    }


def _qualification_binding_schema() -> dict[str, Any]:
    properties = {
        "reference": {"type": "string", "minLength": 1, "maxLength": 20_000},
        "bytes": {"type": "integer", "minimum": 0},
        "sha256": {"type": "string", "pattern": r"^[0-9a-f]{64}$"},
        "canonical_sha256": {"type": "string", "pattern": r"^[0-9a-f]{64}$"},
    }
    return {
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }


def _qualification_result_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": r"^[0-9a-f]{64}$"}
    text = {"type": "string", "minLength": 1, "maxLength": 20_000}
    labels = {"type": "array", "maxItems": 100, "items": text}
    binding = _qualification_binding_schema()
    artifacts = {
        "type": "object",
        "required": ["analysis", "corpus", "evaluation"],
        "properties": {
            "analysis": binding,
            "corpus": binding,
            "evaluation": binding,
        },
        "additionalProperties": False,
    }
    semantic_value = {
        "oneOf": [
            {"type": "string", "maxLength": 20_000},
            {
                "type": "array",
                "maxItems": 100,
                "items": {"type": "string", "maxLength": 20_000},
            },
        ]
    }
    semantic_diagnostic_example = {
        "type": "object",
        "required": [
            "kind",
            "source",
            "component",
            "rule_id",
            "field",
            "expected",
            "actual",
        ],
        "properties": {
            "kind": {"enum": ["missing", "mismatch"]},
            "source": {"type": "string", "maxLength": 20_000},
            "component": text,
            "rule_id": text,
            "field": {"type": ["string", "null"], "maxLength": 20_000},
            "expected": {"oneOf": [semantic_value, {"type": "null"}]},
            "actual": {"oneOf": [semantic_value, {"type": "null"}]},
        },
        "allOf": [
            {
                "if": {"properties": {"kind": {"const": "missing"}}},
                "then": {
                    "properties": {
                        "field": {"type": "null"},
                        "expected": {"type": "null"},
                        "actual": {"type": "null"},
                    }
                },
            },
            {
                "if": {"properties": {"kind": {"const": "mismatch"}}},
                "then": {
                    "properties": {
                        "field": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 20_000,
                        },
                        "expected": semantic_value,
                        "actual": semantic_value,
                    }
                },
            },
        ],
        "additionalProperties": False,
    }
    semantic_diagnostics = {
        "type": "object",
        "required": [
            "missing_count",
            "mismatch_count",
            "examples",
            "examples_omitted",
            "authority",
        ],
        "properties": {
            "missing_count": {"type": "integer", "minimum": 0},
            "mismatch_count": {"type": "integer", "minimum": 0},
            "examples": {
                "type": "array",
                "maxItems": 100,
                "items": semantic_diagnostic_example,
            },
            "examples_omitted": {"type": "integer", "minimum": 0},
            "authority": text,
        },
        "additionalProperties": False,
    }
    repository_properties = {
        "id": text,
        "frameworks": labels,
        "domains": labels,
        "selection_rationale": text,
        "analysis_state_sha256": digest,
        "corpus_governance_qualification_ready": {"type": "boolean"},
        "corpus_governance": {
            "type": "object",
            "required": [
                "independent",
                "repositories",
                "labeled_by",
                "approved_by",
                "approval_date",
                "qualification_ready",
                "authority",
            ],
            "properties": {
                "independent": {"type": "boolean"},
                "repositories": labels,
                "labeled_by": {"type": "string", "maxLength": 20_000},
                "approved_by": {"type": "string", "maxLength": 20_000},
                "approval_date": {"type": "string", "maxLength": 20_000},
                "qualification_ready": {"type": "boolean"},
                "authority": text,
            },
            "additionalProperties": False,
        },
        "evaluation_verifier": {
            "type": "object",
            "required": ["name", "version"],
            "properties": {"name": text, "version": text},
            "additionalProperties": False,
        },
        "quality": {
            "type": "object",
            "required": [
                "duplicate_count",
                "unsupported_verification_claim_count",
                "source_localization_accuracy",
                "citation_link_accuracy",
                "traceability_integrity",
                "adapter_provenance_coverage",
                "repository_source_accounting",
            ],
            "properties": {
                "duplicate_count": {"type": "integer", "minimum": 0},
                "unsupported_verification_claim_count": {
                    "type": "integer",
                    "minimum": 0,
                },
                **{
                    field: {
                        "type": ["number", "null"],
                        "minimum": 0,
                        "maximum": 1,
                    }
                    for field in (
                        "source_localization_accuracy",
                        "citation_link_accuracy",
                        "traceability_integrity",
                        "adapter_provenance_coverage",
                        "repository_source_accounting",
                    )
                },
            },
            "additionalProperties": False,
        },
        "artifacts": artifacts,
        "features": _qualification_features_schema(repository_count=False),
        "by_rule": _qualification_named_metrics_schema(repository_count=False),
        "by_call_resolution": _qualification_named_metrics_schema(
            repository_count=False
        ),
        "by_control_kind": _qualification_named_metrics_schema(repository_count=False),
        "by_semantic_field": _qualification_named_metrics_schema(
            repository_count=False
        ),
        "by_semantic_rule": _qualification_named_metrics_schema(repository_count=False),
        "semantic_diagnostics": semantic_diagnostics,
    }
    segment = {
        "type": "object",
        "required": ["repository_count", "repository_ids", "features"],
        "properties": {
            "repository_count": {"type": "integer", "minimum": 0},
            "repository_ids": labels,
            "features": _qualification_features_schema(repository_count=True),
        },
        "additionalProperties": False,
    }
    segment_map = {
        "type": "object",
        "maxProperties": 100,
        "additionalProperties": segment,
    }
    governance_properties = {
        "independent": {"type": "boolean"},
        "labeled_by": text,
        "approved_by": text,
        "approval_date": text,
        "selection_method": text,
        "representativeness_rationale": text,
        "qualification_ready_claim": {"type": "boolean"},
        "authority": text,
    }
    checks = {
        "type": "object",
        "required": list(QUALIFICATION_CHECKS),
        "properties": {
            name: {"type": ["boolean", "null"]} for name in QUALIFICATION_CHECKS
        },
        "additionalProperties": False,
    }
    properties = {
        "format": {"const": QUALIFICATION_CAMPAIGN_RESULT_FORMAT},
        "tool": {
            "type": "object",
            "required": ["name", "version"],
            "properties": {"name": {"const": "PySFMEA"}, "version": text},
            "additionalProperties": False,
        },
        "campaign": {
            "type": "object",
            "required": ["id", "title", "purpose"],
            "properties": {"id": text, "title": text, "purpose": text},
            "additionalProperties": False,
        },
        "manifest": binding,
        "thresholds": _qualification_threshold_schema(),
        "governance": {
            "type": "object",
            "required": list(governance_properties),
            "properties": governance_properties,
            "additionalProperties": False,
        },
        "repositories": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_QUALIFICATION_REPOSITORIES,
            "items": {
                "type": "object",
                "required": list(repository_properties),
                "properties": repository_properties,
                "additionalProperties": False,
            },
        },
        "summary": {
            "type": "object",
            "required": [
                "repository_count",
                "framework_count",
                "domain_count",
                "frameworks",
                "domains",
                "independently_governed_corpora",
                "semantic_missing_cases",
                "semantic_mismatched_claims",
                "semantic_diagnostic_examples",
                "semantic_diagnostic_examples_omitted",
            ],
            "properties": {
                "repository_count": {"type": "integer", "minimum": 1},
                "framework_count": {"type": "integer", "minimum": 0},
                "domain_count": {"type": "integer", "minimum": 0},
                "frameworks": labels,
                "domains": labels,
                "independently_governed_corpora": {
                    "type": "integer",
                    "minimum": 0,
                },
                "semantic_missing_cases": {"type": "integer", "minimum": 0},
                "semantic_mismatched_claims": {
                    "type": "integer",
                    "minimum": 0,
                },
                "semantic_diagnostic_examples": {
                    "type": "integer",
                    "minimum": 0,
                },
                "semantic_diagnostic_examples_omitted": {
                    "type": "integer",
                    "minimum": 0,
                },
            },
            "additionalProperties": False,
        },
        "features": _qualification_features_schema(repository_count=True),
        "by_rule": _qualification_named_metrics_schema(repository_count=True),
        "by_call_resolution": _qualification_named_metrics_schema(
            repository_count=True
        ),
        "by_control_kind": _qualification_named_metrics_schema(repository_count=True),
        "by_semantic_field": _qualification_named_metrics_schema(repository_count=True),
        "by_semantic_rule": _qualification_named_metrics_schema(repository_count=True),
        "segments": {
            "type": "object",
            "required": ["frameworks", "domains"],
            "properties": {"frameworks": segment_map, "domains": segment_map},
            "additionalProperties": False,
        },
        "checks": checks,
        "eligible_for_independent_review": {"type": "boolean"},
        "status": {
            "enum": [
                "eligible_for_independent_review",
                "qualification_evidence_incomplete",
            ]
        },
        "notice": text,
        "content_sha256": digest,
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("qualification-campaign-result"),
        "title": "PySFMEA qualification campaign result",
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }


def _qualification_verification_schema() -> dict[str, Any]:
    checks = {
        "structure": {"type": "boolean"},
        "content_integrity": {"type": "boolean"},
        "semantic_consistency": {"type": "boolean"},
        "manifest_binding": {"type": ["boolean", "null"]},
        "exact_regeneration": {"type": ["boolean", "null"]},
    }
    properties = {
        "format": {"const": QUALIFICATION_CAMPAIGN_VERIFICATION_FORMAT},
        "valid": {"type": "boolean"},
        "reconciled": {"type": "boolean"},
        "eligible_for_independent_review": {"type": "boolean"},
        "mode": {"enum": ["complete", "integrity_only", "rejected"]},
        "checks": {
            "type": "object",
            "required": list(checks),
            "properties": checks,
            "additionalProperties": False,
        },
        "declared_content_sha256": {"type": "string", "maxLength": 64},
        "actual_content_sha256": {"type": "string", "maxLength": 64},
        "errors": {
            "type": "array",
            "maxItems": 100,
            "items": {"type": "string", "maxLength": 20_000},
        },
        "notice": {"type": "string", "minLength": 1, "maxLength": 20_000},
        "path": {"type": "string", "maxLength": 20_000},
        "source_bytes": {"type": "integer", "minimum": 0},
        "source_sha256": {"type": "string", "maxLength": 64},
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("qualification-campaign-verification"),
        "title": "PySFMEA qualification campaign verification",
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }


def _qualification_report_verification_schema() -> dict[str, Any]:
    declared_properties = {
        "report_format": {"type": "string", "maxLength": 100},
        "result_sha256": {"type": "string", "maxLength": 64},
        "payload_sha256": {"type": "string", "maxLength": 64},
        "document_sha256": {"type": "string", "maxLength": 64},
    }
    actual_properties = {
        "result_sha256": {"type": "string", "maxLength": 64},
        "payload_sha256": {"type": "string", "maxLength": 64},
        "document_sha256": {"type": "string", "maxLength": 64},
    }
    properties = {
        "format": {"const": QUALIFICATION_REPORT_VERIFICATION_FORMAT},
        "valid": {"type": "boolean"},
        "reconciled": {"type": "boolean"},
        "mode": {"enum": ["standalone", "complete", "rejected"]},
        "checks": {
            "type": "object",
            "required": list(QUALIFICATION_REPORT_CHECKS),
            "properties": {
                name: {"type": ["boolean", "null"]}
                for name in QUALIFICATION_REPORT_CHECKS
            },
            "additionalProperties": False,
        },
        "declared": {
            "type": "object",
            "required": list(declared_properties),
            "properties": declared_properties,
            "additionalProperties": False,
        },
        "actual": {
            "type": "object",
            "required": list(actual_properties),
            "properties": actual_properties,
            "additionalProperties": False,
        },
        "errors": {
            "type": "array",
            "maxItems": 100,
            "items": {"type": "string", "maxLength": 20_000},
        },
        "notice": {"type": "string", "minLength": 1, "maxLength": 20_000},
        "path": {"type": "string", "maxLength": 20_000},
        "source_bytes": {"type": "integer", "minimum": 0},
        "source_sha256": {"type": "string", "maxLength": 64},
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("qualification-report-verification"),
        "title": "PySFMEA qualification report verification",
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }


_SCHEMA_BUILDERS = {
    "calibration-comparison": _calibration_comparison_schema,
    "accessibility-evidence": _accessibility_evidence_sealed_schema,
    "accessibility-evidence-draft": _accessibility_evidence_draft_schema,
    "accessibility-evidence-verification": _accessibility_evidence_verification_schema,
    "activation-apply-receipt": _activation_apply_receipt_schema,
    "activation-records": _activation_records_schema,
    "activation-records-import-receipt": _activation_records_import_receipt_schema,
    "activation-workspace": _activation_workspace_schema,
    "activation-workspace-verification": _activation_workspace_verification_schema,
    "configuration-authoring": _configuration_authoring_schema,
    "configuration-authoring-apply-receipt": _configuration_authoring_apply_receipt_schema,
    "configuration-authoring-draft": _configuration_authoring_draft_schema,
    "configuration-authoring-verification": _configuration_authoring_verification_schema,
    "assurance-program": _assurance_program_schema,
    "assurance-program-report-verification": (
        _assurance_program_report_verification_schema
    ),
    "assurance-program-verification": _assurance_program_verification_schema,
    "assurance-scaffold": _assurance_scaffold_schema,
    "assurance-scaffold-verification": _assurance_scaffold_verification_schema,
    "assurance-test-proposal": _assurance_test_proposal_schema,
    "assurance-test-generation-readiness": _assurance_test_generation_readiness_schema,
    "assurance-test-generation-quality-corpus": (
        _assurance_test_generation_quality_corpus_schema
    ),
    "assurance-test-generation-quality-result": (
        _assurance_test_generation_quality_result_schema
    ),
    "assurance-test-proposal-apply-receipt": (
        _assurance_test_proposal_apply_receipt_schema
    ),
    "assurance-test-proposal-apply-receipt-verification": (
        _assurance_test_proposal_apply_receipt_verification_schema
    ),
    "assurance-test-proposal-stage": _assurance_test_proposal_stage_schema,
    "assurance-test-proposal-stage-verification": (
        _assurance_test_proposal_stage_verification_schema
    ),
    "assurance-test-proposal-verification": (
        _assurance_test_proposal_verification_schema
    ),
    "assurance-work-queue": _assurance_work_queue_schema,
    "assurance-work-queue-verification": _assurance_work_queue_verification_schema,
    "detached-signature": _detached_signature_schema,
    "evaluation-result": _evaluation_result_schema,
    "diagram": _diagram_schema,
    "diagram-bundle": _diagram_bundle_schema,
    "diagram-bundle-verification": _diagram_bundle_verification_schema,
    "cross-reference": _cross_reference_schema,
    "cross-reference-verification": _cross_reference_verification_schema,
    "enhancement-workbench": _enhancement_workbench_schema,
    "enhancement-workbench-verification": (_enhancement_workbench_verification_schema),
    "enhancement-scope-preview": _enhancement_scope_preview_schema,
    "evidence-preflight": _evidence_preflight_schema,
    "evidence-onboarding-receipt": _evidence_onboarding_receipt_schema,
    "evidence-onboarding-receipt-verification": (
        _evidence_onboarding_receipt_verification_schema
    ),
    "fault-injection-plan": _fault_injection_plan_schema,
    "fault-injection-plan-verification": _fault_injection_plan_verification_schema,
    "html-report-verification": _html_report_verification_schema,
    "golden-corpus": _golden_corpus_schema,
    "publication-failure-catalog": _publication_failure_catalog_schema,
    "publication-failure-catalog-verification": (
        _publication_failure_catalog_verification_schema
    ),
    "pull-request-analysis": _pull_request_analysis_schema,
    "pull-request-analysis-verification": _pull_request_analysis_verification_schema,
    "qualification-campaign-manifest": _qualification_manifest_schema,
    "qualification-campaign-result": _qualification_result_schema,
    "qualification-campaign-verification": _qualification_verification_schema,
    "qualification-report-verification": _qualification_report_verification_schema,
    "report-browser-quality": _report_browser_quality_schema,
    "report-browser-quality-verification": _report_browser_quality_verification_schema,
    "plugin-manifest": _plugin_manifest_schema,
    "plugin-request": _plugin_request_schema,
    "plugin-response": _plugin_response_schema,
    "plugin-run": _plugin_run_schema,
    "plugin-run-verification": _plugin_run_verification_schema,
    "schema-bundle-verification": _schema_bundle_verification_schema,
    "schema-catalog": _schema_catalog_schema,
    "sfta-authoring": _sfta_authoring_schema,
    "sfta-authoring-apply-receipt": _sfta_authoring_apply_receipt_schema,
    "sfta-authoring-draft": _sfta_authoring_draft_schema,
    "sfta-authoring-verification": _sfta_authoring_verification_schema,
    "synthesis-apply-receipt": _synthesis_apply_receipt_schema,
    "synthesis-apply-receipt-verification": (
        _synthesis_apply_receipt_verification_schema
    ),
    "synthesis-workspace": _synthesis_workspace_sealed_schema,
    "synthesis-workspace-draft": _synthesis_workspace_draft_schema,
    "synthesis-workspace-verification": _synthesis_workspace_verification_schema,
    "review-package-manifest": _review_package_manifest_schema,
    "review-package-verification": _review_package_verification_schema,
    "workflow-status": _workflow_status_schema,
}
_SCHEMA_DESCRIPTIONS = {
    "calibration-comparison": "Governed same-corpus scanner calibration comparison with semantic regression gates.",
    "accessibility-evidence": "Sealed, analysis-bound manual accessibility qualification evidence for the self-contained report.",
    "accessibility-evidence-draft": "Editable accessibility qualification workspace covering the required report scenarios.",
    "accessibility-evidence-verification": "Accessibility evidence integrity, scenario completeness, outcome, and optional exact-analysis binding verdict.",
    "activation-apply-receipt": "Exact-bound finding-review and governance-decision application receipt.",
    "activation-records": "Workspace-bound bulk assignment and decision interchange template.",
    "activation-records-import-receipt": "Transactional bulk activation-record import receipt.",
    "activation-workspace": "Editable, integrity-bound evidence onboarding and governed closure work package.",
    "activation-workspace-verification": "Activation-workspace integrity, decision semantics, and optional exact analysis-binding verdict.",
    "configuration-authoring": "Sealed exact-analysis-and-configuration-bound reviewed project configuration additions.",
    "configuration-authoring-apply-receipt": "Validated configuration publication and addition-count receipt.",
    "configuration-authoring-draft": "Editable guidance, architecture, and interface configuration proposal workspace.",
    "configuration-authoring-verification": "Configuration authoring integrity, semantics, and optional exact-binding verdict.",
    "assurance-program": "Multi-repository bindings, external requirements and trusted evidence, temporal and circuit-breaker relationships, independent validation/model quality, and governance policy.",
    "assurance-program-report-verification": "Standalone HTML report integrity and optional exact assurance-program regeneration verdicts.",
    "assurance-program-verification": "System assurance program integrity, binding, trusted-evidence, timing/resilience, quality-gate, and governance verdicts.",
    "assurance-scaffold": "Analysis-bound executable pytest starting points, property strategies, contract cases, and generated-file identities.",
    "assurance-scaffold-verification": "Scaffold integrity, synthesized-design, generated-file, lifecycle, and exact analysis-binding verdict.",
    "assurance-test-proposal": "Closed, source-bound, allowlisted LLM proposal for one accepted assurance-test obligation.",
    "assurance-test-generation-readiness": "Proposal-to-publication-to-independent-evidence readiness gates for one generated test.",
    "assurance-test-generation-quality-corpus": "Independently labeled provider/model/prompt corpus for generated-test validity, execution, effectiveness, and safety.",
    "assurance-test-generation-quality-result": "Recomputed subject-bound generated-test quality metrics and qualification gates.",
    "assurance-test-proposal-apply-receipt": "Human-reviewed atomic publication receipt for one generated assurance test.",
    "assurance-test-proposal-apply-receipt-verification": "Receipt integrity, proposal, analysis, review attribution, and exact applied-file binding verdict.",
    "assurance-test-proposal-stage": "Integrity-declaring isolated review-stage manifest for a verified generated test.",
    "assurance-test-proposal-stage-verification": "Stage file-set, integrity, proposal, analysis, and exact-content binding verdict.",
    "assurance-test-proposal-verification": "Proposal integrity, response-contract, exact-analysis, and source-binding verdict.",
    "assurance-work-queue": "Accepted-finding hardening states, blockers, eligibility, and next actions.",
    "assurance-work-queue-verification": "Work-queue integrity, analysis binding, and semantic-projection verdicts.",
    "detached-signature": "Detached Ed25519 package-signature envelope and subject binding.",
    "diagram": "Canonical renderer-neutral diagram model.",
    "diagram-bundle": "Generated, state-bound and digest-declaring diagram bundle.",
    "diagram-bundle-verification": "Diagram verification success and rejection verdicts.",
    "cross-reference": "Digest-bound cross-scanner, finding, guidance, SFTA, verification, and evidence relationship fabric.",
    "cross-reference-verification": "Cross-reference integrity, referential consistency, accounting, and exact-regeneration verdict.",
    "enhancement-workbench": "Integrated evidence acquisition, review clustering, assurance portfolio, static surface, and governance activation plan.",
    "enhancement-workbench-verification": "Bounded workbench integrity, register completeness, and optional exact analysis-regeneration verdict.",
    "enhancement-scope-preview": "Read-only bounded metadata preview for proposed evidence-only scope changes.",
    "evidence-preflight": "Read-only, analysis-bound test, coverage, contract, and runtime evidence readiness receipt.",
    "evidence-onboarding-receipt": "Source/result-bound validated import receipt for selected coverage, runtime, and execution evidence.",
    "evidence-onboarding-receipt-verification": "Receipt integrity and optional exact resulting-analysis binding verdict.",
    "evaluation-result": "Exact-key finding, call, control, confidence, and deterministic semantic evaluation result.",
    "fault-injection-plan": "Obligation-bound, integrity-declaring built-in fault-injection plan.",
    "fault-injection-plan-verification": "Fault-injection plan integrity, readiness, closed execution policy, plugin, case, and mandatory exact binding verdicts.",
    "html-report-verification": "HTML report verification success and rejection verdicts.",
    "golden-corpus": "Closed, bounded, identity-stable evaluation corpus for finding, call, control, and semantic qualification.",
    "publication-failure-catalog": "Package-publication failure phases, findings, and remediation actions.",
    "publication-failure-catalog-verification": "Publication catalog integrity and exact-taxonomy verdicts.",
    "pull-request-analysis": "Exact-commit base/head analysis bundle receipt with artifact, configuration, and security declarations.",
    "pull-request-analysis-verification": "Pull-request bundle file-set, integrity, regeneration, report, commit, and security-binding verdict.",
    "qualification-campaign-manifest": "Governed representative-repository selection, retained artifact references, feature thresholds, and independent-review claims for scanner qualification.",
    "qualification-campaign-result": "Exact-regenerated multi-repository finding, call-resolution, and control-detection qualification metrics segmented by rule, framework, and domain.",
    "qualification-campaign-verification": "Qualification campaign integrity, semantic consistency, manifest binding, and exact retained-artifact regeneration verdict.",
    "qualification-report-verification": "Self-contained qualification HTML document, embedded campaign result, and optional exact-result binding verdict.",
    "report-browser-quality": "Content-addressed Chromium navigation, performance, responsive-layout, accessibility, and UI-contract quality receipt.",
    "report-browser-quality-verification": "Receipt integrity, semantic consistency, and optional exact-report binding verdict.",
    "plugin-manifest": "Closed SDK plugin identity, compatibility, capability, entry point, trust, and execution-limit declaration.",
    "plugin-request": "Versioned, analysis-bound request envelope exchanged with an isolated SDK plugin process.",
    "plugin-response": "Versioned SDK plugin observation or error response envelope.",
    "plugin-run": "Content-addressed host receipt for a bounded plugin execution and its validated observations.",
    "plugin-run-verification": "Plugin-run integrity, protocol, observation, process-boundary, and optional analysis/manifest binding verdict.",
    "schema-bundle-verification": "Offline schema-set verification success and rejection verdicts.",
    "schema-catalog": "Content-addressed discovery catalog for public contracts.",
    "sfta-authoring": "Sealed exact-analysis-bound fault-tree engineering inputs.",
    "sfta-authoring-apply-receipt": "Fault-tree replacement and resulting SFTA-state application receipt.",
    "sfta-authoring-draft": "Editable one-entry-per-hazard fault-tree authoring workspace.",
    "sfta-authoring-verification": "SFTA authoring integrity, structure, logic, review, and optional binding verdict.",
    "synthesis-apply-receipt": "Source/result analysis and sealed-workspace bindings for applied synthesis decisions.",
    "synthesis-apply-receipt-verification": "Receipt integrity plus optional complete source/workspace/result and decision-accounting reconciliation verdict.",
    "synthesis-workspace": "Sealed, exact-analysis-bound failure-mode synthesis decisions with contradiction review.",
    "synthesis-workspace-draft": "Editable failure-mode synthesis and contradiction-resolution workspace.",
    "synthesis-workspace-verification": "Synthesis integrity, decision semantics, contradiction, and optional exact-analysis binding verdict.",
    "review-package-manifest": "Checksum, provenance, binding, and file inventory declaration.",
    "review-package-verification": "Package verification success and rejection verdicts.",
    "workflow-status": "Read-only lifecycle, handoff-gate, evidence, and remediation status.",
}


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
        SCHEMA_FILENAMES[name]: schema_document(name)
        for name in sorted(_SCHEMA_BUILDERS)
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
    assurance_program_names = publication_catalog_names | {"assurance-program"}
    assurance_program_verification_names = assurance_program_names | {
        "assurance-program-verification"
    }

    advanced_review_names = {
        "accessibility-evidence",
        "accessibility-evidence-draft",
        "accessibility-evidence-verification",
        "plugin-manifest",
        "plugin-request",
        "plugin-response",
        "plugin-run",
        "plugin-run-verification",
        "pull-request-analysis",
        "pull-request-analysis-verification",
        "cross-reference",
        "cross-reference-verification",
        "synthesis-apply-receipt",
        "synthesis-workspace",
        "synthesis-workspace-draft",
        "synthesis-workspace-verification",
    }
    pre_advanced_review_names = frozenset(_SCHEMA_BUILDERS) - advanced_review_names
    pre_evidence_onboarding_names = pre_advanced_review_names - {
        "evidence-onboarding-receipt",
        "evidence-onboarding-receipt-verification",
    }
    current_without_evidence_onboarding_names = frozenset(_SCHEMA_BUILDERS) - {
        "evidence-onboarding-receipt",
        "evidence-onboarding-receipt-verification",
    }
    pre_assurance_synthesis_names = pre_evidence_onboarding_names - {
        "assurance-scaffold",
        "assurance-scaffold-verification",
    }
    pre_advanced_without_assurance_synthesis_names = pre_advanced_review_names - {
        "assurance-scaffold",
        "assurance-scaffold-verification",
    }
    current_without_assurance_synthesis_names = frozenset(_SCHEMA_BUILDERS) - {
        "assurance-scaffold",
        "assurance-scaffold-verification",
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
        frozenset(assurance_program_names),
        frozenset(assurance_program_verification_names),
        pre_assurance_synthesis_names,
        pre_advanced_without_assurance_synthesis_names,
        current_without_assurance_synthesis_names,
        pre_evidence_onboarding_names,
        current_without_evidence_onboarding_names,
        pre_advanced_review_names,
        frozenset(_SCHEMA_BUILDERS),
    }
    catalog_names = frozenset(by_name)
    catalog_complete = (
        len(by_name) == len(entries) and catalog_names in supported_name_sets
    )
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
            add(
                "schema.file_missing",
                "Required schema-bundle file is missing.",
                filename,
            )
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
        expected_digest = (
            str(entry.get("sha256", "")) if isinstance(entry, dict) else ""
        )
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
                "schema_id": document.get("$id", "")
                if isinstance(document, dict)
                else "",
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
        add(
            "schema.bundle_directory",
            "Schema bundle must be a regular directory.",
            str(path),
        )
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
        add(
            "schema.bundle_entry_limit", "Schema bundle contains more than 100 entries."
        )
    for entry in entries[:101]:
        name = entry.name
        if name not in allowed:
            documents[name] = None
            continue
        if entry.is_symlink() or not entry.is_file():
            add(
                "schema.file_type", "Schema-bundle entries must be regular files.", name
            )
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
            add(
                "schema.file_invalid", f"Schema-bundle file cannot be read: {exc}", name
            )

    result = verify_schema_bundle_documents(documents)
    if input_errors:
        result["errors"] = input_errors + result["errors"]
        result["valid"] = False
        if any(error["code"].startswith("schema.bundle") for error in input_errors):
            result["checks"]["file_set"] = False
    return result


def export_schema_bundle(destination: str | Path, *, overwrite: bool = False) -> Path:
    """Atomically publish the complete offline public-schema bundle."""

    supplied = Path(destination).expanduser().absolute()
    path = supplied.resolve()
    documents = schema_bundle_documents()
    expected = set(documents)
    if supplied.is_symlink():
        raise ValueError(
            f"schema-bundle destination must not be a symbolic link: {supplied}"
        )
    if path.exists():
        if not path.is_dir():
            raise ValueError(
                f"schema-bundle destination must be a regular directory: {path}"
            )
        entries = list(path.iterdir())
        if entries and not overwrite:
            raise ValueError(
                f"schema-bundle destination is not empty: {path}; use --force"
            )
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
