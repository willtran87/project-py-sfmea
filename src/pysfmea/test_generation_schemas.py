"""Public JSON Schemas for governed LLM assurance-test implementation."""

from __future__ import annotations

from typing import Any

from .test_generation import (
    MAX_LIST_ITEMS as MAX_TEST_GENERATION_LIST_ITEMS,
)
from .test_generation import (
    MAX_TEST_FILE_BYTES,
    TEST_GENERATION_PACKET_FORMAT,
    TEST_GENERATION_READINESS_FORMAT,
    TEST_PROPOSAL_APPLY_FORMAT,
    TEST_PROPOSAL_APPLY_VERIFICATION_FORMAT,
    TEST_PROPOSAL_FORMAT,
    TEST_PROPOSAL_STAGE_FORMAT,
    TEST_PROPOSAL_STAGE_VERIFICATION_FORMAT,
    TEST_PROPOSAL_VERIFICATION_FORMAT,
)

JSON_SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"

def _schema_id(name: str) -> str:
    return f"urn:pysfmea:schema:{name}:1"


def _test_generation_response_schema(*, normalized: bool) -> dict[str, Any]:
    text = {"type": "string", "maxLength": 20_000}
    required_text = {**text, "minLength": 1}
    mapping = {
        "type": "object",
        "required": ["index", "assertion_reference"],
        "properties": {
            "index": {"type": "integer", "minimum": 1},
            "assertion_reference": required_text,
        },
        "additionalProperties": False,
    }
    file_value = {
        "type": "object",
        "required": ["path", "content", "purpose"],
        "properties": {
            "path": {
                "type": "string",
                "minLength": 1,
                "maxLength": 1_000,
                "pattern": r"^tests/(?:[^/]+/)*[^/]+\.py$",
            },
            "content": {
                "type": "string",
                "maxLength": MAX_TEST_FILE_BYTES,
            },
            "purpose": required_text,
        },
        "additionalProperties": False,
    }
    properties: dict[str, Any] = {
        "decision": {"enum": ["proposed", "refused"]},
        "rationale": required_text,
        "files": {"type": "array", "maxItems": 1, "items": file_value},
        "oracle_mappings": {
            "type": "array",
            "maxItems": MAX_TEST_GENERATION_LIST_ITEMS,
            "items": mapping,
        },
        "criterion_mappings": {
            "type": "array",
            "maxItems": MAX_TEST_GENERATION_LIST_ITEMS,
            "items": mapping,
        },
        "assumptions": {
            "type": "array",
            "maxItems": MAX_TEST_GENERATION_LIST_ITEMS,
            "items": required_text,
        },
        "unresolved_questions": {
            "type": "array",
            "maxItems": MAX_TEST_GENERATION_LIST_ITEMS,
            "items": required_text,
        },
    }
    if normalized:
        properties.update(
            {
                "implementation_ready": {"type": "boolean"},
                "source_validation": {
                    "type": "object",
                    "properties": {
                        "syntax_valid": {"const": True},
                        "test_functions": {"type": "integer", "minimum": 1},
                        "assertions": {"type": "integer", "minimum": 1},
                        "bytes": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": MAX_TEST_FILE_BYTES,
                        },
                        "sha256": {
                            "type": "string",
                            "pattern": r"^[0-9a-f]{64}$",
                        },
                    },
                    "additionalProperties": False,
                },
            }
        )
    return {
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }
def _assurance_test_proposal_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": r"^[0-9a-f]{64}$"}
    required_text = {"type": "string", "minLength": 1, "maxLength": 20_000}
    binding_properties = {
        "analysis_state_sha256": digest,
        "baseline_id": required_text,
        "obligation_id": required_text,
        "contract_sha256": digest,
        "test_designs_sha256": digest,
        "packet_sha256": digest,
        "response_sha256": digest,
    }
    packet = {
        "type": "object",
        "required": [
            "format",
            "prompt_version",
            "authority",
            "binding",
            "generation_eligibility",
            "allowed_changes",
            "obligation",
            "test_designs",
            "component",
            "source_context",
            "source_context_summary",
            "response_contract",
            "notice",
            "packet_sha256",
        ],
        "properties": {
            "format": {"const": TEST_GENERATION_PACKET_FORMAT},
            "prompt_version": required_text,
            "authority": required_text,
            "binding": {"type": "object", "minProperties": 5},
            "generation_eligibility": {
                "type": "object",
                "required": ["eligible", "blocking_reasons"],
                "properties": {
                    "eligible": {"type": "boolean"},
                    "blocking_reasons": {
                        "type": "array",
                        "maxItems": MAX_TEST_GENERATION_LIST_ITEMS,
                        "items": required_text,
                    },
                },
                "additionalProperties": False,
            },
            "allowed_changes": {"type": "object", "minProperties": 4},
            "obligation": {"type": "object", "minProperties": 1},
            "test_designs": {"type": "object", "minProperties": 1},
            "component": {"type": "object", "minProperties": 1},
            "source_context": {"type": "array", "minItems": 1, "maxItems": 12},
            "source_context_summary": {"type": "object", "minProperties": 3},
            "response_contract": {"type": "object", "minProperties": 1},
            "notice": required_text,
            "packet_sha256": digest,
        },
        "additionalProperties": False,
    }
    properties = {
        "format": {"const": TEST_PROPOSAL_FORMAT},
        "id": required_text,
        "created_at": required_text,
        "authority": required_text,
        "producer": {
            "type": "object",
            "required": ["name", "version", "provider", "model", "prompt_version"],
            "properties": {
                name: required_text
                for name in ["name", "version", "provider", "model", "prompt_version"]
            },
            "additionalProperties": False,
        },
        "generation": {
            "type": "object",
            "required": [
                "maximum_attempts",
                "attempts_used",
                "repair_performed",
                "attempt_records",
            ],
            "properties": {
                "maximum_attempts": {"type": "integer", "minimum": 1, "maximum": 3},
                "attempts_used": {"type": "integer", "minimum": 0, "maximum": 3},
                "repair_performed": {"type": "boolean"},
                "attempt_records": {
                    "type": "array",
                    "maxItems": 3,
                    "items": {
                        "type": "object",
                        "required": [
                            "attempt",
                            "response_sha256",
                            "accepted",
                            "validation_error",
                        ],
                        "properties": {
                            "attempt": {"type": "integer", "minimum": 1, "maximum": 3},
                            "response_sha256": digest,
                            "accepted": {"type": "boolean"},
                            "validation_error": {"type": "string", "maxLength": 20_000},
                        },
                        "additionalProperties": False,
                    },
                },
            },
            "additionalProperties": False,
        },
        "binding": {
            "type": "object",
            "required": list(binding_properties),
            "properties": binding_properties,
            "additionalProperties": False,
        },
        "packet": packet,
        "provider_response": _test_generation_response_schema(normalized=False),
        "response": _test_generation_response_schema(normalized=True),
        "notice": required_text,
        "content_sha256": digest,
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("assurance-test-proposal"),
        "title": "PySFMEA governed LLM assurance-test proposal",
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }

def _assurance_test_proposal_verification_schema() -> dict[str, Any]:
    checks = {
        name: {"type": ["boolean", "null"]}
        for name in [
            "format",
            "content_integrity",
            "packet_integrity",
            "response_contract",
            "analysis_binding",
            "source_binding",
        ]
    }
    properties = {
        "format": {"const": TEST_PROPOSAL_VERIFICATION_FORMAT},
        "verifier": {"type": "object", "minProperties": 2},
        "valid": {"type": "boolean"},
        "status": {"enum": ["valid", "invalid"]},
        "checks": {
            "type": "object",
            "required": list(checks),
            "properties": checks,
            "additionalProperties": False,
        },
        "errors": {
            "type": "array",
            "maxItems": 100,
            "items": {"type": "string", "maxLength": 20_000},
        },
        "proposal_id": {"type": "string", "maxLength": 20_000},
        "implementation_ready": {"type": "boolean"},
        "notice": {"type": "string", "minLength": 1, "maxLength": 20_000},
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("assurance-test-proposal-verification"),
        "title": "PySFMEA assurance-test proposal verification verdict",
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }


def _assurance_test_proposal_stage_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": r"^[0-9a-f]{64}$"}
    properties = {
        "format": {"const": TEST_PROPOSAL_STAGE_FORMAT},
        "proposal_id": {"type": "string", "minLength": 1, "maxLength": 20_000},
        "proposal_sha256": digest,
        "analysis_state_sha256": digest,
        "files": {
            "type": "array",
            "minItems": 1,
            "maxItems": 1,
            "items": {
                "type": "object",
                "required": ["path", "sha256", "bytes"],
                "properties": {
                    "path": {"type": "string", "pattern": r"^tests/.+\.py$"},
                    "sha256": digest,
                    "bytes": {"type": "integer", "minimum": 1, "maximum": MAX_TEST_FILE_BYTES},
                },
                "additionalProperties": False,
            },
        },
        "status": {"const": "staged_unreviewed"},
        "next_actions": {
            "type": "array",
            "minItems": 1,
            "maxItems": 10,
            "items": {"type": "string", "minLength": 1, "maxLength": 20_000},
        },
        "content_sha256": digest,
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("assurance-test-proposal-stage"),
        "title": "PySFMEA isolated assurance-test proposal stage manifest",
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }


def _assurance_test_proposal_stage_verification_schema() -> dict[str, Any]:
    check_names = [
        "directory",
        "manifest_contract",
        "manifest_integrity",
        "proposal_binding",
        "analysis_binding",
        "file_set",
        "file_integrity",
        "file_content",
    ]
    properties = {
        "format": {"const": TEST_PROPOSAL_STAGE_VERIFICATION_FORMAT},
        "verifier": {"type": "object", "minProperties": 2},
        "valid": {"type": "boolean"},
        "status": {"enum": ["valid", "invalid"]},
        "checks": {
            "type": "object",
            "required": check_names,
            "properties": {name: {"type": "boolean"} for name in check_names},
            "additionalProperties": False,
        },
        "errors": {
            "type": "array",
            "maxItems": 100,
            "items": {"type": "string", "maxLength": 20_000},
        },
        "proposal_id": {"type": "string", "maxLength": 20_000},
        "stage": {"type": "string", "maxLength": 20_000},
        "notice": {"type": "string", "minLength": 1, "maxLength": 20_000},
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("assurance-test-proposal-stage-verification"),
        "title": "PySFMEA assurance-test proposal stage verification verdict",
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }


def _assurance_test_proposal_apply_receipt_schema() -> dict[str, Any]:
    digest = {"type": "string", "pattern": r"^[0-9a-f]{64}$"}
    required_text = {"type": "string", "minLength": 1, "maxLength": 20_000}
    properties = {
        "format": {"const": TEST_PROPOSAL_APPLY_FORMAT},
        "id": required_text,
        "applied_at": required_text,
        "status": {"const": "applied_unregistered"},
        "authority": required_text,
        "proposal_id": required_text,
        "proposal_sha256": digest,
        "analysis_state_sha256": digest,
        "baseline_id": required_text,
        "obligation_id": required_text,
        "review": {
            "type": "object",
            "required": ["reviewer", "rationale"],
            "properties": {"reviewer": required_text, "rationale": required_text},
            "additionalProperties": False,
        },
        "file": {
            "type": "object",
            "required": ["path", "sha256", "bytes"],
            "properties": {
                "path": {"type": "string", "pattern": r"^tests/.+\.py$"},
                "sha256": digest,
                "bytes": {"type": "integer", "minimum": 1, "maximum": MAX_TEST_FILE_BYTES},
            },
            "additionalProperties": False,
        },
        "next_actions": {
            "type": "array",
            "minItems": 1,
            "maxItems": 10,
            "items": required_text,
        },
        "content_sha256": digest,
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("assurance-test-proposal-apply-receipt"),
        "title": "PySFMEA assurance-test proposal application receipt",
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }


def _assurance_test_proposal_apply_receipt_verification_schema() -> dict[str, Any]:
    check_names = [
        "contract",
        "content_integrity",
        "proposal_binding",
        "analysis_binding",
        "review_attribution",
        "file_binding",
    ]
    properties = {
        "format": {"const": TEST_PROPOSAL_APPLY_VERIFICATION_FORMAT},
        "verifier": {"type": "object", "minProperties": 2},
        "valid": {"type": "boolean"},
        "status": {"enum": ["valid", "invalid"]},
        "checks": {
            "type": "object",
            "required": check_names,
            "properties": {name: {"type": "boolean"} for name in check_names},
            "additionalProperties": False,
        },
        "errors": {
            "type": "array",
            "maxItems": 100,
            "items": {"type": "string", "maxLength": 20_000},
        },
        "receipt_id": {"type": "string", "maxLength": 20_000},
        "proposal_id": {"type": "string", "maxLength": 20_000},
        "notice": {"type": "string", "minLength": 1, "maxLength": 20_000},
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("assurance-test-proposal-apply-receipt-verification"),
        "title": "PySFMEA assurance-test application receipt verification verdict",
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }


def _assurance_test_generation_readiness_schema() -> dict[str, Any]:
    properties = {
        "format": {"const": TEST_GENERATION_READINESS_FORMAT},
        "ready": {"type": "boolean"},
        "status": {"enum": ["assurance_ready", "blocked"]},
        "proposal_id": {"type": "string", "maxLength": 20_000},
        "receipt_id": {"type": "string", "maxLength": 20_000},
        "obligation_id": {"type": "string", "maxLength": 20_000},
        "gates": {
            "type": "array",
            "minItems": 7,
            "maxItems": 7,
            "items": {
                "type": "object",
                "required": ["id", "passed", "remediation"],
                "properties": {
                    "id": {"type": "string", "minLength": 1, "maxLength": 100},
                    "passed": {"type": "boolean"},
                    "remediation": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 20_000,
                    },
                },
                "additionalProperties": False,
            },
        },
        "passed_gates": {"type": "integer", "minimum": 0, "maximum": 7},
        "required_gates": {"const": 7},
        "execution_ids": {
            "type": "array",
            "maxItems": 10_000,
            "items": {"type": "string", "maxLength": 20_000},
        },
        "notice": {"type": "string", "minLength": 1, "maxLength": 20_000},
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("assurance-test-generation-readiness"),
        "title": "PySFMEA generated assurance-test readiness gates",
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }
