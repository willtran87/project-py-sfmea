"""Focused public-schema builders for authenticated campaign evidence."""

from __future__ import annotations

import copy
from typing import Any

ASSURANCE_EVIDENCE_SCHEMA_DESCRIPTIONS = {
    "json-evidence-signature": "Detached Ed25519 authentication of exact bounded JSON evidence bytes and canonical semantics.",
    "json-evidence-signature-verification": "Exact artifact, trusted-key fingerprint, and Ed25519 signature verdict.",
    "assurance-test-generation-campaign-plan": "Content-sealed pre-outcome sampling design and thresholds for a format-3 generated-test campaign.",
    "assurance-test-generation-campaign-plan-verification": "Campaign-plan integrity, chronology, and completed-corpus design-binding verdict.",
}


def json_evidence_signature_schema(schema_id: str, draft: str) -> dict[str, Any]:
    subject_fields = {
        "filename": {"type": "string", "minLength": 1},
        "bytes": {"type": "integer", "minimum": 0},
        "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "canonical_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "artifact_format": {"type": "string"},
    }
    statement_fields = {
        "format": {"const": "pysfmea-json-evidence-statement-1"},
        "algorithm": {"const": "Ed25519"},
        "signed_at": {"type": "string", "minLength": 1},
        "signer": {"type": "string", "minLength": 1, "maxLength": 4096},
        "subject": {
            "type": "object",
            "required": list(subject_fields),
            "properties": subject_fields,
            "additionalProperties": False,
        },
    }
    properties = {
        "format": {"const": "pysfmea-json-evidence-signature-1"},
        "statement": {
            "type": "object",
            "required": list(statement_fields),
            "properties": statement_fields,
            "additionalProperties": False,
        },
        "key_fingerprint": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
        "signature": {"type": "string", "minLength": 88, "maxLength": 88},
    }
    return _closed(
        schema_id,
        draft,
        "PySFMEA detached JSON evidence signature",
        properties,
    )


def json_evidence_signature_verification_schema(
    schema_id: str, draft: str
) -> dict[str, Any]:
    checks = [
        "artifact_readable",
        "envelope_contract",
        "artifact_binding",
        "trusted_key_binding",
        "signature",
    ]
    properties = {
        "format": {"const": "pysfmea-json-evidence-signature-verification-1"},
        "valid": {"type": "boolean"},
        "checks": {
            "type": "object",
            "required": checks,
            "properties": {name: {"type": "boolean"} for name in checks},
            "additionalProperties": False,
        },
        "signer": {"type": "string", "maxLength": 4096},
        "signed_at": {"type": "string"},
        "key_fingerprint": {"type": "string"},
        "errors": {"type": "array", "maxItems": 20, "items": {"type": "string"}},
        "notice": {"type": "string", "minLength": 1},
    }
    return _closed(
        schema_id,
        draft,
        "PySFMEA JSON evidence signature verification",
        properties,
    )


def test_generation_campaign_plan_schema(
    schema_id: str, draft: str, corpus_schema: dict[str, Any]
) -> dict[str, Any]:
    properties = copy.deepcopy(corpus_schema["properties"])
    properties["format"] = {"const": "pysfmea-test-generation-campaign-plan-1"}
    governance = properties["governance"]
    governance["required"].remove("outcomes_observed_at")
    del governance["properties"]["outcomes_observed_at"]
    sample = properties["samples"]["items"]
    sample["required"].remove("artifacts")
    del sample["properties"]["artifacts"]
    properties.update(
        {
            "sealed_at": {"type": "string", "format": "date-time"},
            "producer": {"type": "string", "minLength": 1, "maxLength": 20_000},
            "notice": {"type": "string", "minLength": 1, "maxLength": 20_000},
            "content_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        }
    )
    return _closed(
        schema_id,
        draft,
        "PySFMEA pre-outcome generated-test campaign plan",
        properties,
    )


def test_generation_campaign_plan_verification_schema(
    schema_id: str, draft: str
) -> dict[str, Any]:
    checks = [
        "plan_contract",
        "content_integrity",
        "selection_precedes_seal",
        "corpus_design_binding",
        "seal_precedes_outcomes",
    ]
    properties = {
        "format": {"const": "pysfmea-test-generation-campaign-plan-verification-1"},
        "valid": {"type": "boolean"},
        "plan_valid": {"type": "boolean"},
        "checks": {
            "type": "object",
            "required": checks,
            "properties": {name: {"type": ["boolean", "null"]} for name in checks},
            "additionalProperties": False,
        },
        "errors": {"type": "array", "maxItems": 20, "items": {"type": "string"}},
        "notice": {"type": "string", "minLength": 1},
    }
    return _closed(
        schema_id,
        draft,
        "PySFMEA generated-test campaign plan verification",
        properties,
    )


def _closed(
    schema_id: str,
    draft: str,
    title: str,
    properties: dict[str, Any],
) -> dict[str, Any]:
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": title,
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }
