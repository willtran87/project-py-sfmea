"""Public schemas for subject-bound LLM test-generation qualification."""

from __future__ import annotations

import copy
from typing import Any

from .test_generation import TEST_GENERATION_PROMPT_VERSION
from .test_generation_quality import (
    MAX_QUALITY_SAMPLES,
    TEST_GENERATION_CAMPAIGN_CORPUS_FORMAT,
    TEST_GENERATION_CAMPAIGN_RESULT_FORMAT,
    TEST_GENERATION_EVIDENCE_CORPUS_FORMAT,
    TEST_GENERATION_EVIDENCE_RESULT_FORMAT,
    TEST_GENERATION_FAULT_EVIDENCE_FORMAT,
    TEST_GENERATION_QUALITY_CORPUS_FORMAT,
    TEST_GENERATION_QUALITY_RESULT_FORMAT,
)

JSON_SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"


def _schema_id(name: str) -> str:
    return f"urn:pysfmea:schema:{name}:1"


def _subject() -> dict[str, Any]:
    text = {"type": "string", "minLength": 1, "maxLength": 20_000}
    return {
        "type": "object",
        "required": ["provider", "model", "prompt_version"],
        "properties": {
            "provider": text,
            "model": text,
            "prompt_version": {"const": TEST_GENERATION_PROMPT_VERSION},
        },
        "additionalProperties": False,
    }


def _governance() -> dict[str, Any]:
    text = {"type": "string", "minLength": 1, "maxLength": 20_000}
    return {
        "type": "object",
        "required": [
            "independent",
            "labeled_by",
            "reviewed_by",
            "review_date",
            "selection_method",
            "representativeness_rationale",
        ],
        "properties": {
            "independent": {"const": True},
            "labeled_by": text,
            "reviewed_by": text,
            "review_date": {"type": "string", "format": "date"},
            "selection_method": text,
            "representativeness_rationale": text,
        },
        "additionalProperties": False,
    }


def _policy() -> dict[str, Any]:
    count = {"type": "integer", "minimum": 1, "maximum": MAX_QUALITY_SAMPLES}
    rate = {"type": "number", "minimum": 0, "maximum": 1}
    fields = [
        "min_samples",
        "min_proposed_samples",
        "min_refused_samples",
        "min_decision_accuracy",
        "min_valid_proposal_rate",
        "min_execution_pass_rate",
        "min_stimulus_observed_rate",
        "min_criteria_pass_rate",
        "min_fault_detection_rate",
        "min_reviewer_acceptance_rate",
        "max_unsafe_change_rate",
    ]
    return {
        "type": "object",
        "required": fields,
        "properties": {
            **{name: count for name in fields[:3]},
            **{name: rate for name in fields[3:]},
        },
        "additionalProperties": False,
    }


def _assurance_test_generation_quality_corpus_schema() -> dict[str, Any]:
    boolean_fields = [
        "proposal_valid",
        "target_binding_valid",
        "restricted_execution_passed",
        "stimulus_observed",
        "acceptance_criteria_passed",
        "seeded_fault_detected",
        "unsafe_change_attempted",
    ]
    sample_fields = [
        "id",
        "expected_decision",
        "actual_decision",
        *boolean_fields,
        "reviewer_decision",
    ]
    properties = {
        "format": {"const": TEST_GENERATION_QUALITY_CORPUS_FORMAT},
        "name": {"type": "string", "minLength": 1, "maxLength": 20_000},
        "subject": _subject(),
        "governance": _governance(),
        "policy": _policy(),
        "samples": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_QUALITY_SAMPLES,
            "items": {
                "type": "object",
                "required": sample_fields,
                "properties": {
                    "id": {"type": "string", "minLength": 1, "maxLength": 20_000},
                    "expected_decision": {"enum": ["proposed", "refused"]},
                    "actual_decision": {"enum": ["proposed", "refused"]},
                    **{name: {"type": "boolean"} for name in boolean_fields},
                    "reviewer_decision": {
                        "enum": ["accepted", "rejected", "not_applicable"]
                    },
                },
                "additionalProperties": False,
            },
        },
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("assurance-test-generation-quality-corpus"),
        "title": "PySFMEA independently labeled LLM test-generation quality corpus",
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }


def _assurance_test_generation_quality_result_schema() -> dict[str, Any]:
    text = {"type": "string", "minLength": 1, "maxLength": 20_000}
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    metric = {"type": ["number", "null"], "minimum": 0, "maximum": 1}
    metric_names = [
        "decision_accuracy",
        "valid_proposal_rate",
        "target_binding_rate",
        "execution_pass_rate",
        "stimulus_observed_rate",
        "criteria_pass_rate",
        "fault_detection_rate",
        "reviewer_acceptance_rate",
        "unsafe_change_rate",
    ]
    properties = {
        "format": {"const": TEST_GENERATION_QUALITY_RESULT_FORMAT},
        "generated_at": text,
        "producer": {
            "type": "object",
            "required": ["name", "version"],
            "properties": {"name": text, "version": text},
            "additionalProperties": False,
        },
        "corpus": {
            "type": "object",
            "required": ["name", "sha256"],
            "properties": {"name": text, "sha256": digest},
            "additionalProperties": False,
        },
        "subject": _subject(),
        "governance": _governance(),
        "policy": _policy(),
        "population": {
            "type": "object",
            "required": [
                "samples",
                "expected_proposed",
                "expected_refused",
                "actual_proposed",
                "actual_refused",
            ],
            "properties": {
                name: {"type": "integer", "minimum": 0, "maximum": MAX_QUALITY_SAMPLES}
                for name in [
                    "samples",
                    "expected_proposed",
                    "expected_refused",
                    "actual_proposed",
                    "actual_refused",
                ]
            },
            "additionalProperties": False,
        },
        "metrics": {
            "type": "object",
            "required": metric_names,
            "properties": {name: metric for name in metric_names},
            "additionalProperties": False,
        },
        "gates": {
            "type": "array",
            "minItems": 14,
            "maxItems": 14,
            "items": {
                "type": "object",
                "required": ["id", "passed", "value", "operator", "threshold"],
                "properties": {
                    "id": text,
                    "passed": {"type": "boolean"},
                    "value": {"type": ["integer", "number", "null"], "minimum": 0},
                    "operator": {"enum": [">=", "<=", "=="]},
                    "threshold": {"type": ["integer", "number"], "minimum": 0},
                },
                "additionalProperties": False,
            },
        },
        "qualified": {"type": "boolean"},
        "status": {"enum": ["qualified_sample", "not_qualified"]},
        "evidence_fingerprint_sha256": digest,
        "notice": text,
        "content_sha256": digest,
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("assurance-test-generation-quality-result"),
        "title": "PySFMEA LLM test-generation qualification result",
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }


def _assurance_test_generation_quality_corpus_v2_schema() -> dict[str, Any]:
    schema = copy.deepcopy(_assurance_test_generation_quality_corpus_schema())
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    reference = {
        "type": "object",
        "required": ["path", "sha256"],
        "properties": {
            "path": {"type": "string", "minLength": 1, "maxLength": 20_000},
            "sha256": digest,
        },
        "additionalProperties": False,
    }
    schema["$id"] = _schema_id("assurance-test-generation-quality-corpus-v2")
    schema["title"] = "PySFMEA artifact-backed LLM test-generation quality corpus"
    schema["properties"]["format"] = {
        "const": TEST_GENERATION_EVIDENCE_CORPUS_FORMAT
    }
    schema["properties"]["samples"]["items"] = {
        "type": "object",
        "required": ["id", "expected_decision", "artifacts"],
        "properties": {
            "id": {"type": "string", "minLength": 1, "maxLength": 20_000},
            "expected_decision": {"enum": ["proposed", "refused"]},
            "artifacts": {
                "type": "object",
                "required": [
                    "analysis",
                    "proposal",
                    "application_receipt",
                    "fault_detection",
                ],
                "properties": {
                    "analysis": reference,
                    "proposal": reference,
                    "application_receipt": {"anyOf": [reference, {"type": "null"}]},
                    "fault_detection": {"anyOf": [reference, {"type": "null"}]},
                },
                "additionalProperties": False,
            },
        },
        "additionalProperties": False,
    }
    return schema


def _assurance_test_generation_quality_result_v2_schema() -> dict[str, Any]:
    schema = copy.deepcopy(_assurance_test_generation_quality_result_schema())
    text = {"type": "string", "minLength": 1, "maxLength": 20_000}
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    schema["$id"] = _schema_id("assurance-test-generation-quality-result-v2")
    schema["title"] = "PySFMEA artifact-backed LLM test-generation qualification result"
    schema["required"].append("evidence")
    schema["properties"]["format"] = {
        "const": TEST_GENERATION_EVIDENCE_RESULT_FORMAT
    }
    schema["properties"]["status"] = {
        "enum": ["qualified_artifact_sample", "not_qualified"]
    }
    schema["properties"]["gates"]["minItems"] = 15
    schema["properties"]["gates"]["maxItems"] = 15
    schema["properties"]["evidence"] = {
        "type": "object",
        "required": ["mode", "artifacts", "manifest_sha256", "records"],
        "properties": {
            "mode": {"const": "artifact_derived"},
            "artifacts": {"type": "integer", "minimum": 1},
            "manifest_sha256": digest,
            "records": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_QUALITY_SAMPLES * 4,
                "items": {
                    "type": "object",
                    "required": ["sample_id", "kind", "path", "sha256", "bytes"],
                    "properties": {
                        "sample_id": text,
                        "kind": {
                            "enum": [
                                "analysis",
                                "proposal",
                                "application_receipt",
                                "fault_detection",
                            ]
                        },
                        "path": text,
                        "sha256": digest,
                        "bytes": {"type": "integer", "minimum": 1},
                    },
                    "additionalProperties": False,
                },
            },
        },
        "additionalProperties": False,
    }
    return schema


def _assurance_test_generation_quality_corpus_v3_schema() -> dict[str, Any]:
    schema = copy.deepcopy(_assurance_test_generation_quality_corpus_v2_schema())
    text = {"type": "string", "minLength": 1, "maxLength": 20_000}
    count = {"type": "integer", "minimum": 1, "maximum": MAX_QUALITY_SAMPLES}
    rate = {"type": "number", "minimum": 0, "maximum": 1}
    schema["$id"] = _schema_id("assurance-test-generation-quality-corpus-v3")
    schema["title"] = (
        "PySFMEA stratified artifact-backed LLM test-generation quality corpus"
    )
    schema["properties"]["format"] = {
        "const": TEST_GENERATION_CAMPAIGN_CORPUS_FORMAT
    }
    governance = schema["properties"]["governance"]
    governance["required"].extend(["selection_frozen_at", "outcomes_observed_at"])
    governance["properties"].update(
        {
            "selection_frozen_at": {"type": "string", "format": "date-time"},
            "outcomes_observed_at": {"type": "string", "format": "date-time"},
        }
    )
    policy = schema["properties"]["policy"]
    campaign_counts = [
        "min_repositories",
        "min_frameworks",
        "min_domains",
        "min_fault_categories",
        "min_samples_per_repository",
        "min_samples_per_framework",
        "min_samples_per_domain",
    ]
    policy["required"].extend(
        [
            *campaign_counts,
            "require_decision_balance_per_repository",
            "max_single_repository_fraction",
        ]
    )
    policy["properties"].update(
        {
            **{name: count for name in campaign_counts},
            "require_decision_balance_per_repository": {"type": "boolean"},
            "max_single_repository_fraction": rate,
        }
    )
    sample = schema["properties"]["samples"]["items"]
    sample["required"].extend(
        ["repository_id", "frameworks", "domains", "fault_category"]
    )
    label_array = {
        "type": "array",
        "minItems": 1,
        "maxItems": 100,
        "uniqueItems": True,
        "items": text,
    }
    sample["properties"].update(
        {
            "repository_id": text,
            "frameworks": label_array,
            "domains": label_array,
            "fault_category": {"anyOf": [text, {"type": "null"}]},
        }
    )
    return schema


def _assurance_test_generation_quality_result_v3_schema() -> dict[str, Any]:
    schema = copy.deepcopy(_assurance_test_generation_quality_result_v2_schema())
    campaign_corpus_schema = _assurance_test_generation_quality_corpus_v3_schema()
    text = {"type": "string", "minLength": 1, "maxLength": 20_000}
    rate = {"type": "number", "minimum": 0, "maximum": 1}
    schema["$id"] = _schema_id("assurance-test-generation-quality-result-v3")
    schema["title"] = (
        "PySFMEA stratified artifact-backed LLM test-generation qualification result"
    )
    schema["properties"]["format"] = {
        "const": TEST_GENERATION_CAMPAIGN_RESULT_FORMAT
    }
    schema["properties"]["status"] = {
        "enum": ["qualified_stratified_artifact_sample", "not_qualified"]
    }
    schema["properties"]["governance"] = copy.deepcopy(
        campaign_corpus_schema["properties"]["governance"]
    )
    schema["properties"]["policy"] = copy.deepcopy(
        campaign_corpus_schema["properties"]["policy"]
    )
    schema["properties"]["gates"]["minItems"] = 25
    schema["properties"]["gates"]["maxItems"] = 25
    schema["required"].append("campaign")
    segment = {
        "type": "object",
        "required": [
            "id",
            "samples",
            "expected_proposed",
            "expected_refused",
            "actual_proposed",
            "actual_refused",
            "decision_accuracy",
            "fault_categories",
        ],
        "properties": {
            "id": text,
            **{
                name: {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": MAX_QUALITY_SAMPLES,
                }
                for name in [
                    "samples",
                    "expected_proposed",
                    "expected_refused",
                    "actual_proposed",
                    "actual_refused",
                ]
            },
            "decision_accuracy": rate,
            "fault_categories": {
                "type": "array",
                "maxItems": MAX_QUALITY_SAMPLES,
                "uniqueItems": True,
                "items": text,
            },
        },
        "additionalProperties": False,
    }
    segment_array = {
        "type": "array",
        "minItems": 1,
        "maxItems": MAX_QUALITY_SAMPLES,
        "items": segment,
    }
    schema["properties"]["campaign"] = {
        "type": "object",
        "required": [
            "design",
            "selection_frozen_at",
            "outcomes_observed_at",
            "repositories",
            "frameworks",
            "domains",
            "fault_categories",
            "max_single_repository_fraction",
            "fault_category_population",
            "segments",
        ],
        "properties": {
            "design": {"const": "stratified_artifact_replay"},
            "selection_frozen_at": {"type": "string", "format": "date-time"},
            "outcomes_observed_at": {"type": "string", "format": "date-time"},
            **{
                name: {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_QUALITY_SAMPLES,
                }
                for name in [
                    "repositories",
                    "frameworks",
                    "domains",
                    "fault_categories",
                ]
            },
            "max_single_repository_fraction": rate,
            "fault_category_population": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_QUALITY_SAMPLES,
                "items": {
                    "type": "object",
                    "required": ["id", "samples"],
                    "properties": {
                        "id": text,
                        "samples": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": MAX_QUALITY_SAMPLES,
                        },
                    },
                    "additionalProperties": False,
                },
            },
            "segments": {
                "type": "object",
                "required": ["repositories", "frameworks", "domains"],
                "properties": {
                    "repositories": segment_array,
                    "frameworks": segment_array,
                    "domains": segment_array,
                },
                "additionalProperties": False,
            },
        },
        "additionalProperties": False,
    }
    return schema


def _assurance_test_generation_fault_evidence_schema() -> dict[str, Any]:
    text = {"type": "string", "minLength": 1, "maxLength": 20_000}
    digest = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    run_properties = {
        "execution_id": {
            **text,
            "description": "Execution identifier in the bound analysis assurance register.",
        },
        "status": {"enum": ["passed", "failed"]},
        "evidence_sha256": {
            **digest,
            "description": (
                "SHA-256 of the execution.json manifest; semantic verification also "
                "replays every artifact named by that manifest."
            ),
        },
    }
    properties = {
        "format": {"const": TEST_GENERATION_FAULT_EVIDENCE_FORMAT},
        "sample_id": text,
        "test_sha256": digest,
        "environment": text,
        "baseline": {
            "type": "object",
            "required": list(run_properties),
            "properties": run_properties,
            "additionalProperties": False,
        },
        "seeded": {
            "type": "object",
            "required": [*run_properties, "fault_id"],
            "properties": {**run_properties, "fault_id": text},
            "additionalProperties": False,
        },
        "content_sha256": digest,
    }
    return {
        "$schema": JSON_SCHEMA_DRAFT,
        "$id": _schema_id("assurance-test-generation-fault-evidence"),
        "title": "PySFMEA paired baseline and seeded-fault detection evidence",
        "description": (
            "A content-sealed claim that receives credit only when reconciled to two "
            "distinct analysis-linked execution manifests and all retained raw artifacts."
        ),
        "type": "object",
        "required": list(properties),
        "properties": properties,
        "additionalProperties": False,
    }
