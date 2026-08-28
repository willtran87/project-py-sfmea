"""Public JSON Schema builders for standards and assurance-case artifacts."""

from __future__ import annotations

from typing import Any, Callable

from .assurance_case import ASSURANCE_CASE_FORMAT, ASSURANCE_CASE_VERIFICATION_FORMAT
from .benchmark_assurance import (
    BENCHMARK_ASSESSMENT_FORMAT,
    BENCHMARK_PROTOCOL_FORMAT,
    BENCHMARK_VERIFICATION_FORMAT,
    METRIC_NAMES,
    REQUALIFICATION_TRIGGERS,
)
from .conformance import (
    APPLICABILITY,
    ASSESSMENT_STATUSES,
    CONFORMANCE_CATALOG_FORMAT,
    CONFORMANCE_VERIFICATION_FORMAT,
    CONFORMANCE_WORKSPACE_FORMAT,
)
from .slsa import (
    SLSA_BUILD_TYPE,
    SLSA_BUILDER_ID,
    SLSA_PREDICATE_TYPE,
    SLSA_STATEMENT_TYPE,
    SLSA_VERIFICATION_FORMAT,
)
from .tool_qualification import (
    ANOMALY_STATUSES,
    TOOL_QUALIFICATION_FORMAT,
    TOOL_QUALIFICATION_VERIFICATION_FORMAT,
)
from .tool_qualification import (
    APPLICABILITY as TOOL_APPLICABILITY,
)
from .tool_qualification import (
    STATUSES as TOOL_STATUSES,
)

INDUSTRY_SCHEMA_DESCRIPTIONS = {
    "standards-catalog": "Content-addressed public metadata and original objective summaries for selectable industry standards profiles.",
    "conformance-workspace": "Exact-analysis-bound applicability, tailoring, objective assessment, evidence-reference, and reviewer workspace.",
    "conformance-verification": "Conformance-workspace integrity, catalog, semantics, summary, and optional analysis-binding verdict.",
    "assurance-case": "ISO 15026 and OMG SACM-aligned claims, arguments, evidence, relationships, assumptions, and defeaters.",
    "assurance-case-verification": "Assurance-case integrity, graph, coverage, status, and optional exact-analysis-binding verdict.",
    "slsa-provenance": "in-toto Statement carrying SLSA Provenance v1 for an exact PySFMEA analysis artifact.",
    "slsa-provenance-verification": "SLSA structure, builder, materials, and optional exact analysis subject/state binding verdict.",
    "independent-benchmark-assessment": "Pre-registered holdout design, Wilson confidence intervals, reviewer agreement, and exact qualification-campaign bindings.",
    "independent-benchmark-verification": "Benchmark assessment integrity, statistical reconciliation, and optional exact-source regeneration verdict.",
    "tool-qualification-dossier": "Exact-bound qualification objectives, intended use, classification, benchmark, conformance, configuration, and anomaly evidence.",
    "tool-qualification-verification": "Tool qualification dossier integrity and authorized-decision-readiness verdict.",
}


def _digest() -> dict[str, Any]:
    return {"type": "string", "pattern": "^[0-9a-f]{64}$"}


def _text(*, required: bool = True) -> dict[str, Any]:
    result: dict[str, Any] = {"type": "string", "maxLength": 20_000}
    if required:
        result["minLength"] = 1
    return result


def _identifier() -> dict[str, Any]:
    return {
        "type": "string",
        "minLength": 1,
        "maxLength": 200,
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    }


def standards_catalog_schema(schema_id: str, draft: str) -> dict[str, Any]:
    objective = {
        "type": "object",
        "required": ["id", "title", "reference_locator", "expected_evidence"],
        "properties": {
            "id": _identifier(),
            "title": _text(),
            "reference_locator": _text(),
            "expected_evidence": {
                "type": "array",
                "minItems": 1,
                "maxItems": 100,
                "uniqueItems": True,
                "items": _text(),
            },
        },
        "additionalProperties": False,
    }
    profile = {
        "type": "object",
        "required": [
            "id",
            "title",
            "publisher",
            "edition",
            "status",
            "reference_url",
            "access",
            "scope",
            "objectives",
        ],
        "properties": {
            "id": _identifier(),
            "title": _text(),
            "publisher": _text(),
            "edition": _text(),
            "status": _text(),
            "reference_url": {"type": "string", "format": "uri", "maxLength": 2_000},
            "access": _text(),
            "scope": _text(),
            "objectives": {
                "type": "array",
                "minItems": 1,
                "maxItems": 100,
                "items": objective,
            },
        },
        "additionalProperties": False,
    }
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA governed industry standards catalog",
        "type": "object",
        "required": [
            "format",
            "version",
            "profiles",
            "authority",
            "notice",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": CONFORMANCE_CATALOG_FORMAT},
            "version": _text(),
            "profiles": {
                "type": "array",
                "minItems": 1,
                "maxItems": 100,
                "items": profile,
            },
            "authority": _text(),
            "notice": _text(),
            "content_sha256": _digest(),
        },
        "additionalProperties": False,
    }


def conformance_workspace_schema(schema_id: str, draft: str) -> dict[str, Any]:
    objective = {
        "type": "object",
        "required": [
            "id",
            "title",
            "reference_locator",
            "expected_evidence",
            "applicability",
            "status",
            "rationale",
            "evidence_refs",
            "reviewer",
            "reviewed_at",
        ],
        "properties": {
            "id": _identifier(),
            "title": _text(),
            "reference_locator": _text(),
            "expected_evidence": {
                "type": "array",
                "minItems": 1,
                "maxItems": 100,
                "items": _text(),
            },
            "applicability": {"enum": sorted(APPLICABILITY)},
            "status": {"enum": sorted(ASSESSMENT_STATUSES)},
            "rationale": _text(required=False),
            "evidence_refs": {
                "type": "array",
                "maxItems": 1_000,
                "uniqueItems": True,
                "items": _text(),
            },
            "reviewer": _text(required=False),
            "reviewed_at": _text(required=False),
        },
        "additionalProperties": False,
    }
    catalog_profile = standards_catalog_schema(schema_id, draft)["properties"][
        "profiles"
    ]["items"]
    profile_properties = dict(catalog_profile["properties"])
    profile_properties["objectives"] = {
        "type": "array",
        "minItems": 1,
        "maxItems": 100,
        "items": objective,
    }
    profile = {**catalog_profile, "properties": profile_properties}
    count_map = {
        "type": "object",
        "additionalProperties": {"type": "integer", "minimum": 0},
    }
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA standards conformance workspace",
        "type": "object",
        "required": [
            "format",
            "generated_at",
            "catalog",
            "scope",
            "binding",
            "profiles",
            "summary",
            "claim",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": CONFORMANCE_WORKSPACE_FORMAT},
            "generated_at": _text(),
            "catalog": {
                "type": "object",
                "required": ["version", "content_sha256"],
                "properties": {"version": _text(), "content_sha256": _digest()},
                "additionalProperties": False,
            },
            "scope": {
                "type": "object",
                "required": [
                    "system",
                    "lifecycle_phase",
                    "applicability_basis",
                    "authority",
                ],
                "properties": {
                    name: _text()
                    for name in (
                        "system",
                        "lifecycle_phase",
                        "applicability_basis",
                        "authority",
                    )
                },
                "additionalProperties": False,
            },
            "binding": {
                "type": "object",
                "required": [
                    "baseline_id",
                    "analysis_schema_version",
                    "analysis_state_sha256",
                ],
                "properties": {
                    "baseline_id": _text(required=False),
                    "analysis_schema_version": _text(),
                    "analysis_state_sha256": _digest(),
                },
                "additionalProperties": False,
            },
            "profiles": {
                "type": "array",
                "minItems": 1,
                "maxItems": 100,
                "items": profile,
            },
            "summary": {
                "type": "object",
                "required": [
                    "profiles",
                    "objectives",
                    "by_applicability",
                    "by_status",
                    "assessment_complete",
                    "conformance_supported",
                    "blocking_objective_ids",
                ],
                "properties": {
                    "profiles": {"type": "integer", "minimum": 1},
                    "objectives": {"type": "integer", "minimum": 1},
                    "by_applicability": count_map,
                    "by_status": count_map,
                    "assessment_complete": {"type": "boolean"},
                    "conformance_supported": {"type": "boolean"},
                    "blocking_objective_ids": {
                        "type": "array",
                        "maxItems": 500,
                        "uniqueItems": True,
                        "items": _identifier(),
                    },
                },
                "additionalProperties": False,
            },
            "claim": _text(),
            "content_sha256": _digest(),
        },
        "additionalProperties": False,
    }


def _checks(names: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "required": names,
        "properties": {name: {"type": ["boolean", "null"]} for name in names},
        "additionalProperties": False,
    }


def conformance_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    check_names = [
        "closed_structure",
        "content_integrity",
        "catalog_binding",
        "profile_integrity",
        "assessment_semantics",
        "summary_reconciliation",
        "analysis_binding",
    ]
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA standards conformance verification",
        "type": "object",
        "required": [
            "format",
            "valid",
            "assessment_complete",
            "conformance_supported",
            "checks",
            "errors",
            "profile_ids",
            "objective_count",
            "content_sha256",
            "notice",
        ],
        "properties": {
            "format": {"const": CONFORMANCE_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "assessment_complete": {"type": "boolean"},
            "conformance_supported": {"type": "boolean"},
            "checks": _checks(check_names),
            "errors": {"type": "array", "maxItems": 1_000, "items": _text()},
            "profile_ids": {
                "type": "array",
                "maxItems": 100,
                "uniqueItems": True,
                "items": _identifier(),
            },
            "objective_count": {"type": "integer", "minimum": 0, "maximum": 500},
            "content_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"},
            "notice": _text(),
        },
        "additionalProperties": False,
    }


def assurance_case_schema(schema_id: str, draft: str) -> dict[str, Any]:
    claim_status = {
        "enum": ["supported", "partially_supported", "unsupported", "indeterminate"]
    }
    claim: dict[str, Any] = {
        "type": "object",
        "required": ["id", "title", "statement", "status", "scope", "assumptions"],
        "properties": {
            "id": _identifier(),
            "title": _text(),
            "statement": _text(),
            "status": claim_status,
            "scope": _text(),
            "assumptions": {"type": "array", "maxItems": 100, "items": _text()},
        },
        "additionalProperties": False,
    }
    argument: dict[str, Any] = {
        "type": "object",
        "required": ["id", "claim_id", "strategy", "reasoning", "status"],
        "properties": {
            "id": _identifier(),
            "claim_id": _identifier(),
            "strategy": _text(),
            "reasoning": _text(),
            "status": claim_status,
        },
        "additionalProperties": False,
    }
    evidence = {
        "type": "object",
        "required": [
            "id",
            "kind",
            "artifact",
            "bytes",
            "sha256",
            "content_sha256",
            "description",
            "authority",
            "limitations",
        ],
        "properties": {
            "id": _identifier(),
            "kind": _identifier(),
            "artifact": _text(),
            "bytes": {"type": "integer", "minimum": 0},
            "sha256": _digest(),
            "content_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"},
            "description": _text(),
            "authority": _text(),
            "limitations": _text(),
        },
        "additionalProperties": False,
    }
    defeater = {
        "type": "object",
        "required": ["id", "claim_id", "statement", "resolution"],
        "properties": {
            "id": _identifier(),
            "claim_id": _identifier(),
            "statement": _text(),
            "resolution": _text(),
        },
        "additionalProperties": False,
    }
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA structured assurance case",
        "type": "object",
        "required": [
            "format",
            "generated_at",
            "tool",
            "binding",
            "standards_alignment",
            "claims",
            "arguments",
            "evidence",
            "relationships",
            "defeaters",
            "summary",
            "authority",
            "notice",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": ASSURANCE_CASE_FORMAT},
            "generated_at": _text(),
            "tool": {
                "type": "object",
                "required": ["name", "version"],
                "properties": {"name": {"const": "PySFMEA"}, "version": _text()},
                "additionalProperties": False,
            },
            "binding": {
                "type": "object",
                "required": [
                    "baseline_id",
                    "analysis_schema_version",
                    "analysis_state_sha256",
                ],
                "properties": {
                    "baseline_id": _text(required=False),
                    "analysis_schema_version": _text(),
                    "analysis_state_sha256": _digest(),
                },
                "additionalProperties": False,
            },
            "standards_alignment": {
                "type": "object",
                "required": ["iso_iec_ieee_15026_2", "omg_sacm_2_3", "conformance"],
                "properties": {
                    name: _text()
                    for name in ("iso_iec_ieee_15026_2", "omg_sacm_2_3", "conformance")
                },
                "additionalProperties": False,
            },
            "claims": {
                "type": "array",
                "minItems": 1,
                "maxItems": 10_000,
                "items": claim,
            },
            "arguments": {
                "type": "array",
                "minItems": 1,
                "maxItems": 10_000,
                "items": argument,
            },
            "evidence": {
                "type": "array",
                "minItems": 1,
                "maxItems": 10_000,
                "items": evidence,
            },
            "relationships": {
                "type": "array",
                "maxItems": 50_000,
                "items": {
                    "type": "object",
                    "required": ["source", "target", "type"],
                    "properties": {
                        "source": _identifier(),
                        "target": _identifier(),
                        "type": {"enum": ["supports", "in_context_of", "challenges"]},
                    },
                    "additionalProperties": False,
                },
            },
            "defeaters": {"type": "array", "maxItems": 10_000, "items": defeater},
            "summary": {
                "type": "object",
                "required": [
                    "top_claim_id",
                    "top_claim_status",
                    "claims",
                    "supported_claims",
                    "arguments",
                    "evidence",
                    "open_defeaters",
                ],
                "properties": {
                    "top_claim_id": {"const": "C-TOP"},
                    "top_claim_status": claim_status,
                    **{
                        name: {"type": "integer", "minimum": 0}
                        for name in (
                            "claims",
                            "supported_claims",
                            "arguments",
                            "evidence",
                            "open_defeaters",
                        )
                    },
                },
                "additionalProperties": False,
            },
            "authority": _text(),
            "notice": _text(),
            "content_sha256": _digest(),
        },
        "additionalProperties": False,
    }


def assurance_case_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    names = [
        "closed_structure",
        "content_integrity",
        "unique_identifiers",
        "evidence_artifact_integrity",
        "relationship_integrity",
        "claim_argument_coverage",
        "status_reconciliation",
        "analysis_binding",
    ]
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA structured assurance-case verification",
        "type": "object",
        "required": [
            "format",
            "valid",
            "top_claim_status",
            "decision_ready",
            "checks",
            "errors",
            "content_sha256",
            "notice",
        ],
        "properties": {
            "format": {"const": ASSURANCE_CASE_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "top_claim_status": {
                "enum": [
                    "supported",
                    "partially_supported",
                    "unsupported",
                    "indeterminate",
                ]
            },
            "decision_ready": {"type": "boolean"},
            "checks": _checks(names),
            "errors": {"type": "array", "maxItems": 1_000, "items": _text()},
            "content_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"},
            "notice": _text(),
        },
        "additionalProperties": False,
    }


def slsa_provenance_schema(schema_id: str, draft: str) -> dict[str, Any]:
    digest_map = {
        "type": "object",
        "minProperties": 1,
        "additionalProperties": {"type": "string", "minLength": 1, "maxLength": 256},
    }
    material = {
        "type": "object",
        "required": ["uri", "digest"],
        "properties": {"uri": _text(), "digest": digest_map},
        "additionalProperties": False,
    }
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA SLSA v1 analysis provenance",
        "type": "object",
        "required": ["_type", "subject", "predicateType", "predicate"],
        "properties": {
            "_type": {"const": SLSA_STATEMENT_TYPE},
            "subject": {
                "type": "array",
                "minItems": 1,
                "maxItems": 1,
                "items": {
                    "type": "object",
                    "required": ["name", "digest"],
                    "properties": {
                        "name": _text(),
                        "digest": {
                            "type": "object",
                            "required": ["sha256"],
                            "properties": {"sha256": _digest()},
                            "additionalProperties": False,
                        },
                    },
                    "additionalProperties": False,
                },
            },
            "predicateType": {"const": SLSA_PREDICATE_TYPE},
            "predicate": {
                "type": "object",
                "required": ["buildDefinition", "runDetails"],
                "properties": {
                    "buildDefinition": {
                        "type": "object",
                        "required": [
                            "buildType",
                            "externalParameters",
                            "internalParameters",
                            "resolvedDependencies",
                        ],
                        "properties": {
                            "buildType": {"const": SLSA_BUILD_TYPE},
                            "externalParameters": {"type": "object"},
                            "internalParameters": {"type": "object"},
                            "resolvedDependencies": {
                                "type": "array",
                                "maxItems": 1_000,
                                "items": material,
                            },
                        },
                        "additionalProperties": False,
                    },
                    "runDetails": {
                        "type": "object",
                        "required": ["builder", "metadata", "byproducts"],
                        "properties": {
                            "builder": {
                                "type": "object",
                                "required": ["id", "version"],
                                "properties": {
                                    "id": {"const": SLSA_BUILDER_ID},
                                    "version": {
                                        "type": "object",
                                        "required": ["pysfmea"],
                                        "properties": {"pysfmea": _text()},
                                        "additionalProperties": False,
                                    },
                                },
                                "additionalProperties": False,
                            },
                            "metadata": {
                                "type": "object",
                                "required": ["invocationId", "startedOn", "finishedOn"],
                                "properties": {
                                    name: _text(required=False)
                                    for name in (
                                        "invocationId",
                                        "startedOn",
                                        "finishedOn",
                                    )
                                },
                                "additionalProperties": False,
                            },
                            "byproducts": {"type": "array", "maxItems": 1_000},
                        },
                        "additionalProperties": False,
                    },
                },
                "additionalProperties": False,
            },
        },
        "additionalProperties": False,
    }


def slsa_provenance_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    names = [
        "statement_type",
        "predicate_type",
        "closed_subject",
        "build_definition",
        "builder_identity",
        "material_digests",
        "analysis_subject_binding",
        "analysis_state_binding",
    ]
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA SLSA provenance verification",
        "type": "object",
        "required": ["format", "valid", "checks", "errors", "subject_sha256", "notice"],
        "properties": {
            "format": {"const": SLSA_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "checks": _checks(names),
            "errors": {"type": "array", "maxItems": 1_000, "items": _text()},
            "subject_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"},
            "notice": _text(),
        },
        "additionalProperties": False,
    }


def _artifact_binding(*, analysis: bool = False) -> dict[str, Any]:
    properties = {
        "reference": _text(),
        "bytes": {"type": "integer", "minimum": 0, "maximum": 100_000_000},
        "sha256": _digest(),
        "canonical_sha256": _digest(),
    }
    required = list(properties)
    if analysis:
        properties["analysis_state_sha256"] = _digest()
        required.append("analysis_state_sha256")
    return {
        "type": "object",
        "required": required,
        "properties": properties,
        "additionalProperties": False,
    }


def _benchmark_protocol() -> dict[str, Any]:
    string_array = {
        "type": "array",
        "minItems": 1,
        "maxItems": 1_000,
        "uniqueItems": True,
        "items": _text(),
    }
    return {
        "type": "object",
        "required": [
            "format",
            "id",
            "title",
            "pre_registered_at",
            "pre_registration_evidence_ref",
            "governance",
            "design",
            "statistics",
            "reviewer_agreement",
            "requalification_triggers",
        ],
        "properties": {
            "format": {"const": BENCHMARK_PROTOCOL_FORMAT},
            "id": _identifier(),
            "title": _text(),
            "pre_registered_at": _text(),
            "pre_registration_evidence_ref": _text(),
            "governance": {
                "type": "object",
                "required": [
                    "protocol_owner",
                    "label_authority",
                    "approval_authority",
                    "independence_basis",
                ],
                "properties": {
                    name: _text()
                    for name in (
                        "protocol_owner",
                        "label_authority",
                        "approval_authority",
                        "independence_basis",
                    )
                },
                "additionalProperties": False,
            },
            "design": {
                "type": "object",
                "required": [
                    "frozen_before_execution",
                    "blinded_holdout",
                    "minimum_holdout_repositories",
                    "holdout_repository_ids",
                    "selection_method",
                    "represented_populations",
                    "excluded_populations",
                ],
                "properties": {
                    "frozen_before_execution": {"const": True},
                    "blinded_holdout": {"const": True},
                    "minimum_holdout_repositories": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 1_000,
                    },
                    "holdout_repository_ids": string_array,
                    "selection_method": _text(),
                    "represented_populations": string_array,
                    "excluded_populations": string_array,
                },
                "additionalProperties": False,
            },
            "statistics": {
                "type": "object",
                "required": [
                    "confidence_level",
                    "minimum_lower_bounds",
                    "minimum_cohen_kappa",
                ],
                "properties": {
                    "confidence_level": {
                        "type": "number",
                        "minimum": 0.8,
                        "exclusiveMaximum": 1.0,
                    },
                    "minimum_lower_bounds": {
                        "type": "object",
                        "required": list(METRIC_NAMES),
                        "properties": {
                            name: {"type": "number", "minimum": 0, "maximum": 1}
                            for name in METRIC_NAMES
                        },
                        "additionalProperties": False,
                    },
                    "minimum_cohen_kappa": {
                        "type": "number",
                        "minimum": -1,
                        "maximum": 1,
                    },
                },
                "additionalProperties": False,
            },
            "reviewer_agreement": {
                "type": "object",
                "required": [
                    "both_positive",
                    "primary_only",
                    "secondary_only",
                    "both_negative",
                    "adjudication_evidence_ref",
                ],
                "properties": {
                    **{
                        name: {"type": "integer", "minimum": 0}
                        for name in (
                            "both_positive",
                            "primary_only",
                            "secondary_only",
                            "both_negative",
                        )
                    },
                    "adjudication_evidence_ref": _text(),
                },
                "additionalProperties": False,
            },
            "requalification_triggers": {
                "type": "array",
                "minItems": len(REQUALIFICATION_TRIGGERS),
                "maxItems": len(REQUALIFICATION_TRIGGERS),
                "uniqueItems": True,
                "items": {"enum": sorted(REQUALIFICATION_TRIGGERS)},
            },
        },
        "additionalProperties": False,
    }


def independent_benchmark_assessment_schema(
    schema_id: str, draft: str
) -> dict[str, Any]:
    interval = {
        "type": "object",
        "required": ["matched", "population", "estimate", "lower", "upper"],
        "properties": {
            "matched": {"type": "integer", "minimum": 0},
            "population": {"type": "integer", "minimum": 0},
            "estimate": {"type": ["number", "null"], "minimum": 0, "maximum": 1},
            "lower": {"type": "number", "minimum": 0, "maximum": 1},
            "upper": {"type": "number", "minimum": 0, "maximum": 1},
        },
        "additionalProperties": False,
    }
    checks = [
        "qualification_integrity",
        "qualification_eligible",
        "independent_governance",
        "frozen_blinded_holdout",
        "holdout_population",
        "confidence_bounds",
        "reviewer_agreement",
        "requalification_policy",
    ]
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA independent benchmark assessment",
        "type": "object",
        "required": [
            "format",
            "generated_at",
            "protocol",
            "bindings",
            "statistics",
            "checks",
            "summary",
            "notice",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": BENCHMARK_ASSESSMENT_FORMAT},
            "generated_at": _text(),
            "protocol": _benchmark_protocol(),
            "bindings": {
                "type": "object",
                "required": [
                    "protocol",
                    "qualification_result",
                    "qualification_manifest",
                ],
                "properties": {
                    name: _artifact_binding()
                    for name in (
                        "protocol",
                        "qualification_result",
                        "qualification_manifest",
                    )
                },
                "additionalProperties": False,
            },
            "statistics": {
                "type": "object",
                "required": ["confidence_intervals", "reviewer_agreement"],
                "properties": {
                    "confidence_intervals": {
                        "type": "object",
                        "required": list(METRIC_NAMES),
                        "properties": {name: interval for name in METRIC_NAMES},
                        "additionalProperties": False,
                    },
                    "reviewer_agreement": {
                        "type": "object",
                        "required": [
                            "items",
                            "observed_agreement",
                            "expected_agreement",
                            "cohen_kappa",
                        ],
                        "properties": {
                            "items": {"type": "integer", "minimum": 2},
                            "observed_agreement": {
                                "type": "number",
                                "minimum": 0,
                                "maximum": 1,
                            },
                            "expected_agreement": {
                                "type": "number",
                                "minimum": 0,
                                "maximum": 1,
                            },
                            "cohen_kappa": {
                                "type": "number",
                                "minimum": -1,
                                "maximum": 1,
                            },
                        },
                        "additionalProperties": False,
                    },
                },
                "additionalProperties": False,
            },
            "checks": _checks(checks),
            "summary": {
                "type": "object",
                "required": [
                    "passed",
                    "status",
                    "confidence_level",
                    "holdout_repositories",
                    "intervals_passing",
                    "intervals_required",
                    "cohen_kappa",
                    "failed_checks",
                ],
                "properties": {
                    "passed": {"type": "boolean"},
                    "status": {
                        "enum": [
                            "eligible_for_authorized_tool_qualification_review",
                            "benchmark_evidence_incomplete",
                        ]
                    },
                    "confidence_level": {"type": "number"},
                    "holdout_repositories": {"type": "integer", "minimum": 1},
                    "intervals_passing": {"type": "integer", "minimum": 0},
                    "intervals_required": {"const": len(METRIC_NAMES)},
                    "cohen_kappa": {"type": "number", "minimum": -1, "maximum": 1},
                    "failed_checks": {
                        "type": "array",
                        "maxItems": len(checks),
                        "uniqueItems": True,
                        "items": {"enum": checks},
                    },
                },
                "additionalProperties": False,
            },
            "notice": _text(),
            "content_sha256": _digest(),
        },
        "additionalProperties": False,
    }


def independent_benchmark_verification_schema(
    schema_id: str, draft: str
) -> dict[str, Any]:
    names = [
        "closed_structure",
        "content_integrity",
        "semantic_reconciliation",
        "binding_structure",
        "source_regeneration",
    ]
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA independent benchmark verification",
        "type": "object",
        "required": [
            "format",
            "valid",
            "passed",
            "checks",
            "errors",
            "content_sha256",
            "notice",
        ],
        "properties": {
            "path": _text(),
            "format": {"const": BENCHMARK_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "passed": {"type": "boolean"},
            "checks": _checks(names),
            "errors": {"type": "array", "maxItems": 1_000, "items": _text()},
            "content_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"},
            "notice": _text(),
        },
        "additionalProperties": False,
    }


def tool_qualification_dossier_schema(schema_id: str, draft: str) -> dict[str, Any]:
    objective = {
        "type": "object",
        "required": [
            "id",
            "title",
            "expected_evidence",
            "applicability",
            "status",
            "rationale",
            "reviewer",
            "reviewed_at",
            "evidence_refs",
        ],
        "properties": {
            "id": _identifier(),
            "title": _text(),
            "expected_evidence": {
                "type": "array",
                "minItems": 1,
                "maxItems": 100,
                "items": _text(),
            },
            "applicability": {"enum": sorted(TOOL_APPLICABILITY)},
            "status": {"enum": sorted(TOOL_STATUSES)},
            "rationale": _text(required=False),
            "reviewer": _text(required=False),
            "reviewed_at": _text(required=False),
            "evidence_refs": {
                "type": "array",
                "maxItems": 1_000,
                "uniqueItems": True,
                "items": _text(),
            },
        },
        "additionalProperties": False,
    }
    anomaly = {
        "type": "object",
        "required": ["id", "title", "status", "impact", "disposition", "evidence_refs"],
        "properties": {
            "id": _identifier(),
            "title": _text(),
            "status": {"enum": sorted(ANOMALY_STATUSES)},
            "impact": _text(),
            "disposition": _text(),
            "evidence_refs": {"type": "array", "maxItems": 1_000, "items": _text()},
        },
        "additionalProperties": False,
    }
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA tool qualification dossier",
        "type": "object",
        "required": [
            "format",
            "generated_at",
            "tool",
            "classification",
            "bindings",
            "input_assessments",
            "objectives",
            "known_anomalies",
            "summary",
            "claim",
            "content_sha256",
        ],
        "properties": {
            "format": {"const": TOOL_QUALIFICATION_FORMAT},
            "generated_at": _text(),
            "tool": {
                "type": "object",
                "required": ["name", "qualified_baseline"],
                "properties": {
                    "name": {"const": "PySFMEA"},
                    "qualified_baseline": _text(required=False),
                },
                "additionalProperties": False,
            },
            "classification": {
                "type": "object",
                "required": [
                    "intended_use",
                    "reliance",
                    "qualification_basis",
                    "tool_classification",
                    "intended_environment",
                    "classification_authority",
                ],
                "properties": {
                    name: _text()
                    for name in (
                        "intended_use",
                        "reliance",
                        "qualification_basis",
                        "tool_classification",
                        "intended_environment",
                        "classification_authority",
                    )
                },
                "additionalProperties": False,
            },
            "bindings": {
                "type": "object",
                "required": [
                    "analysis",
                    "benchmark_assessment",
                    "conformance_workspace",
                    "known_anomaly_register",
                ],
                "properties": {
                    "analysis": _artifact_binding(analysis=True),
                    "benchmark_assessment": _artifact_binding(),
                    "conformance_workspace": _artifact_binding(),
                    "known_anomaly_register": _artifact_binding(),
                },
                "additionalProperties": False,
            },
            "input_assessments": {
                "type": "object",
                "required": [
                    "benchmark_valid",
                    "benchmark_passed",
                    "conformance_valid",
                    "conformance_supported",
                ],
                "properties": {
                    name: {"type": "boolean"}
                    for name in (
                        "benchmark_valid",
                        "benchmark_passed",
                        "conformance_valid",
                        "conformance_supported",
                    )
                },
                "additionalProperties": False,
            },
            "objectives": {
                "type": "array",
                "minItems": 9,
                "maxItems": 9,
                "items": objective,
            },
            "known_anomalies": {"type": "array", "maxItems": 10_000, "items": anomaly},
            "summary": {
                "type": "object",
                "required": [
                    "objectives",
                    "satisfied",
                    "not_applicable",
                    "blocking_objective_ids",
                    "open_anomaly_ids",
                    "classification_decided",
                    "inputs_ready",
                    "assessment_complete",
                    "eligible_for_authorized_qualification_decision",
                    "status",
                ],
                "properties": {
                    "objectives": {"const": 9},
                    "satisfied": {"type": "integer", "minimum": 0, "maximum": 9},
                    "not_applicable": {"type": "integer", "minimum": 0, "maximum": 9},
                    "blocking_objective_ids": {
                        "type": "array",
                        "maxItems": 9,
                        "items": _identifier(),
                    },
                    "open_anomaly_ids": {
                        "type": "array",
                        "maxItems": 10_000,
                        "items": _identifier(),
                    },
                    "classification_decided": {"type": "boolean"},
                    "inputs_ready": {"type": "boolean"},
                    "assessment_complete": {"type": "boolean"},
                    "eligible_for_authorized_qualification_decision": {
                        "type": "boolean"
                    },
                    "status": {
                        "enum": [
                            "eligible_for_authorized_qualification_decision",
                            "qualification_dossier_incomplete",
                        ]
                    },
                },
                "additionalProperties": False,
            },
            "claim": _text(),
            "content_sha256": _digest(),
        },
        "additionalProperties": False,
    }


def tool_qualification_verification_schema(
    schema_id: str, draft: str
) -> dict[str, Any]:
    names = [
        "closed_structure",
        "content_integrity",
        "metadata_semantics",
        "objective_integrity",
        "assessment_semantics",
        "anomaly_semantics",
        "summary_reconciliation",
        "binding_structure",
        "source_bindings",
    ]
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA tool qualification dossier verification",
        "type": "object",
        "required": [
            "format",
            "valid",
            "eligible_for_authorized_qualification_decision",
            "checks",
            "errors",
            "content_sha256",
            "notice",
        ],
        "properties": {
            "path": _text(),
            "format": {"const": TOOL_QUALIFICATION_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "eligible_for_authorized_qualification_decision": {"type": "boolean"},
            "checks": _checks(names),
            "errors": {"type": "array", "maxItems": 1_000, "items": _text()},
            "content_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"},
            "notice": _text(),
        },
        "additionalProperties": False,
    }


def industry_schema_builders(
    schema_id: Callable[[str], str], draft: str
) -> dict[str, Callable[[], dict[str, Any]]]:
    """Return public builders without expanding the central schema registry module."""

    factories = {
        "assurance-case": assurance_case_schema,
        "assurance-case-verification": assurance_case_verification_schema,
        "conformance-workspace": conformance_workspace_schema,
        "conformance-verification": conformance_verification_schema,
        "independent-benchmark-assessment": independent_benchmark_assessment_schema,
        "independent-benchmark-verification": independent_benchmark_verification_schema,
        "slsa-provenance": slsa_provenance_schema,
        "slsa-provenance-verification": slsa_provenance_verification_schema,
        "standards-catalog": standards_catalog_schema,
        "tool-qualification-dossier": tool_qualification_dossier_schema,
        "tool-qualification-verification": tool_qualification_verification_schema,
    }

    def bind(
        name: str, factory: Callable[[str, str], dict[str, Any]]
    ) -> Callable[[], dict[str, Any]]:
        def build() -> dict[str, Any]:
            return factory(schema_id(name), draft)

        return build

    return {name: bind(name, factory) for name, factory in factories.items()}
