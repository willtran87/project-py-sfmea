"""Public JSON Schema builders for standards and assurance-case artifacts."""

from __future__ import annotations

from typing import Any, Callable

from .assurance_case import ASSURANCE_CASE_FORMAT, ASSURANCE_CASE_VERIFICATION_FORMAT
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

INDUSTRY_SCHEMA_DESCRIPTIONS = {
    "standards-catalog": "Content-addressed public metadata and original objective summaries for selectable industry standards profiles.",
    "conformance-workspace": "Exact-analysis-bound applicability, tailoring, objective assessment, evidence-reference, and reviewer workspace.",
    "conformance-verification": "Conformance-workspace integrity, catalog, semantics, summary, and optional analysis-binding verdict.",
    "assurance-case": "ISO 15026 and OMG SACM-aligned claims, arguments, evidence, relationships, assumptions, and defeaters.",
    "assurance-case-verification": "Assurance-case integrity, graph, coverage, status, and optional exact-analysis-binding verdict.",
    "slsa-provenance": "in-toto Statement carrying SLSA Provenance v1 for an exact PySFMEA analysis artifact.",
    "slsa-provenance-verification": "SLSA structure, builder, materials, and optional exact analysis subject/state binding verdict.",
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


def industry_schema_builders(
    schema_id: Callable[[str], str], draft: str
) -> dict[str, Callable[[], dict[str, Any]]]:
    """Return public builders without expanding the central schema registry module."""

    factories = {
        "assurance-case": assurance_case_schema,
        "assurance-case-verification": assurance_case_verification_schema,
        "conformance-workspace": conformance_workspace_schema,
        "conformance-verification": conformance_verification_schema,
        "slsa-provenance": slsa_provenance_schema,
        "slsa-provenance-verification": slsa_provenance_verification_schema,
        "standards-catalog": standards_catalog_schema,
    }

    def bind(
        name: str, factory: Callable[[str, str], dict[str, Any]]
    ) -> Callable[[], dict[str, Any]]:
        def build() -> dict[str, Any]:
            return factory(schema_id(name), draft)

        return build

    return {name: bind(name, factory) for name, factory in factories.items()}
