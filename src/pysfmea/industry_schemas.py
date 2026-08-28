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
from .benchmark_report_v2 import BENCHMARK_REPORT_V2_VERIFICATION_FORMAT
from .benchmark_v2 import (
    BENCHMARK_ASSESSMENT_V2_FORMAT,
    BENCHMARK_VERIFICATION_V2_FORMAT,
)
from .conformance import (
    APPLICABILITY,
    ASSESSMENT_STATUSES,
    CONFORMANCE_CATALOG_FORMAT,
    CONFORMANCE_VERIFICATION_FORMAT,
    CONFORMANCE_WORKSPACE_FORMAT,
)
from .coverage_observation import (
    COVERAGE_OBSERVATION_FORMAT,
    COVERAGE_OBSERVATION_VERIFICATION_FORMAT,
)
from .csaf import CSAF_VERIFICATION_FORMAT
from .dependability import (
    DEPENDABILITY_ASSESSMENT_FORMAT,
    DEPENDABILITY_AUTHORING_FORMAT,
    DEPENDABILITY_VERIFICATION_FORMAT,
)
from .gsn import GSN_PROJECTION_FORMAT, GSN_VERIFICATION_FORMAT
from .interoperability_validation import (
    NORMATIVE_VALIDATION_FORMAT,
    NORMATIVE_VALIDATION_VERIFICATION_FORMAT,
    ROUNDTRIP_EVIDENCE_FORMAT,
    ROUNDTRIP_VERIFICATION_FORMAT,
)
from .laboratory_governance import (
    LAB_ASSESSMENT_FORMAT,
    LAB_SOURCE_FORMAT,
    LAB_VERIFICATION_FORMAT,
)
from .lifecycle_model import (
    LIFECYCLE_KINDS,
    LIFECYCLE_MODEL_FORMAT,
    LIFECYCLE_MODEL_VERIFICATION_FORMAT,
)
from .qualification_bases import QUALIFICATION_BASES_FORMAT
from .quality_evaluation import (
    QUALITY_EVALUATION_ASSESSMENT_FORMAT,
    QUALITY_EVALUATION_SOURCE_FORMAT,
    QUALITY_EVALUATION_VERIFICATION_FORMAT,
)
from .quantitative_fta import (
    QFTA_ASSESSMENT_FORMAT,
    QFTA_SOURCE_FORMAT,
    QFTA_VERIFICATION_FORMAT,
)
from .release_qualification import (
    RELEASE_QUALIFICATION_ASSESSMENT_FORMAT,
    RELEASE_QUALIFICATION_SOURCE_FORMAT,
    RELEASE_QUALIFICATION_VERIFICATION_FORMAT,
)
from .safety_lifecycle import (
    SAFETY_LIFECYCLE_ASSESSMENT_FORMAT,
    SAFETY_LIFECYCLE_AUTHORING_FORMAT,
    SAFETY_LIFECYCLE_VERIFICATION_FORMAT,
)
from .security_prioritization import (
    SECURITY_ASSESSMENT_FORMAT,
    SECURITY_SOURCE_FORMAT,
    SECURITY_VERIFICATION_FORMAT,
)
from .slsa import (
    SLSA_BUILD_TYPE,
    SLSA_BUILDER_ID,
    SLSA_PREDICATE_TYPE,
    SLSA_STATEMENT_TYPE,
    SLSA_VERIFICATION_FORMAT,
)
from .slsa_policy import (
    SLSA_ASSESSMENT_FORMAT,
    SLSA_OBSERVATION_FORMAT,
    SLSA_POLICY_FORMAT,
    SLSA_POLICY_VERIFICATION_FORMAT,
)
from .ssvc import (
    SSVC_ASSESSMENT_FORMAT,
    SSVC_OBSERVATIONS_FORMAT,
    SSVC_POLICY_FORMAT,
    SSVC_VERIFICATION_FORMAT,
)
from .standards_crosswalk import (
    CROSSWALK_FORMAT,
    CROSSWALK_VERIFICATION_FORMAT,
    RELATIONSHIPS,
)
from .stpa_cast import (
    STPA_CAST_ASSESSMENT_FORMAT,
    STPA_CAST_SOURCE_FORMAT,
    STPA_CAST_VERIFICATION_FORMAT,
)
from .structural_coverage import (
    COVERAGE_ASSESSMENT_FORMAT,
    COVERAGE_SOURCE_FORMAT,
    COVERAGE_VERIFICATION_FORMAT,
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
from .validation_portfolio import (
    VALIDATION_PORTFOLIO_ASSESSMENT_FORMAT,
    VALIDATION_PORTFOLIO_SOURCE_FORMAT,
    VALIDATION_PORTFOLIO_VERIFICATION_FORMAT,
)
from .validation_portfolio_report import (
    VALIDATION_PORTFOLIO_REPORT_VERIFICATION_FORMAT,
)
from .vex import VEX_VERIFICATION_FORMAT

INDUSTRY_SCHEMA_DESCRIPTIONS = {
    "standards-catalog": "Content-addressed public metadata and original objective summaries for selectable industry standards profiles.",
    "standards-crosswalk": "Exact-bound, authority-attributed standards-objective links to findings, obligations, and evidence.",
    "standards-crosswalk-verification": "Standards crosswalk integrity, semantic reconciliation, trace-completeness, and optional source-regeneration verdict.",
    "conformance-workspace": "Exact-analysis-bound applicability, tailoring, objective assessment, evidence-reference, and reviewer workspace.",
    "conformance-verification": "Conformance-workspace integrity, catalog, semantics, summary, and optional analysis-binding verdict.",
    "csaf-verification": "OASIS CSAF 2.0 structure, governed decision, and exact-source-regeneration verdict.",
    "assurance-case": "ISO 15026 and OMG SACM-aligned claims, arguments, evidence, relationships, assumptions, and defeaters.",
    "assurance-case-verification": "Assurance-case integrity, graph, coverage, status, and optional exact-analysis-binding verdict.",
    "slsa-provenance": "in-toto Statement carrying SLSA Provenance v1 for an exact PySFMEA analysis artifact.",
    "slsa-provenance-verification": "SLSA structure, builder, materials, and optional exact analysis subject/state binding verdict.",
    "safety-lifecycle-authoring": "Exact-analysis-bound PHA, FHA, PSSA, SSA, operations, hazard, and common-cause engineering workspace.",
    "safety-lifecycle-assessment": "Reconciled safety-lifecycle traceability, stage evidence, residual-risk decision, and CCFA coverage assessment.",
    "safety-lifecycle-verification": "Safety-lifecycle structure, digest, accounting, and optional exact-source regeneration verdict.",
    "slsa-trust-policy": "Deny-by-default SLSA 1.2 Build and Source track trust policy.",
    "slsa-verification-observation": "Attributable evidence intake record from an external provenance and signature verifier.",
    "slsa-policy-assessment": "SLSA 1.2 achieved-level and local trust-policy decision with exact source bindings.",
    "slsa-policy-verification": "SLSA policy assessment structure, digest, accounting, and optional source regeneration verdict.",
    "independent-benchmark-assessment": "Pre-registered holdout design, Wilson confidence intervals, reviewer agreement, and exact qualification-campaign bindings.",
    "independent-benchmark-report-verification-v2": "Self-contained advanced benchmark HTML integrity, embedded assessment, and optional exact assessment binding verdict.",
    "independent-benchmark-verification": "Benchmark assessment integrity, statistical reconciliation, and optional exact-source regeneration verdict.",
    "independent-benchmark-assessment-v2": "Repository-clustered and stratified metric intervals, calibration, multi-rater agreement, power evidence, and exact source bindings.",
    "independent-benchmark-verification-v2": "Advanced benchmark integrity, summary reconciliation, and optional exact-source regeneration verdict.",
    "normative-schema-validation": "Exact artifact and supplied normative-schema validation receipt with validator and publisher-digest evidence.",
    "normative-schema-validation-verification": "Normative validation receipt integrity and optional exact artifact/schema binding verdict.",
    "independent-roundtrip-evidence": "Independent receiving-tool import, re-export, semantic-preservation, and evidence binding record.",
    "independent-roundtrip-verification": "Round-trip evidence integrity, semantics, and optional exact-file binding verdict.",
    "lifecycle-model": "Conservative normalized ReqIF, SysML v2 JSON, or OSLC JSON-LD entities, relationships, and explicit code links.",
    "lifecycle-model-verification": "Lifecycle bridge integrity, semantic reconciliation, and optional exact-source regeneration verdict.",
    "dependability-authoring": "Exact-analysis-bound HAZOP, reliability block diagram, and Markov engineering authoring artifact.",
    "dependability-assessment": "HAZOP completeness, explicit RBD calculation, bounded Markov transient solution, and review-readiness result.",
    "dependability-verification": "Dependability assessment integrity, semantic reconciliation, and optional exact-source regeneration verdict.",
    "gsn-projection": "Exact-bound Goal Structuring Notation Version 3 semantic projection of a structured assurance case.",
    "gsn-projection-verification": "GSN semantic projection integrity, graph closure, summary reconciliation, and optional exact regeneration verdict.",
    "release-qualification-source": "Pre-registered independent release campaign, temporal holdout, lineage and similarity evidence, non-inferiority margins, and resource budgets.",
    "release-qualification-assessment": "Exact benchmark release qualification with leakage, temporal, statistical non-inferiority, and performance gates.",
    "release-qualification-verification": "Release qualification integrity, accounting, and optional exact-source regeneration verdict.",
    "ssvc-policy": "Controlled, complete, non-overlapping SSVC-style decision table with accountable authority and reassessment triggers.",
    "ssvc-observations": "Policy-bound, attributable vulnerability decision-point evidence and review schedule.",
    "ssvc-assessment": "Deterministic SSVC-style action outcomes generated from an exact controlled policy and evidence set.",
    "ssvc-verification": "SSVC assessment integrity, outcome accounting, and optional exact-source regeneration verdict.",
    "industry-exchange-verification": "SACM, SFPM, ReqIF, or SPDX exchange structure, exact-source binding, and population-reconciliation verdict.",
    "tool-qualification-dossier": "Exact-bound qualification objectives, intended use, classification, benchmark, conformance, configuration, and anomaly evidence.",
    "tool-qualification-bases": "Governed DO-330, ISO 26262, and IEC 61508 navigation packs with classification prompts and generic dossier mappings.",
    "tool-qualification-verification": "Tool qualification dossier integrity and authorized-decision-readiness verdict.",
    "vex-verification": "CycloneDX 1.7 VEX structure, governed-decision, and exact-source-regeneration verdict.",
    "stpa-cast-source": "Exact-analysis-bound STPA control structure, losses, hazards, unsafe control actions, scenarios, CAST incidents, causal factors, and actions.",
    "stpa-cast-assessment": "Deterministic STPA/CAST traceability and method-completeness assessment.",
    "stpa-cast-verification": "STPA/CAST integrity and optional exact-source regeneration verdict.",
    "structural-coverage-source": "Exact-analysis-bound requirements, decisions, conditions, test vectors, MC/DC pairs, deactivated code, and measurement evidence.",
    "structural-coverage-assessment": "Verified requirements, decision, condition, and unique-cause MC/DC coverage accounting.",
    "structural-coverage-verification": "Structural-coverage integrity and optional exact-source regeneration verdict.",
    "quantitative-fta-source": "Exact-analysis-bound fault-tree scope, Boolean logic, probability intervals, and dependency evidence.",
    "quantitative-fta-assessment": "Exact shared-event probability, cut-set, interval, and Birnbaum-importance evaluation.",
    "quantitative-fta-verification": "Quantitative FTA integrity and optional exact-source regeneration verdict.",
    "quality-evaluation-source": "ISO/IEC 25040-aligned quality requirements, evaluation stages, measures, observations, deviations, and conclusion.",
    "quality-evaluation-assessment": "Uncertainty-aware quality-measure and authorized-conclusion readiness assessment.",
    "quality-evaluation-verification": "Quality-evaluation integrity and optional exact-source regeneration verdict.",
    "security-prioritization-source": "CVSS v4 observation, OWASP ASVS 5 evidence, SSVC outcome, disposition, and review workspace.",
    "security-prioritization-assessment": "Cross-referenced vulnerability prioritization evidence completeness assessment.",
    "security-prioritization-verification": "Security-prioritization integrity and optional exact-source regeneration verdict.",
    "laboratory-governance-source": "ISO/IEC 17025-inspired impartiality, competence, method, traceability, uncertainty, proficiency, and control evidence.",
    "laboratory-governance-assessment": "Independent-evaluation governance and authorized-use readiness assessment.",
    "laboratory-governance-verification": "Laboratory-governance integrity and optional exact-source regeneration verdict.",
    "runtime-coverage-observation": "Exact coverage.py JSON, producer configuration, line and branch observations, component mapping, omissions, and claim boundary.",
    "runtime-coverage-observation-verification": "Runtime-coverage integrity, exact analysis/artifact binding, and optional regeneration verdict.",
    "industry-validation-portfolio-source": "External benchmark-suite provenance, comparator baselines, runtime coverage, interoperability, usability, formal-method, and continuity evidence policy.",
    "industry-validation-portfolio-assessment": "Deterministic industry-validation readiness assessment over exact referenced artifacts and declared evidence.",
    "industry-validation-portfolio-verification": "Industry-validation portfolio integrity, semantic reconciliation, and optional exact regeneration verdict.",
    "industry-validation-portfolio-report-verification": "Self-contained validation-portfolio HTML document, payload, semantics, and optional exact-assessment binding verdict.",
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


def standards_crosswalk_schema(schema_id: str, draft: str) -> dict[str, Any]:
    binding = {
        "type": "object",
        "required": ["reference", "bytes", "sha256", "canonical_sha256"],
        "properties": {
            "reference": _text(),
            "bytes": {"type": "integer", "minimum": 1},
            "sha256": _digest(),
            "canonical_sha256": _digest(),
            "analysis_state_sha256": _digest(),
        },
        "additionalProperties": False,
    }
    link = {
        "type": "object",
        "required": [
            "objective_id",
            "relationship",
            "finding_ids",
            "obligation_ids",
            "rationale",
            "authority",
            "evidence_refs",
            "finding_ids_via_obligations",
        ],
        "properties": {
            "objective_id": _identifier(),
            "relationship": {"enum": sorted(RELATIONSHIPS)},
            "finding_ids": {"type": "array", "maxItems": 100_000, "uniqueItems": True, "items": _identifier()},
            "obligation_ids": {"type": "array", "maxItems": 100_000, "uniqueItems": True, "items": _identifier()},
            "rationale": _text(),
            "authority": _text(),
            "evidence_refs": {"type": "array", "maxItems": 100_000, "uniqueItems": True, "items": _text()},
            "finding_ids_via_obligations": {"type": "array", "maxItems": 100_000, "uniqueItems": True, "items": _identifier()},
        },
        "additionalProperties": False,
    }
    objective = {
        "type": "object",
        "required": ["profile_id", "objective_id", "reference_locator", "applicability", "assessment_status", "workspace_evidence_refs", "links", "trace_status"],
        "properties": {
            "profile_id": _identifier(),
            "objective_id": _identifier(),
            "reference_locator": _text(),
            "applicability": {"enum": sorted(APPLICABILITY)},
            "assessment_status": {"enum": sorted(ASSESSMENT_STATUSES)},
            "workspace_evidence_refs": {"type": "array", "maxItems": 100_000, "items": _text()},
            "links": {"type": "array", "maxItems": 100_000, "items": link},
            "trace_status": {"enum": ["linked", "not_applicable", "unlinked"]},
        },
        "additionalProperties": False,
    }
    summary = {
        "type": "object",
        "required": ["objectives", "applicable_objectives", "linked_applicable_objectives", "active_findings", "mapped_findings", "unlinked_objective_ids", "unmapped_finding_ids", "trace_complete"],
        "properties": {
            **{name: {"type": "integer", "minimum": 0} for name in ("objectives", "applicable_objectives", "linked_applicable_objectives", "active_findings", "mapped_findings")},
            "unlinked_objective_ids": {"type": "array", "maxItems": 100_000, "uniqueItems": True, "items": _identifier()},
            "unmapped_finding_ids": {"type": "array", "maxItems": 100_000, "uniqueItems": True, "items": _identifier()},
            "trace_complete": {"type": "boolean"},
        },
        "additionalProperties": False,
    }
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA standards objective crosswalk",
        "type": "object",
        "required": ["format", "generated_at", "binding", "objectives", "summary", "claim", "content_sha256"],
        "properties": {
            "format": {"const": CROSSWALK_FORMAT},
            "generated_at": _text(),
            "binding": {
                "type": "object",
                "required": ["analysis", "conformance_workspace", "mapping"],
                "properties": {"analysis": binding, "conformance_workspace": binding, "mapping": binding},
                "additionalProperties": False,
            },
            "objectives": {"type": "array", "maxItems": 100_000, "items": objective},
            "summary": summary,
            "claim": _text(),
            "content_sha256": _digest(),
        },
        "additionalProperties": False,
    }


def standards_crosswalk_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA standards crosswalk verification",
        "type": "object",
        "required": ["format", "valid", "trace_complete", "checks", "errors", "content_sha256", "notice"],
        "properties": {
            "path": _text(),
            "format": {"const": CROSSWALK_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "trace_complete": {"type": "boolean"},
            "checks": _checks(["closed_structure", "content_integrity", "semantic_reconciliation", "source_regeneration"]),
            "errors": {"type": "array", "maxItems": 1_000, "items": _text()},
            "content_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"},
            "notice": _text(),
        },
        "additionalProperties": False,
    }


def industry_exchange_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA industry exchange verification",
        "type": "object",
        "required": ["format", "kind", "valid", "checks", "errors", "notice"],
        "properties": {
            "path": _text(),
            "format": {"const": "pysfmea-industry-exchange-verification-1"},
            "kind": {"enum": ["reqif", "sacm", "sfpm", "spdx"]},
            "valid": {"type": "boolean"},
            "checks": _checks(["standard_structure", "source_binding", "population_reconciliation"]),
            "errors": {"type": "array", "maxItems": 1_000, "items": _text()},
            "notice": _text(),
        },
        "additionalProperties": False,
    }


def vex_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA CycloneDX VEX verification",
        "type": "object",
        "required": ["format", "valid", "checks", "vulnerabilities", "errors", "notice"],
        "properties": {
            "path": _text(),
            "sha256": _digest(),
            "format": {"const": VEX_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "checks": _checks(["cyclonedx_1_7_structure", "governed_decisions", "exact_source_regeneration"]),
            "vulnerabilities": {"type": "integer", "minimum": 0},
            "errors": {"type": "array", "maxItems": 1_000, "items": _text()},
            "notice": _text(),
        },
        "additionalProperties": False,
    }


def csaf_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA OASIS CSAF 2.0 verification",
        "type": "object",
        "required": ["format", "valid", "checks", "vulnerabilities", "errors", "notice"],
        "properties": {
            "path": _text(),
            "sha256": _digest(),
            "format": {"const": CSAF_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "checks": _checks(["csaf_2_structure", "governed_decisions", "exact_source_regeneration"]),
            "vulnerabilities": {"type": "integer", "minimum": 0},
            "errors": {"type": "array", "maxItems": 1_000, "items": _text()},
            "notice": _text(),
        },
        "additionalProperties": False,
    }


def tool_qualification_bases_schema(schema_id: str, draft: str) -> dict[str, Any]:
    mapping = {
        "type": "object",
        "required": ["objective_id", "evidence_category"],
        "properties": {"objective_id": _identifier(), "evidence_category": _text()},
        "additionalProperties": False,
    }
    pack = {
        "type": "object",
        "required": ["id", "title", "publisher", "edition", "reference_url", "access", "classification_authority_required", "classification_questions", "objective_crosswalk", "tailoring_notes"],
        "properties": {
            "id": _identifier(),
            "title": _text(),
            "publisher": _text(),
            "edition": _text(),
            "reference_url": {"type": "string", "format": "uri"},
            "access": {"const": "licensed_normative_text_required"},
            "classification_authority_required": {"const": True},
            "classification_questions": {"type": "array", "minItems": 1, "maxItems": 100, "items": _text()},
            "objective_crosswalk": {"type": "array", "minItems": 1, "maxItems": 100, "items": mapping},
            "tailoring_notes": {"type": "array", "minItems": 1, "maxItems": 100, "items": _text()},
        },
        "additionalProperties": False,
    }
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA tool qualification basis navigation packs",
        "type": "object",
        "required": ["format", "packs", "notice", "content_sha256"],
        "properties": {
            "format": {"const": QUALIFICATION_BASES_FORMAT},
            "packs": {"type": "array", "minItems": 3, "maxItems": 100, "items": pack},
            "notice": _text(),
            "content_sha256": _digest(),
        },
        "additionalProperties": False,
    }


def _file_binding_schema(*, content_digest: bool = False) -> dict[str, Any]:
    required = ["reference", "bytes", "sha256"]
    properties: dict[str, Any] = {
        "reference": _text(),
        "bytes": {"type": "integer", "minimum": 1},
        "sha256": _digest(),
    }
    if content_digest:
        required.append("content_sha256")
        properties["content_sha256"] = _digest()
    return {
        "type": "object",
        "required": required,
        "properties": properties,
        "additionalProperties": False,
    }


def normative_schema_validation_schema(schema_id: str, draft: str) -> dict[str, Any]:
    schema_binding = _file_binding_schema()
    schema_binding = {
        **schema_binding,
        "required": [*schema_binding["required"], "identifier"],
        "properties": {**schema_binding["properties"], "identifier": _text(required=False)},
    }
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA normative schema validation receipt",
        "type": "object",
        "required": ["format", "generated_at", "schema_kind", "standard", "validator", "artifact", "schema", "outcome", "claim", "content_sha256"],
        "properties": {
            "format": {"const": NORMATIVE_VALIDATION_FORMAT},
            "generated_at": _text(),
            "schema_kind": {"enum": ["json-schema", "xml-schema"]},
            "standard": {
                "type": "object",
                "required": ["name", "edition", "normative_schema_uri", "publisher_schema_sha256"],
                "properties": {
                    "name": _text(),
                    "edition": _text(),
                    "normative_schema_uri": _text(),
                    "publisher_schema_sha256": {"anyOf": [_digest(), {"type": "null"}]},
                },
                "additionalProperties": False,
            },
            "validator": {
                "type": "object",
                "required": ["engine", "version"],
                "properties": {"engine": _text(), "version": _text()},
                "additionalProperties": False,
            },
            "artifact": _file_binding_schema(),
            "schema": schema_binding,
            "outcome": {
                "type": "object",
                "required": ["valid", "error_count", "errors"],
                "properties": {
                    "valid": {"type": "boolean"},
                    "error_count": {"type": "integer", "minimum": 0},
                    "errors": {"type": "array", "maxItems": 1_001, "items": _text()},
                },
                "additionalProperties": False,
            },
            "claim": _text(),
            "content_sha256": _digest(),
        },
        "additionalProperties": False,
    }


def normative_schema_validation_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA normative schema validation verification",
        "type": "object",
        "required": ["format", "valid", "schema_valid", "checks", "errors", "content_sha256", "notice"],
        "properties": {
            "path": _text(),
            "format": {"const": NORMATIVE_VALIDATION_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "schema_valid": {"type": "boolean"},
            "checks": _checks(["closed_structure", "content_integrity", "artifact_binding", "schema_binding"]),
            "errors": {"type": "array", "maxItems": 1_000, "items": _text()},
            "content_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"},
            "notice": _text(),
        },
        "additionalProperties": False,
    }


def independent_roundtrip_evidence_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA independent receiving-tool round-trip evidence",
        "type": "object",
        "required": ["format", "generated_at", "validation_receipt", "observation", "receiver", "operator", "independence_basis", "import", "reexport", "preservation", "passed", "claim", "content_sha256"],
        "properties": {
            "format": {"const": ROUNDTRIP_EVIDENCE_FORMAT},
            "generated_at": _text(),
            "validation_receipt": _file_binding_schema(content_digest=True),
            "observation": _file_binding_schema(),
            "receiver": {
                "type": "object",
                "required": ["name", "version", "vendor"],
                "properties": {"name": _text(), "version": _text(), "vendor": _text()},
                "additionalProperties": False,
            },
            "operator": _text(),
            "independence_basis": _text(),
            "import": {
                "type": "object",
                "required": ["succeeded", "evidence_ref"],
                "properties": {"succeeded": {"type": "boolean"}, "evidence_ref": _text()},
                "additionalProperties": False,
            },
            "reexport": _file_binding_schema(),
            "preservation": {
                "type": "object",
                "required": ["identity", "relationships", "extensions", "differences", "comparison_evidence_ref"],
                "properties": {
                    "identity": {"type": "boolean"},
                    "relationships": {"type": "boolean"},
                    "extensions": {"type": "boolean"},
                    "differences": {"type": "array", "maxItems": 1_000, "items": _text()},
                    "comparison_evidence_ref": _text(),
                },
                "additionalProperties": False,
            },
            "passed": {"type": "boolean"},
            "claim": _text(),
            "content_sha256": _digest(),
        },
        "additionalProperties": False,
    }


def independent_roundtrip_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA independent round-trip verification",
        "type": "object",
        "required": ["format", "valid", "passed", "checks", "errors", "content_sha256", "notice"],
        "properties": {
            "path": _text(),
            "format": {"const": ROUNDTRIP_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "passed": {"type": "boolean"},
            "checks": _checks(["closed_structure", "content_integrity", "semantic_reconciliation", "validation_receipt_binding", "observation_binding", "reexport_binding"]),
            "errors": {"type": "array", "maxItems": 1_000, "items": _text()},
            "content_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"},
            "notice": _text(),
        },
        "additionalProperties": False,
    }


def lifecycle_model_schema(schema_id: str, draft: str) -> dict[str, Any]:
    entity = {
        "type": "object",
        "required": ["id", "source_id", "kind", "standard_type", "name", "description", "properties"],
        "properties": {
            "id": _identifier(),
            "source_id": _text(),
            "kind": _identifier(),
            "standard_type": _text(),
            "name": _text(),
            "description": _text(required=False),
            "properties": {"type": "object", "maxProperties": 100, "additionalProperties": {"type": ["string", "number", "integer", "boolean", "null"]}},
        },
        "additionalProperties": False,
    }
    relationship = {
        "type": "object",
        "required": ["id", "kind", "source_id", "target_id", "authority"],
        "properties": {"id": _identifier(), "kind": _text(), "source_id": _text(), "target_id": _text(), "authority": _text()},
        "additionalProperties": False,
    }
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA normalized lifecycle model bridge",
        "type": "object",
        "required": ["format", "generated_at", "source", "analysis_binding", "entities", "relationships", "code_links", "summary", "limitations", "notice", "content_sha256"],
        "properties": {
            "format": {"const": LIFECYCLE_MODEL_FORMAT},
            "generated_at": _text(),
            "source": {
                "type": "object",
                "required": ["kind", "standard", "reference", "bytes", "sha256"],
                "properties": {"kind": {"enum": sorted(LIFECYCLE_KINDS)}, "standard": _text(), "reference": _text(), "bytes": {"type": "integer", "minimum": 1}, "sha256": _digest()},
                "additionalProperties": False,
            },
            "analysis_binding": {
                "anyOf": [
                    {"type": "null"},
                    {"type": "object", "required": ["baseline_id", "analysis_state_sha256"], "properties": {"baseline_id": _text(required=False), "analysis_state_sha256": _digest()}, "additionalProperties": False},
                ]
            },
            "entities": {"type": "array", "maxItems": 250_000, "items": entity},
            "relationships": {"type": "array", "maxItems": 1_000_000, "items": relationship},
            "code_links": {
                "type": "array",
                "maxItems": 250_000,
                "items": {"type": "object", "required": ["model_entity_id", "component_id", "relationship", "authority"], "properties": {"model_entity_id": _identifier(), "component_id": _identifier(), "relationship": {"const": "explicit_identity_mapping"}, "authority": _text()}, "additionalProperties": False},
            },
            "summary": {"type": "object"},
            "limitations": {"type": "array", "maxItems": 1_000, "items": _text()},
            "notice": _text(),
            "content_sha256": _digest(),
        },
        "additionalProperties": False,
    }


def lifecycle_model_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA lifecycle model verification",
        "type": "object",
        "required": ["format", "valid", "complete", "checks", "errors", "content_sha256", "notice"],
        "properties": {
            "path": _text(),
            "format": {"const": LIFECYCLE_MODEL_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "complete": {"type": "boolean"},
            "checks": _checks(["closed_structure", "content_integrity", "semantic_reconciliation", "source_regeneration"]),
            "errors": {"type": "array", "maxItems": 1_000, "items": _text()},
            "content_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"},
            "notice": _text(),
        },
        "additionalProperties": False,
    }


def independent_benchmark_assessment_v2_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA advanced independent benchmark assessment",
        "type": "object",
        "required": ["format", "generated_at", "protocol", "bindings", "metrics", "strata", "stratum_metrics", "calibration", "reviewer_agreement", "metric_checks", "stratum_checks", "stratum_metric_checks", "checks", "summary", "notice", "content_sha256"],
        "properties": {
            "format": {"const": BENCHMARK_ASSESSMENT_V2_FORMAT},
            "generated_at": _text(),
            "protocol": {"type": "object"},
            "bindings": {"type": "object", "required": ["protocol", "observations"], "properties": {"protocol": {"type": "object"}, "observations": {"type": "object"}}, "additionalProperties": False},
            "metrics": {"type": "object", "minProperties": 1, "maxProperties": 100},
            "strata": {"type": "object"},
            "stratum_metrics": {"type": "object"},
            "calibration": {"type": "object"},
            "reviewer_agreement": {"type": "object"},
            "metric_checks": {"type": "object", "additionalProperties": {"type": "boolean"}},
            "stratum_checks": {"type": "object", "additionalProperties": {"type": "boolean"}},
            "stratum_metric_checks": {"type": "object", "additionalProperties": {"type": "boolean"}},
            "checks": {"type": "object", "additionalProperties": {"type": "boolean"}},
            "summary": {"type": "object"},
            "notice": _text(),
            "content_sha256": _digest(),
        },
        "additionalProperties": False,
    }


def independent_benchmark_verification_v2_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA advanced benchmark verification",
        "type": "object",
        "required": ["format", "valid", "passed", "checks", "errors", "content_sha256", "notice"],
        "properties": {
            "path": _text(),
            "format": {"const": BENCHMARK_VERIFICATION_V2_FORMAT},
            "valid": {"type": "boolean"},
            "passed": {"type": "boolean"},
            "checks": _checks(["closed_structure", "content_integrity", "semantic_reconciliation", "source_regeneration"]),
            "errors": {"type": "array", "maxItems": 1_000, "items": _text()},
            "content_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"},
            "notice": _text(),
        },
        "additionalProperties": False,
    }


def independent_benchmark_report_verification_v2_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return {
        "$schema": draft, "$id": schema_id, "title": "PySFMEA advanced benchmark HTML report verification", "type": "object",
        "required": ["path", "format", "valid", "passed", "checks", "errors", "document_sha256", "notice"],
        "properties": {
            "path": _text(), "format": {"const": BENCHMARK_REPORT_V2_VERIFICATION_FORMAT}, "valid": {"type": "boolean"}, "passed": {"type": "boolean"},
            "checks": _checks(["report_format", "payload_present", "payload_integrity", "payload_semantics", "document_integrity", "assessment_binding"]),
            "errors": {"type": "array", "items": _text()}, "document_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"}, "notice": _text(),
        }, "additionalProperties": False,
    }


def dependability_authoring_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA HAZOP, RBD, and Markov authoring",
        "type": "object",
        "required": ["format", "generated_at", "authority", "analysis_binding", "assumptions", "hazop", "rbd", "markov_models", "notice", "content_sha256"],
        "properties": {
            "format": {"const": DEPENDABILITY_AUTHORING_FORMAT},
            "generated_at": _text(),
            "authority": _text(),
            "analysis_binding": {"type": "object", "required": ["baseline_id", "analysis_state_sha256"], "properties": {"baseline_id": _text(required=False), "analysis_state_sha256": _digest()}, "additionalProperties": False},
            "assumptions": {"type": "array", "maxItems": 10_000, "items": _text()},
            "hazop": {"type": "object"},
            "rbd": {"type": "object"},
            "markov_models": {"type": "array", "maxItems": 1_000, "items": {"type": "object"}},
            "notice": _text(),
            "content_sha256": _digest(),
        },
        "additionalProperties": False,
    }


def dependability_assessment_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA dependability assessment",
        "type": "object",
        "required": ["format", "generated_at", "binding", "authority", "hazop", "rbd", "markov_models", "checks", "summary", "notice", "content_sha256"],
        "properties": {
            "format": {"const": DEPENDABILITY_ASSESSMENT_FORMAT},
            "generated_at": _text(),
            "binding": {"type": "object"},
            "authority": _text(),
            "hazop": {"type": "object"},
            "rbd": {"type": "object"},
            "markov_models": {"type": "array", "items": {"type": "object"}},
            "checks": {"type": "object", "additionalProperties": {"type": "boolean"}},
            "summary": {"type": "object"},
            "notice": _text(),
            "content_sha256": _digest(),
        },
        "additionalProperties": False,
    }


def dependability_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": "PySFMEA dependability verification",
        "type": "object",
        "required": ["format", "valid", "complete", "checks", "errors", "content_sha256", "notice"],
        "properties": {
            "path": _text(),
            "format": {"const": DEPENDABILITY_VERIFICATION_FORMAT},
            "valid": {"type": "boolean"},
            "complete": {"type": "boolean"},
            "checks": _checks(["closed_structure", "content_integrity", "semantic_reconciliation", "source_regeneration"]),
            "errors": {"type": "array", "maxItems": 1_000, "items": _text()},
            "content_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"},
            "notice": _text(),
        },
        "additionalProperties": False,
    }


def safety_lifecycle_authoring_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return {
        "$schema": draft, "$id": schema_id, "title": "PySFMEA safety lifecycle and CCFA authoring",
        "type": "object",
        "required": ["format", "generated_at", "authority", "analysis_binding", "stages", "hazards", "ccfa_candidates", "ccfa_reviews", "operational_feedback", "assumptions", "limitations", "notice", "content_sha256"],
        "properties": {
            "format": {"const": SAFETY_LIFECYCLE_AUTHORING_FORMAT}, "generated_at": _text(), "authority": _text(),
            "analysis_binding": {"type": "object"}, "stages": {"type": "array", "minItems": 5, "maxItems": 5, "items": {"type": "object"}},
            "hazards": {"type": "array", "maxItems": 250_000, "items": {"type": "object"}},
            "ccfa_candidates": {"type": "array", "maxItems": 250_000, "items": {"type": "object"}},
            "ccfa_reviews": {"type": "array", "maxItems": 250_000, "items": {"type": "object"}},
            "operational_feedback": {"type": "object"},
            "assumptions": {"type": "array", "maxItems": 250_000, "items": _text()},
            "limitations": {"type": "array", "maxItems": 250_000, "items": _text()},
            "notice": _text(), "content_sha256": _digest(),
        }, "additionalProperties": False,
    }


def safety_lifecycle_assessment_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return {
        "$schema": draft, "$id": schema_id, "title": "PySFMEA safety lifecycle assessment", "type": "object",
        "required": ["format", "generated_at", "binding", "authority", "stages", "hazards", "ccfa", "operational_feedback", "checks", "summary", "notice", "content_sha256"],
        "properties": {
            "format": {"const": SAFETY_LIFECYCLE_ASSESSMENT_FORMAT}, "generated_at": _text(), "binding": {"type": "object"}, "authority": _text(),
            "stages": {"type": "array", "items": {"type": "object"}}, "hazards": {"type": "array", "items": {"type": "object"}},
            "ccfa": {"type": "object"}, "checks": {"type": "object", "additionalProperties": {"type": "boolean"}},
            "operational_feedback": {"type": "object"},
            "summary": {"type": "object"}, "notice": _text(), "content_sha256": _digest(),
        }, "additionalProperties": False,
    }


def safety_lifecycle_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return {
        "$schema": draft, "$id": schema_id, "title": "PySFMEA safety lifecycle verification", "type": "object",
        "required": ["format", "valid", "complete", "checks", "errors", "content_sha256", "notice"],
        "properties": {"path": _text(), "format": {"const": SAFETY_LIFECYCLE_VERIFICATION_FORMAT}, "valid": {"type": "boolean"}, "complete": {"type": "boolean"}, "checks": _checks(["closed_structure", "content_integrity", "semantic_reconciliation", "source_regeneration"]), "errors": {"type": "array", "items": _text()}, "content_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"}, "notice": _text()},
        "additionalProperties": False,
    }


def slsa_trust_policy_schema(schema_id: str, draft: str) -> dict[str, Any]:
    text_list = {"type": "array", "maxItems": 10_000, "uniqueItems": True, "items": _text()}
    return {
        "$schema": draft, "$id": schema_id, "title": "PySFMEA SLSA 1.2 trust policy", "type": "object",
        "required": ["format", "generated_at", "authority", "minimum_build_track_level", "minimum_source_track_level", "trusted_builders", "trusted_signer_identities", "allowed_build_types", "allowed_source_repositories", "require_authenticated_provenance", "require_two_party_source_review", "policy_evidence_refs", "notice", "content_sha256"],
        "properties": {
            "format": {"const": SLSA_POLICY_FORMAT}, "generated_at": _text(), "authority": _text(),
            "minimum_build_track_level": {"type": "integer", "minimum": 0, "maximum": 3}, "minimum_source_track_level": {"type": "integer", "minimum": 0, "maximum": 3},
            "trusted_builders": text_list, "trusted_signer_identities": text_list, "allowed_build_types": text_list,
            "allowed_source_repositories": text_list, "require_authenticated_provenance": {"type": "boolean"},
            "require_two_party_source_review": {"type": "boolean"}, "policy_evidence_refs": text_list,
            "notice": _text(), "content_sha256": _digest(),
        }, "additionalProperties": False,
    }


def slsa_verification_observation_schema(schema_id: str, draft: str) -> dict[str, Any]:
    boolean_names = ("signature_verified", "hosted_build", "isolated_builds", "ephemeral_environment", "parameterless_rebuild", "source_two_party_reviewed", "source_provenance_verified", "source_history_retained")
    properties: dict[str, Any] = {
        "format": {"const": SLSA_OBSERVATION_FORMAT}, "observed_at": _text(), "verifier": _text(),
        "verification_tool": _text(required=False), "verification_tool_version": _text(required=False),
        "signer_identity": _text(required=False), "verification_evidence_ref": _text(required=False),
        "source_repository": _text(required=False), "evidence_refs": {"type": "array", "items": _text()}, "content_sha256": _digest(),
    }
    properties.update({name: {"type": "boolean"} for name in boolean_names})
    return {"$schema": draft, "$id": schema_id, "title": "PySFMEA SLSA verification observation", "type": "object", "required": list(properties), "properties": properties, "additionalProperties": False}


def slsa_policy_assessment_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return {
        "$schema": draft, "$id": schema_id, "title": "PySFMEA SLSA 1.2 policy assessment", "type": "object",
        "required": ["format", "generated_at", "bindings", "authority", "identities", "levels", "checks", "summary", "notice", "content_sha256"],
        "properties": {
            "format": {"const": SLSA_ASSESSMENT_FORMAT}, "generated_at": _text(), "bindings": {"type": "object"}, "authority": _text(),
            "identities": {"type": "object"}, "levels": {"type": "object"}, "checks": {"type": "object", "additionalProperties": {"type": "boolean"}},
            "summary": {"type": "object"}, "notice": _text(), "content_sha256": _digest(),
        }, "additionalProperties": False,
    }


def slsa_policy_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return {
        "$schema": draft, "$id": schema_id, "title": "PySFMEA SLSA policy verification", "type": "object",
        "required": ["format", "valid", "passed", "checks", "errors", "content_sha256", "notice"],
        "properties": {"path": _text(), "format": {"const": SLSA_POLICY_VERIFICATION_FORMAT}, "valid": {"type": "boolean"}, "passed": {"type": "boolean"}, "checks": _checks(["closed_structure", "content_integrity", "semantic_reconciliation", "source_regeneration"]), "errors": {"type": "array", "items": _text()}, "content_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"}, "notice": _text()},
        "additionalProperties": False,
    }


def _closed_format_schema(
    schema_id: str,
    draft: str,
    *,
    title: str,
    format_value: str,
    fields: dict[str, dict[str, Any]],
    optional_fields: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    properties = {"format": {"const": format_value}, **fields, **(optional_fields or {})}
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": title,
        "type": "object",
        "required": ["format", *fields],
        "properties": properties,
        "additionalProperties": False,
    }


def release_qualification_source_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _closed_format_schema(
        schema_id, draft, title="PySFMEA release qualification source", format_value=RELEASE_QUALIFICATION_SOURCE_FORMAT,
        fields={"id": _identifier(), "pre_registered_at": _text(), "pre_registration_evidence_ref": _text(), "authority": {"type": "object"}, "candidate": {"type": "object"}, "baseline": {"type": "object"}, "corpus": {"type": "object"}, "noninferiority": {"type": "object"}, "performance": {"type": "object"}, "evidence_refs": {"type": "array", "items": _text()}, "notice": _text(), "content_sha256": _digest()},
    )


def release_qualification_assessment_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _closed_format_schema(
        schema_id, draft, title="PySFMEA release qualification assessment", format_value=RELEASE_QUALIFICATION_ASSESSMENT_FORMAT,
        fields={"generated_at": _text(), "id": _identifier(), "authority": {"type": "object"}, "subjects": {"type": "object"}, "bindings": {"type": "object"}, "leakage": {"type": "object"}, "metric_comparisons": {"type": "object"}, "performance": {"type": "object"}, "checks": {"type": "object", "additionalProperties": {"type": "boolean"}}, "summary": {"type": "object"}, "notice": _text(), "content_sha256": _digest()},
    )


def release_qualification_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _closed_format_schema(
        schema_id, draft, title="PySFMEA release qualification verification", format_value=RELEASE_QUALIFICATION_VERIFICATION_FORMAT,
        fields={"valid": {"type": "boolean"}, "passed": {"type": "boolean"}, "checks": _checks(["closed_structure", "content_integrity", "semantic_reconciliation", "source_regeneration"]), "errors": {"type": "array", "items": _text(required=False)}, "content_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"}, "notice": _text()}, optional_fields={"path": _text()},
    )


def ssvc_policy_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _closed_format_schema(
        schema_id, draft, title="PySFMEA controlled SSVC policy", format_value=SSVC_POLICY_FORMAT,
        fields={"model": _text(), "model_version": _text(), "authority": _text(), "approved_at": _text(), "source_url": _text(), "rules": {"type": "array", "items": {"type": "object"}}, "reassessment_triggers": {"type": "array", "items": _text()}, "notice": _text(), "content_sha256": _digest()},
    )


def ssvc_observations_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _closed_format_schema(
        schema_id, draft, title="PySFMEA SSVC observations", format_value=SSVC_OBSERVATIONS_FORMAT,
        fields={"policy_content_sha256": _digest(), "authority": _text(), "observed_at": _text(), "vulnerabilities": {"type": "array", "items": {"type": "object"}}, "content_sha256": _digest()},
    )


def ssvc_assessment_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _closed_format_schema(
        schema_id, draft, title="PySFMEA SSVC assessment", format_value=SSVC_ASSESSMENT_FORMAT,
        fields={"generated_at": _text(), "model": {"type": "object"}, "bindings": {"type": "object"}, "decisions": {"type": "array", "items": {"type": "object"}}, "summary": {"type": "object"}, "notice": _text(), "content_sha256": _digest()},
    )


def ssvc_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _closed_format_schema(
        schema_id, draft, title="PySFMEA SSVC verification", format_value=SSVC_VERIFICATION_FORMAT,
        fields={"valid": {"type": "boolean"}, "complete": {"type": "boolean"}, "checks": _checks(["closed_structure", "content_integrity", "semantic_reconciliation", "source_regeneration"]), "errors": {"type": "array", "items": _text(required=False)}, "content_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"}, "notice": _text()}, optional_fields={"path": _text()},
    )


def gsn_projection_schema(schema_id: str, draft: str) -> dict[str, Any]:
    node = {
        "type": "object",
        "required": ["id", "kind", "source_id", "statement", "status", "metadata"],
        "properties": {"id": _identifier(), "kind": {"enum": ["goal", "strategy", "solution", "assumption", "defeater"]}, "source_id": _text(), "statement": _text(), "status": _text(), "metadata": {"type": "object"}},
        "additionalProperties": False,
    }
    edge = {
        "type": "object",
        "required": ["source", "target", "kind"],
        "properties": {"source": _identifier(), "target": _identifier(), "kind": {"enum": ["supported_by", "in_context_of", "challenges"]}},
        "additionalProperties": False,
    }
    return _closed_format_schema(
        schema_id, draft, title="PySFMEA GSN semantic projection", format_value=GSN_PROJECTION_FORMAT,
        fields={"generated_at": _text(), "binding": {"type": "object"}, "profile": {"type": "object"}, "top_node_id": _identifier(), "nodes": {"type": "array", "minItems": 1, "items": node}, "edges": {"type": "array", "items": edge}, "summary": {"type": "object"}, "notice": _text(), "content_sha256": _digest()},
    )


def gsn_projection_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _closed_format_schema(
        schema_id, draft, title="PySFMEA GSN semantic projection verification", format_value=GSN_VERIFICATION_FORMAT,
        fields={"valid": {"type": "boolean"}, "complete": {"type": "boolean"}, "checks": _checks(["closed_structure", "content_integrity", "graph_integrity", "semantic_reconciliation", "source_regeneration"]), "errors": {"type": "array", "items": _text(required=False)}, "content_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"}, "notice": _text()}, optional_fields={"path": _text()},
    )


def _governed_source_schema(schema_id: str, draft: str, *, title: str, format_value: str, field_names: tuple[str, ...]) -> dict[str, Any]:
    fields: dict[str, dict[str, Any]] = {name: {"type": "object"} for name in field_names}
    array_fields = {
        "requirements", "decisions", "deactivated_code", "analysis_exclusions",
        "evidence_refs", "basic_events", "gates", "dependency_declarations",
        "stages", "quality_requirements", "measures", "observations", "deviations",
        "vulnerabilities", "controls", "nonconformities",
    }
    for name in field_names:
        if name in array_fields:
            fields[name] = {"type": "array", "maxItems": 100_000}
    fields.update({"generated_at": _text(), "authority": _text(), "notice": _text(), "content_sha256": _digest()})
    if "top_gate_id" in fields or "independence_basis" in fields:
        fields["top_gate_id"] = _text(required=False)
        fields["independence_basis"] = _text(required=False)
    return _closed_format_schema(schema_id, draft, title=title, format_value=format_value, fields=fields)


def _governed_assessment_schema(schema_id: str, draft: str, *, title: str, format_value: str, field_names: tuple[str, ...]) -> dict[str, Any]:
    fields: dict[str, dict[str, Any]] = {name: {"type": "object"} for name in field_names}
    for name in field_names:
        if name in {"decisions", "measure_results", "results", "errors"}:
            fields[name] = {"type": "array", "maxItems": 100_000}
    fields.update({"generated_at": _text(), "source_sha256": _digest(), "notice": _text(), "content_sha256": _digest()})
    return _closed_format_schema(schema_id, draft, title=title, format_value=format_value, fields=fields)


def _governed_verification_schema(schema_id: str, draft: str, *, title: str, format_value: str, outcome: str) -> dict[str, Any]:
    return _closed_format_schema(schema_id, draft, title=title, format_value=format_value, fields={"valid": {"type": "boolean"}, outcome: {"type": "boolean"}, "errors": {"type": "array", "maxItems": 100_000, "items": _text(required=False)}, "notice": _text(), "content_sha256": _digest()})


def stpa_cast_source_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _governed_source_schema(schema_id, draft, title="PySFMEA STPA and CAST source", format_value=STPA_CAST_SOURCE_FORMAT, field_names=("generated_at", "authority", "analysis_binding", "system_definition", "control_structure", "stpa", "cast", "evidence_refs", "notice", "content_sha256"))


def stpa_cast_assessment_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _governed_assessment_schema(schema_id, draft, title="PySFMEA STPA and CAST assessment", format_value=STPA_CAST_ASSESSMENT_FORMAT, field_names=("generated_at", "source_sha256", "analysis_binding", "checks", "gaps", "summary", "notice", "content_sha256"))


def stpa_cast_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _governed_verification_schema(schema_id, draft, title="PySFMEA STPA and CAST verification", format_value=STPA_CAST_VERIFICATION_FORMAT, outcome="complete")


def structural_coverage_source_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _governed_source_schema(schema_id, draft, title="PySFMEA structural coverage source", format_value=COVERAGE_SOURCE_FORMAT, field_names=("generated_at", "authority", "analysis_binding", "coverage_basis", "requirements", "decisions", "deactivated_code", "analysis_exclusions", "evidence_refs", "notice", "content_sha256"))


def structural_coverage_assessment_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _governed_assessment_schema(schema_id, draft, title="PySFMEA structural coverage assessment", format_value=COVERAGE_ASSESSMENT_FORMAT, field_names=("generated_at", "source_sha256", "analysis_binding", "decisions", "summary", "notice", "content_sha256"))


def structural_coverage_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _governed_verification_schema(schema_id, draft, title="PySFMEA structural coverage verification", format_value=COVERAGE_VERIFICATION_FORMAT, outcome="complete")


def quantitative_fta_source_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _governed_source_schema(schema_id, draft, title="PySFMEA quantitative FTA source", format_value=QFTA_SOURCE_FORMAT, field_names=("generated_at", "authority", "analysis_binding", "model_scope", "independence_basis", "basic_events", "gates", "top_gate_id", "dependency_declarations", "evidence_refs", "notice", "content_sha256"))


def quantitative_fta_assessment_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _governed_assessment_schema(schema_id, draft, title="PySFMEA quantitative FTA assessment", format_value=QFTA_ASSESSMENT_FORMAT, field_names=("generated_at", "source_sha256", "analysis_binding", "evaluation", "summary", "notice", "content_sha256"))


def quantitative_fta_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _governed_verification_schema(schema_id, draft, title="PySFMEA quantitative FTA verification", format_value=QFTA_VERIFICATION_FORMAT, outcome="complete")


def quality_evaluation_source_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _governed_source_schema(schema_id, draft, title="PySFMEA quality evaluation source", format_value=QUALITY_EVALUATION_SOURCE_FORMAT, field_names=("generated_at", "authority", "analysis_binding", "evaluation_context", "stages", "quality_requirements", "measures", "observations", "deviations", "conclusion", "notice", "content_sha256"))


def quality_evaluation_assessment_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _governed_assessment_schema(schema_id, draft, title="PySFMEA quality evaluation assessment", format_value=QUALITY_EVALUATION_ASSESSMENT_FORMAT, field_names=("generated_at", "source_sha256", "analysis_binding", "measure_results", "summary", "notice", "content_sha256"))


def quality_evaluation_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _governed_verification_schema(schema_id, draft, title="PySFMEA quality evaluation verification", format_value=QUALITY_EVALUATION_VERIFICATION_FORMAT, outcome="eligible_for_authorized_conclusion")


def security_prioritization_source_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _governed_source_schema(schema_id, draft, title="PySFMEA security prioritization source", format_value=SECURITY_SOURCE_FORMAT, field_names=("generated_at", "authority", "policy", "vulnerabilities", "evidence_refs", "notice", "content_sha256"))


def security_prioritization_assessment_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _governed_assessment_schema(schema_id, draft, title="PySFMEA security prioritization assessment", format_value=SECURITY_ASSESSMENT_FORMAT, field_names=("generated_at", "source_sha256", "results", "summary", "notice", "content_sha256"))


def security_prioritization_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _governed_verification_schema(schema_id, draft, title="PySFMEA security prioritization verification", format_value=SECURITY_VERIFICATION_FORMAT, outcome="complete")


def laboratory_governance_source_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _governed_source_schema(schema_id, draft, title="PySFMEA laboratory governance source", format_value=LAB_SOURCE_FORMAT, field_names=("generated_at", "authority", "subject", "roles", "controls", "nonconformities", "approval", "notice", "content_sha256"))


def laboratory_governance_assessment_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _governed_assessment_schema(schema_id, draft, title="PySFMEA laboratory governance assessment", format_value=LAB_ASSESSMENT_FORMAT, field_names=("generated_at", "source_sha256", "subject", "summary", "notice", "content_sha256"))


def laboratory_governance_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _governed_verification_schema(schema_id, draft, title="PySFMEA laboratory governance verification", format_value=LAB_VERIFICATION_FORMAT, outcome="eligible_for_governed_use")


def runtime_coverage_observation_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _closed_format_schema(
        schema_id,
        draft,
        title="PySFMEA runtime coverage observation",
        format_value=COVERAGE_OBSERVATION_FORMAT,
        fields={
            "generated_at": _text(),
            "authority": _text(),
            "analysis_binding": {"type": "object"},
            "artifact": {"type": "object"},
            "producer": {"type": "object"},
            "policy": {"type": "object"},
            "files": {"type": "array", "maxItems": 100_000, "items": {"type": "object"}},
            "components": {"type": "array", "maxItems": 500_000, "items": {"type": "object"}},
            "omissions": {"type": "object"},
            "summary": {"type": "object"},
            "evidence_refs": {"type": "array", "minItems": 1, "maxItems": 100_000, "uniqueItems": True, "items": _text()},
            "claim_boundary": _text(),
            "content_sha256": _digest(),
        },
    )


def runtime_coverage_observation_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _closed_format_schema(
        schema_id,
        draft,
        title="PySFMEA runtime coverage observation verification",
        format_value=COVERAGE_OBSERVATION_VERIFICATION_FORMAT,
        fields={
            "valid": {"type": "boolean"},
            "ready_for_structural_coverage_use": {"type": "boolean"},
            "checks": _checks(["closed_structure", "content_integrity", "semantic_reconciliation", "analysis_binding", "coverage_artifact_binding", "exact_regeneration"]),
            "errors": {"type": "array", "maxItems": 1_000, "items": _text(required=False)},
            "notice": _text(),
            "content_sha256": _digest(),
        },
    )


def industry_validation_portfolio_source_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _closed_format_schema(
        schema_id,
        draft,
        title="PySFMEA industry validation portfolio source",
        format_value=VALIDATION_PORTFOLIO_SOURCE_FORMAT,
        fields={
            "generated_at": _text(),
            "authority": {"type": "object"},
            "product": {"type": "object"},
            "policy": {"type": "object"},
            "benchmark_assessment_paths": {"type": "array", "maxItems": 10_000, "uniqueItems": True, "items": _text()},
            "benchmark_suites": {"type": "array", "maxItems": 10_000, "items": {"type": "object"}},
            "comparator_observations": {"type": "array", "maxItems": 10_000, "items": {"type": "object"}},
            "runtime_coverage_paths": {"type": "array", "maxItems": 10_000, "uniqueItems": True, "items": _text()},
            "roundtrip_evidence": {"type": "array", "maxItems": 10_000, "items": {"type": "object"}},
            "usability_studies": {"type": "array", "maxItems": 10_000, "items": {"type": "object"}},
            "formal_verification_records": {"type": "array", "maxItems": 10_000, "items": {"type": "object"}},
            "continuity_exercises": {"type": "array", "maxItems": 10_000, "items": {"type": "object"}},
            "evidence_refs": {"type": "array", "maxItems": 10_000, "uniqueItems": True, "items": _text()},
            "limitations": {"type": "array", "maxItems": 10_000, "uniqueItems": True, "items": _text()},
            "notice": _text(),
            "content_sha256": _digest(),
        },
    )


def industry_validation_portfolio_assessment_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _closed_format_schema(
        schema_id,
        draft,
        title="PySFMEA industry validation portfolio assessment",
        format_value=VALIDATION_PORTFOLIO_ASSESSMENT_FORMAT,
        fields={
            "generated_at": _text(),
            "source_sha256": _digest(),
            "authority": {"type": "object"},
            "product": {"type": "object"},
            "policy": {"type": "object"},
            "artifacts": {"type": "array", "maxItems": 30_000, "items": {"type": "object"}},
            "benchmark": {"type": "object"},
            "interoperability": {"type": "object"},
            "usability_studies": {"type": "array", "maxItems": 10_000, "items": {"type": "object"}},
            "formal_verification": {"type": "array", "maxItems": 10_000, "items": {"type": "object"}},
            "continuity_exercises": {"type": "array", "maxItems": 10_000, "items": {"type": "object"}},
            "checks": {"type": "object", "additionalProperties": {"type": "boolean"}},
            "summary": {"type": "object"},
            "limitations": {"type": "array", "maxItems": 10_000, "items": _text()},
            "evidence_refs": {"type": "array", "maxItems": 10_000, "items": _text()},
            "notice": _text(),
            "content_sha256": _digest(),
        },
    )


def industry_validation_portfolio_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _closed_format_schema(
        schema_id,
        draft,
        title="PySFMEA industry validation portfolio verification",
        format_value=VALIDATION_PORTFOLIO_VERIFICATION_FORMAT,
        fields={
            "valid": {"type": "boolean"},
            "passed": {"type": "boolean"},
            "checks": _checks(["closed_structure", "content_integrity", "semantic_reconciliation", "source_regeneration"]),
            "errors": {"type": "array", "maxItems": 1_000, "items": _text(required=False)},
            "notice": _text(),
            "content_sha256": _digest(),
        },
    )


def industry_validation_portfolio_report_verification_schema(schema_id: str, draft: str) -> dict[str, Any]:
    return _closed_format_schema(
        schema_id,
        draft,
        title="PySFMEA industry validation portfolio report verification",
        format_value=VALIDATION_PORTFOLIO_REPORT_VERIFICATION_FORMAT,
        fields={
            "valid": {"type": "boolean"},
            "passed": {"type": "boolean"},
            "checks": _checks(["report_format", "payload_present", "payload_integrity", "payload_semantics", "document_integrity", "assessment_binding"]),
            "errors": {"type": "array", "maxItems": 1_000, "items": _text(required=False)},
            "document_sha256": {"type": "string", "pattern": "^$|^[0-9a-f]{64}$"},
            "notice": _text(),
        },
    )


def industry_schema_builders(
    schema_id: Callable[[str], str], draft: str
) -> dict[str, Callable[[], dict[str, Any]]]:
    """Return public builders without expanding the central schema registry module."""

    factories = {
        "assurance-case": assurance_case_schema,
        "assurance-case-verification": assurance_case_verification_schema,
        "conformance-workspace": conformance_workspace_schema,
        "conformance-verification": conformance_verification_schema,
        "csaf-verification": csaf_verification_schema,
        "independent-benchmark-assessment": independent_benchmark_assessment_schema,
        "independent-benchmark-verification": independent_benchmark_verification_schema,
        "independent-benchmark-assessment-v2": independent_benchmark_assessment_v2_schema,
        "independent-benchmark-verification-v2": independent_benchmark_verification_v2_schema,
        "independent-benchmark-report-verification-v2": independent_benchmark_report_verification_v2_schema,
        "independent-roundtrip-evidence": independent_roundtrip_evidence_schema,
        "independent-roundtrip-verification": independent_roundtrip_verification_schema,
        "industry-exchange-verification": industry_exchange_verification_schema,
        "lifecycle-model": lifecycle_model_schema,
        "lifecycle-model-verification": lifecycle_model_verification_schema,
        "normative-schema-validation": normative_schema_validation_schema,
        "normative-schema-validation-verification": normative_schema_validation_verification_schema,
        "dependability-authoring": dependability_authoring_schema,
        "dependability-assessment": dependability_assessment_schema,
        "dependability-verification": dependability_verification_schema,
        "gsn-projection": gsn_projection_schema,
        "gsn-projection-verification": gsn_projection_verification_schema,
        "release-qualification-source": release_qualification_source_schema,
        "release-qualification-assessment": release_qualification_assessment_schema,
        "release-qualification-verification": release_qualification_verification_schema,
        "safety-lifecycle-authoring": safety_lifecycle_authoring_schema,
        "safety-lifecycle-assessment": safety_lifecycle_assessment_schema,
        "safety-lifecycle-verification": safety_lifecycle_verification_schema,
        "slsa-provenance": slsa_provenance_schema,
        "slsa-provenance-verification": slsa_provenance_verification_schema,
        "slsa-trust-policy": slsa_trust_policy_schema,
        "slsa-verification-observation": slsa_verification_observation_schema,
        "slsa-policy-assessment": slsa_policy_assessment_schema,
        "slsa-policy-verification": slsa_policy_verification_schema,
        "ssvc-policy": ssvc_policy_schema,
        "ssvc-observations": ssvc_observations_schema,
        "ssvc-assessment": ssvc_assessment_schema,
        "ssvc-verification": ssvc_verification_schema,
        "standards-catalog": standards_catalog_schema,
        "standards-crosswalk": standards_crosswalk_schema,
        "standards-crosswalk-verification": standards_crosswalk_verification_schema,
        "tool-qualification-dossier": tool_qualification_dossier_schema,
        "tool-qualification-bases": tool_qualification_bases_schema,
        "tool-qualification-verification": tool_qualification_verification_schema,
        "vex-verification": vex_verification_schema,
        "stpa-cast-source": stpa_cast_source_schema,
        "stpa-cast-assessment": stpa_cast_assessment_schema,
        "stpa-cast-verification": stpa_cast_verification_schema,
        "structural-coverage-source": structural_coverage_source_schema,
        "structural-coverage-assessment": structural_coverage_assessment_schema,
        "structural-coverage-verification": structural_coverage_verification_schema,
        "quantitative-fta-source": quantitative_fta_source_schema,
        "quantitative-fta-assessment": quantitative_fta_assessment_schema,
        "quantitative-fta-verification": quantitative_fta_verification_schema,
        "quality-evaluation-source": quality_evaluation_source_schema,
        "quality-evaluation-assessment": quality_evaluation_assessment_schema,
        "quality-evaluation-verification": quality_evaluation_verification_schema,
        "security-prioritization-source": security_prioritization_source_schema,
        "security-prioritization-assessment": security_prioritization_assessment_schema,
        "security-prioritization-verification": security_prioritization_verification_schema,
        "laboratory-governance-source": laboratory_governance_source_schema,
        "laboratory-governance-assessment": laboratory_governance_assessment_schema,
        "laboratory-governance-verification": laboratory_governance_verification_schema,
        "runtime-coverage-observation": runtime_coverage_observation_schema,
        "runtime-coverage-observation-verification": runtime_coverage_observation_verification_schema,
        "industry-validation-portfolio-source": industry_validation_portfolio_source_schema,
        "industry-validation-portfolio-assessment": industry_validation_portfolio_assessment_schema,
        "industry-validation-portfolio-verification": industry_validation_portfolio_verification_schema,
        "industry-validation-portfolio-report-verification": industry_validation_portfolio_report_verification_schema,
    }

    def bind(
        name: str, factory: Callable[[str, str], dict[str, Any]]
    ) -> Callable[[], dict[str, Any]]:
        def build() -> dict[str, Any]:
            return factory(schema_id(name), draft)

        return build

    return {name: bind(name, factory) for name, factory in factories.items()}
