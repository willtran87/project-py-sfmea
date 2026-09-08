"""Schemas for vulnerability-intelligence and longitudinal-performance evidence."""

from __future__ import annotations

from typing import Any, Callable

from .benchmark_case_inventory import (
    BENCHMARK_CASE_INVENTORY_FORMAT,
    BENCHMARK_CASE_INVENTORY_VERIFICATION_FORMAT,
)
from .benchmark_corpus import (
    BENCHMARK_CORPUS_INVENTORY_FORMAT,
    BENCHMARK_CORPUS_VERIFICATION_FORMAT,
)
from .benchmark_differential import (
    DIFFERENTIAL_ASSESSMENT_FORMAT,
    DIFFERENTIAL_SOURCE_FORMAT,
    DIFFERENTIAL_VERIFICATION_FORMAT,
)
from .benchmark_item_quality import (
    BENCHMARK_ITEM_QUALITY_FORMAT,
    BENCHMARK_ITEM_QUALITY_VERIFICATION_FORMAT,
)
from .benchmark_native import (
    NATIVE_BENCHMARK_FORMAT,
    NATIVE_BENCHMARK_VERIFICATION_FORMAT,
)
from .benchmark_proficiency import (
    BENCHMARK_PROFICIENCY_ASSESSMENT_FORMAT,
    BENCHMARK_PROFICIENCY_SOURCE_FORMAT,
    BENCHMARK_PROFICIENCY_VERIFICATION_FORMAT,
)
from .benchmark_source_health import (
    BENCHMARK_SOURCE_HEALTH_FORMAT,
    BENCHMARK_SOURCE_HEALTH_VERIFICATION_FORMAT,
)
from .causal_validation import (
    CAUSAL_VALIDATION_FORMAT,
    CAUSAL_VALIDATION_VERIFICATION_FORMAT,
)
from .clusterfuzz_intake import (
    CLUSTERFUZZ_INTAKE_FORMAT,
    CLUSTERFUZZ_INTAKE_VERIFICATION_FORMAT,
)
from .confidence_calibration import (
    CONFIDENCE_CALIBRATION_FORMAT,
    CONFIDENCE_CALIBRATION_VERIFICATION_FORMAT,
)
from .deployed_tevv import (
    DEPLOYED_TEVV_ASSESSMENT_FORMAT,
    DEPLOYED_TEVV_SOURCE_FORMAT,
    DEPLOYED_TEVV_VERIFICATION_FORMAT,
)
from .evidence_contracts import evidence_contract_builders
from .genai_telemetry import (
    GENAI_TELEMETRY_FORMAT,
    GENAI_TELEMETRY_VERIFICATION_FORMAT,
)
from .industry_qualification_readiness import (
    INDUSTRY_QUALIFICATION_READINESS_FORMAT,
    INDUSTRY_QUALIFICATION_READINESS_VERIFICATION_FORMAT,
)
from .inspect_ai_conformance import (
    INSPECT_AI_CONFORMANCE_FORMAT,
    INSPECT_AI_CONFORMANCE_VERIFICATION_FORMAT,
)
from .inspect_ai_evidence import (
    INSPECT_AI_EVIDENCE_FORMAT,
    INSPECT_AI_EVIDENCE_VERIFICATION_FORMAT,
)
from .performance_history import (
    PERFORMANCE_HISTORY_FORMAT,
    PERFORMANCE_HISTORY_VERIFICATION_FORMAT,
)
from .samate_assessment import (
    SAMATE_ASSESSMENT_FORMAT,
    SAMATE_SOURCE_FORMAT,
    SAMATE_VERIFICATION_FORMAT,
)
from .sarif_conformance import (
    SARIF_CONFORMANCE_FORMAT,
    SARIF_CONFORMANCE_VERIFICATION_FORMAT,
)
from .scorecard_evidence import (
    SCORECARD_EVIDENCE_FORMAT,
    SCORECARD_EVIDENCE_VERIFICATION_FORMAT,
)
from .sfmea_benchmark import (
    SFMEA_BENCHMARK_FORMAT,
    SFMEA_BENCHMARK_VERIFICATION_FORMAT,
)
from .standards_watchlist import (
    STANDARDS_WATCHLIST_FORMAT,
    STANDARDS_WATCHLIST_VERIFICATION_FORMAT,
)
from .test_dossier import TEST_DOSSIER_FORMAT, TEST_DOSSIER_VERIFICATION_FORMAT
from .vulnerability_applicability import (
    VULNERABILITY_APPLICABILITY_FORMAT,
    VULNERABILITY_APPLICABILITY_VERIFICATION_FORMAT,
)
from .vulnerability_intelligence import (
    VULNERABILITY_INTELLIGENCE_FORMAT,
    VULNERABILITY_INTELLIGENCE_MATCH_FORMAT,
    VULNERABILITY_INTELLIGENCE_VERIFICATION_FORMAT,
)
from .vulnerability_workflow import (
    VULNERABILITY_WORKFLOW_FORMAT,
    VULNERABILITY_WORKFLOW_VERIFICATION_FORMAT,
)

GAP_SCHEMA_DESCRIPTIONS = {
    "callgraph-benchmark": "Exact-source PyCG adjacency comparison with edge-level differences and explicit oracle limitations.",
    "tevv-collection": "Telemetry collection population, independent counter attribution, sampling and loss accounting.",
    "scope-trust-policy": "Caller-controlled approval identities, authorized roles, validity intervals, keys and revocation.",
    "upstream-schema-policy": "Caller-approved exact upstream versions, schema URIs, byte digests and configuration projections.",
    "benchmark-case-results": "Per-case execution identities and boolean labels for exact scored-population reconciliation.",
    "tevv-request-events": "Raw deployment request identities, timestamps, errors, and latency measurements.",
    "tevv-evaluation-events": "Version-bound evaluation case identities and boolean outcomes.",
    "tevv-control-events": "Retained containment transitions and rollback recovery measurements.",
    "qualification-scope": "Approved applicability, exclusions, acceptance policy, and change-trigger decisions.",
    "benchmark-differential-source": "Case-paired multi-tool predictions, independent labels, exact provenance, and disagreement adjudications.",
    "benchmark-differential-assessment": "Per-tool confusion metrics, pairwise exact McNemar tests, and fail-visible disagreement queue.",
    "benchmark-differential-verification": "Differential evidence integrity, reconciliation, exact-source replay, and portfolio eligibility verdict.",
    "benchmark-corpus-inventory": "Exact-byte, closed-population inventory of bundled benchmark corpora and protocols.",
    "benchmark-corpus-verification": "Benchmark corpus inventory integrity and optional exact-root replay verdict.",
    "benchmark-proficiency-source": "ISO 17043/13528-inspired controlled proficiency scheme, assigned values, participants, and evidence.",
    "benchmark-proficiency-assessment": "Deterministic quantitative z-score and qualitative proficiency assessment.",
    "benchmark-proficiency-verification": "Proficiency integrity, exact-source replay, and qualification-input eligibility verdict.",
    "benchmark-source-health": "Closed benchmark-source revision, licensing, maturity, and adapter-capability ledger.",
    "benchmark-source-health-verification": "Benchmark source-health integrity, catalog binding, and execution-eligibility verdict.",
    "industry-qualification-readiness": "Exact standards-lifecycle, benchmark-source, adapter, authority, and validation-portfolio qualification readiness assessment.",
    "industry-qualification-readiness-verification": "Qualification-readiness integrity, reconciliation, exact-source replay, and authorized-review eligibility verdict.",
    "native-benchmark-normalization": "Exact-byte native suite-result normalization without fabricating execution evidence.",
    "native-benchmark-normalization-verification": "Native normalization integrity and observation-join eligibility verdict.",
    "benchmark-item-quality": "Exact-population independent audit of task requirements, oracles, hidden tests, coverage, mutation strength, harness reproducibility, ambiguity, gold patches, regressions, exclusions, and reviewers.",
    "benchmark-item-quality-verification": "Benchmark item-quality integrity, policy reconciliation, exact-source replay, and claim-eligibility verdict.",
    "benchmark-case-inventory": "Exact-source, suite-neutral case population for independent item review without guessing result semantics.",
    "benchmark-case-inventory-verification": "Case-inventory integrity and closed-population item-review eligibility verdict.",
    "inspect-ai-evidence": "Exact-byte Inspect AI evaluation-log intake with configuration, sample, score, transcript, tool-event, error, and token-usage identities.",
    "inspect-ai-evidence-verification": "Inspect AI evidence integrity, sample accounting, exact-source replay, and evaluation-join eligibility verdict.",
    "inspect-ai-conformance": "Exact replay, upstream-schema validation, exported run-configuration, and typed execution-identity receipt for Inspect AI evidence.",
    "inspect-ai-conformance-verification": "Inspect conformance integrity, reconciliation, exact-source replay, and evaluation-portfolio eligibility verdict.",
    "deployed-tevv-source": "NIST AI 800-4-aligned system identity, baseline, policy, monitoring windows, six-category evidence, incidents, circuit-breaker, rollback, and change evidence.",
    "deployed-tevv-assessment": "Deterministic deployed monitoring and repeated-TEVV threshold assessment.",
    "deployed-tevv-verification": "Deployed TEVV integrity, reconciliation, exact-source replay, and operational-review eligibility verdict.",
    "genai-telemetry": "Exact-source, version-pinned OpenTelemetry GenAI span normalization for deployed TEVV evidence.",
    "genai-telemetry-verification": "GenAI telemetry integrity, reconciliation, operation-identity completeness, exact replay, and deployed-TEVV eligibility verdict.",
    "confidence-calibration": "Brier score, expected calibration error, Wilson intervals, strata, and risk-coverage evidence.",
    "confidence-calibration-verification": "Confidence-calibration integrity and metric reconciliation verdict.",
    "causal-validation": "Runtime comparison of predicted cascade paths, effects, deadlines, breaker transitions, and recovery.",
    "causal-validation-verification": "Causal-validation integrity, reconciliation, and independent-review verdict.",
    "sarif-conformance": "Exact SARIF validation against a supplied official schema plus consumer semantic invariants.",
    "sarif-conformance-verification": "SARIF conformance receipt integrity and scoped consumption verdict.",
    "openssf-scorecard-evidence": "Lossless OpenSSF Scorecard check intake with controlled OSPS, SSDF, and SLSA evidence mappings.",
    "openssf-scorecard-evidence-verification": "Scorecard intake integrity, mapping, and review-input verdict.",
    "standards-watchlist": "Non-normative governed inventory of relevant standards under development.",
    "standards-watchlist-verification": "Watchlist integrity and governed-inventory verdict.",
    "clusterfuzzlite-intake": "Content-addressed inventory of downloaded ClusterFuzzLite CI artifacts with exact run identity, classified evidence, and a deliberately incomplete fuzz-campaign projection.",
    "clusterfuzzlite-intake-verification": "ClusterFuzzLite intake integrity, manifest reconciliation, and optional artifact-directory rebinding verdict.",
    "vulnerability-intelligence": "Exact local OSV, CISA KEV, and FIRST EPSS snapshots normalized without losing source identity, aliases, affected ranges, exploitation status, probability, freshness, or claim boundaries.",
    "vulnerability-intelligence-verification": "Vulnerability-intelligence integrity, exact source binding, freshness, and governed-priority-input eligibility verdict.",
    "vulnerability-intelligence-match": "Identity-level CVE, PURL, and package matches with KEV and EPSS context and unresolved applicability preserved.",
    "performance-history": "Exact comparable scanner-performance receipt series with environment, repository-population, runtime, memory, variability, and release-ratchet evidence.",
    "performance-history-verification": "Performance-history integrity, comparability, declared policy, and release-gate eligibility verdict.",
    "sfmea-semantic-benchmark": "Direct exact-corpus evaluation of SFMEA findings, call resolution, control detection, and semantic claims with independent-governance eligibility kept separate.",
    "sfmea-semantic-benchmark-verification": "Semantic-benchmark integrity, metric/population reconciliation, source binding, and independent-claim eligibility verdict.",
    "vulnerability-applicability": "Exact CycloneDX component-version applicability against preserved OSV affected versions and supported ecosystem ranges.",
    "vulnerability-applicability-verification": "Vulnerability-applicability integrity and summary reconciliation verdict.",
    "vulnerability-workflow": "Governed lifecycle from version applicability through reachability, exposure, SSVC, remediation, verification, VEX, CSAF, and POA&M readiness.",
    "vulnerability-workflow-verification": "Vulnerability-lifecycle state and population reconciliation verdict.",
    "test-dossier": "Exact-analysis-bound ISO 29119-aligned test documentation, technique, keyword, traceability, and completion projection.",
    "test-dossier-verification": "Test-dossier integrity, population, technique, completion, and analysis-binding verdict.",
    "samate-assessment-source": "NIST SP 500-268 capability claim and SP 500-270-style test-plan, authority, case, label, location, exclusion, and evidence source.",
    "samate-assessment": "Case-reconciled overall and weakness-stratified source-analysis evaluation with uncertainty and localization metrics.",
    "samate-assessment-verification": "SAMATE assessment integrity and case/metric reconciliation verdict.",
}


def _text() -> dict[str, Any]:
    return {"type": "string", "minLength": 1, "maxLength": 20_000}


def _digest() -> dict[str, Any]:
    return {"type": "string", "pattern": "^[0-9a-f]{64}$"}


def _checks(names: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "required": names,
        "properties": {name: {"type": "boolean"} for name in names},
        "additionalProperties": False,
    }


def _closed(
    schema_id: str,
    draft: str,
    *,
    title: str,
    format_value: str,
    fields: dict[str, Any],
) -> dict[str, Any]:
    return {
        "$schema": draft,
        "$id": schema_id,
        "title": title,
        "type": "object",
        "required": ["format", *fields],
        "properties": {"format": {"const": format_value}, **fields},
        "additionalProperties": False,
    }


def gap_schema_builders(
    schema_id: Callable[[str], str], draft: str
) -> dict[str, Callable[[], dict[str, Any]]]:
    definitions: dict[str, tuple[str, str, dict[str, Any]]] = {
        "benchmark-differential-source": (
            "PySFMEA benchmark differential source",
            DIFFERENTIAL_SOURCE_FORMAT,
            {
                "generated_at": _text(),
                "authority": {"type": "object"},
                "suite": {"type": "object"},
                "policy": {"type": "object"},
                "tools": {
                    "type": "array",
                    "maxItems": 100,
                    "items": {"type": "object"},
                },
                "cases": {
                    "type": "array",
                    "maxItems": 1_000_000,
                    "items": {"type": "object"},
                },
                "limitations": {"type": "array", "items": {"type": "string"}},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "benchmark-differential-assessment": (
            "PySFMEA benchmark differential assessment",
            DIFFERENTIAL_ASSESSMENT_FORMAT,
            {
                "generated_at": _text(),
                "source_sha256": _digest(),
                "suite": {"type": "object"},
                "policy": {"type": "object"},
                "tool_results": {"type": "array", "items": {"type": "object"}},
                "pairwise_comparisons": {"type": "array", "items": {"type": "object"}},
                "disagreement_queue": {"type": "array", "items": {"type": "object"}},
                "checks": {"type": "object"},
                "summary": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "benchmark-differential-verification": (
            "PySFMEA benchmark differential verification",
            DIFFERENTIAL_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "passed": {"type": "boolean"},
                "eligible_for_validation_portfolio": {"type": "boolean"},
                "checks": {
                    "type": "object",
                    "required": [
                        "content_integrity",
                        "semantic_reconciliation",
                        "exact_source_replay",
                    ],
                    "properties": {
                        "content_integrity": {"type": "boolean"},
                        "semantic_reconciliation": {"type": "boolean"},
                        "exact_source_replay": {"type": ["boolean", "null"]},
                    },
                    "additionalProperties": False,
                },
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "benchmark-corpus-inventory": (
            "PySFMEA benchmark corpus inventory",
            BENCHMARK_CORPUS_INVENTORY_FORMAT,
            {
                "generated_at": _text(),
                "authority": _text(),
                "root": _text(),
                "corpora": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "object"},
                },
                "summary": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "benchmark-corpus-verification": (
            "PySFMEA benchmark corpus verification",
            BENCHMARK_CORPUS_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "eligible_as_corpus_identity_evidence": {"type": "boolean"},
                "checks": {
                    "type": "object",
                    "required": [
                        "content_integrity",
                        "closed_structure",
                        "exact_root_replay",
                    ],
                    "properties": {
                        "content_integrity": {"type": "boolean"},
                        "closed_structure": {"type": "boolean"},
                        "exact_root_replay": {"type": ["boolean", "null"]},
                    },
                    "additionalProperties": False,
                },
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "benchmark-proficiency-source": (
            "PySFMEA benchmark proficiency source",
            BENCHMARK_PROFICIENCY_SOURCE_FORMAT,
            {
                "generated_at": _text(),
                "scheme": {"type": "object"},
                "authorities": {"type": "object"},
                "policy": {"type": "object"},
                "items": {"type": "array", "items": {"type": "object"}},
                "participants": {"type": "array", "items": {"type": "object"}},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "benchmark-proficiency-assessment": (
            "PySFMEA benchmark proficiency assessment",
            BENCHMARK_PROFICIENCY_ASSESSMENT_FORMAT,
            {
                "generated_at": _text(),
                "source_sha256": _digest(),
                "scheme": {"type": "object"},
                "authorities": {"type": "object"},
                "policy": {"type": "object"},
                "participant_ledger": {"type": "array", "items": {"type": "object"}},
                "checks": {"type": "object"},
                "summary": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "benchmark-proficiency-verification": (
            "PySFMEA benchmark proficiency verification",
            BENCHMARK_PROFICIENCY_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "passed": {"type": "boolean"},
                "eligible_for_qualification_input": {"type": "boolean"},
                "checks": {
                    "type": "object",
                    "required": [
                        "content_integrity",
                        "closed_structure",
                        "exact_source_replay",
                    ],
                    "properties": {
                        "content_integrity": {"type": "boolean"},
                        "closed_structure": {"type": "boolean"},
                        "exact_source_replay": {"type": ["boolean", "null"]},
                    },
                    "additionalProperties": False,
                },
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "benchmark-source-health": (
            "PySFMEA benchmark source health",
            BENCHMARK_SOURCE_HEALTH_FORMAT,
            {
                "generated_at": _text(),
                "authority": _text(),
                "sources": {"type": "array", "items": {"type": "object"}},
                "summary": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "benchmark-source-health-verification": (
            "PySFMEA benchmark source-health verification",
            BENCHMARK_SOURCE_HEALTH_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "eligible_for_external_execution": {"type": "boolean"},
                "checks": _checks(
                    [
                        "content_integrity",
                        "closed_catalog_binding",
                        "all_sources_reviewed_and_pinned",
                    ]
                ),
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "industry-qualification-readiness": (
            "PySFMEA industry qualification readiness",
            INDUSTRY_QUALIFICATION_READINESS_FORMAT,
            {
                "scope_authentication": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "authenticated",
                        "trust_policy_sha256",
                        "signature_sha256",
                        "key_fingerprint",
                        "errors",
                    ],
                    "properties": {
                        "authenticated": {"type": "boolean"},
                        "trust_policy_sha256": {
                            "type": "string",
                            "pattern": "^(?:[0-9a-f]{64})?$",
                        },
                        "signature_sha256": {
                            "type": "string",
                            "pattern": "^(?:[0-9a-f]{64})?$",
                        },
                        "key_fingerprint": {
                            "type": "string",
                            "pattern": "^(?:sha256:[0-9a-f]{64})?$",
                        },
                        "errors": {"type": "array", "items": {"type": "string"}},
                    },
                },
                "generated_at": _text(),
                "authority": _text(),
                "catalogs": {
                    "type": "object",
                    "required": ["standards", "benchmarks"],
                    "properties": {
                        "standards": {
                            "type": "object",
                            "required": ["version", "content_sha256", "profiles"],
                            "properties": {
                                "version": _text(),
                                "content_sha256": _digest(),
                                "profiles": {"type": "integer", "minimum": 1},
                            },
                            "additionalProperties": False,
                        },
                        "benchmarks": {
                            "type": "object",
                            "required": ["version", "content_sha256", "suites"],
                            "properties": {
                                "version": _text(),
                                "content_sha256": _digest(),
                                "suites": {"type": "integer", "minimum": 1},
                            },
                            "additionalProperties": False,
                        },
                    },
                    "additionalProperties": False,
                },
                "evidence": {
                    "type": "array",
                    "minItems": 6,
                    "maxItems": 6,
                    "items": {
                        "type": "object",
                        "required": [
                            "kind",
                            "reference",
                            "bytes",
                            "sha256",
                            "content_sha256",
                            "valid",
                            "ready",
                        ],
                        "properties": {
                            "kind": {
                                "enum": [
                                    "standards_lifecycle",
                                    "benchmark_source_health",
                                    "benchmark_proficiency_source",
                                    "benchmark_proficiency_assessment",
                                    "validation_portfolio_source",
                                    "validation_portfolio_assessment",
                                ]
                            },
                            "reference": _text(),
                            "bytes": {"type": "integer", "minimum": 1},
                            "sha256": _digest(),
                            "content_sha256": {
                                "type": "string",
                                "pattern": "^$|^[0-9a-f]{64}$",
                            },
                            "valid": {"type": "boolean"},
                            "ready": {"type": "boolean"},
                        },
                        "additionalProperties": False,
                    },
                },
                "checks": _checks(
                    [
                        "standards_artifact_valid",
                        "standards_catalog_current",
                        "benchmark_source_artifact_valid",
                        "benchmark_sources_pinned",
                        "benchmark_adapters_operational",
                        "benchmark_proficiency_passed",
                        "independent_validation_portfolio",
                        "benchmark_item_quality_qualified",
                        "readiness_authority_separate",
                        "scope_approval_authenticated",
                    ]
                ),
                "summary": {
                    "type": "object",
                    "required": [
                        "passed",
                        "status",
                        "checks_passed",
                        "checks_required",
                        "blockers",
                    ],
                    "properties": {
                        "passed": {"type": "boolean"},
                        "status": {
                            "enum": [
                                "eligible_for_authorized_industry_qualification_review",
                                "industry_qualification_evidence_incomplete",
                            ]
                        },
                        "checks_passed": {"type": "integer", "minimum": 0},
                        "checks_required": {"type": "integer", "minimum": 1},
                        "blockers": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["check", "remediation"],
                                "properties": {
                                    "check": _text(),
                                    "remediation": _text(),
                                },
                                "additionalProperties": False,
                            },
                        },
                    },
                    "additionalProperties": False,
                },
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "industry-qualification-readiness-verification": (
            "PySFMEA industry qualification readiness verification",
            INDUSTRY_QUALIFICATION_READINESS_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "passed": {"type": "boolean"},
                "eligible_for_authorized_industry_qualification_review": {
                    "type": "boolean"
                },
                "checks": {
                    "type": "object",
                    "required": [
                        "content_integrity",
                        "closed_structure",
                        "semantic_reconciliation",
                        "exact_source_replay",
                    ],
                    "properties": {
                        "content_integrity": {"type": "boolean"},
                        "closed_structure": {"type": "boolean"},
                        "semantic_reconciliation": {"type": "boolean"},
                        "exact_source_replay": {"type": ["boolean", "null"]},
                    },
                    "additionalProperties": False,
                },
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "native-benchmark-normalization": (
            "PySFMEA native benchmark normalization",
            NATIVE_BENCHMARK_FORMAT,
            {
                "generated_at": _text(),
                "authority": _text(),
                "suite": {"type": "object"},
                "source": {"type": "object"},
                "cases": {"type": "array", "items": {"type": "object"}},
                "summary": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "native-benchmark-normalization-verification": (
            "PySFMEA native benchmark verification",
            NATIVE_BENCHMARK_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "eligible_for_observation_join": {"type": "boolean"},
                "checks": _checks(
                    ["content_integrity", "native_mapping_and_reconciliation"]
                ),
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "benchmark-item-quality": (
            "PySFMEA benchmark item quality",
            BENCHMARK_ITEM_QUALITY_FORMAT,
            {
                "generated_at": _text(),
                "authority": _text(),
                "suite": {"type": "object"},
                "policy": {"type": "object"},
                "sources": {"type": "object"},
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 1_000_000,
                    "items": {"type": "object"},
                },
                "summary": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "benchmark-case-inventory": (
            "PySFMEA benchmark case inventory",
            BENCHMARK_CASE_INVENTORY_FORMAT,
            {
                "generated_at": _text(),
                "authority": _text(),
                "suite": {"type": "object"},
                "population_basis": _text(),
                "source": {"type": "object"},
                "cases": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 1_000_000,
                    "items": {"type": "object"},
                },
                "summary": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "benchmark-case-inventory-verification": (
            "PySFMEA benchmark case inventory verification",
            BENCHMARK_CASE_INVENTORY_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "eligible_for_item_review": {"type": "boolean"},
                "checks": {
                    "type": "object",
                    "required": [
                        "content_integrity",
                        "closed_population",
                        "exact_source_replay",
                    ],
                    "properties": {
                        "content_integrity": {"type": "boolean"},
                        "closed_population": {"type": "boolean"},
                        "exact_source_replay": {"type": ["boolean", "null"]},
                    },
                    "additionalProperties": False,
                },
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "benchmark-item-quality-verification": (
            "PySFMEA benchmark item quality verification",
            BENCHMARK_ITEM_QUALITY_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "passed": {"type": "boolean"},
                "eligible_for_benchmark_claim": {"type": "boolean"},
                "checks": {
                    "type": "object",
                    "required": [
                        "content_integrity",
                        "closed_population_and_policy",
                        "exact_source_replay",
                    ],
                    "properties": {
                        "content_integrity": {"type": "boolean"},
                        "closed_population_and_policy": {"type": "boolean"},
                        "exact_source_replay": {"type": ["boolean", "null"]},
                    },
                    "additionalProperties": False,
                },
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "inspect-ai-evidence": (
            "PySFMEA Inspect AI evidence",
            INSPECT_AI_EVIDENCE_FORMAT,
            {
                "generated_at": _text(),
                "authority": _text(),
                "source": {"type": "object"},
                "evaluation": {"type": "object"},
                "samples": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 1_000_000,
                    "items": {"type": "object"},
                },
                "summary": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "inspect-ai-evidence-verification": (
            "PySFMEA Inspect AI evidence verification",
            INSPECT_AI_EVIDENCE_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "eligible_for_evaluation_join": {"type": "boolean"},
                "checks": {
                    "type": "object",
                    "required": [
                        "content_integrity_and_reconciliation",
                        "exact_source_replay",
                    ],
                    "properties": {
                        "content_integrity_and_reconciliation": {"type": "boolean"},
                        "exact_source_replay": {"type": ["boolean", "null"]},
                    },
                    "additionalProperties": False,
                },
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "inspect-ai-conformance": (
            "PySFMEA Inspect AI conformance",
            INSPECT_AI_CONFORMANCE_FORMAT,
            {
                "generated_at": _text(),
                "authority": _text(),
                "upstream": {"type": "object"},
                "bindings": {"type": "object"},
                "execution_identity": {"type": "object"},
                "configuration_keys": {"type": "array", "items": _text()},
                "schema_policy_sha256": {
                    "type": "string",
                    "pattern": "^$|^[0-9a-f]{64}$",
                },
                "schema_errors": {"type": "array", "items": _text()},
                "checks": {"type": "object"},
                "eligible_for_evaluation_portfolio": {"type": "boolean"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "inspect-ai-conformance-verification": (
            "PySFMEA Inspect AI conformance verification",
            INSPECT_AI_CONFORMANCE_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "eligible_for_evaluation_portfolio": {"type": "boolean"},
                "checks": {
                    "type": "object",
                    "required": [
                        "content_integrity",
                        "semantic_reconciliation",
                        "exact_source_replay",
                    ],
                    "properties": {
                        "content_integrity": {"type": "boolean"},
                        "semantic_reconciliation": {"type": "boolean"},
                        "exact_source_replay": {"type": ["boolean", "null"]},
                    },
                    "additionalProperties": False,
                },
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "deployed-tevv-source": (
            "PySFMEA deployed TEVV source",
            DEPLOYED_TEVV_SOURCE_FORMAT,
            {
                "generated_at": _text(),
                "authority": {"type": "object"},
                "system": {"type": "object"},
                "policy": {"type": "object"},
                "baseline": {"type": "object"},
                "monitoring_windows": {"type": "array", "items": {"type": "object"}},
                "category_evidence": {"type": "object"},
                "controls": {"type": "object"},
                "change_records": {"type": "array", "items": {"type": "object"}},
                "limitations": {"type": "array", "items": _text()},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "deployed-tevv-assessment": (
            "PySFMEA deployed TEVV assessment",
            DEPLOYED_TEVV_ASSESSMENT_FORMAT,
            {
                "generated_at": _text(),
                "source_sha256": _digest(),
                "evidence_digests": {
                    "type": "object",
                    "additionalProperties": {"type": ["string", "null"]},
                },
                "system": {"type": "object"},
                "policy": {"type": "object"},
                "windows": {"type": "array", "items": {"type": "object"}},
                "checks": {"type": "object"},
                "summary": {"type": "object"},
                "limitations": {"type": "array", "items": _text()},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "deployed-tevv-verification": (
            "PySFMEA deployed TEVV verification",
            DEPLOYED_TEVV_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "passed": {"type": "boolean"},
                "eligible_for_authorized_operational_review": {"type": "boolean"},
                "checks": {
                    "type": "object",
                    "required": [
                        "content_integrity",
                        "semantic_reconciliation",
                        "exact_source_replay",
                    ],
                    "properties": {
                        "content_integrity": {"type": "boolean"},
                        "semantic_reconciliation": {"type": "boolean"},
                        "exact_source_replay": {"type": ["boolean", "null"]},
                    },
                    "additionalProperties": False,
                },
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "genai-telemetry": (
            "PySFMEA GenAI telemetry",
            GENAI_TELEMETRY_FORMAT,
            {
                "generated_at": _text(),
                "authority": _text(),
                "semantic_convention": {"type": "object"},
                "source": {"type": "object"},
                "spans": {"type": "array", "items": {"type": "object"}},
                "summary": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "genai-telemetry-verification": (
            "PySFMEA GenAI telemetry verification",
            GENAI_TELEMETRY_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "eligible_for_deployed_tevv": {"type": "boolean"},
                "checks": {
                    "type": "object",
                    "required": [
                        "content_integrity",
                        "semantic_reconciliation",
                        "complete_operation_identity",
                        "exact_source_replay",
                    ],
                    "properties": {
                        "content_integrity": {"type": "boolean"},
                        "semantic_reconciliation": {"type": "boolean"},
                        "complete_operation_identity": {"type": "boolean"},
                        "exact_source_replay": {"type": ["boolean", "null"]},
                    },
                    "additionalProperties": False,
                },
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "confidence-calibration": (
            "PySFMEA confidence calibration",
            CONFIDENCE_CALIBRATION_FORMAT,
            {
                "generated_at": _text(),
                "authority": _text(),
                "subject": {"type": "object"},
                "policy": {"type": "object"},
                "observations": {"type": "array", "items": {"type": "object"}},
                "metrics": {"type": "object"},
                "by_stratum": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "confidence-calibration-verification": (
            "PySFMEA confidence calibration verification",
            CONFIDENCE_CALIBRATION_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "checks": _checks(
                    [
                        "content_integrity_and_structure",
                        "metric_and_stratum_reconciliation",
                    ]
                ),
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "causal-validation": (
            "PySFMEA causal validation",
            CAUSAL_VALIDATION_FORMAT,
            {
                "generated_at": _text(),
                "authority": _text(),
                "analysis_sha256": _digest(),
                "governance": {"type": "object"},
                "scenarios": {"type": "array", "items": {"type": "object"}},
                "metrics": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "causal-validation-verification": (
            "PySFMEA causal validation verification",
            CAUSAL_VALIDATION_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "eligible_for_independent_claim": {"type": "boolean"},
                "checks": _checks(
                    [
                        "content_integrity_and_structure",
                        "metric_reconciliation",
                        "independent_review",
                    ]
                ),
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "sarif-conformance": (
            "PySFMEA SARIF conformance",
            SARIF_CONFORMANCE_FORMAT,
            {
                "generated_at": _text(),
                "authority": _text(),
                "sarif": {"type": "object"},
                "official_schema": {"type": "object"},
                "assessment": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "sarif-conformance-verification": (
            "PySFMEA SARIF conformance verification",
            SARIF_CONFORMANCE_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "conformant_for_pysfmea_consumption": {"type": "boolean"},
                "checks": _checks(
                    [
                        "content_integrity_and_structure",
                        "official_schema_and_semantics_passed",
                    ]
                ),
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "openssf-scorecard-evidence": (
            "PySFMEA OpenSSF Scorecard evidence",
            SCORECARD_EVIDENCE_FORMAT,
            {
                "generated_at": _text(),
                "authority": _text(),
                "source": {"type": "object"},
                "run": {"type": "object"},
                "checks": {"type": "array", "items": {"type": "object"}},
                "summary": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "openssf-scorecard-evidence-verification": (
            "PySFMEA OpenSSF Scorecard evidence verification",
            SCORECARD_EVIDENCE_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "eligible_as_review_input": {"type": "boolean"},
                "checks": _checks(
                    ["content_integrity", "closed_mapping_and_reconciliation"]
                ),
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "standards-watchlist": (
            "PySFMEA standards watchlist",
            STANDARDS_WATCHLIST_FORMAT,
            {
                "generated_at": _text(),
                "items": {"type": "array", "items": {"type": "object"}},
                "policy": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "standards-watchlist-verification": (
            "PySFMEA standards watchlist verification",
            STANDARDS_WATCHLIST_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "checks": _checks(["content_integrity", "governed_inventory"]),
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "clusterfuzzlite-intake": (
            "PySFMEA ClusterFuzzLite artifact intake",
            CLUSTERFUZZ_INTAKE_FORMAT,
            {
                "generated_at": _text(),
                "authority": _text(),
                "run": {"type": "object"},
                "artifact_set": {"type": "object"},
                "manifest": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 500_000,
                    "items": {"type": "object"},
                },
                "campaign_projection": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "clusterfuzzlite-intake-verification": (
            "PySFMEA ClusterFuzzLite intake verification",
            CLUSTERFUZZ_INTAKE_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "eligible_for_campaign_input": {"type": "boolean"},
                "checks": _checks(
                    [
                        "content_integrity_and_structure",
                        "manifest_reconciliation",
                        "artifact_directory_binding",
                    ]
                ),
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "vulnerability-intelligence": (
            "PySFMEA governed vulnerability intelligence",
            VULNERABILITY_INTELLIGENCE_FORMAT,
            {
                "generated_at": _text(),
                "authority": _text(),
                "policy": {"type": "object"},
                "sources": {
                    "type": "array",
                    "minItems": 3,
                    "maxItems": 3,
                    "items": {"type": "object"},
                },
                "records": {
                    "type": "array",
                    "maxItems": 500_000,
                    "items": {"type": "object"},
                },
                "summary": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "vulnerability-intelligence-verification": (
            "PySFMEA vulnerability-intelligence verification",
            VULNERABILITY_INTELLIGENCE_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "eligible_for_priority_input": {"type": "boolean"},
                "checks": _checks(
                    ["content_integrity_and_structure", "source_binding", "freshness"]
                ),
                "errors": {
                    "type": "array",
                    "maxItems": 1_000,
                    "items": {"type": "string", "maxLength": 20_000},
                },
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "vulnerability-intelligence-match": (
            "PySFMEA vulnerability-intelligence identity matches",
            VULNERABILITY_INTELLIGENCE_MATCH_FORMAT,
            {
                "generated_at": _text(),
                "intelligence_sha256": _digest(),
                "query": {"type": "object"},
                "matches": {
                    "type": "array",
                    "maxItems": 500_000,
                    "items": {"type": "object"},
                },
                "summary": {"type": "object"},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "performance-history": (
            "PySFMEA longitudinal performance history",
            PERFORMANCE_HISTORY_FORMAT,
            {
                "generated_at": _text(),
                "authority": _text(),
                "policy": {"type": "object"},
                "observations": {
                    "type": "array",
                    "minItems": 2,
                    "maxItems": 1_000,
                    "items": {"type": "object"},
                },
                "comparison": {"type": "object"},
                "checks": {"type": "object"},
                "summary": {"type": "object"},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "performance-history-verification": (
            "PySFMEA performance-history verification",
            PERFORMANCE_HISTORY_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "eligible_for_release_gate": {"type": "boolean"},
                "checks": _checks(["content_integrity_and_structure", "policy_passed"]),
                "errors": {
                    "type": "array",
                    "maxItems": 1_000,
                    "items": {"type": "string", "maxLength": 20_000},
                },
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "sfmea-semantic-benchmark": (
            "PySFMEA semantic benchmark",
            SFMEA_BENCHMARK_FORMAT,
            {
                "generated_at": _text(),
                "tool": {"type": "object"},
                "repository": {"type": "object"},
                "corpus": {"type": "object"},
                "authority": _text(),
                "metrics": {"type": "object"},
                "population": {"type": "object"},
                "eligible_for_independent_claim": {"type": "boolean"},
                "evaluation": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "sfmea-semantic-benchmark-verification": (
            "PySFMEA semantic benchmark verification",
            SFMEA_BENCHMARK_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "eligible_for_independent_claim": {"type": "boolean"},
                "checks": _checks(
                    [
                        "content_integrity_and_structure",
                        "metric_and_population_reconciliation",
                        "source_binding",
                    ]
                ),
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "vulnerability-applicability": (
            "PySFMEA vulnerability applicability",
            VULNERABILITY_APPLICABILITY_FORMAT,
            {
                "generated_at": _text(),
                "authority": _text(),
                "intelligence_sha256": _digest(),
                "sbom": {"type": "object"},
                "resolver": {"type": "object"},
                "results": {
                    "type": "array",
                    "maxItems": 500_000,
                    "items": {"type": "object"},
                },
                "summary": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "vulnerability-applicability-verification": (
            "PySFMEA vulnerability applicability verification",
            VULNERABILITY_APPLICABILITY_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "eligible_for_reachability_review": {"type": "boolean"},
                "checks": _checks(
                    ["content_integrity_and_structure", "summary_reconciliation"]
                ),
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "vulnerability-workflow": (
            "PySFMEA vulnerability workflow",
            VULNERABILITY_WORKFLOW_FORMAT,
            {
                "generated_at": _text(),
                "authority": _text(),
                "applicability_sha256": _digest(),
                "decisions": {
                    "type": "array",
                    "maxItems": 500_000,
                    "items": {"type": "object"},
                },
                "records": {
                    "type": "array",
                    "maxItems": 500_000,
                    "items": {"type": "object"},
                },
                "summary": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "vulnerability-workflow-verification": (
            "PySFMEA vulnerability workflow verification",
            VULNERABILITY_WORKFLOW_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "complete": {"type": "boolean"},
                "checks": _checks(
                    ["content_integrity_and_structure", "summary_reconciliation"]
                ),
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "test-dossier": (
            "PySFMEA ISO 29119-aligned test dossier",
            TEST_DOSSIER_FORMAT,
            {
                "generated_at": _text(),
                "authority": _text(),
                "analysis": {"type": "object"},
                "standards_basis": {"type": "array", "items": {"type": "object"}},
                "policy": {"type": "object"},
                "plan": {"type": "object"},
                "test_cases": {
                    "type": "array",
                    "maxItems": 500_000,
                    "items": {"type": "object"},
                },
                "technique_coverage": {"type": "object"},
                "completion": {"type": "object"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "test-dossier-verification": (
            "PySFMEA test dossier verification",
            TEST_DOSSIER_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "complete": {"type": "boolean"},
                "checks": _checks(
                    [
                        "content_integrity_and_structure",
                        "population_and_technique_reconciliation",
                        "analysis_binding",
                    ]
                ),
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
        "samate-assessment-source": (
            "PySFMEA SAMATE assessment source",
            SAMATE_SOURCE_FORMAT,
            {
                "generated_at": _text(),
                "authority": _text(),
                "capability_claim": {"type": "object"},
                "test_plan": {"type": "object"},
                "governance": {"type": "object"},
                "cases": {
                    "type": "array",
                    "maxItems": 500_000,
                    "items": {"type": "object"},
                },
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "samate-assessment": (
            "PySFMEA SAMATE assessment",
            SAMATE_ASSESSMENT_FORMAT,
            {
                "generated_at": _text(),
                "source_sha256": _digest(),
                "capability_claim": {"type": "object"},
                "test_plan": {"type": "object"},
                "governance": {"type": "object"},
                "metrics": {"type": "object"},
                "by_weakness": {"type": "object"},
                "case_ledger": {
                    "type": "array",
                    "maxItems": 500_000,
                    "items": {"type": "object"},
                },
                "eligible_for_external_conclusion": {"type": "boolean"},
                "claim_boundary": _text(),
                "content_sha256": _digest(),
            },
        ),
        "samate-assessment-verification": (
            "PySFMEA SAMATE assessment verification",
            SAMATE_VERIFICATION_FORMAT,
            {
                "valid": {"type": "boolean"},
                "eligible_for_external_conclusion": {"type": "boolean"},
                "checks": _checks(
                    [
                        "content_integrity_and_structure",
                        "case_and_metric_reconciliation",
                    ]
                ),
                "errors": {"type": "array", "items": _text()},
                "notice": _text(),
                "content_sha256": _digest(),
            },
        ),
    }

    def bind(name: str) -> Callable[[], dict[str, Any]]:
        def build() -> dict[str, Any]:
            title, format_value, fields = definitions[name]
            return _closed(
                schema_id(name),
                draft,
                title=title,
                format_value=format_value,
                fields=fields,
            )

        return build

    return {
        **{name: bind(name) for name in definitions},
        **evidence_contract_builders(schema_id, draft),
    }
