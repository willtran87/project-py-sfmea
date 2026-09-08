"""CLI registration for executable industry-gap evidence workflows."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .benchmark_case_inventory import (
    benchmark_case_inventory,
    export_benchmark_case_inventory,
    verify_benchmark_case_inventory_file,
)
from .benchmark_corpus import (
    benchmark_corpus_inventory,
    export_benchmark_corpus_inventory,
    verify_benchmark_corpus_inventory_file,
)
from .benchmark_differential import (
    assess_benchmark_differential,
    benchmark_differential_template,
    export_benchmark_differential,
    seal_benchmark_differential_source,
    verify_benchmark_differential_file,
)
from .benchmark_item_quality import (
    benchmark_item_quality_audit,
    export_benchmark_item_quality,
    verify_benchmark_item_quality_file,
)
from .benchmark_native import (
    export_native_benchmark,
    normalize_native_benchmark,
    verify_native_benchmark_file,
)
from .benchmark_proficiency import (
    assess_benchmark_proficiency_file,
    benchmark_proficiency_template,
    export_benchmark_proficiency,
    seal_benchmark_proficiency_source,
    verify_benchmark_proficiency_file,
)
from .benchmark_source_health import (
    benchmark_source_health_template,
    export_benchmark_source_health,
    qualify_benchmark_source,
    seal_benchmark_source_health,
    verify_benchmark_source_health_file,
)
from .callgraph_benchmark import compare_callgraphs, verify_callgraph_comparison
from .causal_validation import (
    causal_validation,
    export_causal_validation,
    verify_causal_validation_file,
)
from .clusterfuzz_intake import (
    export_clusterfuzzlite_intake,
    import_clusterfuzzlite_intake,
    verify_clusterfuzzlite_intake_file,
)
from .confidence_calibration import (
    confidence_calibration,
    export_confidence_calibration,
    verify_confidence_calibration_file,
)
from .deployed_tevv import (
    deployed_tevv_assessment,
    deployed_tevv_template,
    export_deployed_tevv_assessment,
    export_deployed_tevv_source,
    seal_deployed_tevv_source,
    verify_deployed_tevv_assessment_file,
)
from .genai_telemetry import (
    export_genai_telemetry,
    import_genai_telemetry,
    verify_genai_telemetry_file,
)
from .governed_artifact import load_json, publish_json, seal
from .industry_qualification_readiness import (
    export_industry_qualification_readiness,
    industry_qualification_readiness,
    verify_industry_qualification_readiness_file,
)
from .inspect_ai_conformance import (
    export_inspect_ai_conformance,
    inspect_ai_conformance_receipt,
    verify_inspect_ai_conformance_file,
)
from .inspect_ai_evidence import (
    export_inspect_ai_evidence,
    import_inspect_ai_log,
    verify_inspect_ai_evidence_file,
)
from .interchange import export_json_document
from .performance_history import (
    export_performance_history,
    performance_history,
    verify_performance_history_file,
)
from .qualification_scope import scope_portfolio
from .samate_assessment import (
    export_samate_assessment,
    samate_assessment,
    samate_source_template,
    seal_samate_source,
    verify_samate_assessment_file,
)
from .sarif_conformance import (
    export_sarif_conformance,
    sarif_conformance,
    verify_sarif_conformance_file,
)
from .scorecard_evidence import (
    export_scorecard_evidence,
    import_scorecard_evidence,
    verify_scorecard_evidence_file,
)
from .sfmea_benchmark import (
    run_sfmea_semantic_benchmark,
    verify_sfmea_semantic_benchmark_file,
)
from .standards_watchlist import (
    export_standards_watchlist,
    verify_standards_watchlist_file,
)
from .store import load_analysis
from .test_dossier import export_test_dossier, test_dossier, verify_test_dossier_file
from .vulnerability_applicability import (
    export_vulnerability_applicability,
    verify_vulnerability_applicability_file,
    vulnerability_applicability,
)
from .vulnerability_intelligence import (
    export_vulnerability_intelligence,
    identifiers_from_cyclonedx,
    import_vulnerability_intelligence,
    verify_vulnerability_intelligence_file,
    vulnerability_intelligence_match,
)
from .vulnerability_workflow import (
    export_vulnerability_workflow,
    seal_vulnerability_workflow,
    verify_vulnerability_workflow_file,
    vulnerability_workflow_template,
)


def _verdict(
    result: dict[str, Any], *, json_output: bool, label: str, status: str
) -> int:
    if json_output:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"{label}: valid={result['valid']}, {status}")
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def register_gap_commands(subparsers: Any) -> None:
    corpus = subparsers.add_parser(
        "benchmark-corpus-inventory",
        help="create an exact inventory of every bundled benchmark corpus",
    )
    corpus.add_argument("root")
    corpus.add_argument("--authority", required=True)
    corpus.add_argument("-o", "--output", required=True)
    corpus.set_defaults(handler=_benchmark_corpus_inventory)
    corpus_verify = subparsers.add_parser(
        "benchmark-corpus-verify",
        help="verify a benchmark corpus inventory and optional exact root replay",
    )
    corpus_verify.add_argument("source")
    corpus_verify.add_argument("--root")
    corpus_verify.add_argument("--json", action="store_true")
    corpus_verify.set_defaults(handler=_benchmark_corpus_verify)

    differential_init = subparsers.add_parser(
        "benchmark-differential-init",
        help="create a case-paired multi-tool benchmark comparison source",
    )
    differential_init.add_argument("--authority", required=True)
    differential_init.add_argument("-o", "--output", required=True)
    differential_init.set_defaults(handler=_benchmark_differential_init)
    differential_seal = subparsers.add_parser(
        "benchmark-differential-seal",
        help="validate and seal an edited differential comparison source",
    )
    differential_seal.add_argument("source")
    differential_seal.add_argument("-o", "--output", required=True)
    differential_seal.set_defaults(handler=_benchmark_differential_seal)
    differential_assess = subparsers.add_parser(
        "benchmark-differential-assess",
        help="calculate paired metrics, McNemar tests, and adjudication queue",
    )
    differential_assess.add_argument("source")
    differential_assess.add_argument("-o", "--output", required=True)
    differential_assess.set_defaults(handler=_benchmark_differential_assess)
    differential_verify = subparsers.add_parser(
        "benchmark-differential-verify",
        help="verify differential evidence and optional exact source replay",
    )
    differential_verify.add_argument("assessment")
    differential_verify.add_argument("--source")
    differential_verify.add_argument("--json", action="store_true")
    differential_verify.set_defaults(handler=_benchmark_differential_verify)

    proficiency_init = subparsers.add_parser(
        "benchmark-proficiency-init",
        help="create an ISO 17043/13528-inspired proficiency scheme source",
    )
    proficiency_init.add_argument("--authority", required=True)
    proficiency_init.add_argument("-o", "--output", required=True)
    proficiency_init.set_defaults(handler=_benchmark_proficiency_init)
    proficiency_seal = subparsers.add_parser(
        "benchmark-proficiency-seal",
        help="validate and seal an edited proficiency source",
    )
    proficiency_seal.add_argument("source")
    proficiency_seal.add_argument("-o", "--output", required=True)
    proficiency_seal.set_defaults(handler=_benchmark_proficiency_seal)
    proficiency_assess = subparsers.add_parser(
        "benchmark-proficiency-assess", help="score a sealed proficiency scheme"
    )
    proficiency_assess.add_argument("source")
    proficiency_assess.add_argument("-o", "--output", required=True)
    proficiency_assess.set_defaults(handler=_benchmark_proficiency_assess)
    proficiency_verify = subparsers.add_parser(
        "benchmark-proficiency-verify",
        help="verify proficiency scoring and source replay",
    )
    proficiency_verify.add_argument("assessment")
    proficiency_verify.add_argument("--source")
    proficiency_verify.add_argument("--json", action="store_true")
    proficiency_verify.set_defaults(handler=_benchmark_proficiency_verify)

    source_init = subparsers.add_parser(
        "benchmark-source-health-init",
        help="create a closed benchmark source-health ledger",
    )
    source_init.add_argument("--authority", required=True)
    source_init.add_argument("-o", "--output", required=True)
    source_init.set_defaults(handler=_benchmark_source_health_init)
    source_qualify = subparsers.add_parser(
        "benchmark-source-qualify",
        help="bind one benchmark source to observed local bytes, license evidence, and independent review",
    )
    source_qualify.add_argument("ledger")
    source_qualify.add_argument("--suite", required=True)
    source_qualify.add_argument("--snapshot", required=True)
    source_qualify.add_argument("--revision", required=True)
    source_qualify.add_argument("--observed-url", required=True)
    source_qualify.add_argument("--license-id", required=True)
    source_qualify.add_argument("--license-evidence", required=True)
    source_qualify.add_argument("--schema-version", required=True)
    source_qualify.add_argument("--reviewer", required=True)
    source_qualify.add_argument("--next-review-at", required=True)
    source_qualify.add_argument("--notes", default="")
    source_qualify.add_argument("-o", "--output", required=True)
    source_qualify.set_defaults(handler=_benchmark_source_qualify)
    source_seal = subparsers.add_parser(
        "benchmark-source-health-seal",
        help="seal an edited benchmark source-health ledger",
    )
    source_seal.add_argument("source")
    source_seal.add_argument("-o", "--output", required=True)
    source_seal.set_defaults(handler=_benchmark_source_health_seal)
    source_verify = subparsers.add_parser(
        "benchmark-source-health-verify",
        help="verify benchmark source identity and pinning",
    )
    source_verify.add_argument("source")
    source_verify.add_argument("--json", action="store_true")
    source_verify.set_defaults(handler=_benchmark_source_health_verify)

    readiness = subparsers.add_parser(
        "industry-qualification-readiness",
        help="assess exact standards and benchmark evidence for authorized qualification review",
    )
    readiness.add_argument("--standards-lifecycle", required=True)
    readiness.add_argument("--benchmark-source-health", required=True)
    readiness.add_argument("--benchmark-proficiency-source", required=True)
    readiness.add_argument("--benchmark-proficiency", required=True)
    readiness.add_argument("--validation-portfolio-source", required=True)
    readiness.add_argument("--validation-portfolio", required=True)
    readiness.add_argument("--authority", required=True)
    readiness.add_argument("--scope-trust-policy")
    readiness.add_argument("-o", "--output", required=True)
    readiness.set_defaults(handler=_industry_qualification_readiness)
    scope = subparsers.add_parser(
        "validation-portfolio-scope",
        help="bind approved applicability to an existing portfolio",
    )
    scope.add_argument("source")
    scope.add_argument("--standard", action="append", required=True)
    for field in (
        "owner",
        "reviewer",
        "approver",
        "approval-ref",
        "approved-at",
        "next-review-at",
        "exclusion-rationale",
    ):
        scope.add_argument(f"--{field}", required=True)
    scope.add_argument("-o", "--output", required=True)
    scope.set_defaults(handler=_validation_portfolio_scope)
    readiness_verify = subparsers.add_parser(
        "industry-qualification-readiness-verify",
        help="verify qualification readiness and optional exact source replay",
    )
    readiness_verify.add_argument("source")
    readiness_verify.add_argument("--standards-lifecycle")
    readiness_verify.add_argument("--benchmark-source-health")
    readiness_verify.add_argument("--benchmark-proficiency-source")
    readiness_verify.add_argument("--benchmark-proficiency")
    readiness_verify.add_argument("--validation-portfolio-source")
    readiness_verify.add_argument("--validation-portfolio")
    readiness_verify.add_argument("--scope-trust-policy")
    readiness_verify.add_argument("--json", action="store_true")
    readiness_verify.set_defaults(handler=_industry_qualification_readiness_verify)

    inventory = subparsers.add_parser(
        "benchmark-case-inventory",
        help="create an exact governed case population for any benchmark suite",
    )
    inventory.add_argument("source", help="JSON array or object containing cases")
    inventory.add_argument("--suite", required=True)
    inventory.add_argument("--revision", required=True)
    inventory.add_argument("--authority", required=True)
    inventory.add_argument("--adapter-mode", default="governed-inventory")
    inventory.add_argument("--population-basis", required=True)
    inventory.add_argument("-o", "--output", required=True)
    inventory.set_defaults(handler=_benchmark_case_inventory)
    inventory_verify = subparsers.add_parser(
        "benchmark-case-inventory-verify",
        help="verify a governed case population and optionally replay its exact manifest",
    )
    inventory_verify.add_argument("source", help="case-inventory artifact")
    inventory_verify.add_argument("--manifest", help="original JSON case manifest")
    inventory_verify.add_argument("--json", action="store_true")
    inventory_verify.set_defaults(handler=_benchmark_case_inventory_verify)

    native = subparsers.add_parser(
        "benchmark-native-normalize", help="normalize supported native benchmark output"
    )
    native.add_argument("source")
    native.add_argument("--suite", required=True)
    native.add_argument("--revision", required=True)
    native.add_argument("--authority", required=True)
    native.add_argument("-o", "--output", required=True)
    native.set_defaults(handler=_benchmark_native_normalize)
    graph = subparsers.add_parser(
        "callgraph-benchmark",
        help="compare exact PyCG simple-JSON graph edges against a reviewed oracle",
    )
    graph.add_argument("expected")
    graph.add_argument("actual")
    graph.add_argument("--revision", required=True)
    graph.add_argument("--authority", required=True)
    graph.add_argument("-o", "--output", required=True)
    graph.set_defaults(handler=_callgraph_benchmark)
    graph_verify = subparsers.add_parser(
        "callgraph-benchmark-verify", help="exactly replay a graph comparison"
    )
    graph_verify.add_argument("source")
    graph_verify.add_argument("expected")
    graph_verify.add_argument("actual")
    graph_verify.set_defaults(handler=_callgraph_benchmark_verify)
    native_verify = subparsers.add_parser(
        "benchmark-native-verify", help="verify native benchmark normalization"
    )
    native_verify.add_argument("source")
    native_verify.add_argument("--json", action="store_true")
    native_verify.set_defaults(handler=_benchmark_native_verify)

    item_quality = subparsers.add_parser(
        "benchmark-item-quality",
        help="audit every normalized benchmark item against independent quality criteria",
    )
    item_quality.add_argument("normalization")
    item_quality.add_argument("reviews")
    item_quality.add_argument("--authority", required=True)
    item_quality.add_argument("--max-exclusion-rate", type=float, default=0.05)
    item_quality.add_argument("-o", "--output", required=True)
    item_quality.set_defaults(handler=_benchmark_item_quality)
    item_quality_verify = subparsers.add_parser(
        "benchmark-item-quality-verify",
        help="verify item-quality accounting and optional exact source replay",
    )
    item_quality_verify.add_argument("source")
    item_quality_verify.add_argument("--normalization")
    item_quality_verify.add_argument("--reviews")
    item_quality_verify.add_argument("--json", action="store_true")
    item_quality_verify.set_defaults(handler=_benchmark_item_quality_verify)

    inspect_import = subparsers.add_parser(
        "inspect-ai-import",
        help="import an exact JSON Inspect AI log as governed evaluation evidence",
    )
    inspect_import.add_argument("source")
    inspect_import.add_argument("--authority", required=True)
    inspect_import.add_argument("-o", "--output", required=True)
    inspect_import.set_defaults(handler=_inspect_ai_import)
    inspect_verify = subparsers.add_parser(
        "inspect-ai-verify",
        help="verify Inspect AI evidence and optionally replay the exact source log",
    )
    inspect_verify.add_argument("artifact")
    inspect_verify.add_argument("--source")
    inspect_verify.add_argument("--json", action="store_true")
    inspect_verify.set_defaults(handler=_inspect_ai_verify)
    inspect_conformance = subparsers.add_parser(
        "inspect-ai-conformance",
        help="validate Inspect evidence against an upstream schema and exported run config",
    )
    inspect_conformance.add_argument("evidence")
    inspect_conformance.add_argument("log")
    inspect_conformance.add_argument("schema")
    inspect_conformance.add_argument("run_config")
    inspect_conformance.add_argument("--authority", required=True)
    inspect_conformance.add_argument("--inspect-version", required=True)
    inspect_conformance.add_argument("--schema-uri", required=True)
    inspect_conformance.add_argument("--schema-policy")
    inspect_conformance.add_argument("-o", "--output", required=True)
    inspect_conformance.set_defaults(handler=_inspect_ai_conformance)
    inspect_conformance_verify = subparsers.add_parser(
        "inspect-ai-conformance-verify",
        help="verify and optionally replay an Inspect conformance receipt",
    )
    inspect_conformance_verify.add_argument("source")
    inspect_conformance_verify.add_argument("--evidence")
    inspect_conformance_verify.add_argument("--log")
    inspect_conformance_verify.add_argument("--schema")
    inspect_conformance_verify.add_argument("--run-config")
    inspect_conformance_verify.add_argument("--schema-policy")
    inspect_conformance_verify.add_argument("--json", action="store_true")
    inspect_conformance_verify.set_defaults(handler=_inspect_ai_conformance_verify)

    tevv_init = subparsers.add_parser(
        "deployed-tevv-init",
        help="create a NIST AI 800-4-aligned deployed monitoring and TEVV source",
    )
    tevv_init.add_argument("--authority", required=True)
    tevv_init.add_argument("-o", "--output", required=True)
    tevv_init.set_defaults(handler=_deployed_tevv_init)
    tevv_seal = subparsers.add_parser(
        "deployed-tevv-seal", help="validate and seal a deployed TEVV source"
    )
    tevv_seal.add_argument("source")
    tevv_seal.add_argument("-o", "--output", required=True)
    tevv_seal.set_defaults(handler=_deployed_tevv_seal)
    tevv_assess = subparsers.add_parser(
        "deployed-tevv-assess", help="assess deployed monitoring and repeated TEVV"
    )
    tevv_assess.add_argument("source")
    tevv_assess.add_argument("-o", "--output", required=True)
    tevv_assess.set_defaults(handler=_deployed_tevv_assess)
    tevv_verify = subparsers.add_parser(
        "deployed-tevv-verify",
        help="verify and optionally replay a deployed TEVV assessment",
    )
    tevv_verify.add_argument("assessment")
    tevv_verify.add_argument("--source")
    tevv_verify.add_argument("--json", action="store_true")
    tevv_verify.set_defaults(handler=_deployed_tevv_verify)
    genai_telemetry = subparsers.add_parser(
        "genai-telemetry-import",
        help="normalize a version-pinned OpenTelemetry GenAI span export",
    )
    genai_telemetry.add_argument("source")
    genai_telemetry.add_argument("--authority", required=True)
    genai_telemetry.add_argument("--convention-version", required=True)
    genai_telemetry.add_argument(
        "--stability",
        choices=["development", "alpha", "beta", "release_candidate", "stable"],
        default="development",
    )
    genai_telemetry.add_argument("-o", "--output", required=True)
    genai_telemetry.set_defaults(handler=_genai_telemetry_import)
    genai_telemetry_verify = subparsers.add_parser(
        "genai-telemetry-verify",
        help="verify GenAI telemetry and optionally replay the exact OTLP source",
    )
    genai_telemetry_verify.add_argument("artifact")
    genai_telemetry_verify.add_argument("--source")
    genai_telemetry_verify.add_argument("--json", action="store_true")
    genai_telemetry_verify.set_defaults(handler=_genai_telemetry_verify)

    calibration = subparsers.add_parser(
        "confidence-calibrate",
        help="calculate calibration, uncertainty, and risk-coverage metrics",
    )
    calibration.add_argument(
        "observations", help="JSON array of calibration observations"
    )
    calibration.add_argument("--subject-id", required=True)
    calibration.add_argument("--subject-sha256", required=True)
    calibration.add_argument("--authority", required=True)
    calibration.add_argument("--bins", type=int, default=10)
    calibration.add_argument("-o", "--output", required=True)
    calibration.set_defaults(handler=_confidence_calibrate)
    calibration_verify = subparsers.add_parser(
        "confidence-calibrate-verify", help="verify calibration metrics"
    )
    calibration_verify.add_argument("source")
    calibration_verify.add_argument("--json", action="store_true")
    calibration_verify.set_defaults(handler=_confidence_calibrate_verify)

    causal = subparsers.add_parser(
        "causal-validate",
        help="compare static cascades with runtime fault observations",
    )
    causal.add_argument("scenarios", help="JSON array of causal-validation scenarios")
    causal.add_argument("--analysis-sha256", required=True)
    causal.add_argument("--producer", required=True)
    causal.add_argument("--reviewer", required=True)
    causal.add_argument("--authority", required=True)
    causal.add_argument("-o", "--output", required=True)
    causal.set_defaults(handler=_causal_validate)
    causal_verify = subparsers.add_parser(
        "causal-validate-verify", help="verify causal-validation evidence"
    )
    causal_verify.add_argument("source")
    causal_verify.add_argument("--json", action="store_true")
    causal_verify.set_defaults(handler=_causal_validate_verify)

    sarif = subparsers.add_parser(
        "sarif-conformance",
        help="validate SARIF against an official schema and consumer semantics",
    )
    sarif.add_argument("sarif")
    sarif.add_argument("official_schema")
    sarif.add_argument("--authority", required=True)
    sarif.add_argument("--schema-release", default="SARIF 2.1.0")
    sarif.add_argument("-o", "--output", required=True)
    sarif.set_defaults(handler=_sarif_conformance)
    sarif_verify = subparsers.add_parser(
        "sarif-conformance-verify", help="verify a SARIF conformance receipt"
    )
    sarif_verify.add_argument("source")
    sarif_verify.add_argument("--json", action="store_true")
    sarif_verify.set_defaults(handler=_sarif_conformance_verify)

    scorecard = subparsers.add_parser(
        "scorecard-import",
        help="import OpenSSF Scorecard JSON as mapped review evidence",
    )
    scorecard.add_argument("source")
    scorecard.add_argument("--authority", required=True)
    scorecard.add_argument("-o", "--output", required=True)
    scorecard.set_defaults(handler=_scorecard_import)
    scorecard_verify = subparsers.add_parser(
        "scorecard-verify", help="verify mapped OpenSSF Scorecard evidence"
    )
    scorecard_verify.add_argument("source")
    scorecard_verify.add_argument("--json", action="store_true")
    scorecard_verify.set_defaults(handler=_scorecard_verify)

    watchlist = subparsers.add_parser(
        "standards-watchlist",
        help="export the non-normative standards-development watchlist",
    )
    watchlist.add_argument("-o", "--output", required=True)
    watchlist.set_defaults(handler=_standards_watchlist)
    watchlist_verify = subparsers.add_parser(
        "standards-watchlist-verify", help="verify the governed standards watchlist"
    )
    watchlist_verify.add_argument("source")
    watchlist_verify.add_argument("--json", action="store_true")
    watchlist_verify.set_defaults(handler=_standards_watchlist_verify)

    clusterfuzz = subparsers.add_parser(
        "clusterfuzzlite-intake",
        help="inventory downloaded ClusterFuzzLite artifacts with exact CI provenance",
    )
    clusterfuzz.add_argument("artifact_root")
    for name in (
        "authority",
        "repository",
        "revision",
        "run-id",
        "workflow",
        "job",
        "event",
        "sanitizer",
        "action-sha",
        "run-url",
    ):
        clusterfuzz.add_argument(f"--{name}", required=True)
    clusterfuzz.add_argument("--run-attempt", type=int, default=1)
    clusterfuzz.add_argument(
        "--mode",
        choices=["code-change", "batch", "prune", "coverage", "build"],
        required=True,
    )
    clusterfuzz.add_argument("-o", "--output", required=True)
    clusterfuzz.set_defaults(handler=_clusterfuzzlite_intake)

    clusterfuzz_verify = subparsers.add_parser(
        "clusterfuzzlite-intake-verify",
        help="verify ClusterFuzzLite intake and optionally rebind downloaded artifacts",
    )
    clusterfuzz_verify.add_argument("intake")
    clusterfuzz_verify.add_argument("--artifact-root")
    clusterfuzz_verify.add_argument("--json", action="store_true")
    clusterfuzz_verify.set_defaults(handler=_clusterfuzzlite_intake_verify)

    vuln_import = subparsers.add_parser(
        "vulnerability-intelligence-import",
        help="normalize exact local OSV, CISA KEV, and FIRST EPSS snapshots",
    )
    for name in ("osv", "kev", "epss", "authority"):
        vuln_import.add_argument(f"--{name}", required=True)
    vuln_import.add_argument("--observed-at")
    vuln_import.add_argument("--max-age-days", type=int, default=2)
    vuln_import.add_argument("-o", "--output", required=True)
    vuln_import.set_defaults(handler=_vulnerability_intelligence_import)

    vuln_verify = subparsers.add_parser(
        "vulnerability-intelligence-verify",
        help="verify intelligence integrity, exact source bindings, and freshness",
    )
    vuln_verify.add_argument("artifact")
    for name in ("osv", "kev", "epss", "as-of"):
        vuln_verify.add_argument(f"--{name}")
    vuln_verify.add_argument("--json", action="store_true")
    vuln_verify.set_defaults(handler=_vulnerability_intelligence_verify)

    vuln_match = subparsers.add_parser(
        "vulnerability-intelligence-match",
        help="match CVEs, PURLs, packages, or CycloneDX identities",
    )
    vuln_match.add_argument("artifact")
    vuln_match.add_argument("--sbom")
    for name in ("cve", "purl", "package"):
        vuln_match.add_argument(f"--{name}", action="append", default=[])
    vuln_match.add_argument("-o", "--output", required=True)
    vuln_match.set_defaults(handler=_vulnerability_intelligence_match)

    benchmark = subparsers.add_parser(
        "sfmea-benchmark-run",
        help="run direct finding, call, control, and semantic SFMEA scoring",
    )
    benchmark.add_argument("repository")
    benchmark.add_argument("corpus")
    benchmark.add_argument("--authority", required=True)
    benchmark.add_argument("-o", "--output", required=True)
    benchmark.set_defaults(handler=_sfmea_benchmark_run)

    benchmark_verify = subparsers.add_parser(
        "sfmea-benchmark-verify", help="verify a direct SFMEA benchmark result"
    )
    benchmark_verify.add_argument("result")
    benchmark_verify.add_argument("--repository")
    benchmark_verify.add_argument("--corpus")
    benchmark_verify.add_argument("--json", action="store_true")
    benchmark_verify.set_defaults(handler=_sfmea_benchmark_verify)

    applicability = subparsers.add_parser(
        "vulnerability-applicability",
        help="resolve exact CycloneDX versions against OSV affected versions",
    )
    applicability.add_argument("intelligence")
    applicability.add_argument("sbom")
    applicability.add_argument("--authority", required=True)
    applicability.add_argument("-o", "--output", required=True)
    applicability.set_defaults(handler=_vulnerability_applicability)

    applicability_verify = subparsers.add_parser(
        "vulnerability-applicability-verify",
        help="verify version-applicability reconciliation",
    )
    applicability_verify.add_argument("artifact")
    applicability_verify.add_argument("--json", action="store_true")
    applicability_verify.set_defaults(handler=_vulnerability_applicability_verify)

    workflow_init = subparsers.add_parser(
        "vulnerability-workflow-init",
        help="create a governed vulnerability decision lifecycle",
    )
    workflow_init.add_argument("applicability")
    workflow_init.add_argument("--authority", required=True)
    workflow_init.add_argument("-o", "--output", required=True)
    workflow_init.set_defaults(handler=_vulnerability_workflow_init)

    workflow_seal = subparsers.add_parser(
        "vulnerability-workflow-seal",
        help="assess and seal an edited vulnerability lifecycle",
    )
    workflow_seal.add_argument("source")
    workflow_seal.add_argument("applicability")
    workflow_seal.add_argument("-o", "--output", required=True)
    workflow_seal.set_defaults(handler=_vulnerability_workflow_seal)

    workflow_verify = subparsers.add_parser(
        "vulnerability-workflow-verify",
        help="verify lifecycle state and population accounting",
    )
    workflow_verify.add_argument("workflow")
    workflow_verify.add_argument("--json", action="store_true")
    workflow_verify.set_defaults(handler=_vulnerability_workflow_verify)

    dossier = subparsers.add_parser(
        "test-dossier",
        help="project SFMEA obligations into an ISO 29119-aligned test package",
    )
    dossier.add_argument("analysis")
    dossier.add_argument("--authority", required=True)
    dossier.add_argument("-o", "--output", required=True)
    dossier.set_defaults(handler=_test_dossier)

    dossier_verify = subparsers.add_parser(
        "test-dossier-verify",
        help="verify test-dossier integrity and exact analysis binding",
    )
    dossier_verify.add_argument("dossier")
    dossier_verify.add_argument("--analysis")
    dossier_verify.add_argument("--json", action="store_true")
    dossier_verify.set_defaults(handler=_test_dossier_verify)

    samate_init = subparsers.add_parser(
        "samate-assessment-init", help="create an SP 500-268/270 evaluation source"
    )
    samate_init.add_argument("--authority", required=True)
    samate_init.add_argument("-o", "--output", required=True)
    samate_init.set_defaults(handler=_samate_assessment_init)

    samate_seal = subparsers.add_parser(
        "samate-assessment-seal", help="validate and seal an edited SAMATE source"
    )
    samate_seal.add_argument("source")
    samate_seal.add_argument("-o", "--output", required=True)
    samate_seal.set_defaults(handler=_samate_assessment_seal)

    samate = subparsers.add_parser(
        "samate-assessment", help="derive weakness-stratified SP 500-270-style metrics"
    )
    samate.add_argument("source")
    samate.add_argument("-o", "--output", required=True)
    samate.set_defaults(handler=_samate_assessment)

    samate_verify = subparsers.add_parser(
        "samate-assessment-verify", help="verify SAMATE case and metric reconciliation"
    )
    samate_verify.add_argument("assessment")
    samate_verify.add_argument("--json", action="store_true")
    samate_verify.set_defaults(handler=_samate_assessment_verify)

    performance = subparsers.add_parser(
        "performance-history",
        help="build a comparable scanner-performance release gate",
    )
    performance.add_argument("receipts", nargs="+")
    performance.add_argument("--authority", required=True)
    performance.add_argument(
        "--max-runtime-regression-percent", type=float, default=10.0
    )
    performance.add_argument(
        "--max-memory-regression-percent", type=float, default=10.0
    )
    performance.add_argument("--minimum-observations", type=int, default=3)
    performance.add_argument("-o", "--output", required=True)
    performance.set_defaults(handler=_performance_history)

    performance_verify = subparsers.add_parser(
        "performance-history-verify",
        help="verify performance integrity and release-gate status",
    )
    performance_verify.add_argument("history")
    performance_verify.add_argument("--receipt", action="append", default=[])
    performance_verify.add_argument("--json", action="store_true")
    performance_verify.set_defaults(handler=_performance_history_verify)


def _benchmark_source_health_init(args: argparse.Namespace) -> int:
    destination = export_benchmark_source_health(
        benchmark_source_health_template(authority=args.authority), args.output
    )
    print(f"Created benchmark source-health ledger: {destination}")
    return 0


def _benchmark_source_qualify(args: argparse.Namespace) -> int:
    ledger = load_json(args.ledger, label="benchmark source-health ledger")
    value = qualify_benchmark_source(
        ledger,
        suite_id=args.suite,
        snapshot=args.snapshot,
        observed_revision=args.revision,
        observed_url=args.observed_url,
        license_id=args.license_id,
        license_evidence=args.license_evidence,
        schema_version=args.schema_version,
        reviewer=args.reviewer,
        next_review_at=args.next_review_at,
        notes=args.notes,
    )
    destination = export_benchmark_source_health(value, args.output)
    print(
        f"Qualified benchmark source: {args.suite}; ledger={destination}; "
        f"complete={value['summary']['complete']}/{value['summary']['sources']}"
    )
    return 0


def _benchmark_corpus_inventory(args: argparse.Namespace) -> int:
    value = benchmark_corpus_inventory(args.root, authority=args.authority)
    destination = export_benchmark_corpus_inventory(value, args.output)
    print(
        f"Created benchmark corpus inventory: {destination}; "
        f"corpora={value['summary']['corpora']}; files={value['summary']['files']}"
    )
    print(value["claim_boundary"])
    return 0


def _benchmark_corpus_verify(args: argparse.Namespace) -> int:
    result = verify_benchmark_corpus_inventory_file(args.source, root=args.root)
    return _verdict(
        result,
        json_output=args.json,
        label="Benchmark corpus inventory",
        status=f"identity_evidence={result['eligible_as_corpus_identity_evidence']}",
    )


def _benchmark_differential_init(args: argparse.Namespace) -> int:
    value = benchmark_differential_template(authority=args.authority)
    destination = export_benchmark_differential(value, args.output)
    print(f"Created benchmark differential source: {destination}")
    return 0


def _benchmark_differential_seal(args: argparse.Namespace) -> int:
    destination = seal_benchmark_differential_source(args.source, args.output)
    print(f"Sealed benchmark differential source: {destination}")
    return 0


def _benchmark_differential_assess(args: argparse.Namespace) -> int:
    value = assess_benchmark_differential(args.source)
    destination = export_benchmark_differential(value, args.output)
    print(
        f"Created benchmark differential assessment: {destination}; "
        f"passed={value['summary']['passed']}; "
        f"disagreements={value['summary']['disagreements']}"
    )
    return 0


def _benchmark_differential_verify(args: argparse.Namespace) -> int:
    result = verify_benchmark_differential_file(
        args.assessment, evidence_source=args.source
    )
    return _verdict(
        result,
        json_output=args.json,
        label="Benchmark differential assessment",
        status=f"portfolio_eligible={result['eligible_for_validation_portfolio']}",
    )


def _benchmark_proficiency_init(args: argparse.Namespace) -> int:
    destination = export_benchmark_proficiency(
        benchmark_proficiency_template(authority=args.authority), args.output
    )
    print(f"Created benchmark proficiency source: {destination}")
    return 0


def _benchmark_proficiency_seal(args: argparse.Namespace) -> int:
    print(
        f"Sealed benchmark proficiency source: "
        f"{seal_benchmark_proficiency_source(args.source, args.output)}"
    )
    return 0


def _benchmark_proficiency_assess(args: argparse.Namespace) -> int:
    print(
        f"Created benchmark proficiency assessment: "
        f"{assess_benchmark_proficiency_file(args.source, args.output)}"
    )
    return 0


def _benchmark_proficiency_verify(args: argparse.Namespace) -> int:
    result = verify_benchmark_proficiency_file(
        args.assessment, scheme_source=args.source
    )
    return _verdict(
        result,
        json_output=args.json,
        label="Benchmark proficiency assessment",
        status=f"qualification_input={result['eligible_for_qualification_input']}",
    )


def _benchmark_source_health_seal(args: argparse.Namespace) -> int:
    print(
        f"Sealed benchmark source-health ledger: {seal_benchmark_source_health(args.source, args.output)}"
    )
    return 0


def _benchmark_source_health_verify(args: argparse.Namespace) -> int:
    result = verify_benchmark_source_health_file(args.source)
    return _verdict(
        result,
        json_output=args.json,
        label="Benchmark source health",
        status=f"execution_eligible={result['eligible_for_external_execution']}",
    )


def _callgraph_benchmark(args: argparse.Namespace) -> int:
    value = compare_callgraphs(
        args.expected,
        args.actual,
        subject_revision=args.revision,
        authority=args.authority,
    )
    print(f"Created exact callgraph comparison: {publish_json(value, args.output)}")
    return 0


def _callgraph_benchmark_verify(args: argparse.Namespace) -> int:
    valid = verify_callgraph_comparison(
        load_json(args.source, label="callgraph comparison"), args.expected, args.actual
    )
    print(f"Callgraph exact replay: {valid}")
    return 0 if valid else 1


def _industry_qualification_readiness(args: argparse.Namespace) -> int:
    value = industry_qualification_readiness(
        scope_trust_policy=args.scope_trust_policy,
        standards_lifecycle=args.standards_lifecycle,
        benchmark_source_health=args.benchmark_source_health,
        benchmark_proficiency_source=args.benchmark_proficiency_source,
        benchmark_proficiency_assessment=args.benchmark_proficiency,
        validation_portfolio_source=args.validation_portfolio_source,
        validation_portfolio_assessment=args.validation_portfolio,
        authority=args.authority,
    )
    destination = export_industry_qualification_readiness(value, args.output)
    print(
        "Created industry qualification readiness assessment: "
        f"{destination}; passed={value['summary']['passed']}; "
        f"blockers={len(value['summary']['blockers'])}"
    )
    return 0


def _validation_portfolio_scope(args: argparse.Namespace) -> int:
    value = scope_portfolio(
        load_json(args.source, label="validation portfolio"),
        standards=args.standard,
        owner=args.owner,
        reviewer=args.reviewer,
        approver=args.approver,
        approval_ref=args.approval_ref,
        approved_at=args.approved_at,
        next_review_at=args.next_review_at,
        exclusion_rationale=args.exclusion_rationale,
    )
    print(
        f"Created scoped validation portfolio: {publish_json(seal(value), args.output)}"
    )
    return 0


def _industry_qualification_readiness_verify(args: argparse.Namespace) -> int:
    result = verify_industry_qualification_readiness_file(
        args.source,
        scope_trust_policy=args.scope_trust_policy,
        standards_lifecycle=args.standards_lifecycle,
        benchmark_source_health=args.benchmark_source_health,
        benchmark_proficiency_source=args.benchmark_proficiency_source,
        benchmark_proficiency_assessment=args.benchmark_proficiency,
        validation_portfolio_source=args.validation_portfolio_source,
        validation_portfolio_assessment=args.validation_portfolio,
    )
    return _verdict(
        result,
        json_output=args.json,
        label="Industry qualification readiness",
        status=(
            "review_eligible="
            f"{result['eligible_for_authorized_industry_qualification_review']}"
        ),
    )


def _benchmark_native_normalize(args: argparse.Namespace) -> int:
    value = normalize_native_benchmark(
        args.source,
        suite_id=args.suite,
        suite_revision=args.revision,
        authority=args.authority,
    )
    print(
        f"Created native benchmark normalization: {export_native_benchmark(value, args.output)}; cases={value['summary']['cases']}"
    )
    return 0


def _benchmark_case_inventory(args: argparse.Namespace) -> int:
    value = benchmark_case_inventory(
        args.source,
        suite_id=args.suite,
        suite_revision=args.revision,
        authority=args.authority,
        adapter_mode=args.adapter_mode,
        population_basis=args.population_basis,
    )
    destination = export_benchmark_case_inventory(value, args.output)
    print(
        f"Created benchmark case inventory: {destination}; "
        f"cases={value['summary']['cases']}"
    )
    print(value["claim_boundary"])
    return 0


def _benchmark_case_inventory_verify(args: argparse.Namespace) -> int:
    result = verify_benchmark_case_inventory_file(args.source, source=args.manifest)
    return _verdict(
        result,
        json_output=args.json,
        label="Benchmark case inventory",
        status=(
            f"item_review_eligible={result['eligible_for_item_review']}; "
            f"exact_source_replay={result['checks']['exact_source_replay']}"
        ),
    )


def _benchmark_native_verify(args: argparse.Namespace) -> int:
    result = verify_native_benchmark_file(args.source)
    return _verdict(
        result,
        json_output=args.json,
        label="Native benchmark normalization",
        status=f"join_eligible={result['eligible_for_observation_join']}",
    )


def _benchmark_item_quality(args: argparse.Namespace) -> int:
    value = benchmark_item_quality_audit(
        args.normalization,
        args.reviews,
        authority=args.authority,
        max_exclusion_rate=args.max_exclusion_rate,
    )
    destination = export_benchmark_item_quality(value, args.output)
    print(
        f"Created benchmark item-quality audit: {destination}; "
        f"passed={value['summary']['passed']}; accepted={value['summary']['accepted']}; "
        f"excluded={value['summary']['excluded']}"
    )
    print(value["claim_boundary"])
    return 0


def _benchmark_item_quality_verify(args: argparse.Namespace) -> int:
    result = verify_benchmark_item_quality_file(
        args.source,
        normalization_source=args.normalization,
        reviews_source=args.reviews,
    )
    return _verdict(
        result,
        json_output=args.json,
        label="Benchmark item quality",
        status=f"claim_eligible={result['eligible_for_benchmark_claim']}",
    )


def _inspect_ai_import(args: argparse.Namespace) -> int:
    value = import_inspect_ai_log(args.source, authority=args.authority)
    destination = export_inspect_ai_evidence(value, args.output)
    print(
        f"Imported Inspect AI evidence: {destination}; "
        f"samples={value['summary']['samples']}; errors={value['summary']['error_samples']}"
    )
    print(value["claim_boundary"])
    return 0


def _inspect_ai_verify(args: argparse.Namespace) -> int:
    result = verify_inspect_ai_evidence_file(args.artifact, source=args.source)
    return _verdict(
        result,
        json_output=args.json,
        label="Inspect AI evidence",
        status=f"join_eligible={result['eligible_for_evaluation_join']}",
    )


def _inspect_ai_conformance(args: argparse.Namespace) -> int:
    value = inspect_ai_conformance_receipt(
        args.evidence,
        args.log,
        args.schema,
        args.run_config,
        authority=args.authority,
        inspect_version=args.inspect_version,
        schema_uri=args.schema_uri,
        schema_policy_source=args.schema_policy,
    )
    destination = export_inspect_ai_conformance(value, args.output)
    print(
        f"Created Inspect AI conformance receipt: {destination}; "
        f"eligible={value['eligible_for_evaluation_portfolio']}"
    )
    print(value["claim_boundary"])
    return 0


def _inspect_ai_conformance_verify(args: argparse.Namespace) -> int:
    result = verify_inspect_ai_conformance_file(
        args.source,
        evidence_source=args.evidence,
        log_source=args.log,
        schema_source=args.schema,
        run_config_source=args.run_config,
        schema_policy_source=args.schema_policy,
    )
    return _verdict(
        result,
        json_output=args.json,
        label="Inspect AI conformance",
        status=f"portfolio_eligible={result['eligible_for_evaluation_portfolio']}",
    )


def _deployed_tevv_init(args: argparse.Namespace) -> int:
    value = deployed_tevv_template(authority=args.authority)
    destination = export_deployed_tevv_source(value, args.output)
    print(f"Created deployed TEVV source: {destination}")
    print(value["claim_boundary"])
    return 0


def _deployed_tevv_seal(args: argparse.Namespace) -> int:
    destination = seal_deployed_tevv_source(args.source, args.output)
    print(f"Sealed deployed TEVV source: {destination}")
    return 0


def _deployed_tevv_assess(args: argparse.Namespace) -> int:
    value = deployed_tevv_assessment(args.source)
    destination = export_deployed_tevv_assessment(value, args.output)
    print(
        f"Created deployed TEVV assessment: {destination}; "
        f"passed={value['summary']['passed']}"
    )
    print(value["claim_boundary"])
    return 0


def _deployed_tevv_verify(args: argparse.Namespace) -> int:
    result = verify_deployed_tevv_assessment_file(
        args.assessment, campaign_source=args.source
    )
    return _verdict(
        result,
        json_output=args.json,
        label="Deployed TEVV",
        status=(
            "operational_review_eligible="
            f"{result['eligible_for_authorized_operational_review']}"
        ),
    )


def _genai_telemetry_import(args: argparse.Namespace) -> int:
    value = import_genai_telemetry(
        args.source,
        authority=args.authority,
        convention_version=args.convention_version,
        stability=args.stability,
    )
    destination = export_genai_telemetry(value, args.output)
    print(
        f"Created GenAI telemetry artifact: {destination}; "
        f"spans={value['summary']['genai_spans']}"
    )
    print(value["claim_boundary"])
    return 0


def _genai_telemetry_verify(args: argparse.Namespace) -> int:
    result = verify_genai_telemetry_file(args.artifact, otel_source=args.source)
    return _verdict(
        result,
        json_output=args.json,
        label="GenAI telemetry",
        status=f"tevv_eligible={result['eligible_for_deployed_tevv']}",
    )


def _confidence_calibrate(args: argparse.Namespace) -> int:
    observations = load_json(args.observations, label="calibration observations")
    if not isinstance(observations, list):
        raise ValueError("calibration observations must be a JSON array")
    value = confidence_calibration(
        observations,
        subject_id=args.subject_id,
        subject_sha256=args.subject_sha256,
        authority=args.authority,
        bins=args.bins,
    )
    print(
        f"Created confidence calibration: {export_confidence_calibration(value, args.output)}; brier={value['metrics']['brier_score']}; ece={value['metrics']['expected_calibration_error']}"
    )
    return 0


def _confidence_calibrate_verify(args: argparse.Namespace) -> int:
    result = verify_confidence_calibration_file(args.source)
    return _verdict(
        result,
        json_output=args.json,
        label="Confidence calibration",
        status=f"reconciled={result['checks']['metric_and_stratum_reconciliation']}",
    )


def _causal_validate(args: argparse.Namespace) -> int:
    scenarios = load_json(args.scenarios, label="causal-validation scenarios")
    if not isinstance(scenarios, list):
        raise ValueError("causal-validation scenarios must be a JSON array")
    value = causal_validation(
        scenarios,
        analysis_sha256=args.analysis_sha256,
        producer=args.producer,
        reviewer=args.reviewer,
        authority=args.authority,
    )
    print(
        f"Created causal validation: {export_causal_validation(value, args.output)}; path_recall={value['metrics']['path_edge_recall']}"
    )
    return 0


def _causal_validate_verify(args: argparse.Namespace) -> int:
    result = verify_causal_validation_file(args.source)
    return _verdict(
        result,
        json_output=args.json,
        label="Causal validation",
        status=f"independent={result['eligible_for_independent_claim']}",
    )


def _sarif_conformance(args: argparse.Namespace) -> int:
    value = sarif_conformance(
        args.sarif,
        args.official_schema,
        authority=args.authority,
        schema_release=args.schema_release,
    )
    print(
        f"Created SARIF conformance receipt: {export_sarif_conformance(value, args.output)}; conformant={value['assessment']['schema_valid'] and value['assessment']['semantic_valid']}"
    )
    return 0


def _sarif_conformance_verify(args: argparse.Namespace) -> int:
    result = verify_sarif_conformance_file(args.source)
    return _verdict(
        result,
        json_output=args.json,
        label="SARIF conformance",
        status=f"conformant={result['conformant_for_pysfmea_consumption']}",
    )


def _scorecard_import(args: argparse.Namespace) -> int:
    value = import_scorecard_evidence(args.source, authority=args.authority)
    print(
        f"Imported OpenSSF Scorecard evidence: {export_scorecard_evidence(value, args.output)}; mapped={value['summary']['mapped_checks']}"
    )
    return 0


def _scorecard_verify(args: argparse.Namespace) -> int:
    result = verify_scorecard_evidence_file(args.source)
    return _verdict(
        result,
        json_output=args.json,
        label="OpenSSF Scorecard evidence",
        status=f"review_input={result['eligible_as_review_input']}",
    )


def _standards_watchlist(args: argparse.Namespace) -> int:
    print(
        f"Exported non-normative standards watchlist: {export_standards_watchlist(args.output)}"
    )
    return 0


def _standards_watchlist_verify(args: argparse.Namespace) -> int:
    result = verify_standards_watchlist_file(args.source)
    return _verdict(
        result,
        json_output=args.json,
        label="Standards watchlist",
        status="non_normative=true",
    )


def _clusterfuzzlite_intake(args: argparse.Namespace) -> int:
    value = import_clusterfuzzlite_intake(
        args.artifact_root,
        authority=args.authority,
        repository=args.repository,
        revision=args.revision,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
        workflow=args.workflow,
        job=args.job,
        event=args.event,
        mode=args.mode,
        sanitizer=args.sanitizer,
        action_sha=args.action_sha,
        run_url=args.run_url,
    )
    destination = export_clusterfuzzlite_intake(value, args.output)
    print(
        f"Imported ClusterFuzzLite artifacts: {destination}; files={value['artifact_set']['files']}; sarif_results={value['artifact_set']['sarif_results']}"
    )
    print(value["claim_boundary"])
    return 0


def _clusterfuzzlite_intake_verify(args: argparse.Namespace) -> int:
    result = verify_clusterfuzzlite_intake_file(
        args.intake, artifact_root=args.artifact_root
    )
    return _verdict(
        result,
        json_output=args.json,
        label="ClusterFuzzLite intake",
        status=f"campaign_input={result['eligible_for_campaign_input']}",
    )


def _vulnerability_intelligence_import(args: argparse.Namespace) -> int:
    value = import_vulnerability_intelligence(
        osv=args.osv,
        kev=args.kev,
        epss=args.epss,
        authority=args.authority,
        observed_at=args.observed_at,
        max_age_days=args.max_age_days,
    )
    destination = export_vulnerability_intelligence(value, args.output)
    print(
        f"Imported vulnerability intelligence: {destination}; records={value['summary']['records']}; known_exploited={value['summary']['known_exploited']}"
    )
    print(value["claim_boundary"])
    return 0


def _vulnerability_intelligence_verify(args: argparse.Namespace) -> int:
    sources = {
        kind: path
        for kind, path in (
            ("osv", args.osv),
            ("cisa-kev", args.kev),
            ("first-epss", args.epss),
        )
        if path
    }
    result = verify_vulnerability_intelligence_file(
        args.artifact, as_of=args.as_of, sources=sources or None
    )
    return _verdict(
        result,
        json_output=args.json,
        label="Vulnerability intelligence",
        status=f"eligible={result['eligible_for_priority_input']}",
    )


def _vulnerability_intelligence_match(args: argparse.Namespace) -> int:
    cves, purls, packages = list(args.cve), list(args.purl), list(args.package)
    if args.sbom:
        extra = identifiers_from_cyclonedx(args.sbom)
        cves.extend(extra[0])
        purls.extend(extra[1])
        packages.extend(extra[2])
    value = vulnerability_intelligence_match(
        load_json(args.artifact, label="vulnerability intelligence"),
        cves=cves,
        purls=purls,
        package_names=packages,
    )
    destination = export_json_document(value, args.output)
    print(
        f"Matched vulnerability intelligence: {destination}; matches={value['summary']['matches']}; known_exploited={value['summary']['known_exploited']}"
    )
    print(value["notice"])
    return 0


def _sfmea_benchmark_run(args: argparse.Namespace) -> int:
    value = run_sfmea_semantic_benchmark(
        args.repository, args.corpus, authority=args.authority, destination=args.output
    )
    print(f"Created direct SFMEA semantic benchmark: {Path(args.output).resolve()}")
    print(
        f"Finding P/R={value['metrics']['finding_precision']}/{value['metrics']['finding_recall']}; semantic P/R={value['metrics']['semantic_claim_precision']}/{value['metrics']['semantic_claim_recall']}; independent={value['eligible_for_independent_claim']}."
    )
    return 0


def _sfmea_benchmark_verify(args: argparse.Namespace) -> int:
    result = verify_sfmea_semantic_benchmark_file(
        args.result, repository=args.repository, corpus=args.corpus
    )
    return _verdict(
        result,
        json_output=args.json,
        label="SFMEA semantic benchmark",
        status=f"independent={result['eligible_for_independent_claim']}",
    )


def _vulnerability_applicability(args: argparse.Namespace) -> int:
    value = vulnerability_applicability(
        load_json(args.intelligence, label="vulnerability intelligence"),
        args.sbom,
        authority=args.authority,
    )
    destination = export_vulnerability_applicability(value, args.output)
    print(
        f"Created vulnerability applicability: {destination}; affected={value['summary']['affected']}; not_affected={value['summary']['not_affected']}; unresolved={value['summary']['unresolved']}"
    )
    print(value["claim_boundary"])
    return 0


def _vulnerability_applicability_verify(args: argparse.Namespace) -> int:
    result = verify_vulnerability_applicability_file(args.artifact)
    return _verdict(
        result,
        json_output=args.json,
        label="Vulnerability applicability",
        status=f"reachability_ready={result['eligible_for_reachability_review']}",
    )


def _vulnerability_workflow_init(args: argparse.Namespace) -> int:
    value = vulnerability_workflow_template(
        load_json(args.applicability, label="vulnerability applicability"),
        authority=args.authority,
    )
    destination = export_vulnerability_workflow(value, args.output)
    print(f"Created vulnerability lifecycle workspace: {destination}")
    print(value["claim_boundary"])
    return 0


def _vulnerability_workflow_seal(args: argparse.Namespace) -> int:
    print(
        f"Assessed and sealed vulnerability lifecycle: {seal_vulnerability_workflow(args.source, load_json(args.applicability, label='vulnerability applicability'), args.output)}"
    )
    return 0


def _vulnerability_workflow_verify(args: argparse.Namespace) -> int:
    result = verify_vulnerability_workflow_file(args.workflow)
    return _verdict(
        result,
        json_output=args.json,
        label="Vulnerability lifecycle",
        status=f"complete={result['complete']}",
    )


def _test_dossier(args: argparse.Namespace) -> int:
    value = test_dossier(load_analysis(args.analysis), authority=args.authority)
    destination = export_test_dossier(value, args.output)
    print(
        f"Created ISO 29119-aligned test dossier: {destination}; planned={value['completion']['planned']}; verified={value['completion']['verified']}; gaps={value['completion']['planning_gaps']}"
    )
    print(value["claim_boundary"])
    return 0


def _test_dossier_verify(args: argparse.Namespace) -> int:
    result = verify_test_dossier_file(
        args.dossier, analysis=load_analysis(args.analysis) if args.analysis else None
    )
    return _verdict(
        result,
        json_output=args.json,
        label="Test dossier",
        status=f"complete={result['complete']}",
    )


def _samate_assessment_init(args: argparse.Namespace) -> int:
    value = samate_source_template(authority=args.authority)
    destination = export_json_document(value, args.output)
    print(f"Created SAMATE assessment source: {destination}")
    print(value["claim_boundary"])
    return 0


def _samate_assessment_seal(args: argparse.Namespace) -> int:
    print(
        f"Sealed SAMATE assessment source: {seal_samate_source(args.source, args.output)}"
    )
    return 0


def _samate_assessment(args: argparse.Namespace) -> int:
    value = samate_assessment(load_json(args.source, label="SAMATE source"))
    destination = export_samate_assessment(value, args.output)
    print(
        f"Created SAMATE assessment: {destination}; cases={value['metrics']['population']}; precision={value['metrics']['precision']}; recall={value['metrics']['recall']}; external={value['eligible_for_external_conclusion']}"
    )
    print(value["claim_boundary"])
    return 0


def _samate_assessment_verify(args: argparse.Namespace) -> int:
    result = verify_samate_assessment_file(args.assessment)
    return _verdict(
        result,
        json_output=args.json,
        label="SAMATE assessment",
        status=f"external={result['eligible_for_external_conclusion']}",
    )


def _performance_history(args: argparse.Namespace) -> int:
    value = performance_history(
        args.receipts,
        authority=args.authority,
        maximum_runtime_regression_percent=args.max_runtime_regression_percent,
        maximum_memory_regression_percent=args.max_memory_regression_percent,
        minimum_observations=args.minimum_observations,
    )
    destination = export_performance_history(value, args.output)
    print(
        f"Created performance history: {destination}; observations={value['summary']['observations']}; passed={value['summary']['passed']}"
    )
    print(value["notice"])
    return 0 if value["summary"]["passed"] else 1


def _performance_history_verify(args: argparse.Namespace) -> int:
    result = verify_performance_history_file(
        args.history, receipts=args.receipt or None
    )
    return _verdict(
        result,
        json_output=args.json,
        label="Performance history",
        status=f"eligible={result['eligible_for_release_gate']}",
    )
