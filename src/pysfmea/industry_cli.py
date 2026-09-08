"""Focused CLI registration and handlers for industry assurance artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .assurance_case import (
    assurance_case,
    export_assurance_case,
    verify_assurance_case_file,
)
from .benchmark_adapter import (
    benchmark_adapter_template,
    export_benchmark_adapter,
    seal_benchmark_adapter,
    verify_benchmark_adapter_file,
)
from .benchmark_assurance import (
    benchmark_assessment,
    export_benchmark_assessment,
    verify_benchmark_assessment_file,
)
from .benchmark_observations import (
    seal_benchmark_observations,
    verify_benchmark_observations_file,
)
from .benchmark_report_v2 import (
    export_benchmark_v2_report,
    verify_benchmark_v2_report_file,
)
from .benchmark_v2 import (
    benchmark_v2_assessment,
    export_benchmark_v2_assessment,
    seal_benchmark_v2_source,
    verify_benchmark_v2_assessment_file,
)
from .campaign_runner import (
    repository_snapshot_sha256,
    run_benchmark_campaign,
    run_fuzz_campaign,
)
from .conformance import (
    APPLICABILITY,
    ASSESSMENT_STATUSES,
    assess_objective,
    conformance_workspace,
    export_conformance_workspace,
    load_conformance_workspace,
    standards_catalog,
    verify_conformance_workspace_file,
)
from .coverage_observation import (
    export_runtime_coverage_observation,
    runtime_coverage_observation,
    verify_runtime_coverage_observation_file,
)
from .csaf import export_csaf, verify_csaf_file
from .dependability import (
    dependability_assessment,
    dependability_authoring_template,
    export_dependability_assessment,
    export_dependability_authoring,
    seal_dependability_authoring,
    verify_dependability_assessment_file,
)
from .fuzz_campaign import (
    export_fuzz_campaign,
    fuzz_campaign_template,
    seal_fuzz_campaign,
    verify_fuzz_campaign_file,
)
from .gap_cli import register_gap_commands
from .gsn import export_gsn_projection, gsn_projection, verify_gsn_projection_file
from .guidance import GUIDANCE_SOURCES, GUIDELINE_PROFILES, METHODOLOGY_NOTICE
from .industry_benchmarks import (
    benchmark_execution_template,
    benchmark_suite_catalog,
    export_benchmark_catalog,
    export_benchmark_execution,
    seal_benchmark_execution_source,
    verify_benchmark_execution_file,
)
from .industry_exchange import export_exchange, verify_exchange_file
from .interchange import export_json_document
from .interoperability_validation import (
    export_independent_roundtrip_evidence,
    export_normative_schema_validation,
    independent_roundtrip_evidence,
    normative_schema_validation,
    verify_independent_roundtrip_evidence_file,
    verify_normative_schema_validation_file,
)
from .laboratory_governance import (
    export_laboratory_governance_assessment,
    export_laboratory_governance_source,
    laboratory_governance_assessment,
    laboratory_governance_template,
    seal_laboratory_governance_source,
    verify_laboratory_governance_assessment_file,
)
from .lifecycle_model import (
    export_lifecycle_model,
    import_lifecycle_model,
    verify_lifecycle_model_file,
)
from .oscal_exchange import (
    export_oscal_assessment_results,
    oscal_assessment_results,
    verify_oscal_assessment_results_file,
)
from .oscal_lifecycle import (
    export_oscal_assessment_plan,
    export_oscal_poam,
    oscal_assessment_plan,
    oscal_poam,
    verify_oscal_assessment_plan_file,
    verify_oscal_poam_file,
)
from .qualification_bases import qualification_bases_catalog
from .quality_evaluation import (
    export_quality_evaluation_assessment,
    export_quality_evaluation_source,
    quality_evaluation_assessment,
    quality_evaluation_template,
    seal_quality_evaluation_source,
    verify_quality_evaluation_assessment_file,
)
from .quantitative_fta import (
    export_quantitative_fta_assessment,
    export_quantitative_fta_source,
    quantitative_fta_assessment,
    quantitative_fta_template,
    seal_quantitative_fta_source,
    verify_quantitative_fta_assessment_file,
)
from .release_qualification import (
    export_release_qualification_assessment,
    export_release_qualification_source,
    release_qualification_assessment,
    release_qualification_source_template,
    seal_release_qualification_source,
    verify_release_qualification_assessment_file,
)
from .safety_lifecycle import (
    export_safety_lifecycle_assessment,
    export_safety_lifecycle_authoring,
    safety_lifecycle_assessment,
    safety_lifecycle_authoring_template,
    seal_safety_lifecycle_authoring,
    verify_safety_lifecycle_assessment_file,
)
from .sarif_ingestion import (
    export_sarif_fusion,
    sarif_fusion,
    verify_sarif_fusion_file,
)
from .security_prioritization import (
    export_security_prioritization_assessment,
    export_security_prioritization_source,
    seal_security_prioritization_source,
    security_prioritization_assessment,
    security_prioritization_template,
    verify_security_prioritization_assessment_file,
)
from .security_taxonomy import (
    export_security_taxonomy,
    import_security_taxonomy,
    verify_security_taxonomy_file,
)
from .sigstore_verification import (
    execute_sigstore_verification,
    verify_sigstore_verification_file,
)
from .slsa import (
    export_slsa_provenance,
    slsa_provenance_statement,
    verify_slsa_provenance_file,
)
from .slsa_policy import (
    export_slsa_policy_assessment,
    export_slsa_trust_policy,
    export_slsa_verification_observation,
    seal_slsa_trust_policy,
    seal_slsa_verification_observation,
    slsa_policy_assessment,
    slsa_trust_policy_template,
    slsa_verification_observation_template,
    verify_slsa_policy_assessment_file,
)
from .ssvc import (
    export_ssvc_assessment,
    export_ssvc_source,
    seal_ssvc_source,
    ssvc_assessment,
    ssvc_observations_template,
    ssvc_policy_template,
    verify_ssvc_assessment_file,
)
from .standards_crosswalk import (
    export_standards_crosswalk,
    standards_crosswalk,
    verify_standards_crosswalk_file,
)
from .standards_lifecycle import (
    export_standards_lifecycle,
    seal_standards_lifecycle,
    standards_lifecycle_template,
    verify_standards_lifecycle_file,
)
from .store import load_analysis
from .stpa_cast import (
    export_stpa_cast_assessment,
    export_stpa_cast_source,
    seal_stpa_cast_source,
    stpa_cast_assessment,
    stpa_cast_template,
    verify_stpa_cast_assessment_file,
)
from .structural_coverage import (
    export_structural_coverage_assessment,
    export_structural_coverage_source,
    seal_structural_coverage_source,
    structural_coverage_assessment,
    structural_coverage_template,
    verify_structural_coverage_assessment_file,
)
from .tool_qualification import (
    APPLICABILITY as TOOL_APPLICABILITY,
)
from .tool_qualification import (
    STATUSES as TOOL_STATUSES,
)
from .tool_qualification import (
    assess_tool_qualification_objective,
    export_tool_qualification_dossier,
    load_tool_qualification_dossier,
    tool_qualification_dossier,
    verify_tool_qualification_dossier_file,
)
from .validation_portfolio import (
    export_validation_portfolio_assessment,
    export_validation_portfolio_source,
    seal_validation_portfolio_source,
    validation_portfolio_assessment,
    validation_portfolio_template,
    verify_validation_portfolio_assessment_file,
)
from .validation_portfolio_report import (
    export_validation_portfolio_report,
    verify_validation_portfolio_report_file,
)
from .vex import export_cyclonedx_vex, verify_cyclonedx_vex_file

_BOUND_METHODS: dict[str, dict[str, Any]] = {
    "stpa-cast": {
        "template": stpa_cast_template,
        "export_source": export_stpa_cast_source,
        "seal": seal_stpa_cast_source,
        "assess": stpa_cast_assessment,
        "export_assessment": export_stpa_cast_assessment,
        "verify": verify_stpa_cast_assessment_file,
        "label": "STPA/CAST",
    },
    "structural-coverage": {
        "template": structural_coverage_template,
        "export_source": export_structural_coverage_source,
        "seal": seal_structural_coverage_source,
        "assess": structural_coverage_assessment,
        "export_assessment": export_structural_coverage_assessment,
        "verify": verify_structural_coverage_assessment_file,
        "label": "requirements-based structural coverage",
    },
    "quantitative-fta": {
        "template": quantitative_fta_template,
        "export_source": export_quantitative_fta_source,
        "seal": seal_quantitative_fta_source,
        "assess": quantitative_fta_assessment,
        "export_assessment": export_quantitative_fta_assessment,
        "verify": verify_quantitative_fta_assessment_file,
        "label": "quantitative FTA",
    },
    "quality-evaluation": {
        "template": quality_evaluation_template,
        "export_source": export_quality_evaluation_source,
        "seal": seal_quality_evaluation_source,
        "assess": quality_evaluation_assessment,
        "export_assessment": export_quality_evaluation_assessment,
        "verify": verify_quality_evaluation_assessment_file,
        "label": "quality evaluation",
    },
}

_UNBOUND_METHODS: dict[str, dict[str, Any]] = {
    "security-prioritization": {
        "template": security_prioritization_template,
        "export_source": export_security_prioritization_source,
        "seal": seal_security_prioritization_source,
        "assess": security_prioritization_assessment,
        "export_assessment": export_security_prioritization_assessment,
        "verify": verify_security_prioritization_assessment_file,
        "label": "security prioritization",
    },
    "laboratory-governance": {
        "template": laboratory_governance_template,
        "export_source": export_laboratory_governance_source,
        "seal": seal_laboratory_governance_source,
        "assess": laboratory_governance_assessment,
        "export_assessment": export_laboratory_governance_assessment,
        "verify": verify_laboratory_governance_assessment_file,
        "label": "laboratory governance",
    },
}


def _add_industry_method_commands(subparsers: Any) -> None:
    for name, spec in _BOUND_METHODS.items():
        init = subparsers.add_parser(
            f"{name}-init",
            help=f"create an exact-analysis-bound {spec['label']} workspace",
        )
        init.add_argument("analysis")
        init.add_argument("--authority", required=True)
        init.add_argument("-o", "--output", required=True)
        init.set_defaults(handler=_bound_method_init, industry_method=name)
        seal_command = subparsers.add_parser(
            f"{name}-seal", help=f"reseal and validate edited {spec['label']} evidence"
        )
        seal_command.add_argument("analysis")
        seal_command.add_argument("source")
        seal_command.add_argument("-o", "--output", required=True)
        seal_command.set_defaults(handler=_bound_method_seal, industry_method=name)
        assess = subparsers.add_parser(
            f"{name}-assess", help=f"derive a deterministic {spec['label']} assessment"
        )
        assess.add_argument("analysis")
        assess.add_argument("source")
        assess.add_argument("-o", "--output", required=True)
        assess.set_defaults(handler=_bound_method_assess, industry_method=name)
        verify = subparsers.add_parser(
            f"{name}-verify",
            help=f"verify {spec['label']} integrity and optional exact regeneration",
        )
        verify.add_argument("assessment")
        verify.add_argument("--analysis")
        verify.add_argument("--source")
        verify.add_argument("--json", action="store_true")
        verify.set_defaults(handler=_bound_method_verify, industry_method=name)
    for name, spec in _UNBOUND_METHODS.items():
        init = subparsers.add_parser(
            f"{name}-init", help=f"create a governed {spec['label']} workspace"
        )
        init.add_argument("--authority", required=True)
        if name == "laboratory-governance":
            init.add_argument("--subject-sha256", default="0" * 64)
        init.add_argument("-o", "--output", required=True)
        init.set_defaults(handler=_unbound_method_init, industry_method=name)
        seal_command = subparsers.add_parser(
            f"{name}-seal", help=f"reseal and validate edited {spec['label']} evidence"
        )
        seal_command.add_argument("source")
        seal_command.add_argument("-o", "--output", required=True)
        seal_command.set_defaults(handler=_unbound_method_seal, industry_method=name)
        assess = subparsers.add_parser(
            f"{name}-assess", help=f"derive a deterministic {spec['label']} assessment"
        )
        assess.add_argument("source")
        assess.add_argument("-o", "--output", required=True)
        assess.set_defaults(handler=_unbound_method_assess, industry_method=name)
        verify = subparsers.add_parser(
            f"{name}-verify",
            help=f"verify {spec['label']} integrity and optional exact regeneration",
        )
        verify.add_argument("assessment")
        verify.add_argument("--source")
        verify.add_argument("--json", action="store_true")
        verify.set_defaults(handler=_unbound_method_verify, industry_method=name)


def add_industry_commands(subparsers: Any) -> None:
    """Register standards, assurance-case, and provenance commands."""

    guidance = subparsers.add_parser(
        "guidance", help="show methodology sources and limitations"
    )
    guidance.set_defaults(handler=_guidance)

    standards = subparsers.add_parser(
        "standards-catalog",
        help="show governed industry conformance profiles and objective summaries",
    )
    standards.add_argument("--json", action="store_true", help="emit catalog JSON")
    standards.add_argument("-o", "--output", help="atomically export catalog JSON")
    standards.set_defaults(handler=_standards_catalog)

    qualification_bases = subparsers.add_parser(
        "tool-qualification-bases",
        help="show governed DO-330, ISO 26262, and IEC 61508 navigation packs",
    )
    qualification_bases.add_argument("--json", action="store_true")
    qualification_bases.add_argument("-o", "--output")
    qualification_bases.set_defaults(handler=_qualification_bases)

    conformance_init = subparsers.add_parser(
        "conformance-init",
        help="create an exact-analysis-bound standards assessment workspace",
    )
    conformance_init.add_argument("analysis", help="analysis JSON path")
    conformance_init.add_argument(
        "--profile",
        action="append",
        required=True,
        help="catalog profile ID; repeatable",
    )
    conformance_init.add_argument("--system", required=True)
    conformance_init.add_argument("--phase", required=True, help="lifecycle phase")
    conformance_init.add_argument(
        "--basis", required=True, help="profile applicability basis"
    )
    conformance_init.add_argument(
        "--authority", required=True, help="selection and tailoring authority"
    )
    conformance_init.add_argument("-o", "--output", required=True)
    conformance_init.set_defaults(handler=_conformance_init)

    conformance_assess = subparsers.add_parser(
        "conformance-assess",
        help="record one governed objective assessment and reseal the workspace",
    )
    conformance_assess.add_argument("workspace")
    conformance_assess.add_argument("objective_id")
    conformance_assess.add_argument(
        "--applicability",
        choices=tuple(sorted(APPLICABILITY)),
        required=True,
    )
    conformance_assess.add_argument(
        "--status", choices=tuple(sorted(ASSESSMENT_STATUSES)), required=True
    )
    conformance_assess.add_argument("--rationale", required=True)
    conformance_assess.add_argument("--reviewer", required=True)
    conformance_assess.add_argument("--evidence-ref", action="append", default=[])
    conformance_assess.add_argument(
        "-o", "--output", help="destination; defaults to the source workspace"
    )
    conformance_assess.set_defaults(handler=_conformance_assess)

    conformance_verify = subparsers.add_parser(
        "conformance-verify",
        help="verify conformance-workspace integrity and optional exact analysis binding",
    )
    conformance_verify.add_argument("workspace")
    conformance_verify.add_argument("--analysis")
    conformance_verify.add_argument("--json", action="store_true")
    conformance_verify.set_defaults(handler=_conformance_verify)

    crosswalk = subparsers.add_parser(
        "standards-crosswalk",
        help="generate an exact-bound standards-objective/finding/evidence crosswalk",
    )
    crosswalk.add_argument("analysis")
    crosswalk.add_argument("conformance")
    crosswalk.add_argument("mapping")
    crosswalk.add_argument("-o", "--output", required=True)
    crosswalk.set_defaults(handler=_standards_crosswalk)

    crosswalk_verify = subparsers.add_parser(
        "standards-crosswalk-verify",
        help="verify a crosswalk and optionally regenerate it from all exact sources",
    )
    crosswalk_verify.add_argument("crosswalk")
    crosswalk_verify.add_argument("--analysis")
    crosswalk_verify.add_argument("--conformance")
    crosswalk_verify.add_argument("--mapping")
    crosswalk_verify.add_argument("--json", action="store_true")
    crosswalk_verify.set_defaults(handler=_standards_crosswalk_verify)

    case_command = subparsers.add_parser(
        "assurance-case",
        help="generate an ISO 15026 / SACM-aligned claims-arguments-evidence case",
    )
    case_command.add_argument("analysis")
    case_command.add_argument(
        "--conformance", help="optional exact-bound conformance workspace"
    )
    case_command.add_argument(
        "--qualification", help="optional qualification campaign result"
    )
    case_command.add_argument("-o", "--output", required=True)
    case_command.set_defaults(handler=_assurance_case)

    case_verify = subparsers.add_parser(
        "assurance-case-verify",
        help="verify assurance-case integrity, graph, status, and optional analysis binding",
    )
    case_verify.add_argument("case")
    case_verify.add_argument("--analysis")
    case_verify.add_argument("--json", action="store_true")
    case_verify.set_defaults(handler=_assurance_case_verify)

    gsn = subparsers.add_parser(
        "gsn-project",
        help="project a structured assurance case into closed GSN v3 semantic nodes",
    )
    gsn.add_argument("case")
    gsn.add_argument("-o", "--output", required=True)
    gsn.set_defaults(handler=_gsn_project)

    gsn_verify = subparsers.add_parser(
        "gsn-verify",
        help="verify GSN graph integrity and optional exact assurance-case regeneration",
    )
    gsn_verify.add_argument("projection")
    gsn_verify.add_argument("--case")
    gsn_verify.add_argument("--json", action="store_true")
    gsn_verify.set_defaults(handler=_gsn_verify)

    exchange = subparsers.add_parser(
        "industry-exchange",
        help="export SACM, SFPM, ReqIF, or SPDX 3 standards-oriented interchange",
    )
    exchange.add_argument("kind", choices=("sacm", "sfpm", "reqif", "spdx"))
    exchange.add_argument(
        "source", help="assurance case for SACM; analysis for other kinds"
    )
    exchange.add_argument("-o", "--output", required=True)
    exchange.set_defaults(handler=_industry_exchange)

    exchange_verify = subparsers.add_parser(
        "industry-exchange-verify",
        help="verify exchange structure, source binding, and population reconciliation",
    )
    exchange_verify.add_argument("kind", choices=("sacm", "sfpm", "reqif", "spdx"))
    exchange_verify.add_argument("artifact")
    exchange_verify.add_argument("source")
    exchange_verify.add_argument("--json", action="store_true")
    exchange_verify.set_defaults(handler=_industry_exchange_verify)

    schema_validate = subparsers.add_parser(
        "industry-schema-validate",
        help="validate exact exchange bytes against a supplied normative JSON or XML Schema",
    )
    schema_validate.add_argument("artifact")
    schema_validate.add_argument("schema")
    schema_validate.add_argument(
        "--schema-kind",
        choices=("json-schema", "yaml-json-schema", "xml-schema"),
        required=True,
    )
    schema_validate.add_argument("--standard", required=True)
    schema_validate.add_argument("--edition", required=True)
    schema_validate.add_argument("--schema-uri", required=True)
    schema_validate.add_argument("--schema-sha256")
    schema_validate.add_argument("-o", "--output", required=True)
    schema_validate.set_defaults(handler=_industry_schema_validate)

    schema_verify = subparsers.add_parser(
        "industry-schema-verify",
        help="verify a normative-schema receipt and optional exact artifact/schema bindings",
    )
    schema_verify.add_argument("receipt")
    schema_verify.add_argument("--artifact")
    schema_verify.add_argument("--schema")
    schema_verify.add_argument("--json", action="store_true")
    schema_verify.set_defaults(handler=_industry_schema_verify)

    roundtrip_seal = subparsers.add_parser(
        "industry-roundtrip-seal",
        help="seal independent receiving-tool import/re-export evidence",
    )
    roundtrip_seal.add_argument("validation_receipt")
    roundtrip_seal.add_argument("observation")
    roundtrip_seal.add_argument("-o", "--output", required=True)
    roundtrip_seal.set_defaults(handler=_industry_roundtrip_seal)

    roundtrip_verify = subparsers.add_parser(
        "industry-roundtrip-verify",
        help="verify independent round-trip evidence and optional exact files",
    )
    roundtrip_verify.add_argument("evidence")
    roundtrip_verify.add_argument("--validation-receipt")
    roundtrip_verify.add_argument("--observation")
    roundtrip_verify.add_argument("--reexport")
    roundtrip_verify.add_argument("--json", action="store_true")
    roundtrip_verify.set_defaults(handler=_industry_roundtrip_verify)

    lifecycle_import = subparsers.add_parser(
        "lifecycle-import",
        help="normalize an exact ReqIF, SysML v2 JSON, or OSLC JSON-LD snapshot",
    )
    lifecycle_import.add_argument(
        "kind", choices=("reqif", "sysml2-json", "oslc-jsonld")
    )
    lifecycle_import.add_argument("source")
    lifecycle_import.add_argument("--analysis")
    lifecycle_import.add_argument("-o", "--output", required=True)
    lifecycle_import.set_defaults(handler=_lifecycle_import)

    lifecycle_verify = subparsers.add_parser(
        "lifecycle-import-verify",
        help="verify a lifecycle bridge and optional exact-source regeneration",
    )
    lifecycle_verify.add_argument("model")
    lifecycle_verify.add_argument("--source")
    lifecycle_verify.add_argument("--analysis")
    lifecycle_verify.add_argument("--json", action="store_true")
    lifecycle_verify.set_defaults(handler=_lifecycle_import_verify)

    provenance = subparsers.add_parser(
        "provenance",
        help="export an in-toto Statement with SLSA Provenance v1 for an analysis",
    )
    provenance.add_argument("analysis", help="analysis JSON path")
    provenance.add_argument("-o", "--output", required=True)
    provenance.set_defaults(handler=_provenance)

    provenance_verify = subparsers.add_parser(
        "provenance-verify",
        help="verify SLSA structure and optional exact analysis subject/state binding",
    )
    provenance_verify.add_argument("provenance", help="SLSA provenance JSON path")
    provenance_verify.add_argument("--analysis", help="exact analysis JSON subject")
    provenance_verify.add_argument("--json", action="store_true")
    provenance_verify.set_defaults(handler=_provenance_verify)

    slsa_policy_init = subparsers.add_parser(
        "slsa-policy-init", help="create a deny-by-default SLSA 1.2 trust policy"
    )
    slsa_policy_init.add_argument("--authority", required=True)
    slsa_policy_init.add_argument("-o", "--output", required=True)
    slsa_policy_init.set_defaults(handler=_slsa_policy_init)

    slsa_observation_init = subparsers.add_parser(
        "slsa-observation-init",
        help="create an external-verifier evidence intake record",
    )
    slsa_observation_init.add_argument("--verifier", required=True)
    slsa_observation_init.add_argument("-o", "--output", required=True)
    slsa_observation_init.set_defaults(handler=_slsa_observation_init)

    slsa_policy_seal = subparsers.add_parser(
        "slsa-policy-seal", help="reseal and validate a SLSA trust policy"
    )
    slsa_policy_seal.add_argument("source")
    slsa_policy_seal.add_argument("-o", "--output", required=True)
    slsa_policy_seal.set_defaults(handler=_slsa_policy_seal)

    slsa_observation_seal = subparsers.add_parser(
        "slsa-observation-seal",
        help="reseal and validate external SLSA verification evidence",
    )
    slsa_observation_seal.add_argument("source")
    slsa_observation_seal.add_argument("-o", "--output", required=True)
    slsa_observation_seal.set_defaults(handler=_slsa_observation_seal)

    slsa_policy_assess = subparsers.add_parser(
        "slsa-policy-assess",
        help="evaluate SLSA 1.2 Build and Source levels against local trust policy",
    )
    slsa_policy_assess.add_argument("provenance")
    slsa_policy_assess.add_argument("policy")
    slsa_policy_assess.add_argument("observation")
    slsa_policy_assess.add_argument("-o", "--output", required=True)
    slsa_policy_assess.set_defaults(handler=_slsa_policy_assess)

    slsa_policy_verify = subparsers.add_parser(
        "slsa-policy-verify",
        help="verify SLSA policy accounting and optional exact-source regeneration",
    )
    slsa_policy_verify.add_argument("assessment")
    slsa_policy_verify.add_argument("--provenance")
    slsa_policy_verify.add_argument("--policy")
    slsa_policy_verify.add_argument("--observation")
    slsa_policy_verify.add_argument("--json", action="store_true")
    slsa_policy_verify.set_defaults(handler=_slsa_policy_verify)

    sigstore_verify = subparsers.add_parser(
        "sigstore-verify",
        help="verify an exact artifact against an offline Sigstore bundle with cosign",
    )
    sigstore_verify.add_argument("artifact")
    sigstore_verify.add_argument("bundle")
    sigstore_verify.add_argument("--trusted-root", required=True)
    sigstore_verify.add_argument("--certificate-identity", required=True)
    sigstore_verify.add_argument("--certificate-oidc-issuer", required=True)
    sigstore_verify.add_argument("--authority", required=True)
    sigstore_verify.add_argument("--cosign", default="cosign")
    sigstore_verify.add_argument("-o", "--output", required=True)
    sigstore_verify.set_defaults(handler=_sigstore_verify)

    sigstore_receipt_verify = subparsers.add_parser(
        "sigstore-receipt-verify",
        help="verify a Sigstore receipt and optional exact artifact/bundle bindings",
    )
    sigstore_receipt_verify.add_argument("receipt")
    sigstore_receipt_verify.add_argument("--artifact")
    sigstore_receipt_verify.add_argument("--bundle")
    sigstore_receipt_verify.add_argument("--trusted-root")
    sigstore_receipt_verify.add_argument("--json", action="store_true")
    sigstore_receipt_verify.set_defaults(handler=_sigstore_receipt_verify)

    ssvc_policy_init = subparsers.add_parser(
        "ssvc-policy-init",
        help="create a controlled SSVC-style decision-table template",
    )
    ssvc_policy_init.add_argument("--authority", required=True)
    ssvc_policy_init.add_argument("-o", "--output", required=True)
    ssvc_policy_init.set_defaults(handler=_ssvc_policy_init)

    ssvc_observations_init = subparsers.add_parser(
        "ssvc-observations-init",
        help="create policy-bound vulnerability evidence intake",
    )
    ssvc_observations_init.add_argument("--policy-digest", required=True)
    ssvc_observations_init.add_argument("--authority", required=True)
    ssvc_observations_init.add_argument("-o", "--output", required=True)
    ssvc_observations_init.set_defaults(handler=_ssvc_observations_init)

    ssvc_seal = subparsers.add_parser(
        "ssvc-seal", help="reseal and validate an SSVC policy or observation set"
    )
    ssvc_seal.add_argument("source")
    ssvc_seal.add_argument("--policy", help="required for an observation set")
    ssvc_seal.add_argument("-o", "--output", required=True)
    ssvc_seal.set_defaults(handler=_ssvc_seal)

    ssvc_assess = subparsers.add_parser(
        "ssvc-assess", help="deterministically apply a controlled SSVC decision table"
    )
    ssvc_assess.add_argument("policy")
    ssvc_assess.add_argument("observations")
    ssvc_assess.add_argument("-o", "--output", required=True)
    ssvc_assess.set_defaults(handler=_ssvc_assess)

    ssvc_verify = subparsers.add_parser(
        "ssvc-verify",
        help="verify SSVC outcome accounting and optional exact regeneration",
    )
    ssvc_verify.add_argument("assessment")
    ssvc_verify.add_argument("--policy")
    ssvc_verify.add_argument("--observations")
    ssvc_verify.add_argument("--json", action="store_true")
    ssvc_verify.set_defaults(handler=_ssvc_verify)

    vex = subparsers.add_parser(
        "vex",
        help="publish CycloneDX 1.7 VEX from explicit authority-attributed decisions",
    )
    vex.add_argument("analysis")
    vex.add_argument("decisions")
    vex.add_argument("-o", "--output", required=True)
    vex.set_defaults(handler=_vex)

    vex_verify = subparsers.add_parser(
        "vex-verify",
        help="verify CycloneDX VEX against exact analysis and decision sources",
    )
    vex_verify.add_argument("vex")
    vex_verify.add_argument("analysis")
    vex_verify.add_argument("decisions")
    vex_verify.add_argument("--json", action="store_true")
    vex_verify.set_defaults(handler=_vex_verify)

    csaf = subparsers.add_parser(
        "csaf",
        help="publish an OASIS CSAF 2.0 advisory from governed VEX decisions",
    )
    csaf.add_argument("analysis")
    csaf.add_argument("decisions")
    csaf.add_argument("-o", "--output", required=True)
    csaf.set_defaults(handler=_csaf)

    csaf_verify = subparsers.add_parser(
        "csaf-verify",
        help="verify CSAF projection against exact analysis and decision sources",
    )
    csaf_verify.add_argument("csaf")
    csaf_verify.add_argument("analysis")
    csaf_verify.add_argument("decisions")
    csaf_verify.add_argument("--json", action="store_true")
    csaf_verify.set_defaults(handler=_csaf_verify)

    benchmark = subparsers.add_parser(
        "benchmark-assess",
        help="apply a pre-registered statistical benchmark protocol to a qualification campaign",
    )
    benchmark.add_argument("protocol")
    benchmark.add_argument("qualification_result")
    benchmark.add_argument("qualification_manifest")
    benchmark.add_argument("--execution-started-at", required=True)
    benchmark.add_argument("--execution-evidence-ref", required=True)
    benchmark.add_argument("-o", "--output", required=True)
    benchmark.set_defaults(handler=_benchmark_assess)

    benchmark_verify = subparsers.add_parser(
        "benchmark-verify",
        help="verify benchmark statistics and optional exact-source regeneration",
    )
    benchmark_verify.add_argument("assessment")
    benchmark_verify.add_argument("--protocol")
    benchmark_verify.add_argument("--qualification-result")
    benchmark_verify.add_argument("--qualification-manifest")
    benchmark_verify.add_argument("--json", action="store_true")
    benchmark_verify.set_defaults(handler=_benchmark_verify)

    benchmark_v2 = subparsers.add_parser(
        "benchmark-assess-v2",
        help="assess repository-clustered, stratified independent benchmark observations",
    )
    benchmark_v2.add_argument("protocol")
    benchmark_v2.add_argument("observations")
    benchmark_v2.add_argument("-o", "--output", required=True)
    benchmark_v2.set_defaults(handler=_benchmark_assess_v2)

    benchmark_v2_seal = subparsers.add_parser(
        "benchmark-seal-v2",
        help="reseal and validate an edited format-2 benchmark protocol or observation set",
    )
    benchmark_v2_seal.add_argument("source")
    benchmark_v2_seal.add_argument(
        "--protocol", help="required when sealing an observation set"
    )
    benchmark_v2_seal.add_argument("-o", "--output", required=True)
    benchmark_v2_seal.set_defaults(handler=_benchmark_seal_v2)

    benchmark_v2_verify = subparsers.add_parser(
        "benchmark-verify-v2",
        help="verify advanced benchmark statistics and optional exact regeneration",
    )
    benchmark_v2_verify.add_argument("assessment")
    benchmark_v2_verify.add_argument("--protocol")
    benchmark_v2_verify.add_argument("--observations")
    benchmark_v2_verify.add_argument("--json", action="store_true")
    benchmark_v2_verify.set_defaults(handler=_benchmark_verify_v2)

    benchmark_v2_report = subparsers.add_parser(
        "benchmark-report-v2",
        help="publish a self-contained advanced benchmark review report",
    )
    benchmark_v2_report.add_argument("assessment")
    benchmark_v2_report.add_argument("--title", default="Independent benchmark review")
    benchmark_v2_report.add_argument("-o", "--output", required=True)
    benchmark_v2_report.set_defaults(handler=_benchmark_report_v2)

    benchmark_v2_report_verify = subparsers.add_parser(
        "benchmark-report-verify-v2",
        help="verify benchmark report integrity and optional assessment binding",
    )
    benchmark_v2_report_verify.add_argument("report")
    benchmark_v2_report_verify.add_argument("--assessment")
    benchmark_v2_report_verify.add_argument("--json", action="store_true")
    benchmark_v2_report_verify.set_defaults(handler=_benchmark_report_verify_v2)

    release_init = subparsers.add_parser(
        "release-qualification-init",
        help="create a pre-registered independent benchmark release gate",
    )
    release_init.add_argument("--authority", required=True)
    release_init.add_argument("-o", "--output", required=True)
    release_init.set_defaults(handler=_release_qualification_init)

    release_seal = subparsers.add_parser(
        "release-qualification-seal",
        help="reseal and validate an edited release qualification source",
    )
    release_seal.add_argument("source")
    release_seal.add_argument("-o", "--output", required=True)
    release_seal.set_defaults(handler=_release_qualification_seal)

    release_assess = subparsers.add_parser(
        "release-qualification-assess",
        help="apply leakage, temporal, non-inferiority, and performance release gates",
    )
    release_assess.add_argument("source")
    release_assess.add_argument("candidate")
    release_assess.add_argument("baseline")
    release_assess.add_argument("-o", "--output", required=True)
    release_assess.set_defaults(handler=_release_qualification_assess)

    release_verify = subparsers.add_parser(
        "release-qualification-verify",
        help="verify release gate accounting and optional exact-source regeneration",
    )
    release_verify.add_argument("assessment")
    release_verify.add_argument("--source")
    release_verify.add_argument("--candidate")
    release_verify.add_argument("--baseline")
    release_verify.add_argument("--json", action="store_true")
    release_verify.set_defaults(handler=_release_qualification_verify)

    dependability_init = subparsers.add_parser(
        "dependability-init",
        help="create an exact-analysis-bound IEC HAZOP/RBD/Markov authoring template",
    )
    dependability_init.add_argument("analysis")
    dependability_init.add_argument("--authority", required=True)
    dependability_init.add_argument("-o", "--output", required=True)
    dependability_init.set_defaults(handler=_dependability_init)

    dependability_assess = subparsers.add_parser(
        "dependability-assess",
        help="evaluate a completed HAZOP, RBD, and Markov authoring artifact",
    )
    dependability_assess.add_argument("analysis")
    dependability_assess.add_argument("authoring")
    dependability_assess.add_argument("-o", "--output", required=True)
    dependability_assess.set_defaults(handler=_dependability_assess)

    dependability_seal = subparsers.add_parser(
        "dependability-seal",
        help="reseal and validate edited HAZOP/RBD/Markov authoring against its analysis",
    )
    dependability_seal.add_argument("analysis")
    dependability_seal.add_argument("authoring")
    dependability_seal.add_argument("-o", "--output", required=True)
    dependability_seal.set_defaults(handler=_dependability_seal)

    dependability_verify = subparsers.add_parser(
        "dependability-verify",
        help="verify a dependability assessment and optional exact-source regeneration",
    )
    dependability_verify.add_argument("assessment")
    dependability_verify.add_argument("--analysis")
    dependability_verify.add_argument("--authoring")
    dependability_verify.add_argument("--json", action="store_true")
    dependability_verify.set_defaults(handler=_dependability_verify)

    safety_init = subparsers.add_parser(
        "safety-lifecycle-init",
        help="create exact-bound PHA/FHA/PSSA/SSA/operations and CCFA review scope",
    )
    safety_init.add_argument("analysis")
    safety_init.add_argument("--authority", required=True)
    safety_init.add_argument("-o", "--output", required=True)
    safety_init.set_defaults(handler=_safety_lifecycle_init)

    safety_seal = subparsers.add_parser(
        "safety-lifecycle-seal",
        help="reseal edited safety lifecycle authoring against its analysis",
    )
    safety_seal.add_argument("analysis")
    safety_seal.add_argument("authoring")
    safety_seal.add_argument("-o", "--output", required=True)
    safety_seal.set_defaults(handler=_safety_lifecycle_seal)

    safety_assess = subparsers.add_parser(
        "safety-lifecycle-assess",
        help="assess safety lifecycle traceability and CCFA coverage",
    )
    safety_assess.add_argument("analysis")
    safety_assess.add_argument("authoring")
    safety_assess.add_argument("-o", "--output", required=True)
    safety_assess.set_defaults(handler=_safety_lifecycle_assess)

    safety_verify = subparsers.add_parser(
        "safety-lifecycle-verify",
        help="verify safety lifecycle accounting and optional exact-source regeneration",
    )
    safety_verify.add_argument("assessment")
    safety_verify.add_argument("--analysis")
    safety_verify.add_argument("--authoring")
    safety_verify.add_argument("--json", action="store_true")
    safety_verify.set_defaults(handler=_safety_lifecycle_verify)

    tool_init = subparsers.add_parser(
        "tool-qualification-init",
        help="create an exact-bound, fail-visible tool qualification dossier",
    )
    tool_init.add_argument("analysis")
    tool_init.add_argument("--benchmark", required=True)
    tool_init.add_argument("--conformance", required=True)
    tool_init.add_argument("--anomalies", required=True)
    tool_init.add_argument("--intended-use", required=True)
    tool_init.add_argument("--reliance", required=True)
    tool_init.add_argument("--basis", required=True)
    tool_init.add_argument("--classification", required=True)
    tool_init.add_argument("--environment", required=True)
    tool_init.add_argument("--authority", required=True)
    tool_init.add_argument("-o", "--output", required=True)
    tool_init.set_defaults(handler=_tool_qualification_init)

    tool_assess = subparsers.add_parser(
        "tool-qualification-assess",
        help="record one governed tool qualification objective decision",
    )
    tool_assess.add_argument("dossier")
    tool_assess.add_argument("objective_id")
    tool_assess.add_argument(
        "--applicability", choices=tuple(sorted(TOOL_APPLICABILITY)), required=True
    )
    tool_assess.add_argument(
        "--status", choices=tuple(sorted(TOOL_STATUSES)), required=True
    )
    tool_assess.add_argument("--rationale", required=True)
    tool_assess.add_argument("--reviewer", required=True)
    tool_assess.add_argument("--evidence-ref", action="append", default=[])
    tool_assess.add_argument("-o", "--output")
    tool_assess.set_defaults(handler=_tool_qualification_assess)

    tool_verify = subparsers.add_parser(
        "tool-qualification-verify",
        help="verify a dossier and optional exact source-artifact bindings",
    )
    tool_verify.add_argument("dossier")
    tool_verify.add_argument("--analysis")
    tool_verify.add_argument("--benchmark")
    tool_verify.add_argument("--conformance")
    tool_verify.add_argument("--anomalies")
    tool_verify.add_argument("--json", action="store_true")
    tool_verify.set_defaults(handler=_tool_qualification_verify)

    coverage_import = subparsers.add_parser(
        "runtime-coverage-import",
        help="import exact coverage.py JSON as analysis-bound runtime evidence",
    )
    coverage_import.add_argument("analysis")
    coverage_import.add_argument("coverage_json")
    coverage_import.add_argument("--authority", required=True)
    coverage_import.add_argument("--command", required=True)
    coverage_import.add_argument("--configuration-sha256", required=True)
    coverage_import.add_argument("--environment", required=True)
    coverage_import.add_argument("--test-run-ref", required=True)
    coverage_import.add_argument("--evidence-ref", action="append", required=True)
    coverage_import.add_argument("--minimum-statement-rate", type=float, default=0.9)
    coverage_import.add_argument("--minimum-branch-rate", type=float, default=0.9)
    coverage_import.add_argument("--require-all-components", action="store_true")
    coverage_import.add_argument(
        "--object-code-basis",
        choices=("not_required", "required_complete", "required_incomplete"),
        default="not_required",
    )
    coverage_import.add_argument("-o", "--output", required=True)
    coverage_import.set_defaults(handler=_runtime_coverage_import)

    coverage_verify = subparsers.add_parser(
        "runtime-coverage-verify",
        help="verify runtime coverage integrity and optional exact regeneration",
    )
    coverage_verify.add_argument("observation")
    coverage_verify.add_argument("--analysis")
    coverage_verify.add_argument("--coverage-json")
    coverage_verify.add_argument("--json", action="store_true")
    coverage_verify.set_defaults(handler=_runtime_coverage_verify)

    portfolio_init = subparsers.add_parser(
        "validation-portfolio-init",
        help="create an industry-validation portfolio workspace",
    )
    portfolio_init.add_argument("--authority", required=True)
    portfolio_init.add_argument("-o", "--output", required=True)
    portfolio_init.set_defaults(handler=_validation_portfolio_init)

    portfolio_seal = subparsers.add_parser(
        "validation-portfolio-seal",
        help="reseal and validate an edited industry-validation portfolio",
    )
    portfolio_seal.add_argument("source")
    portfolio_seal.add_argument("-o", "--output", required=True)
    portfolio_seal.set_defaults(handler=_validation_portfolio_seal)

    portfolio_assess = subparsers.add_parser(
        "validation-portfolio-assess",
        help="assess an exact external benchmark and validation portfolio",
    )
    portfolio_assess.add_argument("source")
    portfolio_assess.add_argument("-o", "--output", required=True)
    portfolio_assess.set_defaults(handler=_validation_portfolio_assess)

    portfolio_verify = subparsers.add_parser(
        "validation-portfolio-verify",
        help="verify portfolio assessment integrity and optional exact regeneration",
    )
    portfolio_verify.add_argument("assessment")
    portfolio_verify.add_argument("--source")
    portfolio_verify.add_argument("--json", action="store_true")
    portfolio_verify.set_defaults(handler=_validation_portfolio_verify)

    portfolio_report = subparsers.add_parser(
        "validation-portfolio-report",
        help="render a self-contained industry-validation portfolio report",
    )
    portfolio_report.add_argument("assessment")
    portfolio_report.add_argument("--title", default="Industry validation portfolio")
    portfolio_report.add_argument("-o", "--output", required=True)
    portfolio_report.set_defaults(handler=_validation_portfolio_report)

    portfolio_report_verify = subparsers.add_parser(
        "validation-portfolio-report-verify",
        help="verify portfolio report integrity and optional exact assessment binding",
    )
    portfolio_report_verify.add_argument("report")
    portfolio_report_verify.add_argument("--assessment")
    portfolio_report_verify.add_argument("--json", action="store_true")
    portfolio_report_verify.set_defaults(handler=_validation_portfolio_report_verify)

    sarif_import = subparsers.add_parser(
        "sarif-fuse",
        help="fuse exact SARIF 2.1.0 results into an analysis-bound triage artifact",
    )
    sarif_import.add_argument("analysis")
    sarif_import.add_argument("sarif", nargs="+")
    sarif_import.add_argument("--authority", required=True)
    sarif_import.add_argument("--evidence-ref", action="append", required=True)
    sarif_import.add_argument("-o", "--output", required=True)
    sarif_import.set_defaults(handler=_sarif_fuse)

    sarif_verify = subparsers.add_parser(
        "sarif-fuse-verify",
        help="verify SARIF fusion integrity and optional exact regeneration",
    )
    sarif_verify.add_argument("fusion")
    sarif_verify.add_argument("--analysis")
    sarif_verify.add_argument("--sarif", action="append")
    sarif_verify.add_argument("--json", action="store_true")
    sarif_verify.set_defaults(handler=_sarif_fuse_verify)

    oscal_export = subparsers.add_parser(
        "oscal-assessment-results",
        help="export exact-analysis-bound OSCAL Assessment Results observations",
    )
    oscal_export.add_argument("analysis")
    oscal_export.add_argument("--authority", required=True)
    oscal_export.add_argument(
        "--title", default="PySFMEA software assurance assessment results"
    )
    oscal_export.add_argument("--assessment-plan-href")
    oscal_export.add_argument("--evidence-base-href")
    oscal_export.add_argument("-o", "--output", required=True)
    oscal_export.set_defaults(handler=_oscal_assessment_results)

    oscal_verify = subparsers.add_parser(
        "oscal-assessment-results-verify",
        help="verify the supported OSCAL subset and optional exact analysis binding",
    )
    oscal_verify.add_argument("oscal")
    oscal_verify.add_argument("--analysis")
    oscal_verify.add_argument("--json", action="store_true")
    oscal_verify.set_defaults(handler=_oscal_assessment_results_verify)

    oscal_plan = subparsers.add_parser(
        "oscal-assessment-plan",
        help="export an exact-analysis-bound OSCAL Assessment Plan scaffold",
    )
    oscal_plan.add_argument("analysis")
    oscal_plan.add_argument("--authority", required=True)
    oscal_plan.add_argument("--ssp-href", required=True)
    oscal_plan.add_argument(
        "--title", default="PySFMEA software assurance assessment plan"
    )
    oscal_plan.add_argument("-o", "--output", required=True)
    oscal_plan.set_defaults(handler=_oscal_assessment_plan)

    oscal_plan_verify = subparsers.add_parser(
        "oscal-assessment-plan-verify",
        help="verify the OSCAL Assessment Plan subset and optional exact analysis binding",
    )
    oscal_plan_verify.add_argument("oscal")
    oscal_plan_verify.add_argument("--analysis")
    oscal_plan_verify.add_argument("--json", action="store_true")
    oscal_plan_verify.set_defaults(handler=_oscal_assessment_plan_verify)

    oscal_poam_parser = subparsers.add_parser(
        "oscal-poam",
        help="export open findings as exact-analysis-bound OSCAL POA&M items",
    )
    oscal_poam_parser.add_argument("analysis")
    oscal_poam_parser.add_argument("--authority", required=True)
    oscal_poam_parser.add_argument("--ssp-href", required=True)
    oscal_poam_parser.add_argument(
        "--title", default="PySFMEA plan of action and milestones"
    )
    oscal_poam_parser.add_argument("-o", "--output", required=True)
    oscal_poam_parser.set_defaults(handler=_oscal_poam)

    oscal_poam_verify = subparsers.add_parser(
        "oscal-poam-verify",
        help="verify the OSCAL POA&M subset and optional exact analysis binding",
    )
    oscal_poam_verify.add_argument("oscal")
    oscal_poam_verify.add_argument("--analysis")
    oscal_poam_verify.add_argument("--json", action="store_true")
    oscal_poam_verify.set_defaults(handler=_oscal_poam_verify)

    benchmark_catalog = subparsers.add_parser(
        "benchmark-suite-catalog",
        help="show governed external Python benchmark targets",
    )
    benchmark_catalog.add_argument("--json", action="store_true")
    benchmark_catalog.add_argument("-o", "--output")
    benchmark_catalog.set_defaults(handler=_benchmark_suite_catalog)

    adapter_init = subparsers.add_parser(
        "benchmark-adapter-init",
        help="create a governed suite-specific benchmark adapter contract",
    )
    adapter_init.add_argument("--suite", required=True)
    adapter_init.add_argument("--authority", required=True)
    adapter_init.add_argument("-o", "--output", required=True)
    adapter_init.set_defaults(handler=_benchmark_adapter_init)

    adapter_seal = subparsers.add_parser(
        "benchmark-adapter-seal",
        help="validate and seal an edited benchmark adapter contract",
    )
    adapter_seal.add_argument("source")
    adapter_seal.add_argument("-o", "--output", required=True)
    adapter_seal.set_defaults(handler=_benchmark_adapter_seal)

    adapter_verify = subparsers.add_parser(
        "benchmark-adapter-verify",
        help="verify adapter integrity, provenance, normalization, and independent review",
    )
    adapter_verify.add_argument("adapter")
    adapter_verify.add_argument("--json", action="store_true")
    adapter_verify.set_defaults(handler=_benchmark_adapter_verify)

    taxonomy_import = subparsers.add_parser(
        "security-taxonomy-import",
        help="import an exact official MITRE CWE or CAPEC XML release",
    )
    taxonomy_import.add_argument("source")
    taxonomy_import.add_argument("--authority", required=True)
    taxonomy_import.add_argument("--kind", choices=("cwe", "capec"))
    taxonomy_import.add_argument("--version")
    taxonomy_import.add_argument("-o", "--output", required=True)
    taxonomy_import.set_defaults(handler=_security_taxonomy_import)

    taxonomy_verify = subparsers.add_parser(
        "security-taxonomy-verify",
        help="verify taxonomy integrity and optional exact XML regeneration",
    )
    taxonomy_verify.add_argument("artifact")
    taxonomy_verify.add_argument("--source")
    taxonomy_verify.add_argument("--json", action="store_true")
    taxonomy_verify.set_defaults(handler=_security_taxonomy_verify)

    lifecycle_init = subparsers.add_parser(
        "standards-lifecycle-init",
        help="create an exact-catalog standards revision review ledger",
    )
    lifecycle_init.add_argument("--authority", required=True)
    lifecycle_init.add_argument("-o", "--output", required=True)
    lifecycle_init.set_defaults(handler=_standards_lifecycle_init)

    lifecycle_seal = subparsers.add_parser(
        "standards-lifecycle-seal",
        help="recompute and seal an edited standards revision ledger",
    )
    lifecycle_seal.add_argument("source")
    lifecycle_seal.add_argument("-o", "--output", required=True)
    lifecycle_seal.set_defaults(handler=_standards_lifecycle_seal)

    lifecycle_verify = subparsers.add_parser(
        "standards-lifecycle-verify",
        help="verify standards review completeness, currency, and reapproval state",
    )
    lifecycle_verify.add_argument("ledger")
    lifecycle_verify.add_argument("--json", action="store_true")
    lifecycle_verify.set_defaults(handler=_standards_lifecycle_verify)

    benchmark_execution_init = subparsers.add_parser(
        "benchmark-execution-init",
        help="create an isolated benchmark execution evidence contract",
    )
    benchmark_execution_init.add_argument("--suite", required=True)
    benchmark_execution_init.add_argument("--authority", required=True)
    benchmark_execution_init.add_argument("-o", "--output", required=True)
    benchmark_execution_init.set_defaults(handler=_benchmark_execution_init)

    benchmark_execution_seal = subparsers.add_parser(
        "benchmark-execution-seal",
        help="validate and seal an edited benchmark execution receipt",
    )
    benchmark_execution_seal.add_argument("source")
    benchmark_execution_seal.add_argument("-o", "--output", required=True)
    benchmark_execution_seal.set_defaults(handler=_benchmark_execution_seal)

    benchmark_execution_verify = subparsers.add_parser(
        "benchmark-execution-verify",
        help="verify benchmark execution integrity and governed-use eligibility",
    )
    benchmark_execution_verify.add_argument("receipt")
    benchmark_execution_verify.add_argument("--json", action="store_true")
    benchmark_execution_verify.set_defaults(handler=_benchmark_execution_verify)

    benchmark_observations_seal = subparsers.add_parser(
        "benchmark-observations-seal",
        help="validate, recompute, and seal case-level benchmark observations",
    )
    benchmark_observations_seal.add_argument("source")
    benchmark_observations_seal.add_argument("-o", "--output", required=True)
    benchmark_observations_seal.set_defaults(handler=_benchmark_observations_seal)

    benchmark_observations_verify = subparsers.add_parser(
        "benchmark-observations-verify",
        help="verify case-level benchmark evidence and aggregate metrics",
    )
    benchmark_observations_verify.add_argument("observations")
    benchmark_observations_verify.add_argument("--json", action="store_true")
    benchmark_observations_verify.set_defaults(handler=_benchmark_observations_verify)

    benchmark_run = subparsers.add_parser(
        "benchmark-execution-run",
        help="execute a pinned benchmark in a network-denied read-only container",
    )
    benchmark_run.add_argument("receipt")
    benchmark_run.add_argument("suite_source")
    benchmark_run.add_argument("--adapter", required=True)
    benchmark_run.add_argument("--evidence-directory", required=True)
    benchmark_run.add_argument(
        "--engine", choices=["auto", "docker", "podman"], default="auto"
    )
    benchmark_run.add_argument("-o", "--output", required=True)
    benchmark_run.set_defaults(handler=_benchmark_execution_run)

    snapshot = subparsers.add_parser(
        "campaign-snapshot",
        help="calculate the deterministic source-tree SHA-256 used by campaign contracts",
    )
    snapshot.add_argument("source")
    snapshot.set_defaults(handler=_campaign_snapshot)

    fuzz_init = subparsers.add_parser(
        "fuzz-campaign-init",
        help="create a governed isolated fuzz-campaign evidence contract",
    )
    fuzz_init.add_argument("--authority", required=True)
    fuzz_init.add_argument("-o", "--output", required=True)
    fuzz_init.set_defaults(handler=_fuzz_campaign_init)

    fuzz_seal = subparsers.add_parser(
        "fuzz-campaign-seal", help="validate and seal an edited fuzz-campaign receipt"
    )
    fuzz_seal.add_argument("source")
    fuzz_seal.add_argument("-o", "--output", required=True)
    fuzz_seal.set_defaults(handler=_fuzz_campaign_seal)

    fuzz_verify = subparsers.add_parser(
        "fuzz-campaign-verify",
        help="verify fuzz-campaign integrity and assurance-use eligibility",
    )
    fuzz_verify.add_argument("campaign")
    fuzz_verify.add_argument("--json", action="store_true")
    fuzz_verify.set_defaults(handler=_fuzz_campaign_verify)

    fuzz_run = subparsers.add_parser(
        "fuzz-campaign-run",
        help="execute a pinned fuzz campaign in a network-denied read-only container",
    )
    fuzz_run.add_argument("campaign")
    fuzz_run.add_argument("repository")
    fuzz_run.add_argument("--evidence-directory", required=True)
    fuzz_run.add_argument(
        "--engine", choices=["auto", "docker", "podman"], default="auto"
    )
    fuzz_run.add_argument("-o", "--output", required=True)
    fuzz_run.set_defaults(handler=_fuzz_campaign_run)

    register_gap_commands(subparsers)

    _add_industry_method_commands(subparsers)


def _guidance(args: argparse.Namespace) -> int:
    print("PySFMEA methodology notice")
    print(METHODOLOGY_NOTICE)
    print("\nApplicability profiles:")
    for profile in GUIDELINE_PROFILES:
        print(
            f"- {profile['id']}: {profile['title']} ({profile['status']})\n  "
            f"{profile['applicability']}\n  Tailoring: {profile['tailoring']}"
        )
    print("\nPublic guidance basis:")
    for source in GUIDANCE_SOURCES:
        print(
            f"- {source['title']} ({source.get('version', 'unversioned')}; "
            f"{source.get('status', 'status unknown')})\n  {source['url']}\n  "
            f"Applicability: {source.get('applicability', 'not recorded')}\n  {source['use']}"
        )
    return 0


def _standards_catalog(args: argparse.Namespace) -> int:
    catalog = standards_catalog()
    if args.output:
        result = export_json_document(catalog, args.output)
        print(result)
    elif args.json:
        print(json.dumps(catalog, indent=2, ensure_ascii=False))
    else:
        print(f"PySFMEA industry standards catalog {catalog['version']}")
        for profile in catalog["profiles"]:
            print(
                f"- {profile['id']}: {profile['title']} "
                f"[{profile['access']}; {len(profile['objectives'])} objectives]"
            )
            print(f"  {profile['scope']}")
        print(catalog["notice"])
    return 0


def _qualification_bases(args: argparse.Namespace) -> int:
    catalog = qualification_bases_catalog()
    if args.output:
        print(export_json_document(catalog, args.output))
    elif args.json:
        print(json.dumps(catalog, indent=2, ensure_ascii=False))
    else:
        print("PySFMEA tool qualification basis navigation packs")
        for pack in catalog["packs"]:
            print(f"- {pack['id']}: {pack['title']}")
            print(
                f"  {len(pack['classification_questions'])} classification questions; "
                f"{len(pack['objective_crosswalk'])} dossier mappings"
            )
        print(catalog["notice"])
    return 0


def _conformance_init(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    workspace = conformance_workspace(
        analysis,
        args.profile,
        system=args.system,
        lifecycle_phase=args.phase,
        applicability_basis=args.basis,
        authority=args.authority,
    )
    result = export_conformance_workspace(workspace, args.output)
    print(f"Created standards conformance workspace: {result}")
    print(
        f"Profiles={workspace['summary']['profiles']}, "
        f"objectives={workspace['summary']['objectives']}; all begin unassessed."
    )
    print(workspace["claim"])
    return 0


def _conformance_assess(args: argparse.Namespace) -> int:
    source = Path(args.workspace).expanduser().resolve()
    workspace = load_conformance_workspace(source)
    updated = assess_objective(
        workspace,
        args.objective_id,
        applicability=args.applicability,
        status=args.status,
        rationale=args.rationale,
        reviewer=args.reviewer,
        evidence_refs=args.evidence_ref,
    )
    destination = Path(args.output).expanduser().resolve() if args.output else source
    result = export_conformance_workspace(updated, destination)
    print(f"Recorded and sealed {args.objective_id}: {result}")
    print(
        f"Assessment complete={updated['summary']['assessment_complete']}; "
        f"conformance supported={updated['summary']['conformance_supported']}; "
        f"blockers={len(updated['summary']['blocking_objective_ids'])}."
    )
    return 0


def _conformance_verify(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis) if args.analysis else None
    result = verify_conformance_workspace_file(args.workspace, analysis=analysis)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Conformance workspace: valid={result['valid']}, "
            f"complete={result['assessment_complete']}, "
            f"supported={result['conformance_supported']}"
        )
        print(
            f"Profiles={len(result['profile_ids'])}, "
            f"objectives={result['objective_count']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _standards_crosswalk(args: argparse.Namespace) -> int:
    source = Path(args.analysis).expanduser().resolve()
    value = standards_crosswalk(
        load_analysis(source), source, args.conformance, args.mapping
    )
    result = export_standards_crosswalk(value, args.output)
    print(f"Created standards trace crosswalk: {result}")
    print(
        f"Applicable objectives={value['summary']['applicable_objectives']}; "
        f"active findings={value['summary']['active_findings']}; "
        f"trace complete={value['summary']['trace_complete']}."
    )
    print(value["claim"])
    return 0


def _standards_crosswalk_verify(args: argparse.Namespace) -> int:
    result = verify_standards_crosswalk_file(
        args.crosswalk,
        analysis_source=args.analysis,
        workspace_source=args.conformance,
        mapping_source=args.mapping,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Standards crosswalk: valid={result['valid']}, "
            f"trace complete={result['trace_complete']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _assurance_case(args: argparse.Namespace) -> int:
    analysis_path = Path(args.analysis).expanduser().resolve()
    analysis = load_analysis(analysis_path)
    case = assurance_case(
        analysis,
        analysis_path,
        conformance_path=args.conformance,
        qualification_path=args.qualification,
    )
    result = export_assurance_case(case, args.output)
    print(f"Created structured assurance case: {result}")
    print(
        f"Top claim={case['summary']['top_claim_status']}; "
        f"claims={case['summary']['claims']}; "
        f"open defeaters={case['summary']['open_defeaters']}."
    )
    print(case["notice"])
    return 0


def _assurance_case_verify(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis) if args.analysis else None
    result = verify_assurance_case_file(args.case, analysis=analysis)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Assurance case: valid={result['valid']}, "
            f"top claim={result['top_claim_status']}, "
            f"decision ready={result['decision_ready']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _gsn_project(args: argparse.Namespace) -> int:
    value = gsn_projection(args.case)
    destination = export_gsn_projection(value, args.output)
    print(f"Created GSN semantic projection: {destination}")
    print(
        f"Goals={value['summary']['goals']}; strategies={value['summary']['strategies']}; "
        f"solutions={value['summary']['solutions']}; open defeaters={value['summary']['open_defeaters']}."
    )
    print(value["notice"])
    return 0


def _gsn_verify(args: argparse.Namespace) -> int:
    result = verify_gsn_projection_file(
        args.projection, assurance_case_source=args.case
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"GSN projection: valid={result['valid']}, complete={result['complete']}")
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _industry_source(kind: str, source: str) -> dict[str, Any]:
    if kind == "sacm":
        from .assurance_case import load_assurance_case

        return load_assurance_case(source)
    return load_analysis(source)


def _industry_exchange(args: argparse.Namespace) -> int:
    result = export_exchange(
        args.kind, _industry_source(args.kind, args.source), args.output
    )
    print(f"Exported {args.kind.upper()} industry exchange: {result}")
    print(
        "The artifact declares its supported standards subset and exact source "
        "binding; validate it in the intended receiving tool before operational use."
    )
    return 0


def _industry_exchange_verify(args: argparse.Namespace) -> int:
    result = verify_exchange_file(
        args.kind, args.artifact, _industry_source(args.kind, args.source)
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"{args.kind.upper()} exchange: valid={result['valid']}")
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _industry_schema_validate(args: argparse.Namespace) -> int:
    receipt = normative_schema_validation(
        args.artifact,
        args.schema,
        schema_kind=args.schema_kind,
        standard_name=args.standard,
        standard_edition=args.edition,
        normative_schema_uri=args.schema_uri,
        schema_publisher_sha256=args.schema_sha256,
    )
    destination = export_normative_schema_validation(receipt, args.output)
    print(f"Created normative schema validation receipt: {destination}")
    print(
        f"Schema valid={receipt['outcome']['valid']}; "
        f"errors={receipt['outcome']['error_count']}; "
        f"validator={receipt['validator']['engine']} {receipt['validator']['version']}."
    )
    print(receipt["claim"])
    return 0 if receipt["outcome"]["valid"] else 1


def _industry_schema_verify(args: argparse.Namespace) -> int:
    result = verify_normative_schema_validation_file(
        args.receipt,
        artifact_source=args.artifact,
        schema_source=args.schema,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Normative schema receipt: valid={result['valid']}, "
            f"schema valid={result['schema_valid']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _industry_roundtrip_seal(args: argparse.Namespace) -> int:
    value = independent_roundtrip_evidence(args.validation_receipt, args.observation)
    destination = export_independent_roundtrip_evidence(value, args.output)
    print(f"Created independent round-trip evidence: {destination}")
    print(
        f"Receiver={value['receiver']['name']} {value['receiver']['version']}; "
        f"passed={value['passed']}."
    )
    print(value["claim"])
    return 0 if value["passed"] else 1


def _industry_roundtrip_verify(args: argparse.Namespace) -> int:
    result = verify_independent_roundtrip_evidence_file(
        args.evidence,
        validation_receipt_source=args.validation_receipt,
        observation_source=args.observation,
        reexport_source=args.reexport,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Independent round trip: valid={result['valid']}, passed={result['passed']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _lifecycle_import(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis) if args.analysis else None
    value = import_lifecycle_model(args.kind, args.source, analysis=analysis)
    destination = export_lifecycle_model(value, args.output)
    print(f"Created normalized lifecycle model bridge: {destination}")
    print(
        f"Entities={value['summary']['entities']}; "
        f"relationships={value['summary']['relationships']}; "
        f"exact code links={value['summary']['code_links']}; "
        f"complete={value['summary']['complete']}."
    )
    print(value["notice"])
    return 0


def _lifecycle_import_verify(args: argparse.Namespace) -> int:
    result = verify_lifecycle_model_file(
        args.model,
        lifecycle_source=args.source,
        analysis=load_analysis(args.analysis) if args.analysis else None,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Lifecycle model bridge: valid={result['valid']}, complete={result['complete']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _provenance(args: argparse.Namespace) -> int:
    source = Path(args.analysis).expanduser().resolve()
    analysis = load_analysis(source)
    statement = slsa_provenance_statement(analysis, source)
    result = export_slsa_provenance(statement, args.output)
    print(f"Exported SLSA v1 analysis provenance: {result}")
    print(
        "Sign and transparently publish the statement under the organization's release "
        "policy when authenticated provenance is required."
    )
    return 0


def _provenance_verify(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis) if args.analysis else None
    result = verify_slsa_provenance_file(
        args.provenance,
        analysis=analysis,
        analysis_path=args.analysis,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"SLSA provenance: valid={result['valid']}")
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _vex(args: argparse.Namespace) -> int:
    result = export_cyclonedx_vex(
        load_analysis(args.analysis), args.decisions, args.output
    )
    print(f"Published authority-attributed CycloneDX 1.7 VEX: {result}")
    print("Exploitability states came only from the supplied governed decision file.")
    return 0


def _vex_verify(args: argparse.Namespace) -> int:
    result = verify_cyclonedx_vex_file(
        args.vex, load_analysis(args.analysis), args.decisions
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"CycloneDX VEX: valid={result['valid']}, "
            f"vulnerabilities={result['vulnerabilities']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _csaf(args: argparse.Namespace) -> int:
    destination = export_csaf(load_analysis(args.analysis), args.decisions, args.output)
    print(f"Published governed OASIS CSAF 2.0 advisory: {destination}")
    print(
        "Product status came only from the supplied governed decisions. Validate the "
        "result with the OASIS normative schema before operational publication."
    )
    return 0


def _csaf_verify(args: argparse.Namespace) -> int:
    result = verify_csaf_file(args.csaf, load_analysis(args.analysis), args.decisions)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"CSAF 2.0 advisory: valid={result['valid']}, "
            f"vulnerabilities={result['vulnerabilities']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _benchmark_assess(args: argparse.Namespace) -> int:
    assessment = benchmark_assessment(
        args.protocol,
        args.qualification_result,
        args.qualification_manifest,
        execution_started_at=args.execution_started_at,
        execution_evidence_ref=args.execution_evidence_ref,
    )
    result = export_benchmark_assessment(assessment, args.output)
    print(f"Created independent benchmark assessment: {result}")
    print(
        f"Status={assessment['summary']['status']}; "
        f"confidence intervals={assessment['summary']['intervals_passing']}/"
        f"{assessment['summary']['intervals_required']}; "
        f"kappa={assessment['summary']['cohen_kappa']}."
    )
    print(assessment["notice"])
    return 0


def _benchmark_verify(args: argparse.Namespace) -> int:
    result = verify_benchmark_assessment_file(
        args.assessment,
        protocol_source=args.protocol,
        qualification_result_source=args.qualification_result,
        qualification_manifest_source=args.qualification_manifest,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Independent benchmark: valid={result['valid']}, passed={result['passed']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _benchmark_assess_v2(args: argparse.Namespace) -> int:
    value = benchmark_v2_assessment(args.protocol, args.observations)
    destination = export_benchmark_v2_assessment(value, args.output)
    print(f"Created advanced independent benchmark assessment: {destination}")
    print(
        f"Status={value['summary']['status']}; "
        f"metrics={value['summary']['metrics_passing']}/"
        f"{value['summary']['metrics_required']}; "
        f"strata={value['summary']['strata_passing']}/"
        f"{value['summary']['strata_required']}; "
        f"stratum metrics={value['summary']['stratum_metrics_passing']}/"
        f"{value['summary']['stratum_metrics_required']}; "
        f"Krippendorff alpha={value['reviewer_agreement']['alpha']}."
    )
    print(value["notice"])
    return 0


def _benchmark_seal_v2(args: argparse.Namespace) -> int:
    destination = seal_benchmark_v2_source(
        args.source, args.output, protocol_source=args.protocol
    )
    print(f"Sealed benchmark v2 authoring source: {destination}")
    print(
        "The digest proves integrity only; it does not prove pre-registration, "
        "independence, label correctness, or approval."
    )
    return 0


def _benchmark_verify_v2(args: argparse.Namespace) -> int:
    result = verify_benchmark_v2_assessment_file(
        args.assessment,
        protocol_source=args.protocol,
        observations_source=args.observations,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"Advanced benchmark: valid={result['valid']}, passed={result['passed']}")
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _benchmark_report_v2(args: argparse.Namespace) -> int:
    destination = export_benchmark_v2_report(
        args.assessment, args.output, title=args.title
    )
    print(f"Created self-contained advanced benchmark report: {destination}")
    return 0


def _benchmark_report_verify_v2(args: argparse.Namespace) -> int:
    result = verify_benchmark_v2_report_file(
        args.report, assessment_source=args.assessment
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Advanced benchmark report: valid={result['valid']}, passed={result['passed']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _release_qualification_init(args: argparse.Namespace) -> int:
    value = release_qualification_source_template(authority=args.authority)
    destination = export_release_qualification_source(value, args.output)
    print(f"Created release qualification source: {destination}")
    print(value["notice"])
    return 0


def _release_qualification_seal(args: argparse.Namespace) -> int:
    destination = seal_release_qualification_source(args.source, args.output)
    print(f"Sealed release qualification source: {destination}")
    return 0


def _release_qualification_assess(args: argparse.Namespace) -> int:
    value = release_qualification_assessment(args.source, args.candidate, args.baseline)
    destination = export_release_qualification_assessment(value, args.output)
    print(f"Created release qualification assessment: {destination}")
    print(
        f"Status={value['summary']['status']}; failed checks={len(value['summary']['failed_checks'])}."
    )
    print(value["notice"])
    return 0


def _release_qualification_verify(args: argparse.Namespace) -> int:
    result = verify_release_qualification_assessment_file(
        args.assessment,
        source_path=args.source,
        candidate_assessment_path=args.candidate,
        baseline_assessment_path=args.baseline,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Release qualification: valid={result['valid']}, passed={result['passed']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _dependability_init(args: argparse.Namespace) -> int:
    value = dependability_authoring_template(
        load_analysis(args.analysis), authority=args.authority
    )
    destination = export_dependability_authoring(value, args.output)
    print(f"Created HAZOP/RBD/Markov authoring template: {destination}")
    print(
        f"HAZOP nodes={len(value['hazop']['nodes'])}; "
        f"RBD blocks={len(value['rbd']['blocks'])}; "
        f"Markov candidates={len(value['markov_models'])}."
    )
    print(value["notice"])
    return 0


def _safety_lifecycle_init(args: argparse.Namespace) -> int:
    value = safety_lifecycle_authoring_template(
        load_analysis(args.analysis), authority=args.authority
    )
    destination = export_safety_lifecycle_authoring(value, args.output)
    print(f"Created safety lifecycle and CCFA authoring workspace: {destination}")
    print(
        f"Hazards={len(value['hazards'])}; CCFA candidates={len(value['ccfa_candidates'])}; "
        f"stages={len(value['stages'])}."
    )
    print(value["notice"])
    return 0


def _safety_lifecycle_seal(args: argparse.Namespace) -> int:
    destination = seal_safety_lifecycle_authoring(
        load_analysis(args.analysis), args.authoring, args.output
    )
    print(f"Sealed safety lifecycle authoring workspace: {destination}")
    return 0


def _safety_lifecycle_assess(args: argparse.Namespace) -> int:
    value = safety_lifecycle_assessment(load_analysis(args.analysis), args.authoring)
    destination = export_safety_lifecycle_assessment(value, args.output)
    print(f"Created safety lifecycle assessment: {destination}")
    print(
        f"Status={value['summary']['status']}; hazards={len(value['hazards'])}; "
        f"uncovered CCFA candidates={len(value['ccfa']['uncovered_candidate_ids'])}."
    )
    print(value["notice"])
    return 0


def _safety_lifecycle_verify(args: argparse.Namespace) -> int:
    result = verify_safety_lifecycle_assessment_file(
        args.assessment,
        analysis=load_analysis(args.analysis) if args.analysis else None,
        authoring_source=args.authoring,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Safety lifecycle assessment: valid={result['valid']}, "
            f"complete={result['complete']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _slsa_policy_init(args: argparse.Namespace) -> int:
    value = slsa_trust_policy_template(authority=args.authority)
    destination = export_slsa_trust_policy(value, args.output)
    print(f"Created deny-by-default SLSA 1.2 trust policy: {destination}")
    print(value["notice"])
    return 0


def _slsa_observation_init(args: argparse.Namespace) -> int:
    value = slsa_verification_observation_template(verifier=args.verifier)
    destination = export_slsa_verification_observation(value, args.output)
    print(f"Created external SLSA verifier evidence record: {destination}")
    return 0


def _slsa_policy_seal(args: argparse.Namespace) -> int:
    destination = seal_slsa_trust_policy(args.source, args.output)
    print(f"Sealed SLSA 1.2 trust policy: {destination}")
    return 0


def _slsa_observation_seal(args: argparse.Namespace) -> int:
    destination = seal_slsa_verification_observation(args.source, args.output)
    print(f"Sealed SLSA verification observation: {destination}")
    return 0


def _slsa_policy_assess(args: argparse.Namespace) -> int:
    value = slsa_policy_assessment(args.provenance, args.policy, args.observation)
    destination = export_slsa_policy_assessment(value, args.output)
    print(f"Created SLSA 1.2 trust-policy assessment: {destination}")
    print(
        f"Status={value['summary']['status']}; Build L{value['levels']['build_track_achieved']}; "
        f"Source L{value['levels']['source_track_achieved']}."
    )
    print(value["notice"])
    return 0


def _slsa_policy_verify(args: argparse.Namespace) -> int:
    result = verify_slsa_policy_assessment_file(
        args.assessment,
        provenance_source=args.provenance,
        policy_source=args.policy,
        observation_source=args.observation,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"SLSA policy assessment: valid={result['valid']}, passed={result['passed']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _sigstore_verify(args: argparse.Namespace) -> int:
    destination = execute_sigstore_verification(
        args.artifact,
        args.bundle,
        args.trusted_root,
        certificate_identity=args.certificate_identity,
        certificate_oidc_issuer=args.certificate_oidc_issuer,
        authority=args.authority,
        destination=args.output,
        cosign=args.cosign,
    )
    result = verify_sigstore_verification_file(
        destination,
        artifact=args.artifact,
        bundle=args.bundle,
        trusted_root=args.trusted_root,
    )
    print(
        f"Sigstore verification receipt: {destination}; "
        f"authenticated={result['authenticated']}"
    )
    return 0 if result["authenticated"] else 1


def _sigstore_receipt_verify(args: argparse.Namespace) -> int:
    result = verify_sigstore_verification_file(
        args.receipt,
        artifact=args.artifact,
        bundle=args.bundle,
        trusted_root=args.trusted_root,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Sigstore receipt: valid={result['valid']}, "
            f"authenticated={result['authenticated']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _ssvc_policy_init(args: argparse.Namespace) -> int:
    value = ssvc_policy_template(authority=args.authority)
    destination = export_ssvc_source(value, args.output)
    print(f"Created controlled SSVC policy template: {destination}")
    print(value["notice"])
    return 0


def _ssvc_observations_init(args: argparse.Namespace) -> int:
    value = ssvc_observations_template(
        policy_id=args.policy_digest, authority=args.authority
    )
    destination = export_ssvc_source(value, args.output)
    print(f"Created SSVC evidence intake: {destination}")
    return 0


def _ssvc_seal(args: argparse.Namespace) -> int:
    destination = seal_ssvc_source(args.source, args.output, policy_source=args.policy)
    print(f"Sealed SSVC source: {destination}")
    return 0


def _ssvc_assess(args: argparse.Namespace) -> int:
    value = ssvc_assessment(args.policy, args.observations)
    destination = export_ssvc_assessment(value, args.output)
    print(f"Created SSVC assessment: {destination}")
    print(
        f"Vulnerabilities={value['summary']['vulnerabilities']}; outcomes={value['summary']['outcomes']}."
    )
    print(value["notice"])
    return 0


def _ssvc_verify(args: argparse.Namespace) -> int:
    result = verify_ssvc_assessment_file(
        args.assessment,
        policy_source=args.policy,
        observations_source=args.observations,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"SSVC assessment: valid={result['valid']}, complete={result['complete']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _dependability_assess(args: argparse.Namespace) -> int:
    value = dependability_assessment(load_analysis(args.analysis), args.authoring)
    destination = export_dependability_assessment(value, args.output)
    print(f"Created dependability assessment: {destination}")
    print(
        f"Status={value['summary']['status']}; "
        f"HAZOP complete={value['hazop']['complete']}; "
        f"RBD complete={value['rbd']['complete']}; "
        f"Markov models={len(value['markov_models'])}."
    )
    print(value["notice"])
    return 0


def _dependability_seal(args: argparse.Namespace) -> int:
    destination = seal_dependability_authoring(
        load_analysis(args.analysis), args.authoring, args.output
    )
    print(f"Sealed dependability authoring artifact: {destination}")
    print("The artifact remains subject to authorized engineering review.")
    return 0


def _dependability_verify(args: argparse.Namespace) -> int:
    result = verify_dependability_assessment_file(
        args.assessment,
        analysis=load_analysis(args.analysis) if args.analysis else None,
        authoring_source=args.authoring,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Dependability assessment: valid={result['valid']}, "
            f"complete={result['complete']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _tool_qualification_init(args: argparse.Namespace) -> int:
    analysis_path = Path(args.analysis).expanduser().resolve()
    dossier = tool_qualification_dossier(
        load_analysis(analysis_path),
        analysis_path,
        args.benchmark,
        args.conformance,
        args.anomalies,
        intended_use=args.intended_use,
        reliance=args.reliance,
        qualification_basis=args.basis,
        tool_classification=args.classification,
        intended_environment=args.environment,
        classification_authority=args.authority,
    )
    result = export_tool_qualification_dossier(dossier, args.output)
    print(f"Created tool qualification dossier: {result}")
    print(
        f"Objectives={dossier['summary']['objectives']}; "
        f"blockers={len(dossier['summary']['blocking_objective_ids'])}; "
        f"inputs ready={dossier['summary']['inputs_ready']}."
    )
    print(dossier["claim"])
    return 0


def _tool_qualification_assess(args: argparse.Namespace) -> int:
    source = Path(args.dossier).expanduser().resolve()
    dossier = load_tool_qualification_dossier(source)
    updated = assess_tool_qualification_objective(
        dossier,
        args.objective_id,
        applicability=args.applicability,
        status=args.status,
        rationale=args.rationale,
        reviewer=args.reviewer,
        evidence_refs=args.evidence_ref,
    )
    destination = Path(args.output).expanduser().resolve() if args.output else source
    result = export_tool_qualification_dossier(updated, destination)
    print(f"Recorded and sealed {args.objective_id}: {result}")
    print(
        "Eligible for authorized qualification decision="
        f"{updated['summary']['eligible_for_authorized_qualification_decision']}; "
        f"blockers={len(updated['summary']['blocking_objective_ids'])}."
    )
    return 0


def _tool_qualification_verify(args: argparse.Namespace) -> int:
    result = verify_tool_qualification_dossier_file(
        args.dossier,
        analysis_source=args.analysis,
        benchmark_assessment_source=args.benchmark,
        conformance_workspace_source=args.conformance,
        anomaly_register_source=args.anomalies,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Tool qualification dossier: valid={result['valid']}, "
            "eligible for authorized decision="
            f"{result['eligible_for_authorized_qualification_decision']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _runtime_coverage_import(args: argparse.Namespace) -> int:
    value = runtime_coverage_observation(
        load_analysis(args.analysis),
        args.coverage_json,
        authority=args.authority,
        command=args.command,
        configuration_sha256=args.configuration_sha256,
        environment=args.environment,
        test_run_ref=args.test_run_ref,
        evidence_refs=args.evidence_ref,
        minimum_statement_rate=args.minimum_statement_rate,
        minimum_branch_rate=args.minimum_branch_rate,
        require_all_components=args.require_all_components,
        object_code_basis=args.object_code_basis,
    )
    destination = export_runtime_coverage_observation(value, args.output)
    print(f"Created runtime coverage observation: {destination}")
    print(value["claim_boundary"])
    return 0


def _runtime_coverage_verify(args: argparse.Namespace) -> int:
    result = verify_runtime_coverage_observation_file(
        args.observation,
        analysis=load_analysis(args.analysis) if args.analysis else None,
        coverage_source=args.coverage_json,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Runtime coverage: valid={result['valid']}, "
            f"ready={result['ready_for_structural_coverage_use']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _validation_portfolio_init(args: argparse.Namespace) -> int:
    value = validation_portfolio_template(authority=args.authority)
    destination = export_validation_portfolio_source(value, args.output)
    print(f"Created industry validation portfolio: {destination}")
    print(value["notice"])
    return 0


def _validation_portfolio_seal(args: argparse.Namespace) -> int:
    destination = seal_validation_portfolio_source(args.source, args.output)
    print(f"Sealed industry validation portfolio: {destination}")
    return 0


def _validation_portfolio_assess(args: argparse.Namespace) -> int:
    value = validation_portfolio_assessment(args.source)
    destination = export_validation_portfolio_assessment(value, args.output)
    print(f"Created industry validation portfolio assessment: {destination}")
    print(value["notice"])
    return 0


def _validation_portfolio_verify(args: argparse.Namespace) -> int:
    result = verify_validation_portfolio_assessment_file(
        args.assessment, portfolio_source=args.source
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Industry validation portfolio: valid={result['valid']}, "
            f"passed={result['passed']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _validation_portfolio_report(args: argparse.Namespace) -> int:
    destination = export_validation_portfolio_report(
        args.assessment, args.output, title=args.title
    )
    print(f"Created self-contained industry validation report: {destination}")
    return 0


def _validation_portfolio_report_verify(args: argparse.Namespace) -> int:
    result = verify_validation_portfolio_report_file(
        args.report, assessment_source=args.assessment
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Industry validation report: valid={result['valid']}, "
            f"portfolio passed={result['passed']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _sarif_fuse(args: argparse.Namespace) -> int:
    value = sarif_fusion(
        load_analysis(args.analysis),
        args.sarif,
        authority=args.authority,
        evidence_refs=args.evidence_ref,
    )
    destination = export_sarif_fusion(value, args.output)
    print(f"Created analysis-bound SARIF fusion: {destination}")
    print(
        f"Results={value['summary']['results']}; mapped={value['summary']['mapped']}; "
        f"multi-tool clusters={value['summary']['multi_tool_clusters']}."
    )
    print(value["claim_boundary"])
    return 0


def _sarif_fuse_verify(args: argparse.Namespace) -> int:
    result = verify_sarif_fusion_file(
        args.fusion,
        analysis=load_analysis(args.analysis) if args.analysis else None,
        sarif_sources=args.sarif,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"SARIF fusion: valid={result['valid']}, ready for triage={result['ready_for_triage']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _oscal_assessment_results(args: argparse.Namespace) -> int:
    value = oscal_assessment_results(
        load_analysis(args.analysis),
        authority=args.authority,
        title=args.title,
        assessment_plan_href=args.assessment_plan_href,
        evidence_base_href=args.evidence_base_href,
    )
    destination = export_oscal_assessment_results(value, args.output)
    observations = len(value["assessment-results"]["results"][0]["observations"])
    print(f"Created OSCAL Assessment Results: {destination}")
    print(
        f"Projected observations={observations}. Validate with the official NIST OSCAL schema before interchange."
    )
    return 0


def _oscal_assessment_results_verify(args: argparse.Namespace) -> int:
    result = verify_oscal_assessment_results_file(
        args.oscal, analysis=load_analysis(args.analysis) if args.analysis else None
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"OSCAL Assessment Results: valid={result['valid']}, ready for normative validation={result['ready_for_normative_validation']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _print_oscal_verdict(label: str, result: dict[str, Any], *, as_json: bool) -> int:
    if as_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"{label}: valid={result['valid']}, "
            f"ready for normative validation={result['ready_for_normative_validation']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _oscal_assessment_plan(args: argparse.Namespace) -> int:
    value = oscal_assessment_plan(
        load_analysis(args.analysis),
        authority=args.authority,
        ssp_href=args.ssp_href,
        title=args.title,
    )
    destination = export_oscal_assessment_plan(value, args.output)
    print(f"Created OSCAL Assessment Plan: {destination}")
    print(
        f"Activities={len(value['assessment-plan']['local-definitions']['activities'])}; "
        f"tasks={len(value['assessment-plan']['tasks'])}."
    )
    return 0


def _oscal_assessment_plan_verify(args: argparse.Namespace) -> int:
    result = verify_oscal_assessment_plan_file(
        args.oscal, analysis=load_analysis(args.analysis) if args.analysis else None
    )
    return _print_oscal_verdict("OSCAL Assessment Plan", result, as_json=args.json)


def _oscal_poam(args: argparse.Namespace) -> int:
    value = oscal_poam(
        load_analysis(args.analysis),
        authority=args.authority,
        ssp_href=args.ssp_href,
        title=args.title,
    )
    destination = export_oscal_poam(value, args.output)
    print(f"Created OSCAL POA&M: {destination}")
    print(
        f"Open remediation items={len(value['plan-of-action-and-milestones']['poam-items'])}."
    )
    return 0


def _oscal_poam_verify(args: argparse.Namespace) -> int:
    result = verify_oscal_poam_file(
        args.oscal, analysis=load_analysis(args.analysis) if args.analysis else None
    )
    return _print_oscal_verdict("OSCAL POA&M", result, as_json=args.json)


def _benchmark_suite_catalog(args: argparse.Namespace) -> int:
    value = benchmark_suite_catalog()
    if args.output:
        print(export_benchmark_catalog(args.output))
    elif args.json:
        print(json.dumps(value, indent=2, ensure_ascii=False))
    else:
        print("Governed external Python benchmark targets")
        for suite in value["suites"]:
            print(f"- {suite['id']}: {suite['title']}: {suite['use']}")
        print(value["notice"])
    return 0


def _benchmark_execution_init(args: argparse.Namespace) -> int:
    value = benchmark_execution_template(suite_id=args.suite, authority=args.authority)
    destination = export_benchmark_execution(value, args.output)
    print(f"Created benchmark execution evidence contract: {destination}")
    print(value["claim_boundary"])
    return 0


def _benchmark_adapter_init(args: argparse.Namespace) -> int:
    value = benchmark_adapter_template(suite_id=args.suite, authority=args.authority)
    destination = export_benchmark_adapter(value, args.output)
    print(f"Created benchmark adapter contract: {destination}")
    print(value["claim_boundary"])
    return 0


def _benchmark_adapter_seal(args: argparse.Namespace) -> int:
    print(
        f"Sealed benchmark adapter: {seal_benchmark_adapter(args.source, args.output)}"
    )
    return 0


def _benchmark_adapter_verify(args: argparse.Namespace) -> int:
    result = verify_benchmark_adapter_file(args.adapter)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Benchmark adapter: valid={result['valid']}, "
            f"eligible={result['eligible_for_execution']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _security_taxonomy_import(args: argparse.Namespace) -> int:
    value = import_security_taxonomy(
        args.source,
        authority=args.authority,
        expected_kind=args.kind,
        expected_version=args.version,
    )
    destination = export_security_taxonomy(value, args.output)
    print(
        f"Imported {value['taxonomy']['kind'].upper()} {value['taxonomy']['version']}: "
        f"{destination}; entries={value['summary']['entries']}"
    )
    return 0


def _security_taxonomy_verify(args: argparse.Namespace) -> int:
    result = verify_security_taxonomy_file(args.artifact, source=args.source)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Security taxonomy: valid={result['valid']}, "
            f"eligible={result['eligible_for_mapping']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _standards_lifecycle_init(args: argparse.Namespace) -> int:
    value = standards_lifecycle_template(authority=args.authority)
    destination = export_standards_lifecycle(value, args.output)
    print(f"Created standards lifecycle ledger: {destination}")
    print(value["claim_boundary"])
    return 0


def _standards_lifecycle_seal(args: argparse.Namespace) -> int:
    print(
        f"Sealed standards lifecycle ledger: "
        f"{seal_standards_lifecycle(args.source, args.output)}"
    )
    return 0


def _standards_lifecycle_verify(args: argparse.Namespace) -> int:
    result = verify_standards_lifecycle_file(args.ledger)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Standards lifecycle: valid={result['valid']}, "
            f"eligible={result['eligible_as_current_catalog_evidence']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _benchmark_execution_seal(args: argparse.Namespace) -> int:
    print(
        f"Sealed benchmark execution receipt: {seal_benchmark_execution_source(args.source, args.output)}"
    )
    return 0


def _benchmark_execution_verify(args: argparse.Namespace) -> int:
    result = verify_benchmark_execution_file(args.receipt)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Benchmark execution: valid={result['valid']}, eligible={result['eligible_for_benchmark_assessment']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _benchmark_observations_seal(args: argparse.Namespace) -> int:
    destination = seal_benchmark_observations(args.source, args.output)
    print(f"Sealed benchmark observations: {destination}")
    return 0


def _benchmark_observations_verify(args: argparse.Namespace) -> int:
    result = verify_benchmark_observations_file(args.observations)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Benchmark observations: valid={result['valid']}, "
            f"eligible={result['eligible_for_execution_receipt']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _benchmark_execution_run(args: argparse.Namespace) -> int:
    destination = run_benchmark_campaign(
        args.receipt,
        args.suite_source,
        args.adapter,
        args.evidence_directory,
        args.output,
        engine=args.engine,
    )
    result = verify_benchmark_execution_file(destination)
    print(
        f"Executed benchmark campaign: {destination}; "
        f"eligible={result['eligible_for_benchmark_assessment']}"
    )
    return 0 if result["eligible_for_benchmark_assessment"] else 1


def _campaign_snapshot(args: argparse.Namespace) -> int:
    print(repository_snapshot_sha256(args.source))
    return 0


def _fuzz_campaign_init(args: argparse.Namespace) -> int:
    value = fuzz_campaign_template(authority=args.authority)
    destination = export_fuzz_campaign(value, args.output)
    print(f"Created fuzz-campaign evidence contract: {destination}")
    print(value["claim_boundary"])
    return 0


def _fuzz_campaign_seal(args: argparse.Namespace) -> int:
    print(
        f"Sealed fuzz-campaign receipt: {seal_fuzz_campaign(args.source, args.output)}"
    )
    return 0


def _fuzz_campaign_verify(args: argparse.Namespace) -> int:
    result = verify_fuzz_campaign_file(args.campaign)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Fuzz campaign: valid={result['valid']}, eligible={result['eligible_for_assurance_use']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _fuzz_campaign_run(args: argparse.Namespace) -> int:
    destination = run_fuzz_campaign(
        args.campaign,
        args.repository,
        args.evidence_directory,
        args.output,
        engine=args.engine,
    )
    result = verify_fuzz_campaign_file(destination)
    print(
        f"Executed fuzz campaign: {destination}; "
        f"eligible={result['eligible_for_assurance_use']}"
    )
    return 0 if result["eligible_for_assurance_use"] else 1


def _bound_method_init(args: argparse.Namespace) -> int:
    spec = _BOUND_METHODS[args.industry_method]
    value = spec["template"](load_analysis(args.analysis), authority=args.authority)
    destination = spec["export_source"](value, args.output)
    print(f"Created {spec['label']} workspace: {destination}")
    print(value["notice"])
    return 0


def _bound_method_seal(args: argparse.Namespace) -> int:
    spec = _BOUND_METHODS[args.industry_method]
    destination = spec["seal"](load_analysis(args.analysis), args.source, args.output)
    print(f"Sealed {spec['label']} workspace: {destination}")
    return 0


def _bound_method_assess(args: argparse.Namespace) -> int:
    spec = _BOUND_METHODS[args.industry_method]
    value = spec["assess"](load_analysis(args.analysis), args.source)
    destination = spec["export_assessment"](value, args.output)
    print(f"Created {spec['label']} assessment: {destination}")
    print(value["notice"])
    return 0


def _bound_method_verify(args: argparse.Namespace) -> int:
    spec = _BOUND_METHODS[args.industry_method]
    result = spec["verify"](
        args.assessment,
        analysis=load_analysis(args.analysis) if args.analysis else None,
        source_path=args.source,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        status = result.get(
            "complete", result.get("eligible_for_authorized_conclusion", False)
        )
        print(
            f"{spec['label'].title()}: valid={result['valid']}, complete/eligible={status}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _unbound_method_init(args: argparse.Namespace) -> int:
    spec = _UNBOUND_METHODS[args.industry_method]
    kwargs: dict[str, Any] = {"authority": args.authority}
    if args.industry_method == "laboratory-governance":
        kwargs["subject_sha256"] = args.subject_sha256
    value = spec["template"](**kwargs)
    destination = spec["export_source"](value, args.output)
    print(f"Created {spec['label']} workspace: {destination}")
    print(value["notice"])
    return 0


def _unbound_method_seal(args: argparse.Namespace) -> int:
    spec = _UNBOUND_METHODS[args.industry_method]
    destination = spec["seal"](args.source, args.output)
    print(f"Sealed {spec['label']} workspace: {destination}")
    return 0


def _unbound_method_assess(args: argparse.Namespace) -> int:
    spec = _UNBOUND_METHODS[args.industry_method]
    value = spec["assess"](args.source)
    destination = spec["export_assessment"](value, args.output)
    print(f"Created {spec['label']} assessment: {destination}")
    print(value["notice"])
    return 0


def _unbound_method_verify(args: argparse.Namespace) -> int:
    spec = _UNBOUND_METHODS[args.industry_method]
    result = spec["verify"](args.assessment, source_path=args.source)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        status = result.get("complete", result.get("eligible_for_governed_use", False))
        print(
            f"{spec['label'].title()}: valid={result['valid']}, complete/eligible={status}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1
