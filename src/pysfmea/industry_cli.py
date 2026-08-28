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
from .benchmark_assurance import (
    benchmark_assessment,
    export_benchmark_assessment,
    verify_benchmark_assessment_file,
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
from .gsn import export_gsn_projection, gsn_projection, verify_gsn_projection_file
from .guidance import GUIDANCE_SOURCES, GUIDELINE_PROFILES, METHODOLOGY_NOTICE
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
from .security_prioritization import (
    export_security_prioritization_assessment,
    export_security_prioritization_source,
    seal_security_prioritization_source,
    security_prioritization_assessment,
    security_prioritization_template,
    verify_security_prioritization_assessment_file,
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
        init = subparsers.add_parser(f"{name}-init", help=f"create an exact-analysis-bound {spec['label']} workspace")
        init.add_argument("analysis")
        init.add_argument("--authority", required=True)
        init.add_argument("-o", "--output", required=True)
        init.set_defaults(handler=_bound_method_init, industry_method=name)
        seal_command = subparsers.add_parser(f"{name}-seal", help=f"reseal and validate edited {spec['label']} evidence")
        seal_command.add_argument("analysis")
        seal_command.add_argument("source")
        seal_command.add_argument("-o", "--output", required=True)
        seal_command.set_defaults(handler=_bound_method_seal, industry_method=name)
        assess = subparsers.add_parser(f"{name}-assess", help=f"derive a deterministic {spec['label']} assessment")
        assess.add_argument("analysis")
        assess.add_argument("source")
        assess.add_argument("-o", "--output", required=True)
        assess.set_defaults(handler=_bound_method_assess, industry_method=name)
        verify = subparsers.add_parser(f"{name}-verify", help=f"verify {spec['label']} integrity and optional exact regeneration")
        verify.add_argument("assessment")
        verify.add_argument("--analysis")
        verify.add_argument("--source")
        verify.add_argument("--json", action="store_true")
        verify.set_defaults(handler=_bound_method_verify, industry_method=name)
    for name, spec in _UNBOUND_METHODS.items():
        init = subparsers.add_parser(f"{name}-init", help=f"create a governed {spec['label']} workspace")
        init.add_argument("--authority", required=True)
        if name == "laboratory-governance":
            init.add_argument("--subject-sha256", default="0" * 64)
        init.add_argument("-o", "--output", required=True)
        init.set_defaults(handler=_unbound_method_init, industry_method=name)
        seal_command = subparsers.add_parser(f"{name}-seal", help=f"reseal and validate edited {spec['label']} evidence")
        seal_command.add_argument("source")
        seal_command.add_argument("-o", "--output", required=True)
        seal_command.set_defaults(handler=_unbound_method_seal, industry_method=name)
        assess = subparsers.add_parser(f"{name}-assess", help=f"derive a deterministic {spec['label']} assessment")
        assess.add_argument("source")
        assess.add_argument("-o", "--output", required=True)
        assess.set_defaults(handler=_unbound_method_assess, industry_method=name)
        verify = subparsers.add_parser(f"{name}-verify", help=f"verify {spec['label']} integrity and optional exact regeneration")
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
    exchange.add_argument("source", help="assurance case for SACM; analysis for other kinds")
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
        "--schema-kind", choices=("json-schema", "xml-schema"), required=True
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
        "slsa-observation-init", help="create an external-verifier evidence intake record"
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
        "slsa-observation-seal", help="reseal and validate external SLSA verification evidence"
    )
    slsa_observation_seal.add_argument("source")
    slsa_observation_seal.add_argument("-o", "--output", required=True)
    slsa_observation_seal.set_defaults(handler=_slsa_observation_seal)

    slsa_policy_assess = subparsers.add_parser(
        "slsa-policy-assess", help="evaluate SLSA 1.2 Build and Source levels against local trust policy"
    )
    slsa_policy_assess.add_argument("provenance")
    slsa_policy_assess.add_argument("policy")
    slsa_policy_assess.add_argument("observation")
    slsa_policy_assess.add_argument("-o", "--output", required=True)
    slsa_policy_assess.set_defaults(handler=_slsa_policy_assess)

    slsa_policy_verify = subparsers.add_parser(
        "slsa-policy-verify", help="verify SLSA policy accounting and optional exact-source regeneration"
    )
    slsa_policy_verify.add_argument("assessment")
    slsa_policy_verify.add_argument("--provenance")
    slsa_policy_verify.add_argument("--policy")
    slsa_policy_verify.add_argument("--observation")
    slsa_policy_verify.add_argument("--json", action="store_true")
    slsa_policy_verify.set_defaults(handler=_slsa_policy_verify)

    ssvc_policy_init = subparsers.add_parser(
        "ssvc-policy-init", help="create a controlled SSVC-style decision-table template"
    )
    ssvc_policy_init.add_argument("--authority", required=True)
    ssvc_policy_init.add_argument("-o", "--output", required=True)
    ssvc_policy_init.set_defaults(handler=_ssvc_policy_init)

    ssvc_observations_init = subparsers.add_parser(
        "ssvc-observations-init", help="create policy-bound vulnerability evidence intake"
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
        "ssvc-verify", help="verify SSVC outcome accounting and optional exact regeneration"
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
        "benchmark-report-v2", help="publish a self-contained advanced benchmark review report"
    )
    benchmark_v2_report.add_argument("assessment")
    benchmark_v2_report.add_argument("--title", default="Independent benchmark review")
    benchmark_v2_report.add_argument("-o", "--output", required=True)
    benchmark_v2_report.set_defaults(handler=_benchmark_report_v2)

    benchmark_v2_report_verify = subparsers.add_parser(
        "benchmark-report-verify-v2", help="verify benchmark report integrity and optional assessment binding"
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
        "safety-lifecycle-init", help="create exact-bound PHA/FHA/PSSA/SSA/operations and CCFA review scope"
    )
    safety_init.add_argument("analysis")
    safety_init.add_argument("--authority", required=True)
    safety_init.add_argument("-o", "--output", required=True)
    safety_init.set_defaults(handler=_safety_lifecycle_init)

    safety_seal = subparsers.add_parser(
        "safety-lifecycle-seal", help="reseal edited safety lifecycle authoring against its analysis"
    )
    safety_seal.add_argument("analysis")
    safety_seal.add_argument("authoring")
    safety_seal.add_argument("-o", "--output", required=True)
    safety_seal.set_defaults(handler=_safety_lifecycle_seal)

    safety_assess = subparsers.add_parser(
        "safety-lifecycle-assess", help="assess safety lifecycle traceability and CCFA coverage"
    )
    safety_assess.add_argument("analysis")
    safety_assess.add_argument("authoring")
    safety_assess.add_argument("-o", "--output", required=True)
    safety_assess.set_defaults(handler=_safety_lifecycle_assess)

    safety_verify = subparsers.add_parser(
        "safety-lifecycle-verify", help="verify safety lifecycle accounting and optional exact-source regeneration"
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
    result = verify_gsn_projection_file(args.projection, assurance_case_source=args.case)
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
    value = independent_roundtrip_evidence(
        args.validation_receipt, args.observation
    )
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
    destination = export_csaf(
        load_analysis(args.analysis), args.decisions, args.output
    )
    print(f"Published governed OASIS CSAF 2.0 advisory: {destination}")
    print(
        "Product status came only from the supplied governed decisions. Validate the "
        "result with the OASIS normative schema before operational publication."
    )
    return 0


def _csaf_verify(args: argparse.Namespace) -> int:
    result = verify_csaf_file(
        args.csaf, load_analysis(args.analysis), args.decisions
    )
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
        args.protocol, args.qualification_result, args.qualification_manifest
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
        print(
            f"Advanced benchmark: valid={result['valid']}, passed={result['passed']}"
        )
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
        print(f"Advanced benchmark report: valid={result['valid']}, passed={result['passed']}")
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
    print(f"Status={value['summary']['status']}; failed checks={len(value['summary']['failed_checks'])}.")
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
        print(f"Release qualification: valid={result['valid']}, passed={result['passed']}")
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
    value = safety_lifecycle_assessment(
        load_analysis(args.analysis), args.authoring
    )
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
        print(f"SLSA policy assessment: valid={result['valid']}, passed={result['passed']}")
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
    print(f"Vulnerabilities={value['summary']['vulnerabilities']}; outcomes={value['summary']['outcomes']}.")
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
        print(f"SSVC assessment: valid={result['valid']}, complete={result['complete']}")
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1


def _dependability_assess(args: argparse.Namespace) -> int:
    value = dependability_assessment(
        load_analysis(args.analysis), args.authoring
    )
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
        status = result.get("complete", result.get("eligible_for_authorized_conclusion", False))
        print(f"{spec['label'].title()}: valid={result['valid']}, complete/eligible={status}")
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
        print(f"{spec['label'].title()}: valid={result['valid']}, complete/eligible={status}")
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return 0 if result["valid"] else 1
