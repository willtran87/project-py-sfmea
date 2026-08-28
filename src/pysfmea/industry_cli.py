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
from .guidance import GUIDANCE_SOURCES, GUIDELINE_PROFILES, METHODOLOGY_NOTICE
from .interchange import export_json_document
from .slsa import (
    export_slsa_provenance,
    slsa_provenance_statement,
    verify_slsa_provenance_file,
)
from .store import load_analysis
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
