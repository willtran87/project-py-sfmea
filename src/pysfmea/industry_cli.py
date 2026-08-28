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
