"""Command-line entry points for scanning, reviewing, and exporting SFMEA data."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import uuid
from os import replace as atomic_replace
from os.path import lexists
from pathlib import Path
from typing import Any

from .accessibility import (
    export_accessibility_evidence,
    seal_accessibility_evidence,
    verify_accessibility_evidence_file,
)
from .activation import (
    DECISION_CHOICES,
    apply_activation_workspace,
    export_activation_records_template,
    export_activation_workspace,
    import_activation_records,
    load_activation_workspace,
    record_activation_assignment,
    record_activation_decision,
    verify_activation_workspace_file,
)
from .architecture import export_architecture
from .assurance import (
    ASSURANCE_WORK_QUEUE_VERIFICATION_FORMAT,
    PLANNING_REVIEW_STATUSES,
    archive_pytest_scaffold,
    ensure_assurance_register,
    export_assurance_register,
    export_pytest_scaffold,
    refresh_pytest_scaffold,
    review_obligation,
    verify_assurance_work_queue_file,
    verify_pytest_scaffold,
)
from .browser_quality import verify_browser_quality_receipt_file
from .config import load_config, write_config_template
from .configuration_authoring import (
    apply_configuration_authoring,
    export_configuration_authoring_draft,
    load_configuration_authoring,
    seal_configuration_authoring_draft,
    verify_configuration_authoring_file,
)
from .diagnostics import analysis_diagnostics
from .diagrams import (
    DEFAULT_PROPAGATION_DEPTH,
    DEFAULT_PROPAGATION_PATH_LIMIT,
    DEFAULT_PROPAGATION_RECORD_LIMIT,
    DIAGRAM_BUNDLE_VERIFICATION_FORMAT,
    GENERATED_DIAGRAM_KINDS,
    MAX_PROPAGATION_DEPTH,
    MAX_PROPAGATION_PATH_LIMIT,
    MAX_PROPAGATION_RECORD_LIMIT,
    export_diagram_bundle,
    verify_diagram_bundle_file,
    verify_diagram_bundle_integrity,
)
from .discovery import (
    OpenAICompatibleProvider,
    compare_evaluation_results,
    deterministic_summary,
    discover_suggestions,
    evaluate_candidates,
    evidence_packets,
    generate_summary,
    load_evaluation_spec,
    review_suggestion,
)
from .enhancements import (
    enhancement_scope_preview,
    enhancement_workbench,
    enhancement_workbench_markdown,
    evidence_preflight,
    export_enhancement_workbench,
    verify_enhancement_workbench_file,
)
from .evidence_onboarding import (
    onboard_evidence,
    verify_evidence_onboarding_receipt,
    verify_evidence_onboarding_receipt_file,
)
from .execution import (
    CRITERION_RESULTS,
    EVIDENCE_REVIEW_DECISIONS,
    import_execution_evidence,
    prepare_sandbox_execution,
    register_test_implementation,
    review_execution_evidence,
    run_sandbox_execution,
)
from .fault_injection import (
    export_completed_fault_injection_plan,
    export_fault_injection_plan,
    export_fault_injection_pytest,
    fault_injection_plugin_catalog,
    load_fault_injection_case,
    load_fault_injection_plan,
    verify_fault_injection_plan,
)
from .file_publication import (
    atomic_publish_bytes,
    atomic_publish_pair,
    inspect_artifact_destination,
)
from .guidance import GUIDANCE_SOURCES, GUIDELINE_PROFILES, METHODOLOGY_NOTICE
from .html_report import (
    HTML_REPORT_VERIFICATION_FORMAT,
    MAX_HTML_REPORT_VERIFY_BYTES,
    MAX_REPORT_RECORDS,
    export_html_report,
    verify_html_report_file,
)
from .integrity import canonical_json_sha256
from .interchange import (
    cyclonedx_document,
    differential_analysis,
    export_json_document,
    sarif_document,
)
from .json_ingestion import load_bounded_file_snapshot, load_bounded_json_document
from .manifest import create_run_manifest
from .pdf_report import export_pdf_report
from .program import (
    PROGRAM_REPORT_VERIFICATION_CHECKS,
    PROGRAM_REPORT_VERIFICATION_FORMAT,
    ProgramReportPublicationError,
    export_program_report_verification,
    export_program_verification,
    program_verification_html,
    program_verification_markdown,
    seal_program_file,
    verify_assurance_program,
    verify_program_report_file,
    write_program_template,
)
from .publication import (
    export_publication_failure_catalog,
    publication_failure_catalog,
    verify_publication_failure_catalog_file,
)
from .pull_request import analyze_pull_request, verify_pull_request_analysis
from .qualification import (
    build_qualification_campaign,
    qualification_validation_cohorts,
    verify_qualification_campaign_file,
)
from .qualification_report import (
    export_qualification_report,
    verify_qualification_report_file,
)
from .readiness import repository_readiness
from .report import (
    export_audit,
    export_csv,
    export_guidance_traceability,
    export_inventory,
    export_markdown,
    export_review_archive,
    export_review_package,
    package_publication_error_result,
    verify_review_package,
)
from .repository_inventory import repository_inventory_summary_projection
from .runtime import import_runtime_trace
from .scan_cache import load_fact_cache, save_fact_cache
from .scanner import scan_repository
from .schemas import (
    export_schema,
    export_schema_bundle,
    schema_catalog,
    schema_document,
    verify_schema_bundle_path,
)
from .sdk.host import (
    export_plugin_run,
    load_plugin_manifest,
    run_plugin,
    verify_plugin_run_file,
)
from .security import export_service_threat_model
from .server import serve_review
from .sfta import export_sfta
from .sfta_authoring import (
    apply_sfta_authoring,
    export_sfta_authoring_draft,
    load_sfta_authoring,
    seal_sfta_authoring_draft,
    verify_sfta_authoring_file,
)
from .signing import (
    passphrase_from_environment,
    sign_review_package,
    verify_review_signature,
)
from .store import MAX_ANALYSIS_BYTES, load_analysis, merge_rescan, save_analysis
from .synthesis import (
    apply_synthesis_workspace,
    export_synthesis_workspace,
    load_synthesis_workspace,
    seal_synthesis_workspace,
    suggestion_relationships,
    verify_synthesis_apply_receipt_file,
    verify_synthesis_workspace_file,
)
from .validation import review_queue, validate_analysis
from .version import __version__
from .visuals import export_coverage, export_sequence, export_traceability
from .workflow import workflow_status

VERIFICATION_NOTICE = (
    "Integrity and binding checks detect unreconciled changes and staleness; "
    "they do not authenticate an author, approve the analysis, or accept risk."
)
HTML_REPORT_VERIFICATION_CHECKS = (
    "metadata_complete",
    "report_format",
    "payload_present",
    "payload_json",
    "payload_integrity",
    "payload_binding",
    "document_integrity",
    "baseline",
    "schema",
    "analysis_state",
)
DIAGRAM_BUNDLE_VERIFICATION_CHECKS = (
    "content_integrity",
    "diagram_schema",
    "analysis_binding",
)
ASSURANCE_WORK_QUEUE_VERIFICATION_CHECKS = (
    "format",
    "structure",
    "content_integrity",
    "baseline",
    "schema",
    "analysis_state",
    "semantic_projection",
)
VERIFICATION_EXCEPTIONS = (OSError, RuntimeError, ValueError)


def _verification_error_result(
    *,
    format_name: str,
    source: str,
    check_names: tuple[str, ...],
    binding_requested: bool,
    code: str,
    error: Exception,
) -> dict[str, Any]:
    """Create a stable machine-readable result when verification cannot complete."""

    try:
        display_path = str(Path(source).expanduser().absolute())
    except (OSError, RuntimeError, ValueError):
        display_path = str(source)
    return {
        "format": format_name,
        "verifier": {"name": "PySFMEA", "version": __version__},
        "path": display_path,
        "valid": False,
        "status": "invalid",
        "binding_requested": binding_requested,
        "binding_checked": False,
        "checks": {name: None for name in check_names},
        "failed_checks": [],
        "unchecked_checks": list(check_names),
        "errors": [{"code": code, "message": str(error)}],
        "notice": VERIFICATION_NOTICE,
    }


def _html_report_publication_receipt(
    verification: dict[str, Any],
    *,
    status: str,
    phase: str,
    destination_existed: bool,
) -> dict[str, Any]:
    """Attach transactional publication state to a report-generation verdict."""

    verification["publication"] = {
        "status": status,
        "phase": phase,
        "destination_existed": destination_existed,
        "prior_destination_preserved": bool(
            destination_existed and status == "not_published"
        ),
    }
    return verification


def _program_report_publication_receipt(
    verification: dict[str, Any],
    *,
    status: str,
    phase: str,
    destination_existed: bool,
) -> dict[str, Any]:
    """Attach transactional publication state to a program-report verdict."""

    verification["publication"] = {
        "status": status,
        "phase": phase,
        "destination_existed": destination_existed,
        "prior_destination_preserved": bool(
            destination_existed and status == "not_published"
        ),
    }
    return verification


def _program_report_publication_error(
    *,
    destination: str | Path,
    code: str,
    message: str,
    phase: str,
    destination_existed: bool,
) -> dict[str, Any]:
    """Create a schema-backed, sanitized program-report publication failure."""

    checks: dict[str, bool | None] = {
        name: (
            None
            if name.startswith("program_") or name == "artifact_identity"
            else False
        )
        for name in PROGRAM_REPORT_VERIFICATION_CHECKS
    }
    try:
        display_path = str(Path(destination).expanduser().absolute())
    except (OSError, RuntimeError, ValueError):
        display_path = str(destination)
    result: dict[str, Any] = {
        "format": PROGRAM_REPORT_VERIFICATION_FORMAT,
        "verifier": {"name": "PySFMEA", "version": __version__},
        "path": display_path,
        "bytes": 0,
        "artifact_sha256": "",
        "expected_artifact_sha256": "",
        "artifact_binding_requested": False,
        "artifact_binding_checked": False,
        "valid": False,
        "status": "invalid",
        "assurance_valid": None,
        "checks": checks,
        "declared": {},
        "current": {},
        "binding_requested": True,
        "binding_checked": False,
        "failed_checks": sorted(
            name for name, value in checks.items() if value is False
        ),
        "unchecked_checks": sorted(
            name for name, value in checks.items() if value is None
        ),
        "errors": [{"code": code, "message": message, "path": display_path}],
        "notice": (
            "Report integrity and exact-program regeneration detect tampering and stale "
            "conclusions; they do not authenticate an author, approve risk, or establish "
            "certification."
        ),
    }
    return _program_report_publication_receipt(
        result,
        status="not_published",
        phase=phase,
        destination_existed=destination_existed,
    )


def _add_propagation_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--propagation-include-finding",
        dest="propagation_include_finding",
        action="append",
        default=[],
        metavar="FINDING_ID",
        help=(
            "active finding ID guaranteed inclusion in the bounded propagation "
            "diagram; repeat for multiple findings (count must not exceed the "
            "record limit)"
        ),
    )
    parser.add_argument(
        "--propagation-record-limit",
        type=int,
        default=DEFAULT_PROPAGATION_RECORD_LIMIT,
        help=(
            "findings embedded in the failure-propagation diagram "
            f"(1-{MAX_PROPAGATION_RECORD_LIMIT}; default: "
            f"{DEFAULT_PROPAGATION_RECORD_LIMIT}); combined limits must fit the "
            "canonical node budget"
        ),
    )
    parser.add_argument(
        "--propagation-path-limit",
        type=int,
        default=DEFAULT_PROPAGATION_PATH_LIMIT,
        help=(
            "caller paths embedded per component "
            f"(0-{MAX_PROPAGATION_PATH_LIMIT}; default: "
            f"{DEFAULT_PROPAGATION_PATH_LIMIT})"
        ),
    )
    parser.add_argument(
        "--propagation-depth",
        type=int,
        default=DEFAULT_PROPAGATION_DEPTH,
        help=(
            f"caller levels rendered per path (0-{MAX_PROPAGATION_DEPTH}; "
            f"default: {DEFAULT_PROPAGATION_DEPTH})"
        ),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sfmea",
        description="Scan a Python repository and create a reviewable Software FMEA starter.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Core workflow:\n"
            "  sfmea init REPOSITORY\n"
            "  sfmea doctor REPOSITORY\n"
            "  sfmea scan REPOSITORY\n"
            "  sfmea review REPOSITORY/sfmea-analysis.json\n"
            "  sfmea report REPOSITORY/sfmea-analysis.json\n"
            "  sfmea package REPOSITORY/sfmea-analysis.json --portable --zip\n\n"
            "Run `sfmea status REPOSITORY` at any point for the current stage and "
            "recommended next commands."
        ),
    )
    parser.add_argument("--version", action="version", version=f"PySFMEA {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="create an sfmea.toml project template")
    init.add_argument(
        "path", nargs="?", default="sfmea.toml", help="file or directory path"
    )
    init.add_argument(
        "--force", action="store_true", help="replace an existing template"
    )
    init.set_defaults(handler=_init)

    schema_command = subparsers.add_parser(
        "schema", help="discover or export public JSON Schema contracts"
    )
    schema_command.add_argument("name", nargs="?", help="stable schema catalog name")
    schema_mode = schema_command.add_mutually_exclusive_group()
    schema_mode.add_argument(
        "--list", action="store_true", help="list available schema contracts"
    )
    schema_mode.add_argument(
        "--bundle",
        metavar="DIRECTORY",
        help="atomically export the complete offline schema bundle",
    )
    schema_mode.add_argument(
        "--verify-bundle",
        metavar="DIRECTORY",
        help="verify a standalone offline schema-bundle directory",
    )
    schema_command.add_argument(
        "--json", action="store_true", help="emit machine-readable JSON output"
    )
    schema_command.add_argument("-o", "--output", help="schema JSON destination")
    schema_command.add_argument(
        "--force",
        action="store_true",
        help="replace a recognized schema bundle; valid only with --bundle",
    )
    schema_command.set_defaults(handler=_schema)

    publication_catalog = subparsers.add_parser(
        "publication-catalog",
        help="show package-publication failure codes and remediation actions",
    )
    publication_catalog.add_argument(
        "--json", action="store_true", help="emit the schema-backed catalog as JSON"
    )
    publication_catalog.add_argument(
        "--verify",
        metavar="FILE",
        help="verify a bounded catalog JSON file against the shipped taxonomy",
    )
    publication_catalog.add_argument(
        "-o", "--output", help="atomically export deterministic catalog JSON"
    )
    publication_catalog.add_argument(
        "--force",
        action="store_true",
        help="replace an existing recognized catalog; valid only with --output",
    )
    publication_catalog.set_defaults(handler=_publication_catalog)

    doctor = subparsers.add_parser(
        "doctor", help="check repository and SFMEA configuration readiness"
    )
    doctor.add_argument("repository", nargs="?", default=".")
    doctor.add_argument("--config", help="sfmea.toml path")
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(handler=_doctor)

    status = subparsers.add_parser(
        "status",
        help="show the current workflow stage, artifact freshness, and next actions",
    )
    status.add_argument("repository", nargs="?", default=".")
    status.add_argument("--config", help="sfmea.toml path; auto-discovered by default")
    status.add_argument(
        "--analysis", help="analysis JSON path; auto-discovered by default"
    )
    status.add_argument(
        "--assurance-scaffold",
        action="append",
        default=[],
        help=(
            "optional scaffold directory; repeat for multiple queues; conventional nearby "
            "names are auto-discovered when omitted"
        ),
    )
    status.add_argument(
        "--json", action="store_true", help="emit machine-readable status"
    )
    status.add_argument(
        "--require-handoff-ready",
        action="store_true",
        help="exit nonzero unless every handoff gate is satisfied",
    )
    status.set_defaults(handler=_status)

    diagnostics = subparsers.add_parser(
        "diagnostics",
        help="explain accounting, review-load, coverage, and evidence improvement priorities",
    )
    diagnostics.add_argument("analysis", help="analysis JSON path")
    diagnostics.add_argument(
        "--json",
        action="store_true",
        help="emit the complete machine-readable diagnostic",
    )
    diagnostics.add_argument(
        "--strict",
        action="store_true",
        help="exit nonzero when adapter contribution accounting is inconsistent",
    )
    diagnostics.set_defaults(handler=_diagnostics)

    enhance = subparsers.add_parser(
        "enhance",
        help=(
            "build an integrated evidence, review, architecture, interface, and "
            "qualification activation workbench"
        ),
    )
    enhance.add_argument("analysis", help="analysis JSON path")
    enhance.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="workbench projection format",
    )
    enhance.add_argument("-o", "--output", help="atomically publish the workbench")
    enhance.set_defaults(handler=_enhance)

    enhance_verify = subparsers.add_parser(
        "enhance-verify",
        help="verify an enhancement workbench and optional exact analysis binding",
    )
    enhance_verify.add_argument("workbench", help="enhancement-workbench JSON path")
    enhance_verify.add_argument(
        "--analysis",
        help="optional governed analysis used for exact deterministic regeneration",
    )
    enhance_verify.add_argument(
        "-o",
        "--output",
        help="atomically publish the schema-backed verification verdict",
    )
    enhance_verify.set_defaults(handler=_enhance_verify)

    enhance_scope_preview = subparsers.add_parser(
        "enhance-scope-preview",
        help="preview files admitted by proposed evidence-only scope changes",
    )
    enhance_scope_preview.add_argument("analysis", help="analysis JSON path")
    enhance_scope_preview.add_argument(
        "repository", help="repository directory to preview"
    )
    enhance_scope_preview.add_argument(
        "-o", "--output", help="atomically publish the metadata-only preview"
    )
    enhance_scope_preview.set_defaults(handler=_enhance_scope_preview)

    enhance_evidence_preflight = subparsers.add_parser(
        "enhance-evidence-preflight",
        help="validate evidence readiness without executing repository code",
    )
    enhance_evidence_preflight.add_argument("analysis", help="analysis JSON path")
    enhance_evidence_preflight.add_argument(
        "repository", help="authorized repository directory to inspect"
    )
    enhance_evidence_preflight.add_argument(
        "-o", "--output", help="atomically publish the evidence-preflight receipt"
    )
    enhance_evidence_preflight.set_defaults(handler=_enhance_evidence_preflight)

    evidence_onboard = subparsers.add_parser(
        "evidence-onboard",
        help="validate and transactionally import selected repository evidence",
    )
    evidence_onboard.add_argument("analysis", help="governed analysis JSON path")
    evidence_onboard.add_argument(
        "repository", help="repository root recorded by the governed analysis"
    )
    evidence_onboard.add_argument(
        "--coverage-json",
        help="coverage.py JSON artifact; discovered coverage is used by default",
    )
    evidence_onboard.add_argument(
        "--no-discovered-coverage",
        action="store_true",
        help="do not automatically select ready coverage found by preflight",
    )
    evidence_onboard.add_argument(
        "--runtime-trace",
        action="append",
        default=[],
        help="runtime trace JSON; repeat for multiple traces",
    )
    evidence_onboard.add_argument(
        "--execution-manifest",
        action="append",
        default=[],
        metavar="OBLIGATION_ID=PATH",
        help="bounded external execution manifest bound to an obligation; repeatable",
    )
    evidence_onboard.add_argument(
        "--initiated-by",
        default="",
        help="initiating identity; required when importing execution evidence",
    )
    evidence_onboard.add_argument(
        "--evidence-root",
        help="managed copied-evidence directory; defaults under REPOSITORY/.artifacts",
    )
    evidence_onboard.add_argument(
        "--apply",
        action="store_true",
        help="publish the validated result; otherwise emit a non-mutating validated plan",
    )
    evidence_destination = evidence_onboard.add_mutually_exclusive_group()
    evidence_destination.add_argument(
        "-o", "--output-analysis", help="updated analysis destination"
    )
    evidence_destination.add_argument(
        "--in-place", action="store_true", help="atomically update the source analysis"
    )
    evidence_onboard.add_argument(
        "--receipt", help="onboarding receipt JSON destination"
    )
    evidence_onboard.add_argument(
        "--work-queue", help="verified assurance work-queue JSON destination"
    )
    evidence_onboard.set_defaults(handler=_evidence_onboard)

    evidence_onboard_verify = subparsers.add_parser(
        "evidence-onboard-verify",
        help="verify an onboarding receipt and optional exact resulting analysis",
    )
    evidence_onboard_verify.add_argument("receipt", help="onboarding receipt JSON")
    evidence_onboard_verify.add_argument(
        "--analysis", help="optional resulting analysis for exact binding"
    )
    evidence_onboard_verify.add_argument(
        "-o", "--output", help="verification verdict JSON destination"
    )
    evidence_onboard_verify.set_defaults(handler=_evidence_onboard_verify)

    activate_init = subparsers.add_parser(
        "activate-init",
        help="create an editable, integrity-bound SFMEA closure workspace",
    )
    activate_init.add_argument("analysis", help="analysis JSON path")
    activate_init.add_argument(
        "repository", help="authorized repository directory for read-only preflight"
    )
    activate_init.add_argument(
        "-o", "--output", help="activation workspace JSON destination"
    )
    activate_init.set_defaults(handler=_activate_init)

    activate_verify = subparsers.add_parser(
        "activate-verify",
        help="verify activation-workspace integrity and optional analysis binding",
    )
    activate_verify.add_argument("workspace", help="activation workspace JSON path")
    activate_verify.add_argument(
        "--analysis",
        help="optional exact source analysis used for binding verification",
    )
    activate_verify.add_argument("-o", "--output", help="verification JSON destination")
    activate_verify.set_defaults(handler=_activate_verify)

    activate_decide = subparsers.add_parser(
        "activate-decide",
        help="transactionally record one governed decision in an activation workspace",
    )
    activate_decide.add_argument("workspace", help="activation workspace JSON path")
    activate_decide.add_argument("kind", choices=tuple(sorted(DECISION_CHOICES)))
    activate_decide.add_argument("subject_id", help="exact queued subject identifier")
    activate_decide.add_argument(
        "decision", help="decision allowed for the selected kind"
    )
    activate_decide.add_argument("--reviewer", required=True, help="named reviewer")
    activate_decide.add_argument(
        "--rationale", required=True, help="decision rationale"
    )
    activate_decide.set_defaults(handler=_activate_decide)

    activate_assign = subparsers.add_parser(
        "activate-assign",
        help="assign one activation subject without recording its disposition",
    )
    activate_assign.add_argument("workspace", help="activation workspace JSON path")
    activate_assign.add_argument("kind", choices=tuple(sorted(DECISION_CHOICES)))
    activate_assign.add_argument("subject_id", help="exact queued subject identifier")
    activate_assign.add_argument("--assignee", required=True, help="named assignee")
    activate_assign.add_argument(
        "--due-date", default="", help="optional due date in YYYY-MM-DD form"
    )
    activate_assign.set_defaults(handler=_activate_assign)

    activate_batch_export = subparsers.add_parser(
        "activate-batch-export",
        help="export a workspace-bound bulk assignment and decision template",
    )
    activate_batch_export.add_argument(
        "workspace", help="activation workspace JSON path"
    )
    activate_batch_export.add_argument(
        "-o", "--output", help="records JSON destination"
    )
    activate_batch_export.set_defaults(handler=_activate_batch_export)

    activate_batch_import = subparsers.add_parser(
        "activate-batch-import",
        help="transactionally import workspace-bound assignments and decisions",
    )
    activate_batch_import.add_argument(
        "workspace", help="activation workspace JSON path"
    )
    activate_batch_import.add_argument(
        "records", help="completed activation records JSON"
    )
    activate_batch_import.add_argument("-o", "--output", help="import receipt JSON")
    activate_batch_import.set_defaults(handler=_activate_batch_import)

    activate_apply = subparsers.add_parser(
        "activate-apply",
        help="apply reviewed workspace decisions to an exact-bound analysis",
    )
    activate_apply.add_argument("analysis", help="source analysis JSON path")
    activate_apply.add_argument("workspace", help="activation workspace JSON path")
    apply_destination = activate_apply.add_mutually_exclusive_group()
    apply_destination.add_argument(
        "-o", "--output", help="updated analysis destination"
    )
    apply_destination.add_argument(
        "--in-place", action="store_true", help="atomically update the source analysis"
    )
    activate_apply.add_argument(
        "--receipt", help="optional activation-apply receipt JSON destination"
    )
    activate_apply.set_defaults(handler=_activate_apply)

    config_authoring_init = subparsers.add_parser(
        "config-authoring-init",
        help="create an editable guidance, architecture, and interface configuration draft",
    )
    config_authoring_init.add_argument("analysis", help="analysis JSON path")
    config_authoring_init.add_argument(
        "--config", required=True, help="exact source sfmea.toml"
    )
    config_authoring_init.add_argument("-o", "--output", help="draft JSON destination")
    config_authoring_init.set_defaults(handler=_config_authoring_init)

    config_authoring_seal = subparsers.add_parser(
        "config-authoring-seal",
        help="validate and seal reviewed configuration additions",
    )
    config_authoring_seal.add_argument("draft", help="edited authoring draft JSON")
    config_authoring_seal.add_argument(
        "--analysis", required=True, help="exact source analysis JSON"
    )
    config_authoring_seal.add_argument(
        "--config", required=True, help="exact source sfmea.toml"
    )
    config_authoring_seal.add_argument("-o", "--output", help="sealed JSON destination")
    config_authoring_seal.set_defaults(handler=_config_authoring_seal)

    config_authoring_verify = subparsers.add_parser(
        "config-authoring-verify",
        help="verify sealed configuration additions and optional exact bindings",
    )
    config_authoring_verify.add_argument("sealed", help="sealed authoring JSON")
    config_authoring_verify.add_argument(
        "--analysis", help="exact source analysis JSON"
    )
    config_authoring_verify.add_argument("--config", help="exact source sfmea.toml")
    config_authoring_verify.add_argument("-o", "--output", help="verification JSON")
    config_authoring_verify.set_defaults(handler=_config_authoring_verify)

    config_authoring_apply = subparsers.add_parser(
        "config-authoring-apply",
        help="publish approved additions as a new validated sfmea.toml",
    )
    config_authoring_apply.add_argument("analysis", help="source analysis JSON")
    config_authoring_apply.add_argument("sealed", help="sealed authoring JSON")
    config_authoring_apply.add_argument(
        "--config", required=True, help="exact source sfmea.toml"
    )
    config_authoring_apply.add_argument(
        "-o", "--output", help="new sfmea.toml destination"
    )
    config_authoring_apply.add_argument("--receipt", help="apply receipt JSON")
    config_authoring_apply.set_defaults(handler=_config_authoring_apply)

    sfta_authoring_init = subparsers.add_parser(
        "sfta-authoring-init",
        help="create an editable fault-tree authoring draft for every configured hazard",
    )
    sfta_authoring_init.add_argument("analysis", help="analysis JSON path")
    sfta_authoring_init.add_argument("-o", "--output", help="draft JSON destination")
    sfta_authoring_init.set_defaults(handler=_sfta_authoring_init)

    sfta_authoring_seal = subparsers.add_parser(
        "sfta-authoring-seal",
        help="validate and seal a reviewed fault-tree authoring draft",
    )
    sfta_authoring_seal.add_argument("draft", help="edited authoring draft JSON")
    sfta_authoring_seal.add_argument(
        "--analysis", required=True, help="exact source analysis JSON"
    )
    sfta_authoring_seal.add_argument("-o", "--output", help="sealed JSON destination")
    sfta_authoring_seal.set_defaults(handler=_sfta_authoring_seal)

    sfta_authoring_verify = subparsers.add_parser(
        "sfta-authoring-verify",
        help="verify sealed fault-tree inputs and optional exact analysis binding",
    )
    sfta_authoring_verify.add_argument("sealed", help="sealed authoring JSON")
    sfta_authoring_verify.add_argument("--analysis", help="exact source analysis JSON")
    sfta_authoring_verify.add_argument("-o", "--output", help="verification JSON")
    sfta_authoring_verify.set_defaults(handler=_sfta_authoring_verify)

    sfta_authoring_apply = subparsers.add_parser(
        "sfta-authoring-apply",
        help="apply approved exact-bound fault-tree replacements to an analysis",
    )
    sfta_authoring_apply.add_argument("analysis", help="source analysis JSON")
    sfta_authoring_apply.add_argument("sealed", help="sealed authoring JSON")
    sfta_apply_destination = sfta_authoring_apply.add_mutually_exclusive_group()
    sfta_apply_destination.add_argument("-o", "--output", help="updated analysis")
    sfta_apply_destination.add_argument(
        "--in-place", action="store_true", help="atomically update the source analysis"
    )
    sfta_authoring_apply.add_argument("--receipt", help="apply receipt JSON")
    sfta_authoring_apply.set_defaults(handler=_sfta_authoring_apply)

    scan = subparsers.add_parser("scan", help="scan a Python repository")
    scan.add_argument("repository", help="path to the Python repository")
    scan.add_argument(
        "-o",
        "--output",
        help="analysis JSON path; defaults to REPOSITORY/sfmea-analysis.json",
    )
    scan.add_argument(
        "--config",
        help="sfmea.toml path; defaults to REPOSITORY/sfmea.toml when present",
    )
    scan.add_argument("--coverage-json", help="coverage.py JSON file")
    scan.add_argument(
        "--allow-ungoverned",
        action="store_true",
        help=(
            "allow a discovery-only scan without sfmea.toml; output remains explicitly "
            "not assurance-ready"
        ),
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="additional relative-path glob to exclude",
    )
    scan.add_argument(
        "--focus",
        action="append",
        default=[],
        help="only analyze matching path:qualname glob",
    )
    scan.add_argument(
        "--review-depth",
        choices=("screening", "focused", "exhaustive"),
        help=(
            "human review-queue depth; the complete machine candidate inventory is retained"
        ),
    )
    private = scan.add_mutually_exclusive_group()
    private.add_argument(
        "--include-private",
        dest="include_private",
        action="store_true",
        default=None,
        help="include underscore-prefixed callables",
    )
    private.add_argument(
        "--exclude-private",
        dest="include_private",
        action="store_false",
        help="exclude underscore-prefixed callables",
    )
    scan.add_argument(
        "--include-tests",
        action="store_true",
        default=None,
        help="analyze test functions as components",
    )
    nested = scan.add_mutually_exclusive_group()
    nested.add_argument(
        "--include-nested",
        dest="include_nested",
        action="store_true",
        default=None,
        help="include nested functions and closures",
    )
    nested.add_argument(
        "--exclude-nested",
        dest="include_nested",
        action="store_false",
        help="exclude nested functions and closures",
    )
    scan.add_argument(
        "--fresh",
        action="store_true",
        help="do not merge review decisions from an existing output",
    )
    cache = scan.add_mutually_exclusive_group()
    cache.add_argument(
        "--cache",
        metavar="FILE",
        help="exact-content derived fact cache path; relative paths use the repository root",
    )
    cache.add_argument(
        "--no-cache",
        action="store_true",
        help="disable reading and publishing the configured derived fact cache",
    )
    scan.add_argument(
        "--read-only",
        action="store_true",
        help=(
            "prohibit writes inside the scanned repository; requires an external analysis "
            "output and disables any in-repository fact cache"
        ),
    )
    scan.add_argument(
        "--pretty-analysis",
        action="store_true",
        help="write indented JSON for manual inspection (compact JSON is the default)",
    )
    scan.set_defaults(handler=_scan)

    review = subparsers.add_parser(
        "review", help="open the local browser review workspace"
    )
    review.add_argument("analysis", help="analysis JSON path")
    review.add_argument(
        "--port", type=int, default=8765, help="local port; use 0 for an available port"
    )
    review.add_argument(
        "--no-browser",
        action="store_true",
        help="do not open the browser automatically",
    )
    review.set_defaults(handler=_review)

    export = subparsers.add_parser("export", help="export the SFMEA worksheet")
    export.add_argument("analysis", help="analysis JSON path")
    export.add_argument("--format", choices=("csv", "markdown"), default="csv")
    export.add_argument("-o", "--output", help="destination path")
    export.set_defaults(handler=_export)

    report = subparsers.add_parser(
        "report", help="create a self-contained interactive HTML analysis report"
    )
    report.add_argument("analysis", help="analysis JSON path")
    report.add_argument("-o", "--output", help="destination HTML path")
    report.add_argument(
        "--json",
        action="store_true",
        help="emit the schema-backed verification receipt after generation",
    )
    report.add_argument("--title", help="custom report title")
    report.add_argument(
        "--notes", help="optional UTF-8 Markdown engineering-notes file to include"
    )
    report.add_argument(
        "--diagram",
        action="append",
        default=[],
        help="custom canonical diagram JSON file; repeat to include multiple files",
    )
    report.add_argument(
        "--max-records",
        type=int,
        default=10_000,
        help=f"maximum embedded records (1-{MAX_REPORT_RECORDS}; default: 10000)",
    )
    report.add_argument(
        "--profile",
        choices=("engineering", "compact", "management"),
        default="engineering",
        help="bounded report projection profile (default: engineering)",
    )
    report.add_argument(
        "--max-output-bytes",
        type=int,
        default=MAX_HTML_REPORT_VERIFY_BYTES,
        help=(
            "fail closed before publication when the self-contained report exceeds "
            f"this byte budget (default: {MAX_HTML_REPORT_VERIFY_BYTES})"
        ),
    )
    _add_propagation_arguments(report)
    report.set_defaults(handler=_html_report)

    report_verify = subparsers.add_parser(
        "report-verify",
        help="verify a self-contained HTML report and optional analysis-state binding",
    )
    report_verify.add_argument("report", help="self-contained HTML report path")
    report_verify.add_argument(
        "--analysis",
        help="current analysis JSON; when supplied, require an exact state binding",
    )
    report_verify.add_argument(
        "--json", action="store_true", help="emit machine-readable verification JSON"
    )
    report_verify.set_defaults(handler=_html_report_verify)

    report_browser_verify = subparsers.add_parser(
        "report-browser-verify",
        help="verify a browser-quality receipt and optional exact report binding",
    )
    report_browser_verify.add_argument(
        "receipt", help="browser-quality receipt JSON path"
    )
    report_browser_verify.add_argument(
        "--report",
        help="exact HTML report; when supplied, require a byte-for-byte binding",
    )
    report_browser_verify.add_argument(
        "-o", "--output", help="atomically publish the verification JSON"
    )
    report_browser_verify.set_defaults(handler=_report_browser_verify)

    accessibility_init = subparsers.add_parser(
        "accessibility-init",
        help="create an exact-report assistive-technology qualification checklist",
    )
    accessibility_init.add_argument("report", help="self-contained HTML report")
    accessibility_init.add_argument("-o", "--output", help="evidence JSON path")
    accessibility_init.set_defaults(handler=_accessibility_init)

    accessibility_seal = subparsers.add_parser(
        "accessibility-seal", help="seal completed accessibility evidence"
    )
    accessibility_seal.add_argument("evidence", help="accessibility evidence JSON")
    accessibility_seal.set_defaults(handler=_accessibility_seal)

    accessibility_verify = subparsers.add_parser(
        "accessibility-verify", help="verify accessibility evidence and report binding"
    )
    accessibility_verify.add_argument("evidence", help="sealed evidence JSON")
    accessibility_verify.add_argument("--report", help="exact HTML report")
    accessibility_verify.add_argument("--json", action="store_true")
    accessibility_verify.set_defaults(handler=_accessibility_verify)

    pdf = subparsers.add_parser(
        "pdf", help="render the complete analysis report as a paginated PDF"
    )
    pdf.add_argument("analysis", help="analysis JSON path")
    pdf.add_argument("-o", "--output", help="destination PDF path")
    pdf.add_argument("--title", help="custom report title")
    pdf.add_argument("--notes", help="optional UTF-8 Markdown engineering-notes file")
    pdf.add_argument(
        "--diagram",
        action="append",
        default=[],
        help="custom canonical diagram JSON file; repeat to include multiple files",
    )
    pdf.add_argument(
        "--max-records",
        type=int,
        default=10_000,
        help=f"maximum rendered records (1-{MAX_REPORT_RECORDS}; default: 10000)",
    )
    pdf.add_argument(
        "--browser",
        help="explicit Edge, Chrome, or Chromium executable path",
    )
    pdf.add_argument("--timeout-seconds", type=int, default=180)
    _add_propagation_arguments(pdf)
    pdf.set_defaults(handler=_pdf_report)

    diagram = subparsers.add_parser(
        "diagram", help="export canonical, renderer-neutral SFMEA diagram models"
    )
    diagram.add_argument("analysis", help="analysis JSON path")
    diagram.add_argument(
        "--type",
        choices=GENERATED_DIAGRAM_KINDS,
        default="all",
        help="diagram category to generate",
    )
    diagram.add_argument("-o", "--output", help="destination JSON path")
    _add_propagation_arguments(diagram)
    diagram.set_defaults(handler=_diagram)

    diagram_verify = subparsers.add_parser(
        "diagram-verify",
        help="verify a canonical diagram bundle and optional analysis-state binding",
    )
    diagram_verify.add_argument("bundle", help="diagram bundle JSON path")
    diagram_verify.add_argument(
        "--analysis",
        help="current analysis JSON; when supplied, require an exact state binding",
    )
    diagram_verify.add_argument(
        "--json", action="store_true", help="emit machine-readable verification JSON"
    )
    diagram_verify.set_defaults(handler=_diagram_verify)

    sfta = subparsers.add_parser(
        "sfta",
        help="export Software Fault Trees and bottom-up/top-down reconciliation gaps",
    )
    sfta.add_argument("analysis", help="analysis JSON path")
    sfta.add_argument("--format", choices=("json", "csv"), default="json")
    sfta.add_argument("-o", "--output", help="destination path")
    sfta.set_defaults(handler=_sfta)

    sarif = subparsers.add_parser(
        "sarif", help="export SFMEA screening candidates as SARIF 2.1.0"
    )
    sarif.add_argument("analysis", help="analysis JSON path")
    sarif.add_argument("-o", "--output", help="destination .sarif path")
    sarif.set_defaults(handler=_sarif)

    sbom = subparsers.add_parser(
        "sbom", help="export declared dependency inventory as CycloneDX 1.6"
    )
    sbom.add_argument("analysis", help="analysis JSON path")
    sbom.add_argument("-o", "--output", help="destination CycloneDX JSON path")
    sbom.set_defaults(handler=_sbom)

    difference = subparsers.add_parser(
        "diff", help="compare two canonical SFMEA analysis runs"
    )
    difference.add_argument("previous", help="previous analysis JSON")
    difference.add_argument("current", help="current analysis JSON")
    difference.add_argument("-o", "--output", help="destination diff JSON path")
    difference.set_defaults(handler=_diff)

    pr_analysis = subparsers.add_parser(
        "pr-analyze",
        help="scan exact Git base/head commits and publish a differential review bundle",
    )
    pr_analysis.add_argument("repository", help="local Git repository")
    pr_analysis.add_argument("--base", required=True, help="base revision")
    pr_analysis.add_argument("--head", required=True, help="head revision")
    pr_analysis.add_argument("-o", "--output", required=True, help="new output directory")
    pr_analysis.set_defaults(handler=_pr_analyze)

    pr_verify = subparsers.add_parser(
        "pr-verify", help="verify a published pull-request differential bundle"
    )
    pr_verify.add_argument("bundle", help="pull-request analysis directory")
    pr_verify.add_argument("--json", action="store_true")
    pr_verify.set_defaults(handler=_pr_verify)

    plugin_verify = subparsers.add_parser(
        "plugin-verify", help="validate a versioned process-plugin manifest"
    )
    plugin_verify.add_argument("manifest", help="plugin manifest JSON")
    plugin_verify.add_argument("--json", action="store_true")
    plugin_verify.set_defaults(handler=_plugin_verify)

    plugin_run = subparsers.add_parser(
        "plugin-run", help="run one explicitly selected plugin against an analysis"
    )
    plugin_run.add_argument("manifest", help="plugin manifest JSON")
    plugin_run.add_argument("analysis", help="analysis JSON path")
    plugin_run.add_argument(
        "--capability", default="analyze", help="declared capability to invoke"
    )
    plugin_run.add_argument("-o", "--output", help="plugin-run JSON path")
    plugin_run.set_defaults(handler=_plugin_run)

    plugin_run_verify = subparsers.add_parser(
        "plugin-run-verify", help="verify a plugin-run receipt and optional bindings"
    )
    plugin_run_verify.add_argument("run", help="plugin-run JSON path")
    plugin_run_verify.add_argument("--analysis", help="exact analysis JSON")
    plugin_run_verify.add_argument("--manifest", help="exact plugin manifest JSON")
    plugin_run_verify.add_argument("--json", action="store_true")
    plugin_run_verify.set_defaults(handler=_plugin_run_verify)

    package = subparsers.add_parser(
        "package", help="create a complete checksum-manifested review package"
    )
    package.add_argument("analysis", help="analysis JSON path")
    package.add_argument(
        "-o",
        "--output",
        help="destination directory or .zip archive (.zip implies --zip)",
    )
    package.add_argument(
        "--force",
        action="store_true",
        help="refresh a generated directory or replace an existing ZIP",
    )
    package.add_argument(
        "--portable",
        action="store_true",
        help="remove machine-local absolute paths from the packaged analysis snapshot",
    )
    package.add_argument(
        "--zip",
        action="store_true",
        help="create a single archive (also inferred from a .zip output path)",
    )
    package.add_argument(
        "--json",
        action="store_true",
        help="emit the schema-backed post-publication verification verdict",
    )
    package.set_defaults(handler=_package)

    sign_package = subparsers.add_parser(
        "sign-package", help="create an optional detached Ed25519 package signature"
    )
    sign_package.add_argument(
        "package", help="verified review package directory or ZIP"
    )
    sign_package.add_argument(
        "--private-key", required=True, help="Ed25519 PEM private key"
    )
    sign_package.add_argument("--signer", required=True, help="signed identity label")
    sign_package.add_argument("-o", "--output", help="detached .sig.json destination")
    sign_package.add_argument(
        "--passphrase-env",
        help="environment variable containing the private-key passphrase",
    )
    sign_package.add_argument(
        "--force", action="store_true", help="replace an existing detached signature"
    )
    sign_package.set_defaults(handler=_sign_package)

    verify_package = subparsers.add_parser(
        "verify-package",
        help="verify checksums, contents, contracts, and provenance of a review package",
    )
    verify_package.add_argument("package", help="review package directory or ZIP")
    verify_package.add_argument(
        "--json",
        action="store_true",
        help="emit the complete verification report as JSON",
    )
    verify_package.add_argument(
        "--signature", help="detached signature produced by sign-package"
    )
    verify_package.add_argument(
        "--public-key", help="trusted Ed25519 PEM public key for signature verification"
    )
    verify_package.set_defaults(handler=_verify_package)

    summary = subparsers.add_parser("summary", help="print analysis progress")
    summary.add_argument("analysis", help="analysis JSON path")
    summary.add_argument("--json", action="store_true", help="emit summary JSON")
    summary.set_defaults(handler=_summary)

    validate = subparsers.add_parser(
        "validate", help="check review completeness and quality gates"
    )
    validate.add_argument("analysis", help="analysis JSON path")
    validate.add_argument(
        "--strict", action="store_true", help="also fail when warnings are present"
    )
    validate.add_argument(
        "--json", action="store_true", help="emit the validation report as JSON"
    )
    validate.add_argument(
        "--max-findings",
        type=int,
        default=100,
        help="maximum findings printed in text mode",
    )
    validate.set_defaults(handler=_validate)

    architecture = subparsers.add_parser(
        "architecture",
        help="export the functional call and system-interface propagation view",
    )
    architecture.add_argument("analysis", help="analysis JSON path")
    architecture.add_argument(
        "--format", choices=("markdown", "json"), default="markdown"
    )
    architecture.add_argument("-o", "--output", help="destination path")
    architecture.set_defaults(handler=_architecture)

    audit = subparsers.add_parser("audit", help="export scan and review change history")
    audit.add_argument("analysis", help="analysis JSON path")
    audit.add_argument("-o", "--output", help="destination CSV path")
    audit.set_defaults(handler=_audit)

    inventory = subparsers.add_parser(
        "inventory", help="export the system-definition and component worksheet"
    )
    inventory.add_argument("analysis", help="analysis JSON path")
    inventory.add_argument("-o", "--output", help="destination Markdown path")
    inventory.set_defaults(handler=_inventory)

    queue = subparsers.add_parser(
        "queue", help="show the next prioritized records to review"
    )
    queue.add_argument("analysis", help="analysis JSON path")
    queue.add_argument("--limit", type=int, default=25, help="maximum records to show")
    queue.add_argument(
        "--max-per-component",
        type=int,
        help="override the governed per-component queue cap",
    )
    queue.add_argument(
        "--minimum-priority",
        choices=("high", "medium", "low"),
        help=(
            "override the analysis review-depth priority floor; manual records are always included"
        ),
    )
    queue.add_argument(
        "--all-records",
        action="store_true",
        help="disable component/failure-class family grouping and include low-priority records",
    )
    queue.add_argument("--json", action="store_true", help="emit structured JSON")
    queue.set_defaults(handler=_queue)

    sequence = subparsers.add_parser(
        "sequence", help="export a bounded static/observed sequence view"
    )
    sequence.add_argument("analysis", help="analysis JSON path")
    sequence.add_argument(
        "--entrypoint", required=True, help="component ID, qualname, or path:qualname"
    )
    sequence.add_argument("--format", choices=("markdown", "json"), default="markdown")
    sequence.add_argument("--max-depth", type=int, default=6)
    sequence.add_argument("--max-interactions", type=int, default=100)
    sequence.add_argument(
        "--static-only", action="store_true", help="exclude imported runtime edges"
    )
    sequence.add_argument("-o", "--output", help="destination path")
    sequence.set_defaults(handler=_sequence)

    traceability = subparsers.add_parser(
        "traceability", help="export requirement-to-hazard trace graph"
    )
    traceability.add_argument("analysis", help="analysis JSON path")
    traceability.add_argument(
        "--format", choices=("markdown", "json"), default="markdown"
    )
    traceability.add_argument("-o", "--output", help="destination path")
    traceability.set_defaults(handler=_traceability)

    coverage = subparsers.add_parser(
        "coverage", help="report SFMEA linkage and review coverage"
    )
    coverage.add_argument("analysis", help="analysis JSON path")
    coverage.add_argument("--format", choices=("markdown", "json"), default="markdown")
    coverage.add_argument("-o", "--output", help="destination path")
    coverage.set_defaults(handler=_coverage)

    trace_import = subparsers.add_parser(
        "trace-import", help="import simple or OTLP JSON runtime spans"
    )
    trace_import.add_argument("analysis", help="analysis JSON path")
    trace_import.add_argument("trace", help="runtime trace JSON path")
    trace_import.add_argument(
        "--label", default="", help="human-readable evidence label"
    )
    trace_import.set_defaults(handler=_trace_import)

    discover = subparsers.add_parser(
        "discover", help="generate grounded machine suggestions"
    )
    discover.add_argument("analysis", help="analysis JSON path")
    discover.add_argument("--scope", default="*", help="path:qualname glob")
    discover.add_argument(
        "--limit", type=int, default=25, help="maximum component packets"
    )
    discover.add_argument(
        "--dry-run",
        action="store_true",
        help="print evidence packets without calling a model",
    )
    _add_provider_arguments(discover)
    discover.set_defaults(handler=_discover)

    suggestions = subparsers.add_parser(
        "suggestions", help="list governed machine suggestions"
    )
    suggestions.add_argument("analysis", help="analysis JSON path")
    suggestions.add_argument(
        "--status",
        choices=("all", "proposed", "accepted", "rejected", "stale"),
        default="proposed",
    )
    suggestions.add_argument("--json", action="store_true")
    suggestions.add_argument(
        "--relationships",
        action="store_true",
        help="include deterministic duplicate, contradiction, and divergence leads",
    )
    suggestions.set_defaults(handler=_suggestions)

    suggestion_review = subparsers.add_parser(
        "suggestion-review", help="accept or reject a machine suggestion"
    )
    suggestion_review.add_argument("analysis", help="analysis JSON path")
    suggestion_review.add_argument("suggestion_id")
    suggestion_review.add_argument(
        "--decision", choices=("accept", "reject"), required=True
    )
    suggestion_review.add_argument("--reviewer", required=True)
    suggestion_review.add_argument("--rationale", required=True)
    suggestion_review.set_defaults(handler=_suggestion_review)

    synthesis_init = subparsers.add_parser(
        "synthesis-init",
        help="create a side-by-side human editing workspace for machine suggestions",
    )
    synthesis_init.add_argument("analysis", help="analysis JSON path")
    synthesis_init.add_argument("-o", "--output", help="workspace JSON path")
    synthesis_init.set_defaults(handler=_synthesis_init)

    synthesis_seal = subparsers.add_parser(
        "synthesis-seal", help="seal an edited suggestion synthesis workspace"
    )
    synthesis_seal.add_argument("workspace", help="workspace JSON path")
    synthesis_seal.set_defaults(handler=_synthesis_seal)

    synthesis_verify = subparsers.add_parser(
        "synthesis-verify", help="verify synthesis integrity and optional freshness"
    )
    synthesis_verify.add_argument("workspace", help="sealed workspace JSON path")
    synthesis_verify.add_argument("--analysis", help="analysis JSON for exact binding")
    synthesis_verify.add_argument("--json", action="store_true")
    synthesis_verify.set_defaults(handler=_synthesis_verify)

    synthesis_apply = subparsers.add_parser(
        "synthesis-apply", help="apply reviewed synthesis decisions transactionally"
    )
    synthesis_apply.add_argument("analysis", help="analysis JSON path")
    synthesis_apply.add_argument("workspace", help="sealed workspace JSON path")
    synthesis_apply.add_argument(
        "--receipt", help="apply-receipt JSON path; defaults beside the analysis"
    )
    synthesis_apply.add_argument(
        "--source-snapshot",
        help="publish the exact pre-application analysis bytes for later reconciliation",
    )
    synthesis_apply.set_defaults(handler=_synthesis_apply)

    synthesis_apply_verify = subparsers.add_parser(
        "synthesis-apply-verify",
        help="verify an apply receipt in integrity-only or complete reconciliation mode",
    )
    synthesis_apply_verify.add_argument("receipt", help="apply-receipt JSON path")
    synthesis_apply_verify.add_argument(
        "--source-analysis", help="exact analysis state before application"
    )
    synthesis_apply_verify.add_argument(
        "--workspace", help="exact sealed synthesis workspace"
    )
    synthesis_apply_verify.add_argument(
        "--result-analysis", help="exact persisted analysis state after application"
    )
    synthesis_apply_verify.add_argument(
        "--integrity-only",
        action="store_true",
        help="verify only receipt structure and integrity; do not claim reconciliation",
    )
    synthesis_apply_verify.add_argument(
        "-o", "--output", help="atomically publish the verification JSON"
    )
    synthesis_apply_verify.set_defaults(handler=_synthesis_apply_verify)

    summarize = subparsers.add_parser(
        "summarize", help="produce deterministic or grounded model summaries"
    )
    summarize.add_argument("analysis", help="analysis JSON path")
    summarize.add_argument(
        "--by",
        choices=("project", "subsystem", "hazard", "component"),
        default="project",
    )
    summarize.add_argument("--key", default="")
    summarize.add_argument(
        "--llm",
        action="store_true",
        help="request a grounded narrative from the configured provider",
    )
    summarize.add_argument("--json", action="store_true")
    _add_provider_arguments(summarize)
    summarize.set_defaults(handler=_summarize)

    evaluate = subparsers.add_parser(
        "evaluate", help="compare candidates with an exact-key golden corpus"
    )
    evaluate.add_argument("analysis", help="analysis JSON path")
    evaluate.add_argument("expected", help="golden evaluation JSON path")
    evaluate.add_argument(
        "--json", action="store_true", help="emit the complete result"
    )
    evaluate.add_argument(
        "-o", "--output", help="atomically publish the complete evaluation result JSON"
    )
    evaluate.add_argument("--max-findings", type=int, default=25)
    evaluate.set_defaults(handler=_evaluate)

    evaluate_compare = subparsers.add_parser(
        "evaluate-compare",
        help="compare governed same-corpus before/after calibration results",
    )
    evaluate_compare.add_argument("before", help="before evaluation-result JSON")
    evaluate_compare.add_argument("after", help="after evaluation-result JSON")
    evaluate_compare.add_argument("change", help="governed calibration-change JSON")
    evaluate_compare.add_argument(
        "--json", action="store_true", help="emit the complete comparison"
    )
    evaluate_compare.set_defaults(handler=_evaluate_compare)

    qualification_build = subparsers.add_parser(
        "qualification-build",
        help="regenerate a governed multi-repository scanner qualification campaign",
    )
    qualification_build.add_argument(
        "manifest", help="qualification campaign manifest JSON"
    )
    qualification_build.add_argument(
        "-o", "--output", required=True, help="campaign result JSON destination"
    )
    qualification_build.add_argument(
        "--require-eligible",
        action="store_true",
        help="return a failing exit status unless every qualification gate passes",
    )
    qualification_build.set_defaults(handler=_qualification_build)

    qualification_verify = subparsers.add_parser(
        "qualification-verify",
        help="verify campaign integrity and exact retained-artifact regeneration",
    )
    qualification_verify.add_argument("result", help="campaign result JSON")
    qualification_verify.add_argument(
        "--manifest",
        help="exact campaign manifest; required unless --integrity-only is used",
    )
    qualification_verify.add_argument(
        "--integrity-only",
        action="store_true",
        help="verify internal integrity without claiming retained-artifact reconciliation",
    )
    qualification_verify.add_argument(
        "--require-eligible",
        action="store_true",
        help="also fail unless the campaign is eligible for independent review",
    )
    qualification_verify.add_argument(
        "-o", "--output", help="atomically publish the verification JSON"
    )
    qualification_verify.set_defaults(handler=_qualification_verify)

    qualification_report = subparsers.add_parser(
        "qualification-report",
        help="publish a self-contained qualification campaign review report",
    )
    qualification_report.add_argument("result", help="campaign result JSON")
    qualification_report.add_argument(
        "--manifest", required=True, help="exact retained-artifact campaign manifest"
    )
    qualification_report.add_argument(
        "-o", "--output", required=True, help="HTML report destination"
    )
    qualification_report.add_argument("--title", help="report title override")
    qualification_report.set_defaults(handler=_qualification_report)

    qualification_report_verify = subparsers.add_parser(
        "qualification-report-verify",
        help="verify qualification report integrity and optional exact-result binding",
    )
    qualification_report_verify.add_argument("report", help="HTML report path")
    qualification_report_verify.add_argument(
        "--result", help="exact campaign result for complete reconciliation"
    )
    qualification_report_verify.add_argument(
        "--integrity-only",
        action="store_true",
        help="verify standalone report integrity without claiming result reconciliation",
    )
    qualification_report_verify.add_argument(
        "-o", "--output", help="atomically publish verification JSON"
    )
    qualification_report_verify.set_defaults(handler=_qualification_report_verify)

    threat_model = subparsers.add_parser(
        "threat-model",
        help="export the versioned service threat and residual-risk model",
    )
    threat_model.add_argument("-o", "--output", required=True)
    threat_model.add_argument("--format", choices=("json", "markdown"), default="json")
    threat_model.set_defaults(handler=_threat_model)

    program_init = subparsers.add_parser(
        "program-init",
        help="create a state-bound multi-repository assurance-program template",
    )
    program_init.add_argument(
        "--analysis",
        action="append",
        required=True,
        metavar="ID=PATH",
        help="repository ID and governed analysis path; repeat for multiple repositories",
    )
    program_init.add_argument(
        "-o", "--output", required=True, help="program JSON destination"
    )
    program_init.add_argument("--name", default="System assurance program")
    program_init.add_argument(
        "--qualification-result",
        help="completely reconciled qualification campaign result to import",
    )
    program_init.add_argument(
        "--qualification-manifest",
        help="exact retained-artifact manifest for --qualification-result",
    )
    program_init.add_argument(
        "--force", action="store_true", help="replace only a recognized program"
    )
    program_init.set_defaults(handler=_program_init)

    program_seal = subparsers.add_parser(
        "program-seal",
        help="refresh assurance-program integrity after intentional edits",
    )
    program_seal.add_argument("program", help="assurance-program JSON path")
    program_seal.set_defaults(handler=_program_seal)

    program_verify = subparsers.add_parser(
        "program-verify",
        help="verify multi-repository bindings, evidence, timing, validation, and governance",
    )
    program_verify.add_argument("program", help="assurance-program JSON path")
    program_verify.add_argument(
        "--format", choices=("human", "json", "markdown", "html"), default="human"
    )
    program_verify.add_argument(
        "-o", "--output", help="JSON, Markdown, or HTML verification output"
    )
    program_verify.add_argument("--max-findings", type=int, default=50)
    program_verify.add_argument(
        "--publication-json",
        action="store_true",
        help=(
            "emit one schema-backed transactional publication receipt; requires "
            "--format html and --output"
        ),
    )
    program_verify.set_defaults(handler=_program_verify)

    program_report_verify = subparsers.add_parser(
        "program-report-verify",
        help="verify a program HTML report and optionally regenerate its exact verdict",
    )
    program_report_verify.add_argument(
        "report", help="assurance-program HTML report path"
    )
    program_report_verify.add_argument(
        "--program",
        help="optional assurance-program JSON for exact content and verdict binding",
    )
    program_report_verify.add_argument(
        "--expect-sha256",
        help="optional lowercase SHA-256 pin for the exact received HTML bytes",
    )
    program_report_emission = program_report_verify.add_mutually_exclusive_group()
    program_report_emission.add_argument(
        "--json", action="store_true", help="emit the public machine-readable verdict"
    )
    program_report_emission.add_argument(
        "-o",
        "--output",
        help="atomically write the machine-readable verdict to this JSON file",
    )
    program_report_verify.set_defaults(handler=_program_report_verify)

    guidance = subparsers.add_parser(
        "guidance", help="show methodology sources and limitations"
    )
    guidance.set_defaults(handler=_guidance)
    citations = subparsers.add_parser(
        "citations", help="export source-to-rule-to-finding guidance traceability"
    )
    citations.add_argument("analysis", help="analysis JSON path")
    citations.add_argument("--format", choices=("json", "csv"), default="json")
    citations.add_argument("-o", "--output", help="destination path")
    citations.set_defaults(handler=_citations)

    assurance = subparsers.add_parser(
        "assurance", help="export the executable verification-obligation checklist"
    )
    assurance.add_argument("analysis", help="analysis JSON path")
    assurance.add_argument(
        "--format", choices=("json", "work-json", "csv", "markdown"), default="json"
    )
    assurance.add_argument("-o", "--output", help="destination path")
    assurance.set_defaults(handler=_assurance)

    assurance_work_verify = subparsers.add_parser(
        "assurance-work-verify",
        help="verify a work queue and optional exact analysis-state projection",
    )
    assurance_work_verify.add_argument("queue", help="assurance work-queue JSON path")
    assurance_work_verify.add_argument(
        "--analysis",
        help="current analysis JSON; when supplied, require exact binding and content",
    )
    assurance_work_verify.add_argument(
        "--json", action="store_true", help="emit machine-readable verification JSON"
    )
    assurance_work_verify.set_defaults(handler=_assurance_work_verify)

    assurance_review = subparsers.add_parser(
        "assurance-review", help="record a governed verification-planning decision"
    )
    assurance_review.add_argument("analysis", help="analysis JSON path")
    assurance_review.add_argument("obligation_id")
    assurance_review.add_argument(
        "--status",
        required=True,
        choices=tuple(sorted(PLANNING_REVIEW_STATUSES)),
    )
    assurance_review.add_argument("--reviewer", required=True)
    assurance_review.add_argument("--rationale", required=True)
    assurance_review.add_argument("--owner", default="")
    assurance_review.set_defaults(handler=_assurance_review)

    fault_plugins = subparsers.add_parser(
        "assurance-fault-plugins",
        help="list governed executable fault-injection plugins",
    )
    fault_plugins.add_argument(
        "--json", action="store_true", help="emit machine-readable plugin metadata"
    )
    fault_plugins.set_defaults(handler=_assurance_fault_plugins)

    fault_plan = subparsers.add_parser(
        "assurance-fault-plan",
        help="create an obligation-bound fault-injection plan requiring explicit bindings",
    )
    fault_plan.add_argument("analysis", help="analysis JSON path")
    fault_plan.add_argument("obligation_id")
    fault_plan.add_argument("-o", "--output", required=True)
    fault_plan.add_argument(
        "--plugin",
        default="",
        help="built-in plugin ID; the obligation recommendation is used when omitted",
    )
    fault_plan.set_defaults(handler=_assurance_fault_plan)

    fault_complete = subparsers.add_parser(
        "assurance-fault-complete",
        help="complete and validate a fault plan from an explicit case JSON object",
    )
    fault_complete.add_argument("plan", help="starter fault-plan JSON path")
    fault_complete.add_argument("case", help="engineer-authored fault-case JSON path")
    fault_complete.add_argument("--analysis", required=True)
    fault_complete.add_argument("-o", "--output", required=True)
    fault_complete.set_defaults(handler=_assurance_fault_complete)

    fault_verify = subparsers.add_parser(
        "assurance-fault-verify",
        help="verify a fault-injection plan and its exact obligation binding",
    )
    fault_verify.add_argument("plan", help="fault-injection plan JSON path")
    fault_verify.add_argument(
        "--analysis",
        required=True,
        help="analysis JSON path for mandatory exact obligation binding",
    )
    fault_verify.add_argument(
        "--json", action="store_true", help="emit machine-readable verification"
    )
    fault_verify.set_defaults(handler=_assurance_fault_verify)

    fault_scaffold = subparsers.add_parser(
        "assurance-fault-scaffold",
        help="generate a pytest bridge for a valid plan and the approved sandbox runner",
    )
    fault_scaffold.add_argument("plan", help="ready fault-plan JSON path")
    fault_scaffold.add_argument("--analysis", required=True)
    fault_scaffold.add_argument("-o", "--output", required=True)
    fault_scaffold.set_defaults(handler=_assurance_fault_scaffold)

    assurance_scaffold = subparsers.add_parser(
        "assurance-scaffold",
        help="create intentionally failing pytest placeholders from verification obligations",
    )
    assurance_scaffold.add_argument("analysis", help="analysis JSON path")
    assurance_scaffold.add_argument("-o", "--output", required=True)
    assurance_scaffold.add_argument(
        "--scope", default="*", help="path:component, finding-ID, or obligation-ID glob"
    )
    assurance_scaffold.add_argument("--limit", type=int, default=100)
    assurance_scaffold.add_argument(
        "--disposition",
        choices=("accepted", "rejected", "unreviewed", "all"),
        default="accepted",
        help="finding disposition to scaffold; accepted is the safe default",
    )
    assurance_scaffold.add_argument(
        "--include-implemented",
        action="store_true",
        help="also emit obligations already bound to implemented tests",
    )
    assurance_scaffold.add_argument(
        "--queue-id", default="", help="stable queue identifier; derived when omitted"
    )
    assurance_scaffold.add_argument(
        "--owner", default="", help="team or person responsible for the queue"
    )
    assurance_scaffold.add_argument(
        "--purpose", default="", help="bounded reason or subsystem scope for the queue"
    )
    assurance_scaffold.set_defaults(handler=_assurance_scaffold)

    assurance_scaffold_refresh = subparsers.add_parser(
        "assurance-scaffold-refresh",
        help="safely refresh an untouched scaffold in place",
    )
    assurance_scaffold_refresh.add_argument("analysis", help="analysis JSON path")
    assurance_scaffold_refresh.add_argument("scaffold", help="scaffold directory")
    assurance_scaffold_refresh.set_defaults(handler=_assurance_scaffold_refresh)

    assurance_scaffold_archive = subparsers.add_parser(
        "assurance-scaffold-archive",
        help="non-destructively archive an untouched retirement-candidate queue",
    )
    assurance_scaffold_archive.add_argument("analysis", help="analysis JSON path")
    assurance_scaffold_archive.add_argument("scaffold", help="scaffold directory")
    assurance_scaffold_archive.add_argument(
        "-o",
        "--output",
        help="archive directory; defaults beneath the queue's sibling .sfmea-archive",
    )
    assurance_scaffold_archive.set_defaults(handler=_assurance_scaffold_archive)

    assurance_scaffold_verify = subparsers.add_parser(
        "assurance-scaffold-verify",
        help="verify a pytest scaffold and its governed-analysis binding",
    )
    assurance_scaffold_verify.add_argument("analysis", help="analysis JSON path")
    assurance_scaffold_verify.add_argument("scaffold", help="scaffold directory")
    assurance_scaffold_verify.add_argument(
        "--json", action="store_true", help="emit machine-readable verification"
    )
    assurance_scaffold_verify.set_defaults(handler=_assurance_scaffold_verify)

    assurance_test = subparsers.add_parser(
        "assurance-test-register",
        help="bind proposed or implemented test source to a verification obligation",
    )
    assurance_test.add_argument("analysis", help="analysis JSON path")
    assurance_test.add_argument("obligation_id")
    assurance_test.add_argument("--test-path", required=True)
    assurance_test.add_argument("--author", required=True)
    assurance_test.add_argument(
        "--origin", choices=("human", "llm_generated", "imported"), required=True
    )
    assurance_test.add_argument(
        "--status", choices=("proposed", "implemented"), default="implemented"
    )
    assurance_test.set_defaults(handler=_assurance_test_register)

    assurance_run = subparsers.add_parser(
        "assurance-run",
        help="execute one implemented assurance test in an approved Docker/Podman sandbox",
    )
    assurance_run.add_argument("analysis", help="analysis JSON path")
    assurance_run.add_argument("obligation_id")
    assurance_run.add_argument(
        "--image", required=True, help="preloaded approved image reference"
    )
    assurance_run.add_argument("--initiated-by", required=True)
    assurance_run.add_argument(
        "--engine", choices=("auto", "docker", "podman"), default="auto"
    )
    assurance_run.add_argument(
        "--evidence-root", help="host directory for immutable execution artifacts"
    )
    assurance_run.add_argument("--cpus", type=float, default=1.0)
    assurance_run.add_argument("--memory-mb", type=int, default=1024)
    assurance_run.add_argument("--pids-limit", type=int, default=128)
    assurance_run.add_argument("--timeout-seconds", type=int, default=900)
    assurance_run.add_argument("--allow-dirty", action="store_true")
    execution_mode = assurance_run.add_mutually_exclusive_group(required=True)
    execution_mode.add_argument("--dry-run", action="store_true")
    execution_mode.add_argument("--approve-execution", action="store_true")
    assurance_run.set_defaults(handler=_assurance_run)

    evidence_import = subparsers.add_parser(
        "assurance-evidence-import",
        help="import bounded CI or externally produced execution evidence",
    )
    evidence_import.add_argument("analysis", help="analysis JSON path")
    evidence_import.add_argument("obligation_id")
    evidence_import.add_argument(
        "--manifest", required=True, help="external evidence manifest JSON"
    )
    evidence_import.add_argument("--initiated-by", required=True)
    evidence_import.add_argument(
        "--evidence-root", help="managed destination for copied evidence"
    )
    evidence_import.set_defaults(handler=_assurance_evidence_import)

    evidence_review = subparsers.add_parser(
        "assurance-evidence-review",
        help="independently evaluate as-run evidence against the original acceptance criteria",
    )
    evidence_review.add_argument("analysis", help="analysis JSON path")
    evidence_review.add_argument("execution_id")
    evidence_review.add_argument("--reviewer", required=True)
    evidence_review.add_argument(
        "--decision", choices=tuple(sorted(EVIDENCE_REVIEW_DECISIONS)), required=True
    )
    evidence_review.add_argument("--rationale", required=True)
    evidence_review.add_argument(
        "--stimulus-observed", choices=("yes", "no"), required=True
    )
    evidence_review.add_argument(
        "--criterion-result",
        action="append",
        required=True,
        help="repeat INDEX=pass|fail|insufficient|not_observed for every criterion",
    )
    evidence_review.set_defaults(handler=_assurance_evidence_review)
    return parser


def _add_provider_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--endpoint", help="OpenAI-compatible chat-completions endpoint"
    )
    parser.add_argument("--model", help="model identifier")
    parser.add_argument("--api-key-env", default="SFMEA_LLM_API_KEY")
    parser.add_argument("--timeout", type=int, default=60)


def _provider(args: argparse.Namespace) -> OpenAICompatibleProvider:
    if not args.endpoint or not args.model:
        raise ValueError(
            "--endpoint and --model are required for model-assisted operation"
        )
    if not 1 <= args.timeout <= 600:
        raise ValueError("--timeout must be from 1 through 600 seconds")
    return OpenAICompatibleProvider(
        endpoint=args.endpoint,
        model=args.model,
        api_key_env=args.api_key_env,
        timeout_seconds=args.timeout,
    )


def _scan(args: argparse.Namespace) -> int:
    repository = Path(args.repository).expanduser().resolve()
    output = (
        Path(args.output).expanduser().resolve()
        if args.output
        else repository / "sfmea-analysis.json"
    )
    if args.read_only:
        try:
            output.relative_to(repository)
        except ValueError:
            pass
        else:
            raise ValueError(
                "--read-only requires --output outside the scanned repository"
            )
    config_path: str | Path | None = args.config
    default_config = repository / "sfmea.toml"
    if config_path is None and default_config.is_file():
        config_path = default_config
    if config_path is None and not args.allow_ungoverned:
        raise ValueError(
            "no SFMEA configuration was found; run `sfmea init` and complete sfmea.toml, "
            "or pass --allow-ungoverned for an explicitly discovery-only scan"
        )
    config, resolved_config = load_config(config_path)
    config["scan"]["exclude"].extend(args.exclude)
    config["scan"]["focus"].extend(args.focus)
    if args.review_depth:
        config["scan"]["review_depth"] = args.review_depth
    cache_enabled = (
        bool(config["scan"].get("cache_enabled", True)) and not args.no_cache
    )
    configured_cache = args.cache or config["scan"].get("cache_path", "")
    cache_path = Path(configured_cache).expanduser() if configured_cache else None
    if cache_path is not None and not cache_path.is_absolute():
        cache_path = repository / cache_path
    if cache_path is not None:
        cache_path = cache_path.absolute()
    cache_inside_repository = False
    if cache_path is not None:
        try:
            cache_path.resolve().relative_to(repository)
        except ValueError:
            pass
        else:
            cache_inside_repository = True
    if args.read_only and cache_inside_repository:
        if args.cache:
            raise ValueError(
                "--read-only cannot publish an explicitly selected cache inside the "
                "scanned repository; choose an external --cache path or --no-cache"
            )
        cache_enabled = False
    if cache_enabled and cache_path is None:
        raise ValueError(
            "scanner fact caching is enabled but no cache path is configured"
        )
    if cache_enabled and cache_path is not None:
        if cache_path == output.absolute() or (
            resolved_config is not None and cache_path == resolved_config.absolute()
        ):
            raise ValueError(
                "scanner fact cache must differ from analysis and configuration files"
            )
        try:
            cache_relative = cache_path.relative_to(repository)
        except ValueError:
            cache_relative = None
        if cache_relative is not None and (
            not cache_relative.parts or not cache_relative.parts[0].startswith(".")
        ):
            raise ValueError(
                "an in-repository fact cache must be under a hidden directory such as .artifacts"
            )
    fact_cache: dict[str, Any] | None = {} if cache_enabled else None
    cache_input: dict[str, Any] = {
        "status": "disabled" if not cache_enabled else "absent",
        "path": str(cache_path or ""),
        "authority": "derived_performance_artifact_not_primary_assurance_evidence",
    }
    cache_warning = ""
    if cache_enabled and cache_path is not None and cache_path.exists():
        try:
            fact_cache, cache_input = load_fact_cache(cache_path)
        except (OSError, ValueError) as exc:
            fact_cache = {}
            cache_input["status"] = "rejected"
            cache_warning = str(exc)
    telemetry: dict[str, Any] = {}
    scanned = scan_repository(
        repository,
        include_private=args.include_private,
        include_tests=args.include_tests,
        include_nested=args.include_nested,
        config=config,
        coverage_json=args.coverage_json,
        telemetry=telemetry,
        fact_cache=fact_cache,
    )
    scanned["project"]["settings"]["config_file"] = str(resolved_config or "")
    governed = resolved_config is not None
    scanned["project"]["settings"]["governance_mode"] = (
        "governed" if governed else "discovery_only"
    )
    scanned["project"]["settings"]["analysis_serialization"] = (
        "pretty" if args.pretty_analysis else "compact"
    )
    scanned["project"]["settings"]["repository_mutation_policy"] = (
        "read_only" if args.read_only else "outputs_may_be_published_in_repository"
    )
    cache_output: dict[str, Any] = {
        "status": "disabled" if not cache_enabled else "not_published",
        "path": str(cache_path or ""),
    }
    if cache_enabled and cache_path is not None and fact_cache is not None:
        try:
            _published_cache, cache_output = save_fact_cache(cache_path, fact_cache)
        except (OSError, ValueError) as exc:
            cache_warning = cache_warning or str(exc)
            cache_output["status"] = "rejected"
    scanned["project"]["settings"]["fact_cache"] = {
        "enabled": cache_enabled,
        "input": cache_input,
        "output": cache_output,
        "run": telemetry.get("fact_cache", {}),
        "notice": (
            "Cache records are derived performance artifacts; source snapshots and governed "
            "configuration remain authoritative."
        ),
    }
    if cache_warning:
        scanned.setdefault("warnings", []).append(
            {
                "path": str(cache_path or ""),
                "type": "FactCacheRejected",
                "message": (
                    "The derived scanner fact cache was rejected and the scan continued from "
                    f"authoritative inputs: {cache_warning}"
                ),
            }
        )
        scanned.setdefault("summary", {})["warnings"] = len(scanned["warnings"])
    if not governed:
        scanned.setdefault("warnings", []).append(
            {
                "path": "sfmea.toml",
                "type": "UngovernedScan",
                "message": (
                    "No SFMEA configuration was supplied. This output is a discovery-only "
                    "inventory and is not assurance-ready until project context, hazards, "
                    "ground rules, mappings, guidance applicability, and reviewers are governed."
                ),
            }
        )
        scanned.setdefault("summary", {})["warnings"] = len(scanned["warnings"])
    merged = False
    if output.exists() and not args.fresh:
        previous = load_analysis(output)
        scanned = merge_rescan(previous, scanned)
        merged = True
    else:
        scanned["history"] = [
            {
                "event": "initial_scan",
                "at": scanned["project"]["scanned_at"],
                "active_candidate_count": len(scanned["items"]),
                "baseline_id": scanned.get("project", {})
                .get("baseline", {})
                .get("id", ""),
            }
        ]
    # The run manifest is an immutable projection of the final resolved scan inputs.
    # Build it only after CLI-only settings and initial history have been settled.
    scanned["run_manifest"] = create_run_manifest(scanned)
    save_analysis(output, scanned, compact=not args.pretty_analysis)
    summary = scanned["summary"]
    action = "Rescanned and merged" if merged else "Scanned"
    print(f"{action} {scanned['project']['root']}")
    print(
        f"Found {summary['python_files']} Python file(s), {summary['components']} component(s), "
        f"and {summary['candidate_failure_modes']} active candidate failure mode(s)."
    )
    if summary.get("warnings"):
        print(f"Warnings: {summary['warnings']} (recorded in the analysis file)")
    print(f"Analysis: {output}")
    print(
        "Governance: "
        + ("governed configuration" if governed else "DISCOVERY ONLY (ungoverned)")
    )
    print(
        "Guidance profiles: "
        + ", ".join(scanned.get("guidance", {}).get("active_profiles", []))
    )
    print(
        "Review depth: "
        + str(scanned.get("project", {}).get("settings", {}).get("review_depth"))
        + " (complete machine inventory retained)"
    )
    print(
        "Repository mutation: "
        + (
            "prohibited by --read-only; analysis and cache outputs are external"
            if args.read_only
            else "analysis and derived cache outputs may be published in the repository"
        )
    )
    cache_run = (
        scanned.get("project", {})
        .get("settings", {})
        .get("fact_cache", {})
        .get("run", {})
    )
    if cache_run.get("enabled"):
        print(
            "Fact cache: "
            f"hits={cache_run.get('hits', 0)}, misses={cache_run.get('misses', 0)}, "
            f"pruned={cache_run.get('pruned_entries', 0)} "
            "(derived performance artifact)"
        )
    print(f'Next: sfmea review "{output}"')
    return 0


def _init(args: argparse.Namespace) -> int:
    destination = Path(args.path).expanduser()
    if (destination.exists() and destination.is_dir()) or (
        destination.suffix.lower() != ".toml"
    ):
        destination = destination / "sfmea.toml"
    result = write_config_template(destination, overwrite=args.force)
    print(f"Created SFMEA configuration: {result}")
    print(
        "Edit the system boundary, hazards, critical functions, and rating guidance before scanning."
    )
    return 0


def _schema(args: argparse.Namespace) -> int:
    if args.bundle:
        if args.name or args.output or args.json:
            raise ValueError(
                "--bundle cannot be combined with a schema name, --output, or --json"
            )
        result = export_schema_bundle(args.bundle, overwrite=args.force)
        print(f"Exported complete JSON Schema bundle: {result}")
        print(f'Next: sfmea schema --verify-bundle "{result}"')
        return 0
    if args.verify_bundle:
        if args.name or args.output or args.force:
            raise ValueError(
                "--verify-bundle cannot be combined with a schema name, --output, or --force"
            )
        verification = verify_schema_bundle_path(args.verify_bundle)
        if args.json:
            print(json.dumps(verification, indent=2, ensure_ascii=False))
        else:
            print(
                f"Schema bundle integrity: valid={verification['valid']}, "
                f"schemas={verification['schema_count']}, "
                f"errors={len(verification['errors'])}"
            )
            for error in verification["errors"]:
                location = f" ({error['path']})" if error.get("path") else ""
                print(f"[ERROR] {error['code']}{location}: {error['message']}")
            print(verification["notice"])
        return int(not verification["valid"])
    if args.list:
        if args.name or args.output or args.force:
            raise ValueError(
                "--list cannot be combined with a schema name, --output, or --force"
            )
        catalog = schema_catalog()
        if args.json:
            print(json.dumps(catalog, indent=2, ensure_ascii=False))
        else:
            print("Available PySFMEA JSON Schemas:")
            for entry in catalog["schemas"]:
                print(f"  {entry['name']}: {entry['description']}")
        return 0
    if not args.name:
        if args.force:
            raise ValueError("--force is valid only with --bundle")
        raise ValueError(
            "provide a schema name or use --list, --bundle, or --verify-bundle"
        )
    if args.force:
        raise ValueError("--force is valid only with --bundle")
    if args.output:
        result = export_schema(args.name, args.output)
        print(f"Exported JSON Schema: {result}")
        return 0
    print(json.dumps(schema_document(args.name), indent=2, ensure_ascii=False))
    return 0


def _publication_catalog(args: argparse.Namespace) -> int:
    if args.verify:
        if args.output or args.force:
            raise ValueError("--verify cannot be combined with --output or --force")
        verification_result = verify_publication_failure_catalog_file(args.verify)
        if args.json:
            print(json.dumps(verification_result, indent=2, ensure_ascii=False))
        else:
            status = "valid" if verification_result["valid"] else "invalid"
            print(
                "Publication failure catalog: "
                f"{status} ({verification_result['source']})"
            )
            print(
                f"Failures: {verification_result['failure_count']}; "
                "declared digest: "
                f"{verification_result['declared_content_sha256'] or 'unavailable'}"
            )
            for error in verification_result["errors"]:
                print(f"[ERROR] {error['code']}: {error['message']}")
            print(verification_result["notice"])
        return 0 if verification_result["valid"] else 1
    if args.force and not args.output:
        raise ValueError("--force is valid only with --output")
    if args.output:
        output_path = export_publication_failure_catalog(
            args.output, overwrite=args.force
        )
        if args.json:
            verification = verify_publication_failure_catalog_file(output_path)
            print(json.dumps(verification, indent=2, ensure_ascii=False))
        else:
            print(f"Exported publication failure catalog: {output_path}")
        return 0
    catalog = publication_failure_catalog()
    if args.json:
        print(json.dumps(catalog, indent=2, ensure_ascii=False))
        return 0
    print(
        "Package publication failures and remediation actions "
        f"({catalog['format']}, {catalog['algorithm']}, "
        f"{catalog['canonicalization']}, digest: {catalog['content_sha256']}):"
    )
    for failure in catalog["failures"]:
        phases = ", ".join(failure["phases"])
        print(
            f"  {failure['code']} ({phases}) -> {failure['next_action']} "
            f"[retry: {failure['retry_policy']}]\n"
            f"    {failure['message']}\n"
            f"    rule: {failure['rule_id']}"
        )
    print(catalog["notice"])
    return 0


def _doctor(args: argparse.Namespace) -> int:
    result = repository_readiness(args.repository, config_path=args.config)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        counts = result["counts"]
        print(
            "Readiness: "
            f"errors={counts['error']}, warnings={counts['warning']}, "
            f"information={counts['information']}, passed={counts['pass']}"
        )
        for check in result["checks"]:
            print(f"[{check['status'].upper()}] {check['id']}: {check['message']}")
            if check.get("next_action"):
                print(f"  Next: {check['next_action']}")
        print(result["notice"])
    return int(not result["ready"])


def _diagnostics(args: argparse.Namespace) -> int:
    result = analysis_diagnostics(load_analysis(args.analysis))
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        accounting = result["accounting"]
        workload = result["workload"]
        evidence = result["evidence"]
        print(
            "Diagnostics: "
            f"accounting={'valid' if accounting['valid'] else 'INVALID'}, "
            f"components={workload['components']}, "
            f"findings={workload['active_findings']}, "
            f"families={workload['review_families']}, "
            f"unreviewed={workload['unreviewed']}"
        )
        coverage = result.get("coverage", {})
        semantic = coverage.get("semantic", {})
        web = coverage.get("web_boundary", {})
        print(
            "Coverage: "
            f"semantic={semantic.get('percent', 0)}%, "
            f"web-boundary={web.get('percent', 0)}%, "
            f"tests={evidence['test_reference_coverage_percent']}%, "
            f"executed-coverage={evidence['coverage_evidence_percent']}%, "
            f"mappings={evidence['mapping_coverage_percent']}%"
        )
        for value in result["recommended_actions"]:
            print(
                f"[{value['priority']}] {value['id']}: {value['reason']}\n"
                f"  Next: {value['command']}"
            )
        print(result["notice"])
    return int(args.strict and not result["accounting"]["valid"])


def _enhance(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    if args.output:
        result = export_enhancement_workbench(
            analysis, args.output, output_format=args.format
        )
        print(f"Exported enhancement workbench: {result}")
        return 0
    workbench = enhancement_workbench(analysis)
    if args.format == "markdown":
        sys.stdout.write(enhancement_workbench_markdown(workbench))
    else:
        print(json.dumps(workbench, indent=2, ensure_ascii=False))
    return 0


def _enhance_verify(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis) if args.analysis else None
    result = verify_enhancement_workbench_file(
        args.workbench,
        analysis=analysis,
    )
    if args.output:
        output = export_json_document(result, args.output)
        print(f"Exported enhancement workbench verification: {output}")
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    return int(not result["valid"])


def _enhance_scope_preview(args: argparse.Namespace) -> int:
    result = enhancement_scope_preview(load_analysis(args.analysis), args.repository)
    if args.output:
        output = export_json_document(result, args.output)
        print(f"Exported enhancement scope preview: {output}")
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    return int(result.get("summary", {}).get("truncated", False))


def _enhance_evidence_preflight(args: argparse.Namespace) -> int:
    result = evidence_preflight(load_analysis(args.analysis), args.repository)
    if args.output:
        output = export_json_document(result, args.output)
        print(f"Exported evidence preflight: {output}")
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    return int(result.get("summary", {}).get("truncated", False))


def _execution_manifest_specs(values: list[str]) -> list[tuple[str, str]]:
    parsed: list[tuple[str, str]] = []
    for value in values:
        obligation_id, separator, path = value.partition("=")
        if not separator or not obligation_id.strip() or not path.strip():
            raise ValueError(
                "--execution-manifest must use the form OBLIGATION_ID=PATH"
            )
        parsed.append((obligation_id.strip(), path.strip()))
    return parsed


def _evidence_analysis_sibling(source: Path) -> Path:
    name = source.name
    if name.casefold().endswith(".json.gz"):
        return source.with_name(name[:-8] + "-evidence.json.gz")
    return source.with_name(source.stem + "-evidence" + source.suffix)


def _evidence_onboard(args: argparse.Namespace) -> int:
    source = Path(args.analysis).expanduser().resolve()
    if not args.apply and (args.output_analysis or args.in_place or args.work_queue):
        raise ValueError(
            "analysis and work-queue destinations require --apply; use --receipt for a plan"
        )
    analysis = load_analysis(source)
    traces = [(value, Path(value).name) for value in args.runtime_trace]
    execution_specs = _execution_manifest_specs(args.execution_manifest)
    updated, receipt, queue = onboard_evidence(
        analysis,
        args.repository,
        coverage_json=args.coverage_json,
        use_discovered_coverage=not args.no_discovered_coverage,
        runtime_traces=traces,
        execution_manifests=execution_specs,
        initiated_by=args.initiated_by,
        evidence_root=args.evidence_root,
        apply=args.apply,
    )
    if not args.apply:
        if args.receipt:
            result = export_json_document(receipt, args.receipt)
            print(f"Exported validated evidence-onboarding plan: {result}")
        else:
            print(json.dumps(receipt, indent=2, ensure_ascii=False))
        return 0

    if not receipt.get("selected_evidence"):
        raise ValueError(
            "--apply requires at least one discovered or explicitly selected artifact"
        )
    destination = (
        source
        if args.in_place
        else Path(args.output_analysis).expanduser().resolve()
        if args.output_analysis
        else _evidence_analysis_sibling(source)
    )
    receipt_path = (
        Path(args.receipt).expanduser().resolve()
        if args.receipt
        else destination.with_name(destination.stem + "-onboarding-receipt.json")
    )
    queue_path = (
        Path(args.work_queue).expanduser().resolve()
        if args.work_queue
        else destination.with_name(destination.stem + "-assurance-work.json")
    )
    identities = {destination, receipt_path, queue_path}
    if len(identities) != 3:
        raise ValueError(
            "analysis, onboarding receipt, and assurance work queue must use distinct paths"
        )
    save_analysis(destination, updated)
    persisted = load_analysis(destination)
    verification = verify_evidence_onboarding_receipt(receipt, analysis=persisted)
    if not verification["valid"]:
        raise RuntimeError("persisted analysis does not match the onboarding receipt")
    export_json_document(queue, queue_path)
    export_json_document(receipt, receipt_path)
    summary = receipt["summary"]
    print(f"Evidence onboarding applied: {destination}")
    print(
        f"Artifacts: selected={summary['selected']}, imported={summary['imported']}, "
        f"duplicates={summary['duplicates']}; coverage components="
        f"{summary['coverage_components']}; runtime imports={summary['runtime_imports']}"
    )
    print(f"Verified assurance work queue: {queue_path}")
    print(f"Exact-bound onboarding receipt: {receipt_path}")
    print(
        "No repository code was executed and no evidence was credited as sufficient or approved."
    )
    return 0


def _evidence_onboard_verify(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis) if args.analysis else None
    verification = verify_evidence_onboarding_receipt_file(
        args.receipt, analysis=analysis
    )
    if args.output:
        result = export_json_document(verification, args.output)
        print(f"Exported evidence-onboarding verification: {result}")
    else:
        print(json.dumps(verification, indent=2, ensure_ascii=False))
    return int(not verification["valid"])


def _activate_init(args: argparse.Namespace) -> int:
    source = Path(args.analysis).expanduser().resolve()
    destination = (
        Path(args.output)
        if args.output
        else source.with_name(source.stem + "-activation.json")
    )
    result = export_activation_workspace(
        load_analysis(source), args.repository, destination
    )
    workspace = load_activation_workspace(result)
    summary = workspace.get("summary", {})
    print(f"Created governed SFMEA activation workspace: {result}")
    print(
        "Queues: "
        f"findings={summary.get('finding_reviews', 0)}, "
        f"consolidations={summary.get('finding_consolidation_candidates', 0)}, "
        f"guidance={summary.get('guidance_dispositions', 0)}, "
        f"SFTA={summary.get('sfta_authoring_items', 0)}, "
        f"architecture={summary.get('architecture_dispositions', 0)}, "
        f"interfaces={summary.get('interface_dispositions', 0)}"
    )
    print(f'Next: sfmea activate-verify "{result}" --analysis "{source}"')
    return int(
        workspace.get("evidence_onboarding", {})
        .get("preflight", {})
        .get("summary", {})
        .get("truncated", False)
    )


def _activate_verify(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis) if args.analysis else None
    result = verify_activation_workspace_file(args.workspace, analysis=analysis)
    if args.output:
        output = export_json_document(result, args.output)
        print(f"Exported activation-workspace verification: {output}")
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    return int(not result["valid"])


def _activate_decide(args: argparse.Namespace) -> int:
    result = record_activation_decision(
        args.workspace,
        kind=args.kind,
        subject_id=args.subject_id,
        decision=args.decision,
        reviewer=args.reviewer,
        rationale=args.rationale,
    )
    workspace = load_activation_workspace(result)
    print(
        f"Recorded {args.kind} decision for {args.subject_id}: {args.decision}; "
        f"workspace decisions={len(workspace.get('decisions', []))}."
    )
    print(f"Updated activation workspace: {result}")
    return 0


def _activate_assign(args: argparse.Namespace) -> int:
    result = record_activation_assignment(
        args.workspace,
        kind=args.kind,
        subject_id=args.subject_id,
        assignee=args.assignee,
        due_date=args.due_date,
    )
    workspace = load_activation_workspace(result)
    print(
        f"Assigned {args.kind} subject {args.subject_id} to {args.assignee}; "
        f"workspace assignments={len(workspace.get('assignments', []))}."
    )
    print(f"Updated activation workspace: {result}")
    return 0


def _activate_batch_export(args: argparse.Namespace) -> int:
    workspace_path = Path(args.workspace).expanduser().resolve()
    output = (
        Path(args.output)
        if args.output
        else workspace_path.with_name(workspace_path.stem + "-records.json")
    )
    output = output.expanduser().absolute()
    if output == workspace_path:
        raise ValueError(
            "activation records destination must differ from the workspace"
        )
    result = export_activation_records_template(
        load_activation_workspace(workspace_path), output
    )
    print(f"Exported workspace-bound activation records template: {result}")
    return 0


def _activate_batch_import(args: argparse.Namespace) -> int:
    workspace_path = Path(args.workspace).expanduser().absolute()
    records_path = Path(args.records).expanduser().absolute()
    output = (
        Path(args.output)
        if args.output
        else workspace_path.with_name(workspace_path.stem + "-import-receipt.json")
    )
    output = output.expanduser().absolute()
    if output in {workspace_path, records_path}:
        raise ValueError(
            "activation import receipt must differ from the workspace and records input"
        )
    workspace, receipt = import_activation_records(workspace_path, records_path)
    result = export_json_document(receipt, output)
    print(
        f"Imported activation records: assignments={receipt['assignments_imported']}, "
        f"decisions={receipt['decisions_imported']}."
    )
    print(f"Updated activation workspace: {workspace}")
    print(f"Import receipt: {result}")
    return 0


def _activate_apply(args: argparse.Namespace) -> int:
    source = Path(args.analysis).expanduser().resolve()
    output = (
        source
        if args.in_place
        else Path(args.output)
        if args.output
        else source.with_name(source.stem + "-activated.json")
    )
    output = output.expanduser().absolute()
    workspace_path = Path(args.workspace).expanduser().absolute()
    if output == workspace_path:
        raise ValueError("updated analysis destination must differ from the workspace")
    receipt_path = (
        Path(args.receipt)
        if args.receipt
        else output.with_name(
            output.name.removesuffix(".gz").removesuffix(".json")
            + "-activation-receipt.json"
        )
    )
    receipt_path = receipt_path.expanduser().absolute()
    if receipt_path in {output, workspace_path, source}:
        raise ValueError(
            "activation receipt destination must differ from the analysis and workspace"
        )
    updated, receipt = apply_activation_workspace(
        load_analysis(source), load_activation_workspace(args.workspace)
    )
    save_analysis(output, updated)
    # Saving refreshes derived state and timestamps, so bind the receipt to the
    # actual published artifact instead of the private pre-save representation.
    published = load_analysis(output)
    receipt["result_analysis_state_sha256"] = canonical_json_sha256(published)
    receipt.pop("content_sha256", None)
    receipt["content_sha256"] = canonical_json_sha256(receipt)
    export_json_document(receipt, receipt_path)
    print(f"Applied governed activation decisions: {output}")
    print(
        f"Finding reviews={receipt['finding_reviews_applied']}; "
        f"canonical groups={receipt['finding_consolidations_applied']}; "
        f"governance decisions={receipt['governance_decisions_recorded']}."
    )
    print(f"Activation receipt: {receipt_path}")
    return 0


def _config_authoring_init(args: argparse.Namespace) -> int:
    analysis_path = Path(args.analysis).expanduser().resolve()
    config_path = Path(args.config).expanduser().resolve()
    output = (
        (
            Path(args.output)
            if args.output
            else analysis_path.with_name(
                analysis_path.stem + "-configuration-draft.json"
            )
        )
        .expanduser()
        .absolute()
    )
    if output in {analysis_path, config_path}:
        raise ValueError("configuration authoring draft must differ from its inputs")
    result = export_configuration_authoring_draft(
        load_analysis(analysis_path), config_path, output
    )
    print(f"Created editable configuration authoring draft: {result}")
    print(
        "Complete selected proposals, set action=apply, and record an approved named "
        "review before sealing. Deferred entries remain unchanged."
    )
    return 0


def _config_authoring_seal(args: argparse.Namespace) -> int:
    analysis_path = Path(args.analysis).expanduser().resolve()
    config_path = Path(args.config).expanduser().resolve()
    draft_path = Path(args.draft).expanduser().resolve()
    output = (
        (
            Path(args.output)
            if args.output
            else draft_path.with_name(
                draft_path.stem.removesuffix("-draft") + "-sealed.json"
            )
        )
        .expanduser()
        .absolute()
    )
    if output in {analysis_path, config_path, draft_path}:
        raise ValueError(
            "sealed configuration authoring output must differ from its inputs"
        )
    result = seal_configuration_authoring_draft(
        draft_path, load_analysis(analysis_path), config_path, output
    )
    print(f"Published sealed configuration authoring input: {result}")
    print(
        f'Next: sfmea config-authoring-verify "{result}" --analysis '
        f'"{analysis_path}" --config "{config_path}"'
    )
    return 0


def _config_authoring_verify(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis) if args.analysis else None
    result = verify_configuration_authoring_file(
        args.sealed,
        analysis=analysis,
        config_source=args.config,
    )
    if args.output:
        output = export_json_document(result, args.output)
        print(f"Exported configuration authoring verification: {output}")
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    return int(not result["valid"])


def _config_authoring_apply(args: argparse.Namespace) -> int:
    analysis_path = Path(args.analysis).expanduser().resolve()
    sealed_path = Path(args.sealed).expanduser().resolve()
    config_path = Path(args.config).expanduser().resolve()
    output = (
        (
            Path(args.output)
            if args.output
            else config_path.with_name(config_path.stem + "-refined.toml")
        )
        .expanduser()
        .absolute()
    )
    receipt_path = (
        (
            Path(args.receipt)
            if args.receipt
            else output.with_name(output.stem + "-configuration-authoring-receipt.json")
        )
        .expanduser()
        .absolute()
    )
    if output in {analysis_path, sealed_path, config_path}:
        raise ValueError(
            "updated configuration destination must differ from every input"
        )
    if receipt_path in {analysis_path, sealed_path, config_path, output}:
        raise ValueError(
            "configuration authoring receipt must differ from inputs and output"
        )
    published, receipt = apply_configuration_authoring(
        load_analysis(analysis_path),
        load_configuration_authoring(sealed_path),
        config_path,
        output,
    )
    export_json_document(receipt, receipt_path)
    print(f"Published reviewed SFMEA configuration: {published}")
    print(
        f"Guidance mappings={receipt['guidance_mappings']}; component mappings="
        f"{receipt['component_mappings']}; interface dispositions="
        f"{receipt['interface_dispositions']}."
    )
    print(f"Configuration authoring receipt: {receipt_path}")
    print(f'Next: sfmea scan REPOSITORY --config "{published}"')
    return 0


def _sfta_authoring_init(args: argparse.Namespace) -> int:
    source = Path(args.analysis).expanduser().resolve()
    output = (
        Path(args.output)
        if args.output
        else source.with_name(source.stem + "-sfta-authoring-draft.json")
    )
    result = export_sfta_authoring_draft(load_analysis(source), output)
    print(f"Created editable SFTA authoring draft: {result}")
    print(
        "Edit each intended replacement, set action=replace, and record an approved "
        "named review before sealing."
    )
    return 0


def _sfta_authoring_seal(args: argparse.Namespace) -> int:
    source = Path(args.analysis).expanduser().resolve()
    draft = Path(args.draft).expanduser().resolve()
    output = (
        Path(args.output)
        if args.output
        else draft.with_name(draft.stem.removesuffix("-draft") + "-sealed.json")
    )
    if output.expanduser().absolute() in {source, draft}:
        raise ValueError("sealed SFTA destination must differ from analysis and draft")
    result = seal_sfta_authoring_draft(draft, load_analysis(source), output)
    print(f"Published sealed SFTA authoring input: {result}")
    print(f'Next: sfmea sfta-authoring-verify "{result}" --analysis "{source}"')
    return 0


def _sfta_authoring_verify(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis) if args.analysis else None
    result = verify_sfta_authoring_file(args.sealed, analysis=analysis)
    if args.output:
        output = export_json_document(result, args.output)
        print(f"Exported SFTA authoring verification: {output}")
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    return int(not result["valid"])


def _sfta_authoring_apply(args: argparse.Namespace) -> int:
    source = Path(args.analysis).expanduser().resolve()
    sealed_path = Path(args.sealed).expanduser().resolve()
    output = (
        (
            source
            if args.in_place
            else Path(args.output)
            if args.output
            else source.with_name(source.stem + "-sfta-authored.json")
        )
        .expanduser()
        .absolute()
    )
    if output == sealed_path:
        raise ValueError(
            "updated analysis destination must differ from sealed SFTA input"
        )
    receipt_path = (
        (
            Path(args.receipt)
            if args.receipt
            else output.with_name(
                output.name.removesuffix(".gz").removesuffix(".json")
                + "-sfta-authoring-receipt.json"
            )
        )
        .expanduser()
        .absolute()
    )
    if receipt_path in {source, sealed_path, output}:
        raise ValueError(
            "SFTA authoring receipt must differ from analysis and sealed input"
        )
    updated, receipt = apply_sfta_authoring(
        load_analysis(source), load_sfta_authoring(sealed_path)
    )
    save_analysis(output, updated)
    published = load_analysis(output)
    receipt["result_analysis_state_sha256"] = canonical_json_sha256(published)
    receipt.pop("content_sha256", None)
    receipt["content_sha256"] = canonical_json_sha256(receipt)
    export_json_document(receipt, receipt_path)
    print(
        f"Applied {len(receipt['replacement_hazards'])} approved SFTA replacement(s): {output}"
    )
    print(f"SFTA authoring receipt: {receipt_path}")
    return 0


def _status(args: argparse.Namespace) -> int:
    result = workflow_status(
        args.repository,
        config_path=args.config,
        analysis_path=args.analysis,
        assurance_scaffold_path=args.assurance_scaffold,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return int(args.require_handoff_ready and not result["ready_for_handoff"])
    readiness = result["readiness"]
    analysis = result["analysis"]
    print(f"Workflow stage: {result['stage'].replace('_', ' ')}")
    print(f"Repository: {result['repository']}")
    print(f"Configuration: {result['paths']['configuration']}")
    print(
        "Readiness: "
        f"errors={readiness['counts']['error']}, "
        f"warnings={readiness['counts']['warning']}, "
        f"ready={'yes' if readiness['ready'] else 'no'}"
    )
    if analysis["exists"]:
        counts = analysis["counts"]
        validation = counts.get("validation", {})
        print(
            f"Analysis: {result['paths']['analysis']} "
            f"(baseline {analysis['baseline_id'] or 'not recorded'})"
        )
        print(
            "Review: "
            f"active={counts.get('active_findings', 0)}, "
            f"unreviewed={counts.get('unreviewed', 0)}, "
            f"accepted={counts.get('accepted', 0)}, "
            f"revalidation={counts.get('revalidation_required', 0)}, "
            f"complete={counts.get('review_percent', 0)}%"
        )
        print(
            "Validation: "
            f"errors={validation.get('error', 0)}, "
            f"warnings={validation.get('warning', 0)}, "
            f"information={validation.get('information', 0)}"
        )
        assurance = counts.get("assurance", {})
        planning_percent = assurance.get("planning_percent")
        planning_label = (
            f"{planning_percent}%" if planning_percent is not None else "n/a"
        )
        print(
            "Assurance: "
            f"obligations={assurance.get('active_obligations', 0)}, "
            f"applicable={assurance.get('applicable_findings', 0)}, "
            f"plan={planning_label}, "
            f"implemented={assurance.get('implemented_tests', 0)}, "
            f"executions={assurance.get('recorded_executions', 0)}, "
            f"verified={assurance.get('verified_obligations', 0)}"
        )

        def print_artifact(name: str, artifact: dict[str, Any]) -> None:
            integrity = artifact.get("integrity")
            integrity_text = (
                f", integrity={'valid' if integrity['valid'] else 'invalid'}, "
                f"checked={integrity['checked_files']}"
                if integrity
                else ""
            )
            schema_catalog = integrity.get("schema_catalog", {}) if integrity else {}
            schema_text = (
                f", schemas={'valid' if schema_catalog.get('valid') else 'invalid'}"
                f"({schema_catalog.get('schema_count', 0)})"
                if schema_catalog.get("present")
                else ", schemas=legacy/not embedded"
                if integrity and "schema_catalog" in integrity
                else ""
            )
            binding = artifact.get("binding")
            binding_text = f", binding={binding['status']}" if binding else ""
            generated_changes = artifact.get("generated_files_changed")
            generated_text = (
                f", generated changes={generated_changes}"
                if generated_changes is not None
                else ""
            )
            contract_summary = artifact.get("contract_change_summary")
            contract_changes = (
                sum(
                    int(contract_summary.get(key, 0))
                    for key in ("added", "removed", "changed")
                )
                if contract_summary
                else None
            )
            contract_text = (
                f", contract changes={contract_changes}"
                if contract_changes is not None
                else ""
            )
            queue = artifact.get("queue", {})
            queue_text = (
                f", queue={queue.get('id', 'unknown')}, "
                f"owner={queue.get('owner') or 'unassigned'}"
                if queue
                else ""
            )
            current_selection = artifact.get("current_selection")
            lifecycle = str(artifact.get("lifecycle", "")).replace("_", " ")
            selection_text = (
                f", selected now={current_selection.get('obligation_count', 0)}, "
                f"lifecycle={lifecycle}"
                if current_selection and lifecycle
                else ""
            )
            print(
                f"  - {name}: {artifact['status']}"
                f"{integrity_text}{schema_text}{binding_text}{generated_text}{contract_text}"
                f"{queue_text}{selection_text} "
                f"({artifact['path']})"
            )

        if result["artifacts"]:
            print("Artifacts:")
            for name, artifact in result["artifacts"].items():
                print_artifact(name.replace("_", " "), artifact)
            for index, artifact in enumerate(
                result.get("assurance_scaffolds", [])[1:], start=2
            ):
                print_artifact(f"assurance scaffold {index}", artifact)
        portfolio = result.get("assurance_scaffold_portfolio", {})
        if portfolio:
            coverage = portfolio.get("coverage_percent")
            coverage_text = f"{coverage}%" if coverage is not None else "n/a"
            print(
                "Assurance queue portfolio: "
                f"queues={portfolio['queue_count']}, "
                f"current={portfolio['current_queues']}, "
                f"accepted coverage={coverage_text}, "
                f"uncovered={portfolio['uncovered_accepted_obligations']}, "
                f"overlaps={portfolio['duplicate_assignment_count']}, "
                f"unowned={portfolio['unowned_current_queues']}, "
                f"duplicate queue IDs={portfolio['duplicate_queue_id_count']}"
            )
            for duplicate in portfolio["duplicate_assignments"][:10]:
                print(
                    f"  - overlap {duplicate['obligation_id']}: "
                    + ", ".join(duplicate["scaffold_paths"])
                )
            if len(portfolio["duplicate_assignments"]) > 10:
                print(
                    f"  ... {len(portfolio['duplicate_assignments']) - 10} additional "
                    "overlap(s) omitted; use --json for the complete portfolio."
                )
            for duplicate in portfolio["duplicate_queue_ids"][:10]:
                print(
                    f"  - duplicate queue ID {duplicate['queue_id']}: "
                    + ", ".join(duplicate["scaffold_paths"])
                )
    else:
        print(f"Analysis: not found ({result['paths']['analysis']})")
    gate_summary = result["handoff_gate_summary"]
    print(
        "Handoff gates: "
        f"passed={gate_summary['passed']}/{gate_summary['total']}, "
        f"blocked={gate_summary['blocked']}"
    )
    for gate in result["handoff_gates"]:
        remediation = (
            f"; action={gate['remediation_action_id']}" if not gate["passed"] else ""
        )
        print(
            f"  [{gate['status'].upper()}] {gate['label']}: "
            f"{gate['detail']}{remediation}"
        )
    if result["next_actions"]:
        print("Next actions:")
        for index, action in enumerate(result["next_actions"], start=1):
            print(f"  {index}. {action['command']}")
            print(f"     {action['reason']}")
    else:
        print(
            "Next actions: none; handoff artifacts are current and gates are satisfied."
        )
    print(result["notice"])
    return int(args.require_handoff_ready and not result["ready_for_handoff"])


def _review(args: argparse.Namespace) -> int:
    if not 0 <= args.port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    serve_review(args.analysis, port=args.port, open_browser=not args.no_browser)
    return 0


def _export(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    source = Path(args.analysis).expanduser().resolve()
    if args.output:
        output = Path(args.output)
    else:
        suffix = ".csv" if args.format == "csv" else ".md"
        output = source.with_name(source.stem + suffix)
    if args.format == "csv":
        result = export_csv(analysis, output)
    else:
        result = export_markdown(analysis, output)
    print(f"Exported {args.format}: {result}")
    return 0


def _html_report(args: argparse.Namespace) -> int:
    source = Path(args.analysis).expanduser().resolve()
    output_candidate = (
        Path(args.output)
        if args.output
        else source.with_name(source.stem + "-report.html")
    )
    output = output_candidate.expanduser().absolute()
    destination_existed = lexists(output)
    destination_error = ""
    if output.is_symlink():
        destination_error = "HTML report destination must not be a symbolic link"
    elif destination_existed and not output.is_file():
        destination_error = (
            "HTML report destination must be absent or an existing regular file"
        )
    elif output.resolve() == source:
        destination_error = "HTML report destination must differ from the analysis file"
    if destination_error:
        error = ValueError(destination_error)
        if not args.json:
            raise error
        verification = _verification_error_result(
            format_name=HTML_REPORT_VERIFICATION_FORMAT,
            source=str(output),
            check_names=HTML_REPORT_VERIFICATION_CHECKS,
            binding_requested=True,
            code="report.invalid_destination",
            error=error,
        )
        _html_report_publication_receipt(
            verification,
            status="not_published",
            phase="input_validation",
            destination_existed=destination_existed,
        )
        print(json.dumps(verification, indent=2, ensure_ascii=False))
        return 2
    try:
        analysis = load_analysis(source)
    except VERIFICATION_EXCEPTIONS:
        if not args.json:
            raise
        verification = _verification_error_result(
            format_name=HTML_REPORT_VERIFICATION_FORMAT,
            source=str(output),
            check_names=HTML_REPORT_VERIFICATION_CHECKS,
            binding_requested=True,
            code="report.analysis_load_failed",
            error=ValueError("Analysis could not be loaded; no report was published."),
        )
        _html_report_publication_receipt(
            verification,
            status="not_published",
            phase="analysis_load",
            destination_existed=destination_existed,
        )
        print(json.dumps(verification, indent=2, ensure_ascii=False))
        return 2

    if args.json:
        staged = output.with_name(f".{output.name}.{uuid.uuid4().hex}.verified.tmp")
        try:
            try:
                result = export_html_report(
                    analysis,
                    staged,
                    title=args.title,
                    notes=args.notes,
                    max_records=args.max_records,
                    profile=args.profile,
                    diagrams=args.diagram,
                    propagation_record_limit=args.propagation_record_limit,
                    propagation_path_limit=args.propagation_path_limit,
                    propagation_depth=args.propagation_depth,
                    propagation_include_finding_ids=(args.propagation_include_finding),
                    max_output_bytes=args.max_output_bytes,
                )
            except VERIFICATION_EXCEPTIONS:
                verification = _verification_error_result(
                    format_name=HTML_REPORT_VERIFICATION_FORMAT,
                    source=str(output),
                    check_names=HTML_REPORT_VERIFICATION_CHECKS,
                    binding_requested=True,
                    code="report.generation_failed",
                    error=ValueError(
                        "HTML report generation did not complete; "
                        "no report was published."
                    ),
                )
                _html_report_publication_receipt(
                    verification,
                    status="not_published",
                    phase="generation",
                    destination_existed=destination_existed,
                )
                print(json.dumps(verification, indent=2, ensure_ascii=False))
                return 1
            try:
                verification = verify_html_report_file(result, analysis=analysis)
            except VERIFICATION_EXCEPTIONS:
                verification = _verification_error_result(
                    format_name=HTML_REPORT_VERIFICATION_FORMAT,
                    source=str(output),
                    check_names=HTML_REPORT_VERIFICATION_CHECKS,
                    binding_requested=True,
                    code="report.post_generation_verification_failed",
                    error=ValueError(
                        "Generated report verification did not complete; "
                        "no report was published."
                    ),
                )
                _html_report_publication_receipt(
                    verification,
                    status="not_published",
                    phase="verification",
                    destination_existed=destination_existed,
                )
                print(json.dumps(verification, indent=2, ensure_ascii=False))
                return 1
            verification["path"] = str(output)
            if not verification["valid"]:
                _html_report_publication_receipt(
                    verification,
                    status="not_published",
                    phase="verification",
                    destination_existed=destination_existed,
                )
                print(json.dumps(verification, indent=2, ensure_ascii=False))
                return 1
            try:
                atomic_replace(result, output)
            except VERIFICATION_EXCEPTIONS:
                verification = _verification_error_result(
                    format_name=HTML_REPORT_VERIFICATION_FORMAT,
                    source=str(output),
                    check_names=HTML_REPORT_VERIFICATION_CHECKS,
                    binding_requested=True,
                    code="report.publication_failed",
                    error=ValueError(
                        "Verified report publication did not complete; "
                        "the prior destination was preserved."
                    ),
                )
                _html_report_publication_receipt(
                    verification,
                    status="not_published",
                    phase="publication",
                    destination_existed=destination_existed,
                )
                print(json.dumps(verification, indent=2, ensure_ascii=False))
                return 1
            _html_report_publication_receipt(
                verification,
                status="published",
                phase="complete",
                destination_existed=destination_existed,
            )
            print(json.dumps(verification, indent=2, ensure_ascii=False))
            return 0
        finally:
            staged.unlink(missing_ok=True)

    result = export_html_report(
        analysis,
        output,
        title=args.title,
        notes=args.notes,
        max_records=args.max_records,
        profile=args.profile,
        diagrams=args.diagram,
        propagation_record_limit=args.propagation_record_limit,
        propagation_path_limit=args.propagation_path_limit,
        propagation_depth=args.propagation_depth,
        propagation_include_finding_ids=args.propagation_include_finding,
        max_output_bytes=args.max_output_bytes,
    )
    size_mib = result.stat().st_size / (1024 * 1024)
    profile_limit = {
        "engineering": args.max_records,
        "compact": 500,
        "management": 250,
    }[args.profile]
    embedded_records = min(
        len(analysis.get("items", [])), args.max_records, profile_limit
    )
    print(
        f"Created self-contained SFMEA report: {result} "
        f"({embedded_records:,} records; {size_mib:.1f} MiB); profile={args.profile}; propagation "
        f"records={args.propagation_record_limit}, "
        f"paths/component={args.propagation_path_limit}, "
        f"depth={args.propagation_depth}, "
        f"included_findings={len(dict.fromkeys(args.propagation_include_finding))}"
    )
    if len(analysis.get("items", [])) > args.max_records:
        print(
            f"Report record set was bounded to {args.max_records}; "
            "increase --max-records to include more records."
        )
    return 0


def _html_report_verify(args: argparse.Namespace) -> int:
    try:
        analysis = load_analysis(args.analysis) if args.analysis else None
    except VERIFICATION_EXCEPTIONS as exc:
        if not args.json:
            raise
        verification = _verification_error_result(
            format_name=HTML_REPORT_VERIFICATION_FORMAT,
            source=args.report,
            check_names=HTML_REPORT_VERIFICATION_CHECKS,
            binding_requested=bool(args.analysis),
            code="analysis.load_failed",
            error=exc,
        )
        print(json.dumps(verification, indent=2, ensure_ascii=False))
        return 2
    try:
        verification = verify_html_report_file(args.report, analysis=analysis)
    except VERIFICATION_EXCEPTIONS as exc:
        verification = _verification_error_result(
            format_name=HTML_REPORT_VERIFICATION_FORMAT,
            source=args.report,
            check_names=HTML_REPORT_VERIFICATION_CHECKS,
            binding_requested=bool(args.analysis),
            code="report.verification_failed",
            error=exc,
        )
        if args.json:
            print(json.dumps(verification, indent=2, ensure_ascii=False))
        else:
            print("HTML report integrity: valid=False, analysis binding=not completed")
            print(f"Error: {exc}")
            print(verification["notice"])
        return 1
    if args.json:
        print(json.dumps(verification, indent=2, ensure_ascii=False))
        return int(not verification["valid"])
    binding_status = (
        "matched"
        if verification["checks"]["analysis_state"] is True
        else "mismatched"
        if verification["checks"]["analysis_state"] is False
        else "not checked"
    )
    print(
        f"HTML report integrity: valid={verification['valid']}, "
        f"scope={verification['integrity_scope']}, "
        f"analysis binding={binding_status}"
    )
    print(f"Report data SHA-256: {verification['declared']['report_data_sha256']}")
    if verification["declared"]["document_sha256"]:
        print(f"Document SHA-256: {verification['declared']['document_sha256']}")
    if verification["failed_checks"]:
        print(f"Failed checks: {', '.join(verification['failed_checks'])}")
    if verification["unchecked_checks"]:
        print(f"Unchecked checks: {', '.join(verification['unchecked_checks'])}")
    print(verification["notice"])
    return int(not verification["valid"])


def _report_browser_verify(args: argparse.Namespace) -> int:
    verification = verify_browser_quality_receipt_file(
        args.receipt, report=args.report
    )
    if args.output:
        output = export_json_document(verification, args.output)
        print(f"Exported browser-quality verification: {output}")
    else:
        print(json.dumps(verification, indent=2, ensure_ascii=False))
    return int(not verification["quality_passed"])


def _accessibility_init(args: argparse.Namespace) -> int:
    report = Path(args.report).expanduser().resolve()
    output = (
        Path(args.output)
        if args.output
        else report.with_name(report.stem + "-accessibility.json")
    )
    result = export_accessibility_evidence(report, output)
    print(f"Created report-bound accessibility qualification checklist: {result}")
    print(
        "Complete every applicable keyboard, zoom, display-preference, and "
        "screen-reader scenario; then run `sfmea accessibility-seal`."
    )
    return 0


def _accessibility_seal(args: argparse.Namespace) -> int:
    result = seal_accessibility_evidence(args.evidence)
    print(f"Sealed accessibility evidence: {result}")
    return 0


def _accessibility_verify(args: argparse.Namespace) -> int:
    result = verify_accessibility_evidence_file(args.evidence, report=args.report)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Accessibility evidence valid={result['valid']}; "
            f"qualified={result['qualified']}"
        )
        for identifier, status in result["scenario_statuses"].items():
            print(f"- {identifier}: {status}")
        for error in result["errors"]:
            print(f"- error: {error}")
        print(result["notice"])
    return int(not result["qualified"])


def _pdf_report(args: argparse.Namespace) -> int:
    source = Path(args.analysis).expanduser().resolve()
    analysis = load_analysis(source)
    output = (
        Path(args.output)
        if args.output
        else source.with_name(source.stem + "-report.pdf")
    )
    result = export_pdf_report(
        analysis,
        output,
        title=args.title,
        notes=args.notes,
        max_records=args.max_records,
        diagrams=args.diagram,
        propagation_record_limit=args.propagation_record_limit,
        propagation_path_limit=args.propagation_path_limit,
        propagation_depth=args.propagation_depth,
        propagation_include_finding_ids=args.propagation_include_finding,
        browser=args.browser,
        timeout_seconds=args.timeout_seconds,
    )
    print(f"Created paginated SFMEA PDF report: {result}")
    return 0


def _diagram(args: argparse.Namespace) -> int:
    source = Path(args.analysis).expanduser().resolve()
    analysis = load_analysis(source)
    output = (
        Path(args.output)
        if args.output
        else source.with_name(source.stem + f"-{args.type}-diagrams.json")
    )
    result = export_diagram_bundle(
        analysis,
        output,
        kind=args.type,
        propagation_record_limit=args.propagation_record_limit,
        propagation_path_limit=args.propagation_path_limit,
        propagation_depth=args.propagation_depth,
        propagation_include_finding_ids=args.propagation_include_finding,
    )
    print(f"Exported canonical SFMEA diagrams: {result}")
    bundle = json.loads(result.read_text(encoding="utf-8"))
    verification = verify_diagram_bundle_integrity(bundle, analysis=analysis)
    print(
        "Verified diagram artifact: "
        f"analysis-state={verification['analysis_state_sha256'][:12]}..., "
        f"content={verification['content_sha256'][:12]}..."
    )
    return 0


def _diagram_verify(args: argparse.Namespace) -> int:
    try:
        analysis = load_analysis(args.analysis) if args.analysis else None
    except VERIFICATION_EXCEPTIONS as exc:
        if not args.json:
            raise
        verification = _verification_error_result(
            format_name=DIAGRAM_BUNDLE_VERIFICATION_FORMAT,
            source=args.bundle,
            check_names=DIAGRAM_BUNDLE_VERIFICATION_CHECKS,
            binding_requested=bool(args.analysis),
            code="analysis.load_failed",
            error=exc,
        )
        print(json.dumps(verification, indent=2, ensure_ascii=False))
        return 2
    try:
        verification = verify_diagram_bundle_file(args.bundle, analysis=analysis)
    except VERIFICATION_EXCEPTIONS as exc:
        verification = _verification_error_result(
            format_name=DIAGRAM_BUNDLE_VERIFICATION_FORMAT,
            source=args.bundle,
            check_names=DIAGRAM_BUNDLE_VERIFICATION_CHECKS,
            binding_requested=bool(args.analysis),
            code="diagram.verification_failed",
            error=exc,
        )
        if args.json:
            print(json.dumps(verification, indent=2, ensure_ascii=False))
        else:
            print(
                "Diagram bundle integrity: valid=False, analysis binding=not completed"
            )
            print(f"Error: {exc}")
            print(verification["notice"])
        return 1
    if args.json:
        print(json.dumps(verification, indent=2, ensure_ascii=False))
        return 0
    binding = verification["checks"]["analysis_binding"]
    binding_status = "matched" if binding is True else "not checked"
    print(f"Diagram bundle integrity: valid=True, analysis binding={binding_status}")
    print(f"Verified canonical diagram bundle: {verification['path']}")
    print(
        f"Diagrams: {verification['diagram_count']}; analysis binding: {binding_status}"
    )
    print(f"Content SHA-256: {verification['content_sha256']}")
    print(
        "Bound analysis-state SHA-256: "
        f"{verification['binding']['analysis_state_sha256']}"
    )
    if verification["unchecked_checks"]:
        print(f"Unchecked checks: {', '.join(verification['unchecked_checks'])}")
    print(verification["notice"])
    return 0


def _sfta(args: argparse.Namespace) -> int:
    source = Path(args.analysis).expanduser().resolve()
    analysis = load_analysis(source)
    suffix = ".json" if args.format == "json" else ".csv"
    output = (
        Path(args.output)
        if args.output
        else source.with_name(source.stem + "-sfta" + suffix)
    )
    result = export_sfta(analysis, output, format=args.format)
    print(f"Exported Software Fault Trees and reconciliation gaps: {result}")
    return 0


def _sarif(args: argparse.Namespace) -> int:
    source = Path(args.analysis).expanduser().resolve()
    analysis = load_analysis(source)
    output = Path(args.output) if args.output else source.with_suffix(".sarif")
    result = export_json_document(sarif_document(analysis), output)
    print(f"Exported SARIF screening results: {result}")
    return 0


def _sbom(args: argparse.Namespace) -> int:
    source = Path(args.analysis).expanduser().resolve()
    analysis = load_analysis(source)
    output = (
        Path(args.output)
        if args.output
        else source.with_name(source.stem + "-cdx.json")
    )
    result = export_json_document(cyclonedx_document(analysis), output)
    print(f"Exported CycloneDX declared-dependency inventory: {result}")
    return 0


def _diff(args: argparse.Namespace) -> int:
    previous_path = Path(args.previous).expanduser().resolve()
    current_path = Path(args.current).expanduser().resolve()
    previous = load_analysis(previous_path)
    current = load_analysis(current_path)
    output = (
        Path(args.output)
        if args.output
        else current_path.with_name(current_path.stem + "-diff.json")
    )
    result = export_json_document(differential_analysis(previous, current), output)
    print(f"Exported differential analysis: {result}")
    return 0


def _package(args: argparse.Namespace) -> int:
    source = Path(args.analysis).expanduser().resolve()
    output_has_zip_suffix = bool(
        args.output and Path(args.output).suffix.lower() == ".zip"
    )
    archive_requested = args.zip or output_has_zip_suffix
    default_name = (
        source.stem + "-review-package" + (".zip" if archive_requested else "")
    )
    output = Path(args.output) if args.output else source.with_name(default_name)
    try:
        analysis = load_analysis(source)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        if not args.json:
            raise
        failure = package_publication_error_result(
            output,
            exc,
            archive=archive_requested,
            phase="analysis_load",
        )
        print(json.dumps(failure, indent=2, ensure_ascii=False))
        return 2
    try:
        if archive_requested:
            result = export_review_archive(
                analysis,
                output,
                source_analysis=source,
                overwrite=args.force,
                portable=args.portable,
            )
            if not args.json:
                print(f"Created SFMEA review archive: {result}")
        else:
            result = export_review_package(
                analysis,
                output,
                source_analysis=source,
                overwrite=args.force,
                portable=args.portable,
            )
            if not args.json:
                print(f"Created SFMEA review package: {result}")
                print(f"Manifest: {result / 'manifest.json'}")
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        if not args.json:
            raise
        failure = package_publication_error_result(
            output,
            exc,
            archive=archive_requested,
            phase="generation",
        )
        print(json.dumps(failure, indent=2, ensure_ascii=False))
        return 2
    if args.json:
        verification = verify_review_package(result)
        verification["publication"] = {
            "status": "published",
            "phase": (
                "complete" if verification["valid"] else "post_publication_verification"
            ),
        }
        print(json.dumps(verification, indent=2, ensure_ascii=False))
        return 0 if verification["valid"] else 1
    print(f'Next: sfmea verify-package "{result}"')
    return 0


def _verify_package(args: argparse.Namespace) -> int:
    if bool(args.signature) != bool(args.public_key):
        raise ValueError("--signature and --public-key must be supplied together")
    if args.signature:
        result = verify_review_signature(
            args.package,
            args.signature,
            args.public_key,
        )
    else:
        result = verify_review_package(args.package)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Package integrity: valid={result['valid']}, container={result['container']}, "
            f"checked={result['checked_files']}, errors={result['counts']['error']}, "
            f"warnings={result['counts']['warning']}"
        )
        if result.get("archive_sha256"):
            print(f"Archive SHA-256: {result['archive_sha256']}")
        if result.get("capabilities"):
            print(f"Capabilities: {', '.join(result['capabilities'])}")
        if result.get("schema_catalog"):
            schema_catalog = result["schema_catalog"]
            print(
                f"Schema catalog: valid={schema_catalog['valid']}, "
                f"schemas={schema_catalog['schema_count']}"
            )
        if result.get("analysis_structure"):
            structure = result["analysis_structure"]
            print(
                "Analysis structure: "
                f"valid={structure['valid']}, nodes={structure['node_count']}, "
                f"depth={structure['max_depth']}, "
                f"limits={structure['limits']['max_nodes']} nodes/"
                f"{structure['limits']['max_depth']} levels"
            )
        if result.get("analysis_diagnostics"):
            diagnostics = result["analysis_diagnostics"]
            print(
                "Analysis diagnostics: "
                f"valid={diagnostics['valid']}, "
                f"artifacts={diagnostics['artifact_count']}"
            )
        if result.get("guidance_traceability"):
            guidance = result["guidance_traceability"]
            print(
                "Guidance traceability: "
                f"valid={guidance['valid']}, "
                f"citations={guidance['citation_count']}, "
                f"finding-links={guidance['finding_link_count']}"
            )
        if result.get("sfta_projection"):
            sfta = result["sfta_projection"]
            print(
                "SFTA projection: "
                f"valid={sfta['valid']}, trees={sfta['tree_count']}, "
                f"gaps={sfta['gap_count']}"
            )
        if result.get("evidence_catalog"):
            evidence = result["evidence_catalog"]
            print(
                "Evidence catalog: "
                f"valid={evidence['valid']}, "
                f"executions={evidence['execution_count']}, "
                f"artifacts={evidence['evidence_artifact_count']}"
            )
        if result.get("interchange_artifacts"):
            interchange = result["interchange_artifacts"]
            print(
                "Interchange artifacts: "
                f"valid={interchange['valid']}, "
                f"SARIF-results={interchange['sarif_result_count']}, "
                "CycloneDX-components="
                f"{interchange['cyclonedx_component_count']}"
            )
        if result.get("review_views"):
            review_views = result["review_views"]
            print(
                "Review views: "
                f"valid={review_views['valid']}, "
                f"artifacts={review_views['artifact_count']}, "
                f"findings={review_views['finding_count']}, "
                f"components={review_views['component_count']}"
            )
        if result.get("package_provenance"):
            provenance = result["package_provenance"]
            print(
                "Package provenance: "
                f"valid={provenance['valid']}, "
                f"review-decisions={provenance['review_decision_count']}, "
                f"executions={provenance['execution_count']}"
            )
        if result.get("assurance_work_queue"):
            work_queue = result["assurance_work_queue"]
            print(
                "Assurance work queue: "
                f"valid={work_queue['valid']}, status={work_queue['status']}"
            )
        if result.get("assurance_register"):
            assurance_register = result["assurance_register"]
            print(
                "Assurance register: "
                f"valid={assurance_register['valid']}, "
                f"obligations={assurance_register['obligation_count']}"
            )
        if result.get("signature"):
            signature = result["signature"]
            print(
                f"Signature: valid={signature['valid']}, signer={signature['signer'] or '<unknown>'}, "
                f"key={signature['key_fingerprint'] or '<unknown>'}"
            )
        for finding in result["findings"]:
            location = f" ({finding['path']})" if finding.get("path") else ""
            print(
                f"[{finding['level'].upper()}] {finding['rule_id']}{location}: "
                f"{finding['message']}"
            )
        print(result["notice"])
    return int(not result["valid"])


def _sign_package(args: argparse.Namespace) -> int:
    result = sign_review_package(
        args.package,
        args.private_key,
        args.signer,
        destination=args.output,
        passphrase=passphrase_from_environment(args.passphrase_env),
        overwrite=args.force,
    )
    print(f"Created detached Ed25519 signature: {result}")
    print(
        f'Next: sfmea verify-package "{args.package}" '
        f'--signature "{result}" --public-key PUBLIC_KEY.pem'
    )
    return 0


def _summary(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    summary: dict[str, Any] = dict(analysis.get("summary", {}))
    repository = repository_inventory_summary_projection(
        analysis.get("repository_inventory", {})
    )
    repository_summary = repository["summary"]
    summary["repository_artifacts"] = repository_summary.get("files")
    summary["opaque_or_unresolved_artifacts"] = repository_summary.get(
        "opaque_or_unresolved"
    )
    summary["repository_inventory"] = repository
    if args.json:
        print(json.dumps(summary, indent=2))
        return 0
    print(f"Project: {analysis.get('project', {}).get('name', '')}")
    print(f"Components: {summary.get('components', 0)}")
    print(f"Active candidates: {summary.get('candidate_failure_modes', 0)}")
    print(f"Removed candidates retained: {summary.get('removed_candidates', 0)}")
    dispositions = summary.get("review_dispositions", {})
    print(
        "Review: "
        + ", ".join(
            f"{name.replace('_', ' ')}={count}"
            for name, count in sorted(dispositions.items())
        )
    )
    print(
        "Failure classes: "
        + ", ".join(
            f"{name}={count}"
            for name, count in sorted(summary.get("failure_classes", {}).items())
        )
    )
    print(
        "Source changes: "
        + ", ".join(
            f"{name}={count}"
            for name, count in sorted(summary.get("source_changes", {}).items())
        )
    )
    print(f"Revalidation required: {summary.get('revalidation_required', 0)}")
    print(
        "Repository inventory: "
        f"status={repository['status']}, "
        f"files={repository_summary.get('files', 'unavailable')}, "
        "opaque/unresolved="
        f"{repository_summary.get('opaque_or_unresolved', 'unavailable')}"
    )
    suggestion_counts = summary.get("suggestions", {})
    print(
        "Machine suggestions: "
        + (
            ", ".join(
                f"{name}={count}" for name, count in sorted(suggestion_counts.items())
            )
            if suggestion_counts
            else "none"
        )
    )
    print(
        f"Runtime evidence: imports={summary.get('runtime_imports', 0)}, "
        f"unique spans={summary.get('runtime_spans', 0)}, "
        f"mapped={summary.get('runtime_mapped_spans', 0)}, "
        f"unmapped={summary.get('runtime_unmapped_spans', 0)}"
    )
    return 0


def _validate(args: argparse.Namespace) -> int:
    if args.max_findings < 1:
        raise ValueError("--max-findings must be at least 1")
    report = validate_analysis(load_analysis(args.analysis))
    counts = report["counts"]
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(
            "Validation: "
            f"errors={counts['error']}, warnings={counts['warning']}, "
            f"information={counts['information']}"
        )
        findings = report["findings"]
        for finding in findings[: args.max_findings]:
            location = finding["item_id"] or "project"
            component = f" ({finding['component']})" if finding["component"] else ""
            print(
                f"[{finding['level'].upper()}] {location}{component} "
                f"{finding['rule_id']}: {finding['message']}"
            )
        if len(findings) > args.max_findings:
            print(
                f"... {len(findings) - args.max_findings} additional finding(s) omitted"
            )
    return int(bool(counts["error"] or (args.strict and counts["warning"])))


def _architecture(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    source = Path(args.analysis).expanduser().resolve()
    if args.output:
        output = Path(args.output)
    else:
        suffix = ".architecture.json" if args.format == "json" else ".architecture.md"
        output = source.with_name(source.stem + suffix)
    result = export_architecture(analysis, output, format=args.format)
    print(f"Exported architecture {args.format}: {result}")
    return 0


def _audit(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    source = Path(args.analysis).expanduser().resolve()
    output = (
        Path(args.output)
        if args.output
        else source.with_name(source.stem + ".audit.csv")
    )
    result = export_audit(analysis, output)
    print(f"Exported audit history: {result}")
    return 0


def _inventory(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    source = Path(args.analysis).expanduser().resolve()
    output = (
        Path(args.output)
        if args.output
        else source.with_name(source.stem + ".inventory.md")
    )
    result = export_inventory(analysis, output)
    print(f"Exported SFMEA inventory: {result}")
    return 0


def _queue(args: argparse.Namespace) -> int:
    if args.limit < 1:
        raise ValueError("--limit must be at least 1")
    analysis = load_analysis(args.analysis)
    review_depth = str(
        analysis.get("project", {}).get("settings", {}).get("review_depth", "focused")
    )
    depth_priority = {
        "screening": "high",
        "focused": "medium",
        "exhaustive": "low",
    }
    minimum_priority = args.minimum_priority or depth_priority.get(
        review_depth, "medium"
    )
    settings = analysis.get("project", {}).get("settings", {})
    governed_total = int(settings.get("review_queue_max_total", 1_000))
    governed_per_component = int(settings.get("review_queue_max_per_component", 3))
    queue = review_queue(
        analysis,
        limit=args.limit if args.all_records else min(args.limit, governed_total),
        minimum_priority="low" if args.all_records else minimum_priority,
        group_families=not args.all_records and review_depth != "exhaustive",
        max_per_component=(
            None
            if args.all_records
            else args.max_per_component or governed_per_component
        ),
        balance_priorities=not args.all_records,
    )
    if args.json:
        print(json.dumps(queue, indent=2))
        return 0
    for item in queue:
        family = (
            f" | family={item['family_size']}" if item.get("family_size", 1) > 1 else ""
        )
        cluster = (
            f" | cluster={item['review_cluster_size']}"
            if item.get("review_cluster_size", 1) > 1
            else ""
        )
        diversity = (
            f" | round={item['diversity_round']}" if item.get("diversity_round") else ""
        )
        print(
            f"{item['id']} | {item['screening_priority']} | {item['source_change']} | "
            f"errors={item['errors']}{family}{cluster}{diversity} | "
            f"{item['component']} | "
            f"{item['failure_mode']}"
        )
    if not queue:
        print("No active records require review.")
    return 0


def _sequence(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    source = Path(args.analysis).expanduser().resolve()
    suffix = ".sequence.json" if args.format == "json" else ".sequence.md"
    output = (
        Path(args.output) if args.output else source.with_name(source.stem + suffix)
    )
    result = export_sequence(
        analysis,
        output,
        args.entrypoint,
        format=args.format,
        max_depth=args.max_depth,
        max_interactions=args.max_interactions,
        include_runtime=not args.static_only,
    )
    print(f"Exported sequence {args.format}: {result}")
    return 0


def _traceability(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    source = Path(args.analysis).expanduser().resolve()
    suffix = ".traceability.json" if args.format == "json" else ".traceability.md"
    output = (
        Path(args.output) if args.output else source.with_name(source.stem + suffix)
    )
    result = export_traceability(analysis, output, format=args.format)
    print(f"Exported traceability {args.format}: {result}")
    return 0


def _coverage(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    source = Path(args.analysis).expanduser().resolve()
    suffix = ".coverage.json" if args.format == "json" else ".coverage.md"
    output = (
        Path(args.output) if args.output else source.with_name(source.stem + suffix)
    )
    result = export_coverage(analysis, output, format=args.format)
    print(f"Exported SFMEA coverage {args.format}: {result}")
    return 0


def _trace_import(args: argparse.Namespace) -> int:
    path = Path(args.analysis).expanduser().resolve()
    analysis = load_analysis(path)
    result = import_runtime_trace(analysis, args.trace, label=args.label)
    if result.get("duplicate"):
        print(f"Runtime evidence {result['id']} was already imported; no changes made.")
        return 0
    save_analysis(path, analysis)
    print(
        f"Imported runtime evidence {result['id']}: spans={result['span_count']}, "
        f"mapped={result['mapped_span_count']}, unmapped={result['unmapped_span_count']}"
    )
    return 0


def _discover(args: argparse.Namespace) -> int:
    if not 1 <= args.limit <= 500:
        raise ValueError("--limit must be from 1 through 500")
    path = Path(args.analysis).expanduser().resolve()
    analysis = load_analysis(path)
    if args.dry_run:
        print(
            json.dumps(
                evidence_packets(analysis, scope=args.scope, limit=args.limit), indent=2
            )
        )
        return 0
    created = discover_suggestions(
        analysis, _provider(args), scope=args.scope, limit=args.limit
    )
    save_analysis(path, analysis)
    print(
        f"Stored {len(created)} new grounded suggestion(s); no reviewer fields were changed."
    )
    return 0


def _suggestions(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    values = analysis.get("suggestions", [])
    if args.status != "all":
        values = [value for value in values if value.get("status") == args.status]
    if args.json:
        payload: Any = values
        if args.relationships:
            payload = {
                "suggestions": values,
                "relationships": suggestion_relationships(analysis),
            }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0
    for value in values:
        print(
            f"{value.get('id')} | {value.get('status')} | {value.get('confidence')} | "
            f"{value.get('component_reference')} | {value.get('content', {}).get('failure_mode')}"
        )
    if not values:
        print("No suggestions match this filter.")
    if args.relationships:
        summary = suggestion_relationships(analysis)["summary"]
        print(
            "Relationship leads: "
            f"duplicates={summary['duplicates']}, "
            f"contradictions={summary['contradictions']}, "
            f"divergences={summary['divergences']}"
        )
    return 0


def _suggestion_review(args: argparse.Namespace) -> int:
    path = Path(args.analysis).expanduser().resolve()
    analysis = load_analysis(path)
    try:
        result = review_suggestion(
            analysis,
            args.suggestion_id,
            decision=args.decision,
            reviewer=args.reviewer,
            rationale=args.rationale,
        )
    except KeyError as exc:
        raise ValueError(f"unknown suggestion: {args.suggestion_id}") from exc
    save_analysis(path, analysis)
    print(
        f"Suggestion {result['id']} {result['status']}"
        + (
            f" as unreviewed worksheet item {result['materialized_item_id']}"
            if result.get("materialized_item_id")
            else ""
        )
    )
    return 0


def _pr_analyze(args: argparse.Namespace) -> int:
    result = analyze_pull_request(
        args.repository,
        base=args.base,
        head=args.head,
        output=args.output,
    )
    print(f"Created pull-request SFMEA review bundle: {result}")
    print(f"Open the head report: {result / 'head-report.html'}")
    print(f"Review the canonical delta: {result / 'differential-analysis.json'}")
    return 0


def _pr_verify(args: argparse.Namespace) -> int:
    result = verify_pull_request_analysis(args.bundle)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Pull-request bundle valid={result['valid']}; "
            f"base={result['base_commit']}; head={result['head_commit']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return int(not result["valid"])


def _plugin_verify(args: argparse.Namespace) -> int:
    manifest = load_plugin_manifest(args.manifest)
    result = {
        "valid": True,
        "id": manifest.id,
        "name": manifest.name,
        "version": manifest.version,
        "sdk_api": manifest.sdk_api,
        "capabilities": manifest.capabilities,
        "execution": (
            "Explicit separate-process execution; not an operating-system sandbox."
        ),
    }
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Plugin manifest valid: {manifest.id} {manifest.version}; "
            f"SDK API {manifest.sdk_api}; capabilities {', '.join(manifest.capabilities)}"
        )
        print(result["execution"])
    return 0


def _plugin_run(args: argparse.Namespace) -> int:
    analysis_path = Path(args.analysis).expanduser().resolve()
    run = run_plugin(
        args.manifest,
        load_analysis(analysis_path),
        capability=args.capability,
    )
    output = (
        Path(args.output)
        if args.output
        else analysis_path.with_name(analysis_path.stem + "-plugin-run.json")
    )
    result = export_plugin_run(run, output)
    print(
        f"Recorded {len(run['observations'])} untrusted plugin observation(s): {result}"
    )
    print(run["notice"])
    return 0


def _plugin_run_verify(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis) if args.analysis else None
    result = verify_plugin_run_file(
        args.run,
        analysis=analysis,
        manifest_source=args.manifest,
    )
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Plugin run valid={result['valid']}; plugin={result['plugin_id']}; "
            f"observations={result['observation_count']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return int(not result["valid"])


def _synthesis_init(args: argparse.Namespace) -> int:
    source = Path(args.analysis).expanduser().resolve()
    analysis = load_analysis(source)
    output = (
        Path(args.output)
        if args.output
        else source.with_name(source.stem + "-synthesis.json")
    )
    result = export_synthesis_workspace(analysis, output)
    print(f"Created editable suggestion synthesis workspace: {result}")
    print(
        "Review existing and proposed claims, edit only evidence-supported content, "
        "record decisions, then run `sfmea synthesis-seal`."
    )
    return 0


def _synthesis_seal(args: argparse.Namespace) -> int:
    result = seal_synthesis_workspace(args.workspace)
    print(f"Sealed suggestion synthesis workspace: {result}")
    return 0


def _synthesis_verify(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis) if args.analysis else None
    result = verify_synthesis_workspace_file(args.workspace, analysis)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Synthesis workspace valid={result['valid']}; "
            f"entries={result['entry_count']}; decisions={result['decision_counts']}"
        )
        for error in result["errors"]:
            print(f"- {error}")
        print(result["notice"])
    return int(not result["valid"])


def _synthesis_apply(args: argparse.Namespace) -> int:
    path = Path(args.analysis).expanduser().resolve()
    workspace_path = Path(args.workspace).expanduser().resolve()
    receipt_path = (
        Path(args.receipt).expanduser().absolute()
        if args.receipt
        else path.with_name(path.stem + "-synthesis-apply-receipt.json")
    )
    if receipt_path.resolve() in {path, workspace_path}:
        raise ValueError("synthesis receipt must differ from analysis and workspace paths")
    source_snapshot_path = (
        Path(args.source_snapshot).expanduser().absolute()
        if args.source_snapshot
        else None
    )
    if source_snapshot_path is not None and source_snapshot_path.resolve() in {
        path,
        workspace_path,
        receipt_path.resolve(),
    }:
        raise ValueError(
            "synthesis source snapshot must differ from analysis, workspace, and receipt paths"
        )
    analysis_destination = inspect_artifact_destination(
        path, label="synthesis result analysis"
    )
    receipt_destination = inspect_artifact_destination(
        receipt_path, label="synthesis apply receipt"
    )
    source_snapshot_destination = (
        inspect_artifact_destination(
            source_snapshot_path, label="synthesis source analysis snapshot"
        )
        if source_snapshot_path is not None
        else None
    )
    if (
        source_snapshot_destination is not None
        and source_snapshot_destination.snapshot is not None
    ):
        raise ValueError(
            "synthesis source snapshot already exists; choose a new destination"
        )
    source_file_snapshot = (
        load_bounded_file_snapshot(
            path,
            label="synthesis source analysis",
            max_bytes=MAX_ANALYSIS_BYTES,
        )
        if source_snapshot_destination is not None
        else None
    )
    analysis = load_analysis(path)
    if (
        inspect_artifact_destination(path, label="synthesis result analysis")
        != analysis_destination
    ):
        raise ValueError("analysis changed while preparing synthesis application")
    workspace = load_synthesis_workspace(workspace_path)
    receipt = apply_synthesis_workspace(analysis, workspace)
    compact = (
        analysis.get("project", {})
        .get("settings", {})
        .get("analysis_serialization")
        == "compact"
    )
    with tempfile.TemporaryDirectory(
        prefix=f".{path.name}.synthesis-", dir=path.parent
    ) as temporary:
        staged_analysis_path = Path(temporary) / path.name
        save_analysis(staged_analysis_path, analysis, compact=compact)
        staged_analysis = load_analysis(staged_analysis_path)
        receipt["result_analysis_state_sha256"] = canonical_json_sha256(
            staged_analysis
        )
        receipt.pop("content_sha256", None)
        receipt["content_sha256"] = canonical_json_sha256(receipt)
        analysis_content = staged_analysis_path.read_bytes()
        receipt_content = (
            json.dumps(receipt, indent=2, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        published_source_snapshot: Path | None = None
        if (
            source_snapshot_destination is not None
            and source_file_snapshot is not None
        ):
            source_digest = receipt["source_analysis_state_sha256"]

            def verify_source_snapshot(candidate: Path) -> bool:
                return bool(
                    canonical_json_sha256(load_analysis(candidate)) == source_digest
                )

            published_source_snapshot = atomic_publish_bytes(
                source_snapshot_destination.path,
                source_file_snapshot.raw,
                max_bytes=MAX_ANALYSIS_BYTES,
                label="synthesis source analysis snapshot",
                expected_destination=source_snapshot_destination,
                staged_verifier=verify_source_snapshot,
            )
        published_analysis, published_receipt = atomic_publish_pair(
            path,
            analysis_content,
            receipt_path,
            receipt_content,
            primary_label="synthesis result analysis",
            secondary_label="synthesis apply receipt",
            primary_max_bytes=MAX_ANALYSIS_BYTES,
            secondary_max_bytes=20_000_000,
            expected_primary=analysis_destination,
            expected_secondary=receipt_destination,
        )
    print(
        f"Applied {len(receipt['applied_suggestion_ids'])} suggestion decision(s); "
        f"{receipt['deferred']} deferred."
    )
    print(f"Updated analysis: {published_analysis}")
    print(f"Apply receipt: {published_receipt}")
    if published_source_snapshot is not None:
        print(f"Source analysis snapshot: {published_source_snapshot}")
    print(receipt["notice"])
    return 0


def _synthesis_apply_verify(args: argparse.Namespace) -> int:
    bindings = (args.source_analysis, args.workspace, args.result_analysis)
    if args.integrity_only:
        if any(value is not None for value in bindings):
            raise ValueError(
                "--integrity-only cannot be combined with binding artifact options"
            )
    elif not all(value is not None for value in bindings):
        raise ValueError(
            "complete verification requires --source-analysis, --workspace, and "
            "--result-analysis; use --integrity-only for receipt-only verification"
        )
    result = verify_synthesis_apply_receipt_file(
        args.receipt,
        source_analysis_path=args.source_analysis,
        workspace_path=args.workspace,
        result_analysis_path=args.result_analysis,
    )
    if args.output:
        output = export_json_document(result, args.output)
        print(f"Exported synthesis apply verification: {output}")
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    return int(not (result["valid"] if args.integrity_only else result["reconciled"]))


def _summarize(args: argparse.Namespace) -> int:
    if args.by != "project" and not args.key:
        raise ValueError("--key is required unless --by project is selected")
    path = Path(args.analysis).expanduser().resolve()
    analysis = load_analysis(path)
    if args.llm:
        result = generate_summary(
            analysis, _provider(args), group_by=args.by, key=args.key
        )
        save_analysis(path, analysis)
    else:
        result = deterministic_summary(analysis, group_by=args.by, key=args.key)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif result.get("summary"):
        print(result["summary"])
        print("\nEvidence IDs: " + ", ".join(result.get("evidence_ids", [])))
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


def _threat_model(args: argparse.Namespace) -> int:
    destination = export_service_threat_model(args.output, format=args.format)
    print(destination)
    return 0


def _evaluate_compare(args: argparse.Namespace) -> int:
    values: list[dict[str, Any]] = []
    for source, label in (
        (args.before, "before evaluation result"),
        (args.after, "after evaluation result"),
        (args.change, "calibration change record"),
    ):
        document = load_bounded_json_document(
            source,
            label=label,
            max_bytes=20_000_000,
            max_depth=30,
            max_nodes=1_000_000,
        )
        if not isinstance(document.value, dict):
            raise ValueError(f"{label} must be a JSON object")
        values.append(document.value)
    result = compare_evaluation_results(values[0], values[1], values[2])
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        global_metrics = result["global"]
        print(
            "Calibration comparison: "
            f"{result['decision']}; precision delta="
            f"{global_metrics.get('precision_delta')}; recall delta="
            f"{global_metrics.get('recall_delta')}; control recall delta="
            f"{global_metrics.get('control_recall_delta')}"
        )
        for gate, passed in result["gates"].items():
            print(f"- {'PASS' if passed else 'BLOCK'} {gate}")
        print(result["authority"])
    return int(not result["eligible_for_product_change_review"])


def _evaluate(args: argparse.Namespace) -> int:
    if args.max_findings < 1:
        raise ValueError("--max-findings must be at least 1")
    if args.json and args.output:
        raise ValueError("--json cannot be combined with --output")
    analysis = load_analysis(args.analysis)
    expected = load_evaluation_spec(args.expected)
    result = evaluate_candidates(analysis, expected)
    if args.output:
        destination = export_json_document(result, args.output)
        print(destination)
    elif args.json:
        print(json.dumps(result, indent=2))
    else:
        print(
            "Evaluation: "
            f"expected={result['expected']}, actual={result['actual']}, "
            f"matched={result['matched']}, recall={result['recall']}, "
            f"precision={result['precision']}"
        )
        metrics = result.get("metrics", {})
        print(
            "Quality metrics: "
            f"duplicates={metrics.get('duplicate_rate')}, "
            f"localization={metrics.get('source_localization_accuracy')}, "
            f"citations={metrics.get('citation_link_accuracy')}, "
            f"traceability={metrics.get('traceability_integrity')}, "
            f"adapter_provenance={metrics.get('adapter_provenance_coverage')}, "
            f"source_accounting={metrics.get('repository_source_accounting')}"
        )
        call_resolution = result.get("call_resolution", {})
        if call_resolution.get("enabled"):
            print(
                "Call resolution: "
                f"expected={call_resolution.get('expected')}, "
                f"actual={call_resolution.get('actual')}, "
                f"matched={call_resolution.get('matched')}, "
                f"recall={call_resolution.get('recall')}, "
                f"precision={call_resolution.get('precision')}"
            )
        confidence = result.get("confidence_calibration", {})
        print(
            "Confidence calibration: "
            f"population={confidence.get('population')}, "
            f"monotonic={confidence.get('monotonic_empirical_precision')}, "
            f"qualification_ready={confidence.get('qualification_ready_corpus')}"
        )
        controls = result.get("control_detection", {})
        if controls.get("enabled"):
            control_population = controls.get("population", {})
            print(
                "Control detection: "
                f"expected={controls.get('expected')}, "
                f"actual={controls.get('actual')}, "
                f"matched={controls.get('matched')}, "
                f"recall={controls.get('recall')}, "
                f"precision={controls.get('precision')}; "
                f"components={control_population.get('evaluated_components')}, "
                f"positive={control_population.get('positive_components')}, "
                f"negative={control_population.get('negative_components')}"
            )
        semantics = result.get("semantic_output", {})
        if semantics.get("enabled"):
            print(
                "Semantic output: "
                f"cases={semantics.get('matched')}/{semantics.get('expected')}, "
                f"recall={semantics.get('recall')}, "
                f"precision={semantics.get('precision')}; "
                f"claims={semantics.get('claim_matched')}/"
                f"{semantics.get('claim_expected')}, "
                f"claim_recall={semantics.get('claim_recall')}, "
                f"claim_precision={semantics.get('claim_precision')}"
            )
        findings = [
            *(
                f"Missing: {value.get('source') or '*'}:{value['component']} / "
                f"{value['rule_id']}"
                for value in result["missing"]
            ),
            *(
                f"Unexpected: {value.get('source') or '*'}:{value['component']} / "
                f"{value['rule_id']}"
                for value in result["unexpected"]
            ),
            *(
                f"Missing call: {value['source']}:{value['component']} / "
                f"{value['raw_reference']} -> {value['reference']} "
                f"({value['resolution']})"
                for value in call_resolution.get("missing", [])
            ),
            *(
                f"Unexpected call: {value['source']}:{value['component']} / "
                f"{value['raw_reference']} -> {value['reference']} "
                f"({value['resolution']})"
                for value in call_resolution.get("unexpected", [])
            ),
            *(
                f"Missing control: {value['source']}:{value['component']} / "
                f"{value['kind']} ({', '.join(value.get('roles', []))})"
                for value in controls.get("missing", [])
            ),
            *(
                f"Unexpected control: {value['source']}:{value['component']} / "
                f"{value['kind']} ({', '.join(value.get('roles', []))})"
                for value in controls.get("unexpected", [])
            ),
            *(
                f"Missing semantic case: {value['source']}:{value['component']} / "
                f"{value['rule_id']}"
                for value in semantics.get("missing", [])
            ),
            *(
                f"Semantic mismatch: {value['source']}:{value['component']} / "
                f"{value['rule_id']} [{value['field']}] "
                f"expected={value['expected']!r}, actual={value['actual']!r}"
                for value in semantics.get("mismatches", [])
            ),
        ]
        for finding in findings[: args.max_findings]:
            print(f"- {finding}")
        if len(findings) > args.max_findings:
            print(
                f"... {len(findings) - args.max_findings} additional finding(s) omitted"
            )
        print(result["notice"])
    return int(
        bool(
            result["missing"]
            or result["unexpected"]
            or result.get("call_resolution", {}).get("missing")
            or result.get("call_resolution", {}).get("unexpected")
            or result.get("control_detection", {}).get("missing")
            or result.get("control_detection", {}).get("unexpected")
            or result.get("semantic_output", {}).get("missing")
            or result.get("semantic_output", {}).get("mismatches")
            or result.get("metrics", {}).get("duplicate_count")
            or result.get("metrics", {}).get("unsupported_verification_claims")
        )
    )


def _program_analysis_references(values: list[str]) -> list[tuple[str, str]]:
    references: list[tuple[str, str]] = []
    for value in values:
        repository_id, separator, path = value.partition("=")
        if not separator or not repository_id.strip() or not path.strip():
            raise ValueError("--analysis must use ID=PATH")
        references.append((repository_id.strip(), path.strip()))
    return references


def _program_init(args: argparse.Namespace) -> int:
    if bool(args.qualification_result) != bool(args.qualification_manifest):
        raise ValueError(
            "--qualification-result and --qualification-manifest must be supplied together"
        )
    cohorts = (
        qualification_validation_cohorts(
            args.qualification_result,
            args.qualification_manifest,
            program_destination=args.output,
        )
        if args.qualification_result
        else []
    )
    destination = write_program_template(
        args.output,
        _program_analysis_references(args.analysis),
        name=args.name,
        force=args.force,
        validation_cohorts=cohorts,
    )
    print(
        f"Created assurance program: {destination}; "
        f"qualification cohorts imported={len(cohorts)}"
    )
    print(
        "Add relationships, requirements, evidence, validation cohorts, and approvals; then run `sfmea program-seal` and `sfmea program-verify`."
    )
    return 0


def _qualification_build(args: argparse.Namespace) -> int:
    result = build_qualification_campaign(args.manifest)
    destination = export_json_document(result, args.output)
    status = str(result["status"])
    print(
        f"Qualification campaign: {status}; "
        f"repositories={result['summary']['repository_count']}; output={destination}"
    )
    semantics = result["features"]["semantic_output"]
    print(
        "Semantic qualification: "
        f"matched={semantics['matched']}/{semantics['expected']}; "
        f"recall={semantics['recall']}; precision={semantics['precision']}"
    )
    print(result["notice"])
    return int(args.require_eligible and not result["eligible_for_independent_review"])


def _qualification_verify(args: argparse.Namespace) -> int:
    if args.integrity_only and args.manifest:
        raise ValueError("--integrity-only cannot be combined with --manifest")
    if not args.integrity_only and not args.manifest:
        raise ValueError("--manifest is required unless --integrity-only is used")
    verdict = verify_qualification_campaign_file(
        args.result,
        manifest=None if args.integrity_only else args.manifest,
    )
    if args.output:
        destination = export_json_document(verdict, args.output)
        print(destination)
    else:
        print(json.dumps(verdict, indent=2, ensure_ascii=False))
    accepted = verdict["valid"] if args.integrity_only else verdict["reconciled"]
    if args.require_eligible:
        accepted = bool(accepted and verdict["eligible_for_independent_review"])
    return int(not accepted)


def _qualification_report(args: argparse.Namespace) -> int:
    destination = export_qualification_report(
        args.result,
        args.manifest,
        args.output,
        title=args.title,
    )
    print(f"Created qualification report: {destination}")
    return 0


def _qualification_report_verify(args: argparse.Namespace) -> int:
    if args.integrity_only and args.result:
        raise ValueError("--integrity-only cannot be combined with --result")
    if not args.integrity_only and not args.result:
        raise ValueError("--result is required unless --integrity-only is used")
    verdict = verify_qualification_report_file(
        args.report,
        result_source=None if args.integrity_only else args.result,
    )
    if args.output:
        destination = export_json_document(verdict, args.output)
        print(destination)
    else:
        print(json.dumps(verdict, indent=2, ensure_ascii=False))
    return int(not (verdict["valid"] if args.integrity_only else verdict["reconciled"]))


def _program_seal(args: argparse.Namespace) -> int:
    destination = seal_program_file(args.program)
    print(f"Sealed assurance program: {destination}")
    return 0


def _program_verify(args: argparse.Namespace) -> int:
    if args.max_findings < 1:
        raise ValueError("--max-findings must be at least 1")
    if args.publication_json and (args.format != "html" or not args.output):
        raise ValueError("--publication-json requires --format html and --output")
    destination_state = None
    destination_existed = False
    if args.publication_json:
        destination_existed = lexists(Path(args.output).expanduser().absolute())
        try:
            destination_state = inspect_artifact_destination(
                args.output, label="assurance program report"
            )
            source = Path(args.program).expanduser().absolute().resolve(strict=True)
            if destination_state.path == source:
                raise ValueError(
                    "assurance program report destination must differ from the "
                    "assurance program file"
                )
        except VERIFICATION_EXCEPTIONS:
            receipt = _program_report_publication_error(
                destination=args.output,
                code="program_report.invalid_destination",
                message=(
                    "Assurance program report destination validation failed; "
                    "no report was published."
                ),
                phase="input_validation",
                destination_existed=destination_existed,
            )
            print(json.dumps(receipt, indent=2, ensure_ascii=False))
            return 2
    try:
        result = verify_assurance_program(args.program)
    except VERIFICATION_EXCEPTIONS:
        if not args.publication_json:
            raise
        receipt = _program_report_publication_error(
            destination=args.output,
            code="program_report.program_verification_failed",
            message=(
                "Assurance program verification did not complete; no report was "
                "published."
            ),
            phase="program_verification",
            destination_existed=destination_existed,
        )
        print(json.dumps(receipt, indent=2, ensure_ascii=False))
        return 2
    if args.output:
        if args.format == "human":
            raise ValueError("--output requires --format json, markdown, or html")
        try:
            output = export_program_verification(
                result,
                args.output,
                format=args.format,
                expected_destination=destination_state,
            )
        except ProgramReportPublicationError as exc:
            if not args.publication_json:
                raise
            receipt = _program_report_publication_error(
                destination=args.output,
                code=f"program_report.{exc.phase}_failed",
                message=(
                    "Assurance program report publication did not complete; "
                    "the prior destination was preserved."
                ),
                phase=exc.phase,
                destination_existed=destination_existed,
            )
            print(json.dumps(receipt, indent=2, ensure_ascii=False))
            return 2
        if args.publication_json:
            try:
                verification = verify_program_report_file(output, program=args.program)
            except VERIFICATION_EXCEPTIONS:
                verification = _program_report_publication_error(
                    destination=args.output,
                    code="program_report.post_publication_verification_failed",
                    message=(
                        "Published assurance program report could not be verified."
                    ),
                    phase="post_publication_verification",
                    destination_existed=destination_existed,
                )
                verification["publication"]["status"] = "published"
                verification["publication"]["prior_destination_preserved"] = False
                print(json.dumps(verification, indent=2, ensure_ascii=False))
                return 2
            _program_report_publication_receipt(
                verification,
                status="published",
                phase=(
                    "complete"
                    if verification.get("valid")
                    else "post_publication_verification"
                ),
                destination_existed=destination_existed,
            )
            print(json.dumps(verification, indent=2, ensure_ascii=False))
            if not verification.get("valid"):
                return 2
            return int(verification.get("assurance_valid") is not True)
        print(f"Exported assurance program verification: {output}")
    elif args.format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.format == "markdown":
        print(program_verification_markdown(result), end="")
    elif args.format == "html":
        print(program_verification_html(result), end="")
    else:
        summary = result.get("summary", {})
        validation = result.get("validation", {})
        print(
            "Assurance program: "
            f"{'VALID' if result.get('valid') else 'NOT READY'}; "
            f"repositories={summary.get('bound_repositories', 0)}/{summary.get('repositories', 0)}, "
            f"relationships={summary.get('relationships', 0)}, "
            f"evidence={summary.get('external_evidence', 0)}, "
            f"validation_repositories={validation.get('repositories', 0)}"
        )
        for finding in result.get("findings", [])[: args.max_findings]:
            print(
                f"- {finding['level'].upper()} {finding['code']}: {finding['message']}"
            )
        remaining = len(result.get("findings", [])) - args.max_findings
        if remaining > 0:
            print(f"... {remaining} additional finding(s) omitted")
        print(result.get("notice", ""))
    return int(not result.get("valid", False))


def _program_report_verify(args: argparse.Namespace) -> int:
    receipt_destination = None
    if args.output:
        receipt_destination = inspect_artifact_destination(
            args.output,
            label="assurance program report verification receipt",
        )
        protected_sources = [args.report]
        if args.program:
            protected_sources.append(args.program)
        for protected_source in protected_sources:
            protected_path = Path(
                os.path.abspath(Path(protected_source).expanduser())
            ).resolve(strict=False)
            if receipt_destination.path == protected_path:
                raise ValueError(
                    "program report verification receipt destination must differ "
                    "from the report and assurance program files"
                )
    result = verify_program_report_file(
        args.report,
        program=args.program,
        expected_sha256=args.expect_sha256,
    )
    if args.output:
        output = export_program_report_verification(
            result,
            args.output,
            expected_destination=receipt_destination,
        )
        print(f"Exported assurance program report verification: {output}")
    elif args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            "Assurance program report: "
            f"{result.get('status', 'invalid').upper()}; "
            f"integrity={'valid' if result.get('valid') else 'invalid'}; "
            f"assurance={'VALID' if result.get('assurance_valid') is True else 'NOT READY' if result.get('assurance_valid') is False else 'unavailable'}"
        )
        if result.get("binding_requested"):
            print(
                "Exact program binding: "
                f"{'matched' if result.get('status') == 'matched' else 'not matched'}"
            )
        if result.get("artifact_binding_requested"):
            print(
                "Exact report SHA-256: "
                f"{'matched' if result.get('checks', {}).get('artifact_identity') is True else 'not matched' if result.get('checks', {}).get('artifact_identity') is False else 'not checked'}"
            )
        for check in result.get("failed_checks", []):
            print(f"- failed: {check}")
        for error in result.get("errors", []):
            print(
                f"- {error.get('code', PROGRAM_REPORT_VERIFICATION_FORMAT)}: "
                f"{error.get('message', 'verification failed')}"
            )
        print(result.get("notice", ""))
    return int(not result.get("valid", False))


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


def _citations(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    source = Path(args.analysis).expanduser().resolve()
    suffix = ".guidance.json" if args.format == "json" else ".guidance.csv"
    output = (
        Path(args.output) if args.output else source.with_name(source.stem + suffix)
    )
    result = export_guidance_traceability(analysis, output, format=args.format)
    print(f"Exported guidance traceability {args.format}: {result}")
    return 0


def _assurance(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    source = Path(args.analysis).expanduser().resolve()
    suffix = {
        "json": ".assurance.json",
        "work-json": ".assurance-work.json",
        "csv": ".assurance.csv",
        "markdown": ".assurance.md",
    }[args.format]
    output = (
        Path(args.output) if args.output else source.with_name(source.stem + suffix)
    )
    result = export_assurance_register(analysis, output, format=args.format)
    print(f"Exported executable assurance checklist {args.format}: {result}")
    return 0


def _assurance_work_verify(args: argparse.Namespace) -> int:
    try:
        analysis = load_analysis(args.analysis) if args.analysis else None
    except VERIFICATION_EXCEPTIONS as exc:
        if not args.json:
            raise
        verification = _verification_error_result(
            format_name=ASSURANCE_WORK_QUEUE_VERIFICATION_FORMAT,
            source=args.queue,
            check_names=ASSURANCE_WORK_QUEUE_VERIFICATION_CHECKS,
            binding_requested=bool(args.analysis),
            code="analysis.load_failed",
            error=exc,
        )
        print(json.dumps(verification, indent=2, ensure_ascii=False))
        return 2
    try:
        verification = verify_assurance_work_queue_file(args.queue, analysis=analysis)
    except VERIFICATION_EXCEPTIONS as exc:
        verification = _verification_error_result(
            format_name=ASSURANCE_WORK_QUEUE_VERIFICATION_FORMAT,
            source=args.queue,
            check_names=ASSURANCE_WORK_QUEUE_VERIFICATION_CHECKS,
            binding_requested=bool(args.analysis),
            code="assurance_work_queue.verification_failed",
            error=exc,
        )
        if args.json:
            print(json.dumps(verification, indent=2, ensure_ascii=False))
        else:
            print("Assurance work queue: valid=False, analysis binding=not completed")
            print(f"Error: {exc}")
            print(verification["notice"])
        return 1
    if args.json:
        print(json.dumps(verification, indent=2, ensure_ascii=False))
    else:
        binding_status = (
            "matched"
            if verification["status"] == "matched"
            else "not checked"
            if verification["status"] == "valid_binding_not_checked"
            else "mismatched"
        )
        print(
            f"Assurance work queue: valid={verification['valid']}, "
            f"analysis binding={binding_status}"
        )
        print(f"Verified queue: {verification['path']}")
        print(f"Content SHA-256: {verification['content_sha256']}")
        if verification["failed_checks"]:
            print(f"Failed checks: {', '.join(verification['failed_checks'])}")
        if verification["unchecked_checks"]:
            print(f"Unchecked checks: {', '.join(verification['unchecked_checks'])}")
        print(verification["notice"])
    return 0 if verification["valid"] else 1


def _assurance_review(args: argparse.Namespace) -> int:
    path = Path(args.analysis).expanduser().resolve()
    analysis = load_analysis(path)
    try:
        result = review_obligation(
            analysis,
            args.obligation_id,
            status=args.status,
            reviewer=args.reviewer,
            rationale=args.rationale,
            owner=args.owner,
        )
    except KeyError as exc:
        raise ValueError(f"unknown assurance obligation: {args.obligation_id}") from exc
    save_analysis(path, analysis)
    print(
        f"Assurance obligation {result['id']} updated to {result['assurance_status']}; "
        "no verification or closure was inferred."
    )
    return 0


def _assurance_fault_plugins(args: argparse.Namespace) -> int:
    catalog = fault_injection_plugin_catalog()
    if args.json:
        print(json.dumps({"plugins": catalog}, indent=2, ensure_ascii=False))
    else:
        for plugin in catalog:
            print(
                f"{plugin['id']}: {plugin['title']} "
                f"({', '.join(plugin['fault_kinds'])})"
            )
        print(
            "Plugins execute only from explicitly bound tests in the approved sandbox; "
            "scanner execution is prohibited."
        )
    return 0


def _assurance_obligation(
    analysis: dict[str, Any], obligation_id: str
) -> dict[str, Any]:
    register = ensure_assurance_register(analysis)
    obligation = next(
        (
            value
            for value in register.get("obligations", [])
            if isinstance(value, dict) and value.get("id") == obligation_id
        ),
        None,
    )
    if obligation is None:
        raise ValueError(f"unknown assurance obligation: {obligation_id}")
    return obligation


def _assurance_fault_plan(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    obligation = _assurance_obligation(analysis, args.obligation_id)
    result = export_fault_injection_plan(obligation, args.output, plugin_id=args.plugin)
    print(f"Created governed fault-injection starter plan: {result}")
    print(
        "Author a fault-case JSON file, then use assurance-fault-complete; execute the "
        "resulting test only through the approved sandbox workflow."
    )
    return 0


def _bound_fault_plan(
    plan: dict[str, Any], analysis_path: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    analysis = load_analysis(analysis_path)
    binding = plan.get("binding", {})
    obligation = _assurance_obligation(
        analysis,
        str(binding.get("obligation_id", "")) if isinstance(binding, dict) else "",
    )
    return analysis, obligation


def _assurance_fault_complete(args: argparse.Namespace) -> int:
    plan = load_fault_injection_plan(args.plan)
    _analysis, obligation = _bound_fault_plan(plan, args.analysis)
    case = load_fault_injection_case(args.case)
    result = export_completed_fault_injection_plan(plan, case, obligation, args.output)
    print(f"Created validated ready fault-injection plan: {result}")
    return 0


def _assurance_fault_verify(args: argparse.Namespace) -> int:
    plan = load_fault_injection_plan(args.plan)
    _analysis, obligation = _bound_fault_plan(plan, args.analysis)
    result = verify_fault_injection_plan(plan, obligation=obligation)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Fault-injection plan: {result['status']} "
            f"(plugin: {result['plugin_id'] or 'unknown'})"
        )
        for finding in result["findings"]:
            print(f"[{finding['code']}] {finding['message']}")
    return 0 if result["valid"] else 1


def _assurance_fault_scaffold(args: argparse.Namespace) -> int:
    plan = load_fault_injection_plan(args.plan)
    _analysis, obligation = _bound_fault_plan(plan, args.analysis)
    result = export_fault_injection_pytest(plan, obligation, args.output)
    print(f"Created approved-sandbox pytest bridge: {result}")
    print(
        "Register it with assurance-test-register, then execute it with assurance-run."
    )
    return 0


def _assurance_scaffold(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    result = export_pytest_scaffold(
        analysis,
        args.output,
        scope=args.scope,
        limit=args.limit,
        disposition=args.disposition,
        include_implemented=args.include_implemented,
        queue_id=args.queue_id,
        owner=args.owner,
        purpose=args.purpose,
    )
    verification = verify_pytest_scaffold(analysis, result)
    if not verification.get("valid"):
        raise RuntimeError("generated assurance scaffold failed immediate verification")
    count = int(verification["obligation_count"])
    designs = verification.get("test_design_summary", {})
    print(f"Created {count} fail-visible assurance test starting point(s): {result}")
    print(
        "Synthesized designs: "
        f"properties={designs.get('property_designs', 0)}, "
        f"contracts={designs.get('contract_designs', 0)}, "
        f"contract cases={designs.get('contract_cases', 0)}, "
        f"unresolved contract bindings={designs.get('unresolved_contract_bindings', 0)}"
    )
    print(
        "Implement and execute them only in an approved sandbox; they are not evidence yet."
    )
    return 0


def _assurance_scaffold_refresh(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    result = refresh_pytest_scaffold(analysis, args.scaffold)
    verification = verify_pytest_scaffold(analysis, result)
    if not verification.get("valid"):
        raise RuntimeError("refreshed assurance scaffold failed immediate verification")
    print(
        f"Refreshed assurance scaffold {verification['queue']['id']} with "
        f"{verification['obligation_count']} test starting point(s): {result}"
    )
    print(
        "Generated-file edits were not present; no implementation work was overwritten."
    )
    return 0


def _assurance_scaffold_archive(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    result = archive_pytest_scaffold(analysis, args.scaffold, args.output)
    record = json.loads((result / "retirement-record.json").read_text(encoding="utf-8"))
    print(f"Archived assurance scaffold {record['queue']['id']}: {result}")
    print(
        "The original manifest, generated files, contract diff, and integrity-protected "
        "retirement record were preserved."
    )
    return 0


def _assurance_scaffold_verify(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    result = verify_pytest_scaffold(analysis, args.scaffold)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"Assurance scaffold: {result['status']} ({result['path']})")
        print(
            f"Queue: {result['queue']['id']} "
            f"(owner: {result['queue']['owner'] or 'unassigned'})"
        )
        print(f"Obligations: {result['obligation_count']}")
        designs = result.get("test_design_summary", {})
        print(
            "Synthesized designs: "
            f"properties={designs.get('property_designs', 0)}, "
            f"contracts={designs.get('contract_designs', 0)}, "
            f"contract cases={designs.get('contract_cases', 0)}, "
            f"unresolved contract bindings="
            f"{designs.get('unresolved_contract_bindings', 0)}"
        )
        print(
            f"Current selection: {result['current_selection']['obligation_count']} "
            f"({result['lifecycle'].replace('_', ' ')})"
        )
        changed = sum(
            not value["unchanged_from_generated"] for value in result["generated_files"]
        )
        print(f"Generated starting files changed or missing: {changed}")
        contract_summary = result["contract_change_summary"]
        print(
            "Contract selection: "
            f"current={contract_summary['current']}, "
            f"added={contract_summary['added']}, "
            f"removed={contract_summary['removed']}, "
            f"changed={contract_summary['changed']}"
        )
        for change in result["contract_changes"][:25]:
            fields = ", ".join(change["changed_fields"]) or "selection membership"
            print(f"  - {change['obligation_id']}: {change['status']} ({fields})")
        if len(result["contract_changes"]) > 25:
            print(
                f"  ... {len(result['contract_changes']) - 25} additional contract "
                "change(s) omitted; use --json for the complete diff."
            )
        for finding in result["findings"]:
            print(
                f"[{finding['level'].upper()}] {finding['rule_id']}: "
                f"{finding['message']}"
            )
        print(result["notice"])
    return 0 if result["valid"] else 1


def _assurance_test_register(args: argparse.Namespace) -> int:
    path = Path(args.analysis).expanduser().resolve()
    analysis = load_analysis(path)
    try:
        result = register_test_implementation(
            analysis,
            args.obligation_id,
            test_path=args.test_path,
            author=args.author,
            origin=args.origin,
            status=args.status,
        )
    except KeyError as exc:
        raise ValueError(f"unknown assurance obligation: {args.obligation_id}") from exc
    save_analysis(path, analysis)
    print(
        f"Registered {result['automation']['implementation_status']} test "
        f"{result['automation']['implemented_test_path']} for {result['id']} "
        f"({result['automation']['test_sha256']})."
    )
    print("The test has not been executed and is not verification evidence.")
    return 0


def _assurance_run(args: argparse.Namespace) -> int:
    path = Path(args.analysis).expanduser().resolve()
    analysis = load_analysis(path)
    evidence_root = (
        Path(args.evidence_root)
        if args.evidence_root
        else path.parent / "assurance-evidence"
    )
    common = {
        "image": args.image,
        "initiated_by": args.initiated_by,
        "engine": args.engine,
        "cpus": args.cpus,
        "memory_mb": args.memory_mb,
        "pids_limit": args.pids_limit,
        "timeout_seconds": args.timeout_seconds,
        "allow_dirty": args.allow_dirty,
    }
    try:
        if args.dry_run:
            result = prepare_sandbox_execution(
                analysis,
                args.obligation_id,
                evidence_directory=evidence_root / "DRY-RUN",
                **common,
            )
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0
        result = run_sandbox_execution(
            analysis,
            args.obligation_id,
            evidence_root=evidence_root,
            approved=args.approve_execution,
            **common,
        )
    except KeyError as exc:
        raise ValueError(f"unknown assurance obligation: {args.obligation_id}") from exc
    save_analysis(path, analysis)
    print(
        f"Sandbox execution {result['id']}: status={result['status']}, "
        f"exit={result.get('exit_code')}, evidence={result['evidence_directory']}"
    )
    print("Execution evidence awaits independent acceptance-criterion review.")
    return int(result["status"] != "passed")


def _criterion_results(values: list[str]) -> dict[int, str]:
    results: dict[int, str] = {}
    for value in values:
        index_text, separator, result = value.partition("=")
        if not separator or not index_text.isdigit() or result not in CRITERION_RESULTS:
            raise ValueError(
                "criterion results must use INDEX=pass|fail|insufficient|not_observed"
            )
        index = int(index_text)
        if index < 1 or index in results:
            raise ValueError(
                "criterion result indexes must be unique positive integers"
            )
        results[index] = result
    return results


def _assurance_evidence_import(args: argparse.Namespace) -> int:
    path = Path(args.analysis).expanduser().resolve()
    analysis = load_analysis(path)
    evidence_root = (
        Path(args.evidence_root)
        if args.evidence_root
        else path.parent / "assurance-evidence"
    )
    before = {
        value.get("id") for value in analysis.get("assurance", {}).get("executions", [])
    }
    try:
        result = import_execution_evidence(
            analysis,
            args.obligation_id,
            manifest_path=args.manifest,
            evidence_root=evidence_root,
            initiated_by=args.initiated_by,
        )
    except KeyError as exc:
        raise ValueError(f"unknown assurance obligation: {args.obligation_id}") from exc
    save_analysis(path, analysis)
    action = "Already imported" if result["id"] in before else "Imported"
    print(
        f"{action} execution evidence {result['id']}: status={result['status']}, "
        f"artifacts={len(result.get('artifacts', []))}."
    )
    print(
        "Imported evidence is externally supplied and unreviewed; independent "
        "acceptance-criterion review is still required."
    )
    return 0


def _assurance_evidence_review(args: argparse.Namespace) -> int:
    path = Path(args.analysis).expanduser().resolve()
    analysis = load_analysis(path)
    try:
        result = review_execution_evidence(
            analysis,
            args.execution_id,
            reviewer=args.reviewer,
            decision=args.decision,
            rationale=args.rationale,
            stimulus_observed=args.stimulus_observed == "yes",
            criterion_results=_criterion_results(args.criterion_result),
        )
    except KeyError as exc:
        raise ValueError(f"unknown assurance execution: {args.execution_id}") from exc
    save_analysis(path, analysis)
    print(
        f"Evidence review {result['id']}: decision={result['decision']}, "
        f"artifacts_valid={result['artifact_integrity_valid']}."
    )
    print("Verification does not close the finding or accept residual risk.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"sfmea: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
