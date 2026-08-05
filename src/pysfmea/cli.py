"""Command-line entry points for scanning, reviewing, and exporting SFMEA data."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from os import replace as atomic_replace
from os.path import lexists
from pathlib import Path
from typing import Any

from .architecture import export_architecture
from .assurance import (
    ASSURANCE_WORK_QUEUE_VERIFICATION_FORMAT,
    PLANNING_REVIEW_STATUSES,
    archive_pytest_scaffold,
    export_assurance_register,
    export_pytest_scaffold,
    refresh_pytest_scaffold,
    review_obligation,
    verify_assurance_work_queue_file,
    verify_pytest_scaffold,
)
from .config import load_config, write_config_template
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
    deterministic_summary,
    discover_suggestions,
    evaluate_candidates,
    evidence_packets,
    generate_summary,
    load_evaluation_spec,
    review_suggestion,
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
from .guidance import GUIDANCE_SOURCES, GUIDELINE_PROFILES, METHODOLOGY_NOTICE
from .html_report import (
    HTML_REPORT_VERIFICATION_FORMAT,
    MAX_REPORT_RECORDS,
    export_html_report,
    verify_html_report_file,
)
from .interchange import (
    cyclonedx_document,
    differential_analysis,
    export_json_document,
    sarif_document,
)
from .pdf_report import export_pdf_report
from .publication import (
    export_publication_failure_catalog,
    publication_failure_catalog,
    verify_publication_failure_catalog_file,
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
from .scanner import scan_repository
from .schemas import (
    export_schema,
    export_schema_bundle,
    schema_catalog,
    schema_document,
    verify_schema_bundle_path,
)
from .server import serve_review
from .sfta import export_sfta
from .signing import (
    passphrase_from_environment,
    sign_review_package,
    verify_review_signature,
)
from .store import load_analysis, merge_rescan, save_analysis
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
    init.add_argument("path", nargs="?", default="sfmea.toml", help="file or directory path")
    init.add_argument("--force", action="store_true", help="replace an existing template")
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
        "status", help="show the current workflow stage, artifact freshness, and next actions"
    )
    status.add_argument("repository", nargs="?", default=".")
    status.add_argument("--config", help="sfmea.toml path; auto-discovered by default")
    status.add_argument("--analysis", help="analysis JSON path; auto-discovered by default")
    status.add_argument(
        "--assurance-scaffold",
        action="append",
        default=[],
        help=(
            "optional scaffold directory; repeat for multiple queues; conventional nearby "
            "names are auto-discovered when omitted"
        ),
    )
    status.add_argument("--json", action="store_true", help="emit machine-readable status")
    status.add_argument(
        "--require-handoff-ready",
        action="store_true",
        help="exit nonzero unless every handoff gate is satisfied",
    )
    status.set_defaults(handler=_status)

    scan = subparsers.add_parser("scan", help="scan a Python repository")
    scan.add_argument("repository", help="path to the Python repository")
    scan.add_argument(
        "-o",
        "--output",
        help="analysis JSON path; defaults to REPOSITORY/sfmea-analysis.json",
    )
    scan.add_argument("--config", help="sfmea.toml path; defaults to REPOSITORY/sfmea.toml when present")
    scan.add_argument("--coverage-json", help="coverage.py JSON file")
    scan.add_argument("--exclude", action="append", default=[], help="additional relative-path glob to exclude")
    scan.add_argument("--focus", action="append", default=[], help="only analyze matching path:qualname glob")
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
    scan.add_argument("--fresh", action="store_true", help="do not merge review decisions from an existing output")
    scan.set_defaults(handler=_scan)

    review = subparsers.add_parser("review", help="open the local browser review workspace")
    review.add_argument("analysis", help="analysis JSON path")
    review.add_argument("--port", type=int, default=8765, help="local port; use 0 for an available port")
    review.add_argument("--no-browser", action="store_true", help="do not open the browser automatically")
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
        "sfta", help="export Software Fault Trees and bottom-up/top-down reconciliation gaps"
    )
    sfta.add_argument("analysis", help="analysis JSON path")
    sfta.add_argument("--format", choices=("json", "csv"), default="json")
    sfta.add_argument("-o", "--output", help="destination path")
    sfta.set_defaults(handler=_sfta)

    sarif = subparsers.add_parser("sarif", help="export SFMEA screening candidates as SARIF 2.1.0")
    sarif.add_argument("analysis", help="analysis JSON path")
    sarif.add_argument("-o", "--output", help="destination .sarif path")
    sarif.set_defaults(handler=_sarif)

    sbom = subparsers.add_parser("sbom", help="export declared dependency inventory as CycloneDX 1.6")
    sbom.add_argument("analysis", help="analysis JSON path")
    sbom.add_argument("-o", "--output", help="destination CycloneDX JSON path")
    sbom.set_defaults(handler=_sbom)

    difference = subparsers.add_parser("diff", help="compare two canonical SFMEA analysis runs")
    difference.add_argument("previous", help="previous analysis JSON")
    difference.add_argument("current", help="current analysis JSON")
    difference.add_argument("-o", "--output", help="destination diff JSON path")
    difference.set_defaults(handler=_diff)

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
    sign_package.add_argument("package", help="verified review package directory or ZIP")
    sign_package.add_argument("--private-key", required=True, help="Ed25519 PEM private key")
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
        "--json", action="store_true", help="emit the complete verification report as JSON"
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

    validate = subparsers.add_parser("validate", help="check review completeness and quality gates")
    validate.add_argument("analysis", help="analysis JSON path")
    validate.add_argument("--strict", action="store_true", help="also fail when warnings are present")
    validate.add_argument("--json", action="store_true", help="emit the validation report as JSON")
    validate.add_argument(
        "--max-findings",
        type=int,
        default=100,
        help="maximum findings printed in text mode",
    )
    validate.set_defaults(handler=_validate)

    architecture = subparsers.add_parser(
        "architecture", help="export the functional call and system-interface propagation view"
    )
    architecture.add_argument("analysis", help="analysis JSON path")
    architecture.add_argument("--format", choices=("markdown", "json"), default="markdown")
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

    queue = subparsers.add_parser("queue", help="show the next prioritized records to review")
    queue.add_argument("analysis", help="analysis JSON path")
    queue.add_argument("--limit", type=int, default=25, help="maximum records to show")
    queue.add_argument("--json", action="store_true", help="emit structured JSON")
    queue.set_defaults(handler=_queue)

    sequence = subparsers.add_parser("sequence", help="export a bounded static/observed sequence view")
    sequence.add_argument("analysis", help="analysis JSON path")
    sequence.add_argument("--entrypoint", required=True, help="component ID, qualname, or path:qualname")
    sequence.add_argument("--format", choices=("markdown", "json"), default="markdown")
    sequence.add_argument("--max-depth", type=int, default=6)
    sequence.add_argument("--max-interactions", type=int, default=100)
    sequence.add_argument("--static-only", action="store_true", help="exclude imported runtime edges")
    sequence.add_argument("-o", "--output", help="destination path")
    sequence.set_defaults(handler=_sequence)

    traceability = subparsers.add_parser("traceability", help="export requirement-to-hazard trace graph")
    traceability.add_argument("analysis", help="analysis JSON path")
    traceability.add_argument("--format", choices=("markdown", "json"), default="markdown")
    traceability.add_argument("-o", "--output", help="destination path")
    traceability.set_defaults(handler=_traceability)

    coverage = subparsers.add_parser("coverage", help="report SFMEA linkage and review coverage")
    coverage.add_argument("analysis", help="analysis JSON path")
    coverage.add_argument("--format", choices=("markdown", "json"), default="markdown")
    coverage.add_argument("-o", "--output", help="destination path")
    coverage.set_defaults(handler=_coverage)

    trace_import = subparsers.add_parser("trace-import", help="import simple or OTLP JSON runtime spans")
    trace_import.add_argument("analysis", help="analysis JSON path")
    trace_import.add_argument("trace", help="runtime trace JSON path")
    trace_import.add_argument("--label", default="", help="human-readable evidence label")
    trace_import.set_defaults(handler=_trace_import)

    discover = subparsers.add_parser("discover", help="generate grounded machine suggestions")
    discover.add_argument("analysis", help="analysis JSON path")
    discover.add_argument("--scope", default="*", help="path:qualname glob")
    discover.add_argument("--limit", type=int, default=25, help="maximum component packets")
    discover.add_argument("--dry-run", action="store_true", help="print evidence packets without calling a model")
    _add_provider_arguments(discover)
    discover.set_defaults(handler=_discover)

    suggestions = subparsers.add_parser("suggestions", help="list governed machine suggestions")
    suggestions.add_argument("analysis", help="analysis JSON path")
    suggestions.add_argument("--status", choices=("all", "proposed", "accepted", "rejected", "stale"), default="proposed")
    suggestions.add_argument("--json", action="store_true")
    suggestions.set_defaults(handler=_suggestions)

    suggestion_review = subparsers.add_parser("suggestion-review", help="accept or reject a machine suggestion")
    suggestion_review.add_argument("analysis", help="analysis JSON path")
    suggestion_review.add_argument("suggestion_id")
    suggestion_review.add_argument("--decision", choices=("accept", "reject"), required=True)
    suggestion_review.add_argument("--reviewer", required=True)
    suggestion_review.add_argument("--rationale", required=True)
    suggestion_review.set_defaults(handler=_suggestion_review)

    summarize = subparsers.add_parser("summarize", help="produce deterministic or grounded model summaries")
    summarize.add_argument("analysis", help="analysis JSON path")
    summarize.add_argument("--by", choices=("project", "subsystem", "hazard", "component"), default="project")
    summarize.add_argument("--key", default="")
    summarize.add_argument("--llm", action="store_true", help="request a grounded narrative from the configured provider")
    summarize.add_argument("--json", action="store_true")
    _add_provider_arguments(summarize)
    summarize.set_defaults(handler=_summarize)

    evaluate = subparsers.add_parser("evaluate", help="compare candidates with an exact-key golden corpus")
    evaluate.add_argument("analysis", help="analysis JSON path")
    evaluate.add_argument("expected", help="golden evaluation JSON path")
    evaluate.add_argument("--json", action="store_true", help="emit the complete result")
    evaluate.add_argument("--max-findings", type=int, default=25)
    evaluate.set_defaults(handler=_evaluate)

    guidance = subparsers.add_parser("guidance", help="show methodology sources and limitations")
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
    assurance_run.add_argument("--image", required=True, help="preloaded approved image reference")
    assurance_run.add_argument("--initiated-by", required=True)
    assurance_run.add_argument("--engine", choices=("auto", "docker", "podman"), default="auto")
    assurance_run.add_argument("--evidence-root", help="host directory for immutable execution artifacts")
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
    evidence_import.add_argument("--manifest", required=True, help="external evidence manifest JSON")
    evidence_import.add_argument("--initiated-by", required=True)
    evidence_import.add_argument("--evidence-root", help="managed destination for copied evidence")
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
    parser.add_argument("--endpoint", help="OpenAI-compatible chat-completions endpoint")
    parser.add_argument("--model", help="model identifier")
    parser.add_argument("--api-key-env", default="SFMEA_LLM_API_KEY")
    parser.add_argument("--timeout", type=int, default=60)


def _provider(args: argparse.Namespace) -> OpenAICompatibleProvider:
    if not args.endpoint or not args.model:
        raise ValueError("--endpoint and --model are required for model-assisted operation")
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
    config_path: str | Path | None = args.config
    default_config = repository / "sfmea.toml"
    if config_path is None and default_config.is_file():
        config_path = default_config
    config, resolved_config = load_config(config_path)
    config["scan"]["exclude"].extend(args.exclude)
    config["scan"]["focus"].extend(args.focus)
    scanned = scan_repository(
        repository,
        include_private=args.include_private,
        include_tests=args.include_tests,
        include_nested=args.include_nested,
        config=config,
        coverage_json=args.coverage_json,
    )
    scanned["project"]["settings"]["config_file"] = str(resolved_config or "")
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
                "baseline_id": scanned.get("project", {}).get("baseline", {}).get("id", ""),
            }
        ]
    save_analysis(output, scanned)
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
    print(f"Next: sfmea review \"{output}\"")
    return 0


def _init(args: argparse.Namespace) -> int:
    destination = Path(args.path).expanduser()
    if (destination.exists() and destination.is_dir()) or (
        destination.suffix.lower() != ".toml"
    ):
        destination = destination / "sfmea.toml"
    result = write_config_template(destination, overwrite=args.force)
    print(f"Created SFMEA configuration: {result}")
    print("Edit the system boundary, hazards, critical functions, and rating guidance before scanning.")
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
        raise ValueError("provide a schema name or use --list, --bundle, or --verify-bundle")
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
        result = verify_publication_failure_catalog_file(args.verify)
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            status = "valid" if result["valid"] else "invalid"
            print(f"Publication failure catalog: {status} ({result['source']})")
            print(
                f"Failures: {result['failure_count']}; "
                f"declared digest: {result['declared_content_sha256'] or 'unavailable'}"
            )
            for error in result["errors"]:
                print(f"[ERROR] {error['code']}: {error['message']}")
            print(result["notice"])
        return 0 if result["valid"] else 1
    if args.force and not args.output:
        raise ValueError("--force is valid only with --output")
    if args.output:
        result = export_publication_failure_catalog(
            args.output, overwrite=args.force
        )
        if args.json:
            verification = verify_publication_failure_catalog_file(result)
            print(json.dumps(verification, indent=2, ensure_ascii=False))
        else:
            print(f"Exported publication failure catalog: {result}")
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
        print(result["notice"])
    return int(not result["ready"])


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
        print("Next actions: none; handoff artifacts are current and gates are satisfied.")
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
            error=ValueError(
                "Analysis could not be loaded; no report was published."
            ),
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
        staged = output.with_name(
            f".{output.name}.{uuid.uuid4().hex}.verified.tmp"
        )
        try:
            try:
                result = export_html_report(
                    analysis,
                    staged,
                    title=args.title,
                    notes=args.notes,
                    max_records=args.max_records,
                    diagrams=args.diagram,
                    propagation_record_limit=args.propagation_record_limit,
                    propagation_path_limit=args.propagation_path_limit,
                    propagation_depth=args.propagation_depth,
                    propagation_include_finding_ids=(
                        args.propagation_include_finding
                    ),
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
        diagrams=args.diagram,
        propagation_record_limit=args.propagation_record_limit,
        propagation_path_limit=args.propagation_path_limit,
        propagation_depth=args.propagation_depth,
        propagation_include_finding_ids=args.propagation_include_finding,
    )
    size_mib = result.stat().st_size / (1024 * 1024)
    embedded_records = min(len(analysis.get("items", [])), args.max_records)
    print(
        f"Created self-contained SFMEA report: {result} "
        f"({embedded_records:,} records; {size_mib:.1f} MiB); propagation "
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
    print(
        "Report data SHA-256: "
        f"{verification['declared']['report_data_sha256']}"
    )
    if verification["declared"]["document_sha256"]:
        print(
            "Document SHA-256: "
            f"{verification['declared']['document_sha256']}"
        )
    if verification["failed_checks"]:
        print(f"Failed checks: {', '.join(verification['failed_checks'])}")
    if verification["unchecked_checks"]:
        print(f"Unchecked checks: {', '.join(verification['unchecked_checks'])}")
    print(verification["notice"])
    return int(not verification["valid"])


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
            print("Diagram bundle integrity: valid=False, analysis binding=not completed")
            print(f"Error: {exc}")
            print(verification["notice"])
        return 1
    if args.json:
        print(json.dumps(verification, indent=2, ensure_ascii=False))
        return 0
    binding = verification["checks"]["analysis_binding"]
    binding_status = "matched" if binding is True else "not checked"
    print(
        f"Diagram bundle integrity: valid=True, analysis binding={binding_status}"
    )
    print(f"Verified canonical diagram bundle: {verification['path']}")
    print(
        f"Diagrams: {verification['diagram_count']}; "
        f"analysis binding: {binding_status}"
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
    output = Path(args.output) if args.output else source.with_name(source.stem + "-cdx.json")
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
                "complete"
                if verification["valid"]
                else "post_publication_verification"
            ),
        }
        print(json.dumps(verification, indent=2, ensure_ascii=False))
        return 0 if verification["valid"] else 1
    print(f"Next: sfmea verify-package \"{result}\"")
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
        f"Next: sfmea verify-package \"{args.package}\" "
        f"--signature \"{result}\" --public-key PUBLIC_KEY.pem"
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
        + ", ".join(f"{name.replace('_', ' ')}={count}" for name, count in sorted(dispositions.items()))
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
            print(f"... {len(findings) - args.max_findings} additional finding(s) omitted")
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
    output = Path(args.output) if args.output else source.with_name(source.stem + ".audit.csv")
    result = export_audit(analysis, output)
    print(f"Exported audit history: {result}")
    return 0


def _inventory(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    source = Path(args.analysis).expanduser().resolve()
    output = Path(args.output) if args.output else source.with_name(source.stem + ".inventory.md")
    result = export_inventory(analysis, output)
    print(f"Exported SFMEA inventory: {result}")
    return 0


def _queue(args: argparse.Namespace) -> int:
    if args.limit < 1:
        raise ValueError("--limit must be at least 1")
    queue = review_queue(load_analysis(args.analysis), limit=args.limit)
    if args.json:
        print(json.dumps(queue, indent=2))
        return 0
    for item in queue:
        print(
            f"{item['id']} | {item['screening_priority']} | {item['source_change']} | "
            f"errors={item['errors']} | {item['component']} | {item['failure_mode']}"
        )
    if not queue:
        print("No active records require review.")
    return 0


def _sequence(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    source = Path(args.analysis).expanduser().resolve()
    suffix = ".sequence.json" if args.format == "json" else ".sequence.md"
    output = Path(args.output) if args.output else source.with_name(source.stem + suffix)
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
    output = Path(args.output) if args.output else source.with_name(source.stem + suffix)
    result = export_traceability(analysis, output, format=args.format)
    print(f"Exported traceability {args.format}: {result}")
    return 0


def _coverage(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    source = Path(args.analysis).expanduser().resolve()
    suffix = ".coverage.json" if args.format == "json" else ".coverage.md"
    output = Path(args.output) if args.output else source.with_name(source.stem + suffix)
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
        print(json.dumps(evidence_packets(analysis, scope=args.scope, limit=args.limit), indent=2))
        return 0
    created = discover_suggestions(
        analysis, _provider(args), scope=args.scope, limit=args.limit
    )
    save_analysis(path, analysis)
    print(f"Stored {len(created)} new grounded suggestion(s); no reviewer fields were changed.")
    return 0


def _suggestions(args: argparse.Namespace) -> int:
    values = load_analysis(args.analysis).get("suggestions", [])
    if args.status != "all":
        values = [value for value in values if value.get("status") == args.status]
    if args.json:
        print(json.dumps(values, indent=2, ensure_ascii=False))
        return 0
    for value in values:
        print(
            f"{value.get('id')} | {value.get('status')} | {value.get('confidence')} | "
            f"{value.get('component_reference')} | {value.get('content', {}).get('failure_mode')}"
        )
    if not values:
        print("No suggestions match this filter.")
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


def _evaluate(args: argparse.Namespace) -> int:
    if args.max_findings < 1:
        raise ValueError("--max-findings must be at least 1")
    analysis = load_analysis(args.analysis)
    expected = load_evaluation_spec(args.expected)
    result = evaluate_candidates(analysis, expected)
    if args.json:
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
        ]
        for finding in findings[: args.max_findings]:
            print(f"- {finding}")
        if len(findings) > args.max_findings:
            print(f"... {len(findings) - args.max_findings} additional finding(s) omitted")
        print(result["notice"])
    return int(
        bool(
            result["missing"]
            or result["unexpected"]
            or result.get("metrics", {}).get("duplicate_count")
            or result.get("metrics", {}).get("unsupported_verification_claims")
        )
    )


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
    output = Path(args.output) if args.output else source.with_name(source.stem + suffix)
    result = export_guidance_traceability(analysis, output, format=args.format)
    print(f"Exported guidance traceability {args.format}: {result}")
    return 0


def _assurance(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    source = Path(args.analysis).expanduser().resolve()
    suffix = {"json": ".assurance.json", "work-json": ".assurance-work.json", "csv": ".assurance.csv", "markdown": ".assurance.md"}[
        args.format
    ]
    output = Path(args.output) if args.output else source.with_name(source.stem + suffix)
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
        verification = verify_assurance_work_queue_file(
            args.queue, analysis=analysis
        )
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
    count = len(
        json.loads((result / "assurance-manifest.json").read_text(encoding="utf-8"))[
            "obligations"
        ]
    )
    print(
        f"Created {count} intentionally failing assurance test placeholder(s): {result}"
    )
    print("Implement and execute them only in an approved sandbox; they are not evidence yet.")
    return 0


def _assurance_scaffold_refresh(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    result = refresh_pytest_scaffold(analysis, args.scaffold)
    manifest = json.loads(
        (result / "assurance-manifest.json").read_text(encoding="utf-8")
    )
    print(
        f"Refreshed assurance scaffold {manifest['queue']['id']} with "
        f"{len(manifest['obligations'])} placeholder(s): {result}"
    )
    print("Generated-file edits were not present; no implementation work was overwritten.")
    return 0


def _assurance_scaffold_archive(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    result = archive_pytest_scaffold(analysis, args.scaffold, args.output)
    record = json.loads(
        (result / "retirement-record.json").read_text(encoding="utf-8")
    )
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
        print(
            f"Current selection: {result['current_selection']['obligation_count']} "
            f"({result['lifecycle'].replace('_', ' ')})"
        )
        changed = sum(
            not value["unchanged_from_generated"]
            for value in result["generated_files"]
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
            print(
                f"  - {change['obligation_id']}: {change['status']} "
                f"({fields})"
            )
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
            raise ValueError("criterion result indexes must be unique positive integers")
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
        value.get("id")
        for value in analysis.get("assurance", {}).get("executions", [])
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
