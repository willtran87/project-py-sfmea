"""Command-line entry points for scanning, reviewing, and exporting SFMEA data."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .architecture import export_architecture
from .config import load_config, write_config_template
from .discovery import (
    OpenAICompatibleProvider,
    deterministic_summary,
    discover_suggestions,
    evidence_packets,
    evaluate_candidates,
    generate_summary,
    review_suggestion,
)
from .diagrams import GENERATED_DIAGRAM_KINDS, export_diagram_bundle
from .guidance import GUIDANCE_SOURCES, METHODOLOGY_NOTICE
from .html_report import MAX_REPORT_RECORDS, export_html_report
from .report import (
    export_audit,
    export_csv,
    export_inventory,
    export_markdown,
    export_review_archive,
    export_review_package,
    verify_review_package,
)
from .readiness import repository_readiness
from .scanner import scan_repository
from .runtime import import_runtime_trace
from .server import serve_review
from .signing import (
    passphrase_from_environment,
    sign_review_package,
    verify_review_signature,
)
from .store import load_analysis, merge_rescan, save_analysis
from .validation import review_queue, validate_analysis
from .visuals import export_coverage, export_sequence, export_traceability
from .version import __version__


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sfmea",
        description="Scan a Python repository and create a reviewable Software FMEA starter.",
    )
    parser.add_argument("--version", action="version", version=f"PySFMEA {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="create an sfmea.toml project template")
    init.add_argument("path", nargs="?", default="sfmea.toml", help="file or directory path")
    init.add_argument("--force", action="store_true", help="replace an existing template")
    init.set_defaults(handler=_init)

    doctor = subparsers.add_parser(
        "doctor", help="check repository and SFMEA configuration readiness"
    )
    doctor.add_argument("repository", nargs="?", default=".")
    doctor.add_argument("--config", help="sfmea.toml path")
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(handler=_doctor)

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
    report.set_defaults(handler=_html_report)

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
    diagram.set_defaults(handler=_diagram)

    package = subparsers.add_parser(
        "package", help="create a complete checksum-manifested review package"
    )
    package.add_argument("analysis", help="analysis JSON path")
    package.add_argument(
        "-o", "--output", help="destination directory or, with --zip, .zip path"
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
        help="create a single atomically published ZIP instead of a directory",
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
        "verify-package", help="verify checksums, contents, and provenance of a review package"
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
    if destination.exists() and destination.is_dir():
        destination = destination / "sfmea.toml"
    elif destination.suffix.lower() != ".toml":
        destination = destination / "sfmea.toml"
    result = write_config_template(destination, overwrite=args.force)
    print(f"Created SFMEA configuration: {result}")
    print("Edit the system boundary, hazards, critical functions, and rating guidance before scanning.")
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
    analysis = load_analysis(source)
    output = (
        Path(args.output)
        if args.output
        else source.with_name(source.stem + "-report.html")
    )
    result = export_html_report(
        analysis,
        output,
        title=args.title,
        notes=args.notes,
        max_records=args.max_records,
        diagrams=args.diagram,
    )
    print(f"Created self-contained SFMEA report: {result}")
    if len(analysis.get("items", [])) > args.max_records:
        print(
            f"Report record set was bounded to {args.max_records}; "
            "increase --max-records to include more records."
        )
    return 0


def _diagram(args: argparse.Namespace) -> int:
    source = Path(args.analysis).expanduser().resolve()
    analysis = load_analysis(source)
    output = (
        Path(args.output)
        if args.output
        else source.with_name(source.stem + f"-{args.type}-diagrams.json")
    )
    result = export_diagram_bundle(analysis, output, kind=args.type)
    print(f"Exported canonical SFMEA diagrams: {result}")
    return 0


def _package(args: argparse.Namespace) -> int:
    source = Path(args.analysis).expanduser().resolve()
    analysis = load_analysis(source)
    default_name = source.stem + "-review-package" + (".zip" if args.zip else "")
    output = Path(args.output) if args.output else source.with_name(default_name)
    if args.zip:
        result = export_review_archive(
            analysis,
            output,
            source_analysis=source,
            overwrite=args.force,
            portable=args.portable,
        )
        print(f"Created SFMEA review archive: {result}")
    else:
        result = export_review_package(
            analysis,
            output,
            source_analysis=source,
            overwrite=args.force,
            portable=args.portable,
        )
        print(f"Created SFMEA review package: {result}")
        print(f"Manifest: {result / 'manifest.json'}")
    print(f"Next: sfmea verify-package \"{result}\"")
    return 0


def _verify_package(args: argparse.Namespace) -> int:
    result = verify_review_package(args.package)
    if bool(args.signature) != bool(args.public_key):
        raise ValueError("--signature and --public-key must be supplied together")
    if args.signature:
        result = verify_review_signature(
            args.package,
            args.signature,
            args.public_key,
            package_verification=result,
        )
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
    summary: dict[str, Any] = analysis.get("summary", {})
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
    expected_path = Path(args.expected).expanduser().resolve()
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
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
    return int(bool(result["missing"]))


def _guidance(args: argparse.Namespace) -> int:
    print("PySFMEA methodology notice")
    print(METHODOLOGY_NOTICE)
    print("\nPublic guidance basis:")
    for source in GUIDANCE_SOURCES:
        print(f"- {source['title']}\n  {source['url']}\n  {source['use']}")
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
