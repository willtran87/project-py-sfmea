"""CSV and Markdown export for reviewed SFMEA data."""

from __future__ import annotations

import csv
import copy
import hashlib
import html
import json
import os
import shutil
import stat
import tempfile
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from .architecture import export_architecture
from .model import calculate_rpn, utc_now
from .validation import validate_analysis
from .visuals import export_coverage, export_traceability
from .version import __version__


CSV_FIELDS = [
    "id",
    "baseline_id",
    "source_status",
    "source_change",
    "change_reasons",
    "previous_ids",
    "revalidation_required",
    "source_fingerprint",
    "validated_fingerprint",
    "validated_context_fingerprint",
    "validated_analysis_context_fingerprint",
    "validated_baseline_id",
    "validated_at",
    "reviewed_at",
    "validation_errors",
    "validation_warnings",
    "path",
    "line",
    "component",
    "subsystems",
    "function",
    "requirement",
    "linked_hazards",
    "guideword",
    "failure_mode",
    "trigger",
    "causes",
    "local_effect",
    "next_higher_effect",
    "end_effect",
    "severity",
    "severity_category",
    "severity_rationale",
    "occurrence",
    "occurrence_rationale",
    "detection",
    "detection_rationale",
    "rpn",
    "prevention_controls",
    "detection_controls",
    "recommended_actions",
    "actions_taken",
    "verification_evidence",
    "post_action_severity",
    "post_action_severity_category",
    "post_action_severity_rationale",
    "post_action_occurrence",
    "post_action_occurrence_rationale",
    "post_action_detection",
    "post_action_detection_rationale",
    "post_action_rpn",
    "screening_priority",
    "disposition",
    "disposition_rationale",
    "status",
    "owner",
    "target_date",
    "approved_by",
    "approval_date",
    "reviewer",
    "review_history_entries",
    "notes",
]

REVIEW_PACKAGE_FILES = {
    "analysis.json",
    "worksheet.csv",
    "worksheet.md",
    "inventory.md",
    "architecture.md",
    "traceability.md",
    "coverage.md",
    "audit.csv",
    "validation.json",
    "summary.json",
    "README.md",
}
REVIEW_PACKAGE_ALL_FILES = REVIEW_PACKAGE_FILES | {"manifest.json"}
MAX_ARCHIVE_ENTRIES = 100
MAX_ARCHIVE_FILE_BYTES = 100_000_000
MAX_ARCHIVE_TOTAL_BYTES = 500_000_000


def _join(value: Any) -> str:
    if isinstance(value, list):
        return " | ".join(str(entry) for entry in value)
    return "" if value is None else str(value)


def _csv_safe(value: Any) -> Any:
    """Prevent reviewer-controlled text from becoming a spreadsheet formula."""

    if not isinstance(value, str):
        return value
    stripped = value.lstrip()
    if stripped.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _write_csv_row(writer: csv.DictWriter, row: dict[str, Any]) -> None:
    writer.writerow({field: _csv_safe(value) for field, value in row.items()})


def item_row(
    item: dict[str, Any],
    validation_findings: list[dict[str, Any]] | None = None,
    baseline_id: str = "",
) -> dict[str, Any]:
    source = item.get("source", {})
    component = item.get("component", {})
    scanner = item.get("scanner", {})
    review = item.get("review", {})
    return {
        "id": item.get("id", ""),
        "baseline_id": baseline_id,
        "source_status": item.get("source_status", "active"),
        "source_change": item.get("source_change", ""),
        "change_reasons": _join(item.get("change_reasons", [])),
        "previous_ids": _join(item.get("previous_ids", [])),
        "revalidation_required": review.get("revalidation_required", False),
        "source_fingerprint": scanner.get("source_fingerprint", ""),
        "validated_fingerprint": review.get("validated_fingerprint", ""),
        "validated_context_fingerprint": review.get("validated_context_fingerprint", ""),
        "validated_analysis_context_fingerprint": review.get(
            "validated_analysis_context_fingerprint", ""
        ),
        "validated_baseline_id": review.get("validated_baseline_id", ""),
        "validated_at": review.get("validated_at", ""),
        "reviewed_at": review.get("reviewed_at", ""),
        "validation_errors": _join(
            [
                finding["rule_id"]
                for finding in (validation_findings or [])
                if finding["level"] == "error"
            ]
        ),
        "validation_warnings": _join(
            [
                finding["rule_id"]
                for finding in (validation_findings or [])
                if finding["level"] == "warning"
            ]
        ),
        "path": source.get("path", ""),
        "line": source.get("line", ""),
        "component": component.get("qualname", ""),
        "subsystems": _join(component.get("subsystems", [])),
        "function": review.get("function", ""),
        "requirement": review.get("requirement", ""),
        "linked_hazards": _join(review.get("linked_hazards", [])),
        "guideword": scanner.get("guideword", ""),
        "failure_mode": review.get("failure_mode") or scanner.get("failure_mode", ""),
        "trigger": review.get("trigger") or scanner.get("trigger", ""),
        "causes": _join(review.get("causes", [])),
        "local_effect": review.get("local_effect", ""),
        "next_higher_effect": review.get("next_higher_effect", ""),
        "end_effect": review.get("end_effect", ""),
        "severity": review.get("severity", ""),
        "severity_category": review.get("severity_category", ""),
        "severity_rationale": review.get("severity_rationale", ""),
        "occurrence": review.get("occurrence", ""),
        "occurrence_rationale": review.get("occurrence_rationale", ""),
        "detection": review.get("detection", ""),
        "detection_rationale": review.get("detection_rationale", ""),
        "rpn": calculate_rpn(item) or "",
        "prevention_controls": _join(review.get("prevention_controls", [])),
        "detection_controls": _join(review.get("detection_controls", [])),
        "recommended_actions": _join(review.get("recommended_actions", [])),
        "actions_taken": _join(review.get("actions_taken", [])),
        "verification_evidence": _join(review.get("verification_evidence", [])),
        "post_action_severity": review.get("post_action_severity", ""),
        "post_action_severity_category": review.get("post_action_severity_category", ""),
        "post_action_severity_rationale": review.get("post_action_severity_rationale", ""),
        "post_action_occurrence": review.get("post_action_occurrence", ""),
        "post_action_occurrence_rationale": review.get("post_action_occurrence_rationale", ""),
        "post_action_detection": review.get("post_action_detection", ""),
        "post_action_detection_rationale": review.get("post_action_detection_rationale", ""),
        "post_action_rpn": calculate_rpn(item, post_action=True) or "",
        "screening_priority": scanner.get("screening_priority", ""),
        "disposition": review.get("disposition", ""),
        "disposition_rationale": review.get("disposition_rationale", ""),
        "status": review.get("status", ""),
        "owner": review.get("owner", ""),
        "target_date": review.get("target_date", ""),
        "approved_by": review.get("approved_by", ""),
        "approval_date": review.get("approval_date", ""),
        "reviewer": review.get("reviewer", ""),
        "review_history_entries": len(item.get("review_history", [])),
        "notes": review.get("notes", ""),
    }


def export_csv(analysis: dict[str, Any], destination: str | Path) -> Path:
    path = Path(destination).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        findings_by_item: dict[str, list[dict[str, Any]]] = {}
        for finding in validate_analysis(analysis)["findings"]:
            findings_by_item.setdefault(finding["item_id"], []).append(finding)
        for item in analysis.get("items", []):
            _write_csv_row(
                writer,
                item_row(
                    item,
                    findings_by_item.get(item.get("id", ""), []),
                    analysis.get("project", {}).get("baseline", {}).get("id", ""),
                )
            )
    return path


def _markdown_text(value: Any) -> str:
    return html.escape(_join(value), quote=False)


def _cell(value: Any, limit: int = 160) -> str:
    text = _markdown_text(value).replace("|", "\\|").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def export_markdown(analysis: dict[str, Any], destination: str | Path) -> Path:
    path = Path(destination).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    project = analysis.get("project", {})
    summary = analysis.get("summary", {})
    validation = validate_analysis(analysis)
    lines = [
        f"# Software FMEA — {project.get('name', 'Python project')}",
        "",
        f"Scanned: {project.get('scanned_at', '')}",
        f"Baseline: {project.get('baseline', {}).get('id', '')}",
        "",
        "> " + analysis.get("methodology", {}).get("notice", ""),
        "",
        f"- Components: {summary.get('components', 0)}",
        f"- Active candidate failure modes: {summary.get('candidate_failure_modes', 0)}",
        f"- Removed candidates retained for traceability: {summary.get('removed_candidates', 0)}",
        f"- Validation errors: {validation['counts']['error']}",
        f"- Validation warnings: {validation['counts']['warning']}",
        "",
        "## Worksheet",
        "",
        "| ID | Change | Revalidate | Component | Failure mode | End effect | S | O | D | RPN | Post RPN | Disposition | Status |",
        "|---|---|---|---|---|---|---:|---:|---:|---:|---:|---|---|",
    ]
    lines[0] = "# Software FMEA - " + _markdown_text(
        project.get("name", "Python project")
    )
    for item in analysis.get("items", []):
        review = item.get("review", {})
        scanner = item.get("scanner", {})
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(item.get("id")),
                    _cell(item.get("source_change")),
                    _cell(review.get("revalidation_required")),
                    _cell(item.get("component", {}).get("qualname")),
                    _cell(review.get("failure_mode") or scanner.get("failure_mode")),
                    _cell(review.get("end_effect")),
                    _cell(review.get("severity") or review.get("severity_category")),
                    _cell(review.get("occurrence")),
                    _cell(review.get("detection")),
                    _cell(calculate_rpn(item)),
                    _cell(calculate_rpn(item, post_action=True)),
                    _cell(review.get("disposition")),
                    _cell(review.get("status")),
                ]
            )
            + " |"
        )
    lines.extend(["", "## Guidance basis", ""])
    for source in analysis.get("methodology", {}).get("basis", []):
        lines.append(f"- [{source.get('title')}]({source.get('url')}) — {source.get('use')}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def export_audit(analysis: dict[str, Any], destination: str | Path) -> Path:
    """Export analysis-level and item-level lifecycle history as a flat CSV."""

    path = Path(destination).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "scope",
        "item_id",
        "component",
        "event",
        "at",
        "reviewer",
        "field",
        "before",
        "after",
        "details",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for event in analysis.get("history", []):
            _write_csv_row(
                writer,
                {
                    "scope": "analysis",
                    "event": event.get("event", ""),
                    "at": event.get("at", ""),
                    "details": json.dumps(event, ensure_ascii=False, sort_keys=True),
                }
            )
        for item in analysis.get("items", []):
            for event in item.get("review_history", []):
                changes = event.get("changes", {})
                if not changes:
                    changes = {"": {"before": "", "after": ""}}
                for field, change in changes.items():
                    _write_csv_row(
                        writer,
                        {
                            "scope": "item",
                            "item_id": item.get("id", ""),
                            "component": item.get("component", {}).get("qualname", ""),
                            "event": event.get("event", ""),
                            "at": event.get("at", ""),
                            "reviewer": event.get("reviewer", ""),
                            "field": field,
                            "before": json.dumps(
                                change.get("before"), ensure_ascii=False, sort_keys=True
                            ),
                            "after": json.dumps(
                                change.get("after"), ensure_ascii=False, sort_keys=True
                            ),
                        }
                    )
    return path


def export_inventory(analysis: dict[str, Any], destination: str | Path) -> Path:
    """Export the system-definition and component worksheet supporting the SFMEA."""

    path = Path(destination).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    context = analysis.get("context", {})
    project = dict(context.get("project", {}))
    analysis_context = dict(context.get("analysis", {}))
    for field in ("purpose", "boundary", "operating_context"):
        if project.get(field):
            project[field] = _markdown_text(project[field])
    for field in ("phase", "revision"):
        if analysis_context.get(field):
            analysis_context[field] = _markdown_text(analysis_context[field])
    lines = [
        f"# SFMEA system and component inventory — {analysis.get('project', {}).get('name', '')}",
        "",
        f"- Purpose: {project.get('purpose', '') or 'Not configured'}",
        f"- Boundary: {project.get('boundary', '') or 'Not configured'}",
        f"- Operating context: {project.get('operating_context', '') or 'Not configured'}",
        f"- Lifecycle phase: {analysis_context.get('phase', '') or 'Not configured'}",
        f"- Analysis revision: {analysis_context.get('revision', '') or 'Not configured'}",
        f"- Source/configuration baseline: {analysis.get('project', {}).get('baseline', {}).get('id', '')}",
        "",
        "## Ground rules and assumptions",
        "",
    ]
    lines[0] = "# SFMEA system and component inventory - " + _markdown_text(
        analysis.get("project", {}).get("name", "")
    )
    ground_rules = analysis_context.get("ground_rules", [])
    assumptions = [
        *project.get("assumptions", []),
        *analysis_context.get("fault_tolerance_assumptions", []),
    ]
    lines.extend(f"- {_markdown_text(value)}" for value in [*ground_rules, *assumptions])
    if not ground_rules and not assumptions:
        lines.append("- Not configured")
    lines.extend(
        [
            "",
            "## Components",
            "",
            "| ID | Kind | Source | Component / function | Inputs | Calls | Subsystem | Requirements | Interfaces |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
    )
    for component in analysis.get("components", []):
        source = component.get("source", {})
        lines.append(
            "| "
            + " | ".join(
                [
                    _cell(component.get("id")),
                    _cell(component.get("kind")),
                    _cell(f"{source.get('path', '')}:{source.get('line', '')}"),
                    _cell(component.get("qualname")),
                    _cell(component.get("parameters", [])),
                    _cell(component.get("calls", [])),
                    _cell(component.get("subsystems", [])),
                    _cell(component.get("requirement_ids", [])),
                    _cell(component.get("interface_ids", [])),
                ]
            )
            + " |"
        )
    for heading, key, columns in (
        ("Requirements", "requirements", ("id", "text", "source", "hazards")),
        ("Hazards", "hazards", ("id", "description", "end_effect", "severity")),
        (
            "System interfaces",
            "system_interfaces",
            ("id", "source", "target", "description", "data", "assumptions"),
        ),
        ("Review team", "reviewers", ("name", "role", "organization")),
        ("Dependencies", "dependencies", ("name", "specification", "source")),
        (
            "Interface contracts",
            "contracts",
            ("id", "path", "kind", "operations", "data_types"),
        ),
    ):
        lines.extend(["", f"## {heading}", ""])
        values = context.get(key, [])
        if not values:
            lines.append("Not configured.")
            continue
        lines.append("| " + " | ".join(column.replace("_", " ").title() for column in columns) + " |")
        lines.append("|" + "|".join("---" for _column in columns) + "|")
        for value in values:
            lines.append("| " + " | ".join(_cell(value.get(column)) for column in columns) + " |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def export_review_package(
    analysis: dict[str, Any],
    destination: str | Path,
    *,
    source_analysis: str | Path | None = None,
    overwrite: bool = False,
    portable: bool = False,
) -> Path:
    """Create a checksum-manifested, human- and machine-readable review package."""

    package = Path(destination).expanduser().resolve()
    package_analysis = _portable_analysis_snapshot(analysis) if portable else analysis
    if package.exists() and not package.is_dir():
        raise ValueError(f"review package destination is not a directory: {package}")
    output_names = REVIEW_PACKAGE_ALL_FILES
    existing = list(package.iterdir()) if package.exists() else []
    if existing and not overwrite:
        raise ValueError(
            f"review package directory is not empty: {package}; use --force to refresh it"
        )
    unknown = sorted(value.name for value in existing if value.name not in output_names)
    if unknown:
        raise ValueError(
            "review package contains unrecognized files and will not be refreshed: "
            + ", ".join(unknown)
        )

    package.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{package.name}.tmp-", dir=str(package.parent))
    )
    backup: Path | None = None
    try:
        outputs = {
            "analysis.json": lambda path: path.write_text(
                json.dumps(package_analysis, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            ),
            "worksheet.csv": lambda path: export_csv(package_analysis, path),
            "worksheet.md": lambda path: export_markdown(package_analysis, path),
            "inventory.md": lambda path: export_inventory(package_analysis, path),
            "architecture.md": lambda path: export_architecture(package_analysis, path),
            "traceability.md": lambda path: export_traceability(package_analysis, path),
            "coverage.md": lambda path: export_coverage(package_analysis, path),
            "audit.csv": lambda path: export_audit(package_analysis, path),
            "validation.json": lambda path: path.write_text(
                json.dumps(
                    validate_analysis(package_analysis), indent=2, ensure_ascii=False
                )
                + "\n",
                encoding="utf-8",
            ),
            "summary.json": lambda path: path.write_text(
                json.dumps(
                    package_analysis.get("summary", {}), indent=2, ensure_ascii=False
                )
                + "\n",
                encoding="utf-8",
            ),
        }
        for filename, writer in outputs.items():
            writer(staging / filename)

        readme = staging / "README.md"
        readme.write_text(
            "# PySFMEA review package\n\n"
            f"- Project: {package_analysis.get('project', {}).get('name', '')}\n"
            f"- Baseline: {package_analysis.get('project', {}).get('baseline', {}).get('id', '')}\n"
            f"- Generated by: PySFMEA {__version__}\n"
            f"- Portable paths: {'yes' if portable else 'no'}\n"
            f"- Generated: {utc_now()}\n\n"
            "This package contains the governed JSON analysis, worksheets, inventory, "
            "architecture and traceability views, coverage metrics, validation findings, "
            "and audit history. Checksums are recorded in `manifest.json`.\n\n"
            "After transfer or storage, run `sfmea verify-package .` from this directory "
            "to check the complete file set, checksums, and analysis provenance.\n\n"
            "> Scanner output, diagrams, coverage, and machine suggestions are review aids. "
            "They do not establish correctness, risk acceptance, or hazard-analysis completeness.\n",
            encoding="utf-8",
        )

        files = []
        for path in sorted([*(staging / name for name in outputs), readme]):
            raw = path.read_bytes()
            files.append(
                {
                    "path": path.name,
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        manifest = {
            "format": "pysfmea-review-package-1",
            "generated_at": utc_now(),
            "exporter": {"name": "PySFMEA", "version": __version__},
            "analysis_generator": package_analysis.get("generator", {}),
            "analysis_schema_version": package_analysis.get("schema_version", ""),
            "project": package_analysis.get("project", {}).get("name", ""),
            "baseline_id": package_analysis.get("project", {})
            .get("baseline", {})
            .get("id", ""),
            "portable": portable,
            "source_analysis": (
                Path(source_analysis).name
                if source_analysis and portable
                else str(Path(source_analysis).expanduser().resolve())
                if source_analysis
                else ""
            ),
            "files": files,
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        if package.exists():
            backup = package.with_name(f".{package.name}.previous-{uuid.uuid4().hex}")
            os.replace(package, backup)
        try:
            os.replace(staging, package)
        except Exception:
            if backup and backup.exists() and not package.exists():
                os.replace(backup, package)
                backup = None
            raise
        if backup and backup.exists():
            shutil.rmtree(backup)
            backup = None
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        if backup and backup.exists() and not package.exists():
            os.replace(backup, package)
    return package


def export_review_archive(
    analysis: dict[str, Any],
    destination: str | Path,
    *,
    source_analysis: str | Path | None = None,
    overwrite: bool = False,
    portable: bool = False,
) -> Path:
    """Atomically create a single-file ZIP containing a complete review package."""

    archive = Path(destination).expanduser().resolve()
    if archive.suffix.lower() != ".zip":
        raise ValueError("review package archive destination must end in .zip")
    if archive.exists():
        if archive.is_dir():
            raise ValueError(f"review package archive destination is a directory: {archive}")
        if not overwrite:
            raise ValueError(
                f"review package archive already exists: {archive}; use --force to replace it"
            )
    archive.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{archive.stem}.tmp-", dir=str(archive.parent))
    )
    try:
        package = export_review_package(
            analysis,
            staging / "package",
            source_analysis=source_analysis,
            portable=portable,
        )
        staged_archive = staging / archive.name
        with zipfile.ZipFile(
            staged_archive,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            allowZip64=True,
        ) as bundle:
            for path in sorted(package.iterdir(), key=lambda value: value.name):
                info = zipfile.ZipInfo(path.name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                bundle.writestr(info, path.read_bytes(), compresslevel=9)
        os.replace(staged_archive, archive)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return archive


def _portable_analysis_snapshot(analysis: dict[str, Any]) -> dict[str, Any]:
    """Copy an analysis while removing host-specific absolute path prefixes."""

    snapshot = copy.deepcopy(analysis)

    def basename(value: Any) -> str:
        return str(value or "").replace("\\", "/").rsplit("/", 1)[-1]

    project = snapshot.setdefault("project", {})
    project["root"] = "."
    settings = project.setdefault("settings", {})
    for field in ("config_file", "coverage_json"):
        if settings.get(field):
            settings[field] = basename(settings[field])
    for record in snapshot.get("runtime_evidence", {}).get("imports", []):
        if record.get("source"):
            record["source"] = basename(record["source"])
    for event in snapshot.get("history", []):
        if event.get("event") == "runtime_trace_import" and event.get("source"):
            event["source"] = basename(event["source"])
    return snapshot


def _verify_review_archive(source: Path) -> dict[str, Any]:
    """Validate and stage a ZIP package without trusting archive entry paths."""

    archive = source.absolute()
    findings: list[dict[str, str]] = []

    def add(rule_id: str, message: str, path: str = "") -> None:
        findings.append(
            {"rule_id": rule_id, "level": "error", "message": message, "path": path}
        )

    if not archive.is_file() or archive.is_symlink():
        add(
            "package.archive_missing",
            f"A regular ZIP review package is required: {archive}",
        )
        return _package_verification_result(
            archive, findings, 0, "", container="zip"
        )

    staging = Path(tempfile.mkdtemp(prefix="pysfmea-verify-"))
    try:
        try:
            with zipfile.ZipFile(archive, "r", allowZip64=True) as bundle:
                entries = bundle.infolist()
                if len(entries) > MAX_ARCHIVE_ENTRIES:
                    add(
                        "package.archive_entry_limit",
                        f"Archive contains more than {MAX_ARCHIVE_ENTRIES} entries.",
                    )
                names: set[str] = set()
                total_size = 0
                safe_entries: list[zipfile.ZipInfo] = []
                for entry in entries:
                    name = entry.filename
                    relative = PurePosixPath(name)
                    if (
                        not name
                        or "\\" in name
                        or relative.is_absolute()
                        or ".." in relative.parts
                        or relative.as_posix() != name
                        or len(relative.parts) != 1
                    ):
                        add(
                            "package.archive_path_unsafe",
                            "Archive entry is not a canonical root-level POSIX path.",
                            name,
                        )
                        continue
                    if name in names:
                        add(
                            "package.archive_entry_duplicate",
                            "Archive contains a duplicate entry name.",
                            name,
                        )
                        continue
                    names.add(name)
                    mode = (entry.external_attr >> 16) & 0o170000
                    if entry.is_dir() or mode not in (0, stat.S_IFREG):
                        add(
                            "package.archive_entry_type",
                            "Archive entries must be regular files, not directories or symbolic links.",
                            name,
                        )
                        continue
                    if entry.flag_bits & 0x1:
                        add(
                            "package.archive_encrypted",
                            "Encrypted archive entries are not supported.",
                            name,
                        )
                        continue
                    if entry.file_size > MAX_ARCHIVE_FILE_BYTES:
                        add(
                            "package.archive_file_limit",
                            f"Archive entry exceeds the {MAX_ARCHIVE_FILE_BYTES}-byte limit.",
                            name,
                        )
                        continue
                    total_size += entry.file_size
                    if (
                        entry.file_size > 1_000_000
                        and entry.file_size / max(entry.compress_size, 1) > 1_000
                    ):
                        add(
                            "package.archive_ratio_limit",
                            "Archive entry has an unsafe decompression ratio.",
                            name,
                        )
                        continue
                    safe_entries.append(entry)
                if total_size > MAX_ARCHIVE_TOTAL_BYTES:
                    add(
                        "package.archive_total_limit",
                        f"Archive expands beyond the {MAX_ARCHIVE_TOTAL_BYTES}-byte limit.",
                    )
                for name in sorted(REVIEW_PACKAGE_ALL_FILES - names):
                    add(
                        "package.archive_entry_missing",
                        "Required review-package entry is missing from the archive.",
                        name,
                    )
                for name in sorted(names - REVIEW_PACKAGE_ALL_FILES):
                    add(
                        "package.archive_entry_unexpected",
                        "Archive contains an entry outside the review-package format.",
                        name,
                    )
                if findings:
                    return _package_verification_result(
                        archive, findings, 0, "", container="zip"
                    )

                for entry in safe_entries:
                    target = staging / entry.filename
                    written = 0
                    with bundle.open(entry, "r") as source_file, target.open(
                        "wb"
                    ) as target_file:
                        while chunk := source_file.read(1024 * 1024):
                            written += len(chunk)
                            if written > entry.file_size or written > MAX_ARCHIVE_FILE_BYTES:
                                raise ValueError(
                                    f"archive entry expanded beyond its declared size: {entry.filename}"
                                )
                            target_file.write(chunk)
                    if written != entry.file_size:
                        raise ValueError(
                            f"archive entry size differs from its directory record: {entry.filename}"
                        )
        except (
            OSError,
            EOFError,
            RuntimeError,
            ValueError,
            zipfile.BadZipFile,
            zipfile.LargeZipFile,
        ) as exc:
            add("package.archive_invalid", f"Archive cannot be safely read: {exc}")
            return _package_verification_result(
                archive, findings, 0, "", container="zip"
            )

        result = verify_review_package(staging)
        result["package"] = str(archive)
        result["container"] = "zip"
        result["archive_sha256"] = _sha256_file(archive)
        return result
    finally:
        shutil.rmtree(staging)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def verify_review_package(source: str | Path) -> dict[str, Any]:
    """Verify a review package without trusting paths or package content."""

    supplied = Path(source).expanduser().absolute()
    if supplied.suffix.lower() == ".zip":
        return _verify_review_archive(supplied)
    package = supplied.resolve()
    findings: list[dict[str, str]] = []

    def add(rule_id: str, level: str, message: str, path: str = "") -> None:
        findings.append(
            {"rule_id": rule_id, "level": level, "message": message, "path": path}
        )

    if not package.is_dir():
        add("package.directory", "error", f"Package directory does not exist: {package}")
        return _package_verification_result(package, findings, 0, "")
    manifest_path = package / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        add("package.manifest_missing", "error", "A regular manifest.json file is required.")
        return _package_verification_result(package, findings, 0, "")
    try:
        if manifest_path.stat().st_size > 5_000_000:
            raise ValueError("manifest exceeds the 5 MB limit")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        add("package.manifest_invalid", "error", f"Manifest cannot be read: {exc}")
        return _package_verification_result(package, findings, 0, "")
    if not isinstance(manifest, dict):
        add("package.manifest_invalid", "error", "Manifest root must be a JSON object.")
        return _package_verification_result(package, findings, 0, "")
    package_format = str(manifest.get("format", ""))
    if package_format != "pysfmea-review-package-1":
        add(
            "package.format_unsupported",
            "error",
            f"Unsupported or missing package format: {package_format or '<blank>'}",
        )
    entries = manifest.get("files", [])
    if not isinstance(entries, list) or len(entries) > 10_000:
        add(
            "package.file_list_invalid",
            "error",
            "Manifest files must be a list with at most 10,000 entries.",
        )
        return _package_verification_result(package, findings, 0, package_format)

    exporter = manifest.get("exporter")
    metadata_valid = (
        isinstance(manifest.get("generated_at"), str)
        and bool(manifest["generated_at"])
        and isinstance(exporter, dict)
        and isinstance(exporter.get("name"), str)
        and bool(exporter["name"])
        and isinstance(exporter.get("version"), str)
        and bool(exporter["version"])
        and isinstance(manifest.get("analysis_schema_version"), str)
        and isinstance(manifest.get("project"), str)
        and isinstance(manifest.get("baseline_id"), str)
        and isinstance(manifest.get("portable"), bool)
        and isinstance(manifest.get("source_analysis"), str)
    )
    if not metadata_valid:
        add(
            "package.manifest_metadata_invalid",
            "error",
            "Manifest provenance, project, baseline, portability, or source metadata is malformed.",
        )

    listed: set[str] = set()
    checked = 0
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            add(
                "package.file_entry_invalid",
                "error",
                f"Manifest file entry {index} must be an object.",
            )
            continue
        relative_name = entry.get("path", "")
        if not isinstance(relative_name, str) or not relative_name or "\\" in relative_name:
            add(
                "package.path_invalid",
                "error",
                f"Manifest file entry {index} has an invalid POSIX relative path.",
                str(relative_name),
            )
            continue
        relative = PurePosixPath(relative_name)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative_name == "manifest.json"
            or relative.as_posix() != relative_name
        ):
            add(
                "package.path_unsafe",
                "error",
                "Manifest path is absolute, traverses the package, or names the manifest.",
                relative_name,
            )
            continue
        if relative_name in listed:
            add(
                "package.path_duplicate",
                "error",
                "Manifest contains a duplicate file path.",
                relative_name,
            )
            continue
        listed.add(relative_name)
        target = package.joinpath(*relative.parts)
        try:
            resolved = target.resolve()
            resolved.relative_to(package)
        except (OSError, ValueError):
            add(
                "package.path_unsafe",
                "error",
                "Manifest path resolves outside the package.",
                relative_name,
            )
            continue
        if target.is_symlink():
            add(
                "package.symlink",
                "error",
                "Package files must not be symbolic links.",
                relative_name,
            )
            continue
        if not target.is_file():
            add(
                "package.file_missing",
                "error",
                "Manifested file is missing or is not a regular file.",
                relative_name,
            )
            continue
        expected_size = entry.get("bytes")
        expected_hash = entry.get("sha256")
        if (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size < 0
            or not isinstance(expected_hash, str)
            or len(expected_hash) != 64
            or any(character not in "0123456789abcdefABCDEF" for character in expected_hash)
        ):
            add(
                "package.file_metadata_invalid",
                "error",
                "Manifest file size or SHA-256 value is invalid.",
                relative_name,
            )
            continue
        try:
            raw = target.read_bytes()
        except OSError as exc:
            add(
                "package.file_unreadable",
                "error",
                f"Manifested file cannot be read: {exc}",
                relative_name,
            )
            continue
        checked += 1
        if len(raw) != expected_size:
            add(
                "package.size_mismatch",
                "error",
                f"Expected {expected_size} bytes but found {len(raw)}.",
                relative_name,
            )
        actual_hash = hashlib.sha256(raw).hexdigest()
        if actual_hash.lower() != expected_hash.lower():
            add(
                "package.checksum_mismatch",
                "error",
                "SHA-256 checksum does not match the manifest.",
                relative_name,
            )

    for relative_name in sorted(REVIEW_PACKAGE_FILES - listed):
        add(
            "package.required_file_missing",
            "error",
            "Required review artifact is not recorded in the manifest.",
            relative_name,
        )
    for relative_name in sorted(listed - REVIEW_PACKAGE_FILES):
        add(
            "package.file_unrecognized",
            "error",
            "Manifest records a file that is not part of this package format.",
            relative_name,
        )

    actual_files: set[str] = set()
    try:
        for path in package.rglob("*"):
            relative_name = path.relative_to(package).as_posix()
            if path.is_symlink():
                add(
                    "package.symlink",
                    "error",
                    "Package entries must not be symbolic links.",
                    relative_name,
                )
            elif path.is_file() and relative_name != "manifest.json":
                actual_files.add(relative_name)
    except OSError as exc:
        add(
            "package.directory_unreadable",
            "error",
            f"Package contents cannot be enumerated: {exc}",
        )
    for relative_name in sorted(actual_files - listed):
        add(
            "package.file_unexpected",
            "error",
            "File is present but not recorded in the manifest.",
            relative_name,
        )

    analysis_path = package / "analysis.json"
    if "analysis.json" in listed and analysis_path.is_file() and not analysis_path.is_symlink():
        try:
            analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
            if not isinstance(analysis, dict):
                raise ValueError("analysis root is not an object")
            analysis_baseline = (
                analysis.get("project", {}).get("baseline", {}).get("id", "")
            )
            if analysis_baseline != manifest.get("baseline_id", ""):
                add(
                    "package.baseline_mismatch",
                    "error",
                    "Analysis baseline does not match the manifest baseline.",
                    "analysis.json",
                )
            if analysis.get("schema_version", "") != manifest.get(
                "analysis_schema_version", ""
            ):
                add(
                    "package.schema_mismatch",
                    "error",
                    "Analysis schema version does not match the manifest.",
                    "analysis.json",
                )
            manifest_generator = manifest.get("analysis_generator")
            if manifest_generator is None:
                add(
                    "package.provenance_missing",
                    "warning",
                    "Manifest does not record analysis-generator provenance.",
                )
            elif analysis.get("generator", {}) != manifest_generator:
                add(
                    "package.provenance_mismatch",
                    "error",
                    "Analysis generator provenance does not match the manifest.",
                    "analysis.json",
                )
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            add(
                "package.analysis_invalid",
                "error",
                f"Packaged analysis cannot be read: {exc}",
                "analysis.json",
            )
    return _package_verification_result(package, findings, checked, package_format)


def _package_verification_result(
    package: Path,
    findings: list[dict[str, str]],
    checked: int,
    package_format: str,
    *,
    container: str = "directory",
) -> dict[str, Any]:
    errors = sum(value["level"] == "error" for value in findings)
    warnings = sum(value["level"] == "warning" for value in findings)
    return {
        "package": str(package),
        "container": container,
        "format": package_format,
        "valid": errors == 0,
        "checked_files": checked,
        "counts": {"error": errors, "warning": warnings},
        "findings": findings,
        "notice": "Integrity verification proves recorded bytes and provenance consistency, not engineering approval or semantic correctness.",
    }
