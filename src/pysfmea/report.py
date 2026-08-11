"""CSV and Markdown export for reviewed SFMEA data."""

from __future__ import annotations

import copy
import csv
import hashlib
import html
import io
import json
import os
import re
import shutil
import stat
import tempfile
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .architecture import export_architecture
from .assurance import (
    ensure_assurance_register,
    export_assurance_register,
    verify_assurance_register,
    verify_assurance_work_queue_file,
)
from .config import DEFAULT_CONFIG, normalize_config
from .file_publication import atomic_publish_text
from .guidance import guidance_traceability
from .integrity import (
    MAX_GOVERNED_JSON_DEPTH,
    bounded_json_structure_metrics,
    canonical_json_sha256,
)
from .interchange import cyclonedx_document, sarif_document
from .manifest import current_audit_manifest
from .model import calculate_rpn, utc_now
from .publication import (
    PUBLICATION_FAILURE_CATALOG_ALGORITHM,
    PUBLICATION_FAILURE_CATALOG_CANONICALIZATION,
    PUBLICATION_FAILURE_CATALOG_FORMAT,
    PUBLICATION_FAILURE_CATALOG_SHA256,
    classify_publication_failure,
)
from .repository_inventory import repository_inventory_summary_projection
from .schema_registry import PUBLIC_SCHEMA_BUNDLE_FILES
from .sfta import SFTA_GAP_FIELDS, build_sfta, export_sfta, sfta_gap_rows
from .validation import validate_analysis
from .version import __version__
from .visuals import export_coverage, export_traceability

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
    "citation_ids",
    "citation_relationships",
    "citation_applicability",
    "adapter_ids",
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
    "operational_mode",
    "operational_state",
    "causes",
    "local_effect",
    "next_higher_effect",
    "end_effect",
    "required_safe_state",
    "degraded_behavior",
    "recovery_behavior",
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
    "residual_risk",
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
    "citations.json",
    "guidance-traceability.json",
    "guidance-traceability.csv",
    "assurance-register.json",
    "assurance-work.json",
    "assurance-register.csv",
    "assurance-register.md",
    "evidence-catalog.json",
    "sfta.json",
    "sfta-gaps.csv",
    "findings.sarif",
    "components.cdx.json",
    "run-manifest.json",
    "system-context.json",
    "repository-inventory.json",
    "adapter-runs.json",
    "README.md",
}
LEGACY_REVIEW_PACKAGE_FILES = REVIEW_PACKAGE_FILES - {"assurance-work.json"}
REVIEW_PACKAGE_SCHEMA_FILES = PUBLIC_SCHEMA_BUNDLE_FILES
REVIEW_PACKAGE_ALLOWED_FILES = REVIEW_PACKAGE_FILES | REVIEW_PACKAGE_SCHEMA_FILES
REVIEW_PACKAGE_ALL_FILES = REVIEW_PACKAGE_ALLOWED_FILES | {"manifest.json"}
MAX_ARCHIVE_ENTRIES = 100
MAX_ARCHIVE_FILE_BYTES = 200_000_000
MAX_ARCHIVE_TOTAL_BYTES = 500_000_000
MAX_ANALYSIS_JSON_DEPTH = MAX_GOVERNED_JSON_DEPTH
MAX_ANALYSIS_JSON_NODES = 5_000_000
REVIEW_PACKAGE_FORMAT = "pysfmea-review-package-1"
REVIEW_PACKAGE_VERIFICATION_FORMAT = "pysfmea-review-package-verification-1"
ANALYSIS_STRUCTURE_VERIFICATION_FORMAT = "pysfmea-analysis-structure-verification-1"
ANALYSIS_DIAGNOSTICS_VERIFICATION_FORMAT = "pysfmea-analysis-diagnostics-verification-1"
GUIDANCE_TRACEABILITY_VERIFICATION_FORMAT = (
    "pysfmea-guidance-traceability-verification-1"
)
SFTA_PROJECTION_VERIFICATION_FORMAT = "pysfmea-sfta-projection-verification-1"
EVIDENCE_CATALOG_VERIFICATION_FORMAT = "pysfmea-evidence-catalog-verification-1"
INTERCHANGE_ARTIFACTS_VERIFICATION_FORMAT = (
    "pysfmea-interchange-artifacts-verification-1"
)
REVIEW_VIEWS_VERIFICATION_FORMAT = "pysfmea-review-views-verification-1"
PACKAGE_PROVENANCE_VERIFICATION_FORMAT = "pysfmea-package-provenance-verification-1"
ASSURANCE_WORK_QUEUE_PACKAGE_VERSION = (0, 47, 0)
CAPABILITY_DECLARATION_PACKAGE_VERSION = (0, 48, 0)
ASSURANCE_REGISTER_PACKAGE_VERSION = (0, 49, 0)
ANALYSIS_DIAGNOSTICS_PACKAGE_VERSION = (0, 50, 0)
GUIDANCE_TRACEABILITY_PACKAGE_VERSION = (0, 52, 0)
SFTA_PROJECTION_PACKAGE_VERSION = (0, 53, 0)
EVIDENCE_CATALOG_PACKAGE_VERSION = (0, 54, 0)
INTERCHANGE_ARTIFACTS_PACKAGE_VERSION = (0, 55, 0)
REVIEW_VIEWS_PACKAGE_VERSION = (0, 56, 0)
PACKAGE_PROVENANCE_VERSION = (0, 57, 0)
SFTA_EXACT_SELECTOR_VERSION = (0, 57, 2)
RECONCILED_INVENTORY_VIEWS_VERSION = (0, 57, 65)
REVIEW_PACKAGE_CAPABILITIES = (
    "analysis_diagnostics_projection_v1",
    "assurance_register_projection",
    "assurance_work_queue_projection",
    "evidence_catalog_projection_v1",
    "guidance_traceability_projection_v1",
    "interchange_artifacts_projection_v1",
    "package_provenance_projection_v1",
    "review_views_projection_v1",
    "sfta_projection_v1",
)
ANALYSIS_DIAGNOSTIC_FILES = {
    "summary": "summary.json",
    "validation": "validation.json",
    "system_context": "system-context.json",
    "repository_inventory": "repository-inventory.json",
    "adapter_runs": "adapter-runs.json",
}


def _package_version_at_least(value: Any, minimum: tuple[int, int, int]) -> bool:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", str(value or ""))
    return bool(match and tuple(int(part) for part in match.groups()) >= minimum)


def _package_requires_assurance_work_queue(manifest: dict[str, Any]) -> bool:
    capabilities = manifest.get("capabilities", [])
    if (
        isinstance(capabilities, list)
        and "assurance_work_queue_projection" in capabilities
    ):
        return True
    versions = (
        manifest.get("exporter", {}).get("version", ""),
        manifest.get("analysis_generator", {}).get("version", ""),
    )
    return any(
        _package_version_at_least(value, ASSURANCE_WORK_QUEUE_PACKAGE_VERSION)
        for value in versions
    )


def _package_requires_assurance_register_projection(
    manifest: dict[str, Any],
) -> bool:
    capabilities = manifest.get("capabilities", [])
    if (
        isinstance(capabilities, list)
        and "assurance_register_projection" in capabilities
    ):
        return True
    versions = (
        manifest.get("exporter", {}).get("version", ""),
        manifest.get("analysis_generator", {}).get("version", ""),
    )
    return any(
        _package_version_at_least(value, ASSURANCE_REGISTER_PACKAGE_VERSION)
        for value in versions
    )


def _package_requires_analysis_diagnostics_projection(
    manifest: dict[str, Any],
) -> bool:
    capabilities = manifest.get("capabilities", [])
    if (
        isinstance(capabilities, list)
        and "analysis_diagnostics_projection_v1" in capabilities
    ):
        return True
    versions = (
        manifest.get("exporter", {}).get("version", ""),
        manifest.get("analysis_generator", {}).get("version", ""),
    )
    return any(
        _package_version_at_least(value, ANALYSIS_DIAGNOSTICS_PACKAGE_VERSION)
        for value in versions
    )


def _package_requires_guidance_traceability_projection(
    manifest: dict[str, Any],
) -> bool:
    capabilities = manifest.get("capabilities", [])
    if (
        isinstance(capabilities, list)
        and "guidance_traceability_projection_v1" in capabilities
    ):
        return True
    versions = (
        manifest.get("exporter", {}).get("version", ""),
        manifest.get("analysis_generator", {}).get("version", ""),
    )
    return any(
        _package_version_at_least(value, GUIDANCE_TRACEABILITY_PACKAGE_VERSION)
        for value in versions
    )


def _package_requires_sfta_projection(manifest: dict[str, Any]) -> bool:
    capabilities = manifest.get("capabilities", [])
    if isinstance(capabilities, list) and "sfta_projection_v1" in capabilities:
        return True
    versions = (
        manifest.get("exporter", {}).get("version", ""),
        manifest.get("analysis_generator", {}).get("version", ""),
    )
    return any(
        _package_version_at_least(value, SFTA_PROJECTION_PACKAGE_VERSION)
        for value in versions
    )


def _package_requires_evidence_catalog_projection(manifest: dict[str, Any]) -> bool:
    capabilities = manifest.get("capabilities", [])
    if (
        isinstance(capabilities, list)
        and "evidence_catalog_projection_v1" in capabilities
    ):
        return True
    versions = (
        manifest.get("exporter", {}).get("version", ""),
        manifest.get("analysis_generator", {}).get("version", ""),
    )
    return any(
        _package_version_at_least(value, EVIDENCE_CATALOG_PACKAGE_VERSION)
        for value in versions
    )


def _package_requires_interchange_artifacts_projection(
    manifest: dict[str, Any],
) -> bool:
    capabilities = manifest.get("capabilities", [])
    if (
        isinstance(capabilities, list)
        and "interchange_artifacts_projection_v1" in capabilities
    ):
        return True
    versions = (
        manifest.get("exporter", {}).get("version", ""),
        manifest.get("analysis_generator", {}).get("version", ""),
    )
    return any(
        _package_version_at_least(value, INTERCHANGE_ARTIFACTS_PACKAGE_VERSION)
        for value in versions
    )


def _package_requires_review_views_projection(manifest: dict[str, Any]) -> bool:
    capabilities = manifest.get("capabilities", [])
    if isinstance(capabilities, list) and "review_views_projection_v1" in capabilities:
        return True
    versions = (
        manifest.get("exporter", {}).get("version", ""),
        manifest.get("analysis_generator", {}).get("version", ""),
    )
    return any(
        _package_version_at_least(value, REVIEW_VIEWS_PACKAGE_VERSION)
        for value in versions
    )


def _package_requires_provenance_projection(manifest: dict[str, Any]) -> bool:
    capabilities = manifest.get("capabilities", [])
    if (
        isinstance(capabilities, list)
        and "package_provenance_projection_v1" in capabilities
    ):
        return True
    versions = (
        manifest.get("exporter", {}).get("version", ""),
        manifest.get("analysis_generator", {}).get("version", ""),
    )
    return any(
        _package_version_at_least(value, PACKAGE_PROVENANCE_VERSION)
        for value in versions
    )


def _required_package_capabilities(manifest: dict[str, Any]) -> set[str]:
    """Return capabilities required by the package's declared producer generation."""

    versions = (
        manifest.get("exporter", {}).get("version", ""),
        manifest.get("analysis_generator", {}).get("version", ""),
    )
    required: set[str] = set()
    if any(
        _package_version_at_least(value, CAPABILITY_DECLARATION_PACKAGE_VERSION)
        for value in versions
    ):
        required.add("assurance_work_queue_projection")
    if any(
        _package_version_at_least(value, ASSURANCE_REGISTER_PACKAGE_VERSION)
        for value in versions
    ):
        required.add("assurance_register_projection")
    if any(
        _package_version_at_least(value, ANALYSIS_DIAGNOSTICS_PACKAGE_VERSION)
        for value in versions
    ):
        required.add("analysis_diagnostics_projection_v1")
    if any(
        _package_version_at_least(value, GUIDANCE_TRACEABILITY_PACKAGE_VERSION)
        for value in versions
    ):
        required.add("guidance_traceability_projection_v1")
    if any(
        _package_version_at_least(value, SFTA_PROJECTION_PACKAGE_VERSION)
        for value in versions
    ):
        required.add("sfta_projection_v1")
    if any(
        _package_version_at_least(value, EVIDENCE_CATALOG_PACKAGE_VERSION)
        for value in versions
    ):
        required.add("evidence_catalog_projection_v1")
    if any(
        _package_version_at_least(value, INTERCHANGE_ARTIFACTS_PACKAGE_VERSION)
        for value in versions
    ):
        required.add("interchange_artifacts_projection_v1")
    if any(
        _package_version_at_least(value, REVIEW_VIEWS_PACKAGE_VERSION)
        for value in versions
    ):
        required.add("review_views_projection_v1")
    if any(
        _package_version_at_least(value, PACKAGE_PROVENANCE_VERSION)
        for value in versions
    ):
        required.add("package_provenance_projection_v1")
    return required


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


def _write_csv_row(writer: csv.DictWriter[str], row: dict[str, Any]) -> None:
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
    citation_links = [
        link for link in scanner.get("citations", []) if isinstance(link, dict)
    ]
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
        "validated_context_fingerprint": review.get(
            "validated_context_fingerprint", ""
        ),
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
        "citation_ids": _join(
            [str(link.get("citation_id", "")) for link in citation_links]
        ),
        "citation_relationships": _join(
            [str(link.get("relationship", "")) for link in citation_links]
        ),
        "citation_applicability": _join(
            [str(link.get("applicability", "")) for link in citation_links]
        ),
        "adapter_ids": _join(scanner.get("adapter_ids", [])),
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
        "operational_mode": review.get("operational_mode", ""),
        "operational_state": review.get("operational_state", ""),
        "causes": _join(review.get("causes", [])),
        "local_effect": review.get("local_effect", ""),
        "next_higher_effect": review.get("next_higher_effect", ""),
        "end_effect": review.get("end_effect", ""),
        "required_safe_state": review.get("required_safe_state", ""),
        "degraded_behavior": review.get("degraded_behavior", ""),
        "recovery_behavior": review.get("recovery_behavior", ""),
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
        "post_action_severity_category": review.get(
            "post_action_severity_category", ""
        ),
        "post_action_severity_rationale": review.get(
            "post_action_severity_rationale", ""
        ),
        "post_action_occurrence": review.get("post_action_occurrence", ""),
        "post_action_occurrence_rationale": review.get(
            "post_action_occurrence_rationale", ""
        ),
        "post_action_detection": review.get("post_action_detection", ""),
        "post_action_detection_rationale": review.get(
            "post_action_detection_rationale", ""
        ),
        "post_action_rpn": calculate_rpn(item, post_action=True) or "",
        "residual_risk": review.get("residual_risk", ""),
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


def export_csv(
    analysis: dict[str, Any],
    destination: str | Path,
    *,
    legacy_sfta_id_wildcard: bool = False,
) -> Path:
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    findings_by_item: dict[str, list[dict[str, Any]]] = {}
    for finding in validate_analysis(
        analysis, legacy_sfta_id_wildcard=legacy_sfta_id_wildcard
    )["findings"]:
        findings_by_item.setdefault(finding["item_id"], []).append(finding)
    for item in analysis.get("items", []):
        _write_csv_row(
            writer,
            item_row(
                item,
                findings_by_item.get(item.get("id", ""), []),
                analysis.get("project", {}).get("baseline", {}).get("id", ""),
            ),
        )
    return atomic_publish_text(
        destination,
        handle.getvalue(),
        encoding="utf-8-sig",
        label="SFMEA CSV export",
    )


def _markdown_text(value: Any) -> str:
    return html.escape(_join(value), quote=False)


def _cell(value: Any, limit: int = 160) -> str:
    text = _markdown_text(value).replace("|", "\\|").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def export_markdown(
    analysis: dict[str, Any],
    destination: str | Path,
    *,
    legacy_sfta_id_wildcard: bool = False,
) -> Path:
    project = analysis.get("project", {})
    summary = analysis.get("summary", {})
    validation = validate_analysis(
        analysis, legacy_sfta_id_wildcard=legacy_sfta_id_wildcard
    )
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
        "| ID | Change | Revalidate | Component | Failure mode | End effect | Guidance | S | O | D | RPN | Post RPN | Disposition | Status |",
        "|---|---|---|---|---|---|---|---:|---:|---:|---:|---:|---|---|",
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
                    _cell(
                        [
                            link.get("citation_id", "")
                            for link in scanner.get("citations", [])
                            if isinstance(link, dict)
                        ]
                    ),
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
        lines.append(
            f"- [{source.get('title')}]({source.get('url')}) — {source.get('use')}"
        )
    return atomic_publish_text(
        destination,
        "\n".join(lines) + "\n",
        label="SFMEA Markdown export",
    )


GUIDANCE_TRACEABILITY_FIELDS = [
    "finding_id",
    "component_id",
    "component",
    "path",
    "line",
    "rule_id",
    "failure_class",
    "citation_id",
    "source_id",
    "document_title",
    "document_version",
    "document_status",
    "relationship",
    "strength",
    "applicability",
    "section",
    "heading",
    "page",
    "summary",
    "url",
    "mapping_id",
    "mapping_status",
]


def export_guidance_traceability(
    analysis: dict[str, Any], destination: str | Path, *, format: str = "json"
) -> Path:
    """Export the versioned guidance catalog and source-to-finding relationships."""

    if format not in {"json", "csv"}:
        raise ValueError("guidance traceability format must be json or csv")
    trace = guidance_traceability(analysis)
    if format == "json":
        return atomic_publish_text(
            destination,
            json.dumps(trace, indent=2, ensure_ascii=False) + "\n",
            label="guidance traceability JSON export",
        )

    citations = {value["id"]: value for value in trace["citations"]}
    sources = {value["id"]: value for value in trace["sources"]}
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=GUIDANCE_TRACEABILITY_FIELDS)
    writer.writeheader()
    for finding in trace["finding_links"]:
        links = finding["citations"] or [{}]
        for link in links:
            citation = citations.get(link.get("citation_id", ""), {})
            source = sources.get(citation.get("source_id", ""), {})
            locator = citation.get("locator", {})
            _write_csv_row(
                writer,
                {
                    "finding_id": finding.get("finding_id", ""),
                    "component_id": finding.get("component_id", ""),
                    "component": finding.get("component", ""),
                    "path": finding.get("source", {}).get("path", ""),
                    "line": finding.get("source", {}).get("line", ""),
                    "rule_id": finding.get("rule_id", ""),
                    "failure_class": finding.get("failure_class", ""),
                    "citation_id": citation.get("id", ""),
                    "source_id": source.get("id", ""),
                    "document_title": source.get("title", ""),
                    "document_version": source.get("version", ""),
                    "document_status": source.get("status", ""),
                    "relationship": link.get("relationship", ""),
                    "strength": link.get("strength", ""),
                    "applicability": link.get("applicability", ""),
                    "section": locator.get("section", ""),
                    "heading": locator.get("heading", ""),
                    "page": locator.get("page", ""),
                    "summary": citation.get("summary", ""),
                    "url": citation.get("url") or source.get("url", ""),
                    "mapping_id": link.get("mapping_id", ""),
                    "mapping_status": link.get("status", ""),
                },
            )
    return atomic_publish_text(
        destination,
        handle.getvalue(),
        encoding="utf-8-sig",
        label="guidance traceability CSV export",
    )


def export_audit(analysis: dict[str, Any], destination: str | Path) -> Path:
    """Export analysis-level and item-level lifecycle history as a flat CSV."""

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
    handle = io.StringIO(newline="")
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
            },
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
                    },
                )
    return atomic_publish_text(
        destination,
        handle.getvalue(),
        encoding="utf-8-sig",
        label="SFMEA audit CSV export",
    )


def export_inventory(
    analysis: dict[str, Any],
    destination: str | Path,
    *,
    include_repository_accounting: bool = True,
) -> Path:
    """Export the system-definition and component worksheet supporting the SFMEA."""

    context = analysis.get("context", {})
    project = dict(context.get("project", {}))
    analysis_context = dict(context.get("analysis", {}))
    for field in ("purpose", "boundary", "operating_context"):
        if project.get(field):
            project[field] = _markdown_text(project[field])
    for field in ("phase", "revision"):
        if analysis_context.get(field):
            analysis_context[field] = _markdown_text(analysis_context[field])
    repository = repository_inventory_summary_projection(
        analysis.get("repository_inventory", {})
    )
    repository_summary = repository["summary"]
    repository_status = repository_summary.get("by_status", {})
    snapshot_counts = repository_summary.get("by_snapshot_source", {})
    snapshot_text = (
        ", ".join(f"{name}={count}" for name, count in sorted(snapshot_counts.items()))
        or "unavailable"
    )
    semantic_coverage = repository_summary.get("semantic_coverage_percent")
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
    ]
    if include_repository_accounting:
        lines.extend(
            [
                "## Repository artifact accounting",
                "",
                f"- Reconciliation: {repository['status']}",
                f"- Files: {repository_summary.get('files', 'unavailable')}",
                f"- Regions: {repository_summary.get('regions', 'unavailable')}",
                f"- Semantically analyzed: {repository_status.get('analyzed', 'unavailable')}",
                f"- Indexed: {repository_status.get('indexed', 'unavailable')}",
                f"- Opaque or unresolved: {repository_summary.get('opaque_or_unresolved', 'unavailable')}",
                "- Semantic accounting coverage: "
                + (f"{semantic_coverage}%" if semantic_coverage is not None else "n/a"),
                f"- Snapshot provenance: {snapshot_text}",
                "",
                "> " + repository["notice"],
                "",
            ]
        )
    lines.extend(["## Ground rules and assumptions", ""])
    lines[0] = "# SFMEA system and component inventory - " + _markdown_text(
        analysis.get("project", {}).get("name", "")
    )
    ground_rules = analysis_context.get("ground_rules", [])
    assumptions = [
        *project.get("assumptions", []),
        *analysis_context.get("fault_tolerance_assumptions", []),
    ]
    lines.extend(
        f"- {_markdown_text(value)}" for value in [*ground_rules, *assumptions]
    )
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
        lines.append(
            "| "
            + " | ".join(column.replace("_", " ").title() for column in columns)
            + " |"
        )
        lines.append("|" + "|".join("---" for _column in columns) + "|")
        for value in values:
            lines.append(
                "| " + " | ".join(_cell(value.get(column)) for column in columns) + " |"
            )
    return atomic_publish_text(
        destination,
        "\n".join(lines) + "\n",
        label="SFMEA inventory Markdown export",
    )


def evidence_catalog_document(analysis: dict[str, Any]) -> dict[str, Any]:
    """Build the deterministic package-time execution-evidence catalog."""

    assurance = analysis.get("assurance", {})
    return {
        "baseline_id": analysis.get("project", {}).get("baseline", {}).get("id", ""),
        "executions": copy.deepcopy(assurance.get("executions", [])),
        "evidence_artifacts": copy.deepcopy(assurance.get("evidence_artifacts", [])),
        "notice": (
            "Catalog records execution and artifact provenance. Raw external evidence files "
            "must be transferred and verified separately unless an organization-approved "
            "package profile includes them."
        ),
    }


def _review_package_readme(
    analysis: dict[str, Any],
    *,
    portable: bool,
    generated_at: str,
    exporter_version: str,
) -> str:
    project = analysis.get("project", {})
    return (
        "# PySFMEA review package\n\n"
        f"- Project: {project.get('name', '')}\n"
        f"- Baseline: {project.get('baseline', {}).get('id', '')}\n"
        f"- Generated by: PySFMEA {exporter_version}\n"
        f"- Portable paths: {'yes' if portable else 'no'}\n"
        f"- Generated: {generated_at}\n\n"
        "This package contains the governed JSON analysis, resolved system context, "
        "repository coverage and adapter-run provenance, worksheets, inventory, "
        "architecture and traceability views, executable assurance contracts, a "
        "standalone integrity-bound hardening queue, guidance citations, coverage metrics, "
        "validation findings, audit history, and the exact offline JSON Schema contracts "
        "for diagrams, package manifests, and verifier verdicts. Checksums are recorded "
        "in `manifest.json`.\n\n"
        "After transfer or storage, run `sfmea verify-package .` from this directory "
        "to check the complete file set, checksums, analysis provenance, and exact "
        "diagnostic, guidance, SFTA, evidence, interchange, package-provenance, "
        "review-view, assurance-register, and assurance-work projections.\n\n"
        "> Scanner output, diagrams, coverage, and machine suggestions are review aids. "
        "They do not establish correctness, risk acceptance, or hazard-analysis "
        "completeness.\n"
    )


def export_review_package(
    analysis: dict[str, Any],
    destination: str | Path,
    *,
    source_analysis: str | Path | None = None,
    overwrite: bool = False,
    portable: bool = False,
) -> Path:
    """Create a checksum-manifested, human- and machine-readable review package."""

    from .schemas import SCHEMA_CATALOG_FORMAT, schema_bundle_documents

    package = Path(destination).expanduser().resolve()
    package_analysis = (
        _portable_analysis_snapshot(analysis) if portable else copy.deepcopy(analysis)
    )
    ensure_assurance_register(package_analysis)
    package_analysis["sfta"] = build_sfta(package_analysis)
    schema_documents = schema_bundle_documents()
    if set(schema_documents) != REVIEW_PACKAGE_SCHEMA_FILES:
        raise RuntimeError(
            "public schema bundle does not match review-package contract"
        )
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
    package_generated_at = utc_now()
    backup: Path | None = None
    try:
        outputs: dict[str, Callable[[Path], Any]] = {
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
            "citations.json": lambda path: path.write_text(
                json.dumps(
                    guidance_traceability(package_analysis).get("citations", []),
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            ),
            "guidance-traceability.json": lambda path: export_guidance_traceability(
                package_analysis, path, format="json"
            ),
            "guidance-traceability.csv": lambda path: export_guidance_traceability(
                package_analysis, path, format="csv"
            ),
            "assurance-register.json": lambda path: export_assurance_register(
                package_analysis, path, format="json"
            ),
            "assurance-work.json": lambda path: export_assurance_register(
                package_analysis, path, format="work-json"
            ),
            "assurance-register.csv": lambda path: export_assurance_register(
                package_analysis, path, format="csv"
            ),
            "assurance-register.md": lambda path: export_assurance_register(
                package_analysis, path, format="markdown"
            ),
            "evidence-catalog.json": lambda path: path.write_text(
                json.dumps(
                    evidence_catalog_document(package_analysis),
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            ),
            "sfta.json": lambda path: export_sfta(
                package_analysis, path, format="json"
            ),
            "sfta-gaps.csv": lambda path: export_sfta(
                package_analysis, path, format="csv"
            ),
            "findings.sarif": lambda path: path.write_text(
                json.dumps(
                    sarif_document(package_analysis), indent=2, ensure_ascii=False
                )
                + "\n",
                encoding="utf-8",
            ),
            "components.cdx.json": lambda path: path.write_text(
                json.dumps(
                    cyclonedx_document(
                        package_analysis, generated_at=package_generated_at
                    ),
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            ),
            "run-manifest.json": lambda path: path.write_text(
                json.dumps(
                    current_audit_manifest(
                        package_analysis,
                        generated_at=package_generated_at,
                        tool_version=__version__,
                    ),
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            ),
            "system-context.json": lambda path: path.write_text(
                json.dumps(
                    package_analysis.get("system_context", {}),
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            ),
            "repository-inventory.json": lambda path: path.write_text(
                json.dumps(
                    package_analysis.get("repository_inventory", {}),
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            ),
            "adapter-runs.json": lambda path: path.write_text(
                json.dumps(
                    package_analysis.get("adapter_runs", {}),
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            ),
        }
        for filename, writer in outputs.items():
            writer(staging / filename)
        for filename, document in schema_documents.items():
            (staging / filename).write_text(
                json.dumps(document, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

        readme = staging / "README.md"
        readme.write_text(
            _review_package_readme(
                package_analysis,
                portable=portable,
                generated_at=package_generated_at,
                exporter_version=__version__,
            ),
            encoding="utf-8",
        )

        files = []
        for path in sorted(
            [
                *(staging / name for name in outputs),
                *(staging / name for name in schema_documents),
                readme,
            ]
        ):
            raw = path.read_bytes()
            files.append(
                {
                    "path": path.name,
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        manifest = {
            "format": REVIEW_PACKAGE_FORMAT,
            "generated_at": package_generated_at,
            "exporter": {"name": "PySFMEA", "version": __version__},
            "analysis_generator": package_analysis.get("generator", {}),
            "analysis_schema_version": package_analysis.get("schema_version", ""),
            "project": package_analysis.get("project", {}).get("name", ""),
            "baseline_id": package_analysis.get("project", {})
            .get("baseline", {})
            .get("id", ""),
            "analysis_state_sha256": analysis_state_sha256(package_analysis),
            "capabilities": list(REVIEW_PACKAGE_CAPABILITIES),
            "schema_catalog": {
                "format": SCHEMA_CATALOG_FORMAT,
                "path": "schema-catalog.json",
                "canonical_sha256": canonical_json_sha256(
                    schema_documents["schema-catalog.json"]
                ),
                "schema_count": len(schema_documents) - 1,
            },
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

        _require_generated_package_verification(staging)

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


def _require_generated_package_verification(package: Path) -> None:
    verification = verify_review_package(package)
    if verification.get("valid"):
        return
    rule_ids = sorted(
        {
            str(finding.get("rule_id", "")).strip()
            for finding in verification.get("findings", [])
            if isinstance(finding, dict) and str(finding.get("rule_id", "")).strip()
        }
    )
    reason = ", ".join(rule_ids[:8]) or "unknown verification failure"
    raise ValueError(
        "generated review package failed internal verification "
        f"({reason}); destination was not published"
    )


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
            raise ValueError(
                f"review package archive destination is a directory: {archive}"
            )
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
        _require_generated_package_verification(staged_archive)
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
    run_repository = snapshot.get("run_manifest", {}).get("repository")
    if isinstance(run_repository, dict):
        scan_manifest = snapshot["run_manifest"]
        source_manifest_sha256 = scan_manifest.pop("manifest_sha256", "")
        run_repository["root"] = "."
        scan_manifest["portable_redaction"] = {
            "applied": True,
            "source_manifest_sha256": source_manifest_sha256,
            "fields": ["repository.root"],
        }
        scan_manifest["manifest_sha256"] = hashlib.sha256(
            json.dumps(scan_manifest, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
    settings = project.setdefault("settings", {})
    for field in ("config_file", "coverage_json"):
        if settings.get(field):
            settings[field] = basename(settings[field])
    analysis_context = snapshot.get("context", {}).get("analysis", {})
    if isinstance(analysis_context.get("guidance_packs"), list):
        analysis_context["guidance_packs"] = [
            basename(value) for value in analysis_context["guidance_packs"]
        ]
    for record in snapshot.get("runtime_evidence", {}).get("imports", []):
        if record.get("source"):
            record["source"] = basename(record["source"])
    for event in snapshot.get("history", []):
        if event.get("event") == "runtime_trace_import" and event.get("source"):
            event["source"] = basename(event["source"])
    for execution in snapshot.get("assurance", {}).get("executions", []):
        execution_id = str(execution.get("id", "execution"))
        repository = execution.setdefault("repository", {})
        original_root = str(repository.get("root", ""))
        original_evidence = str(execution.get("evidence_directory", ""))
        repository["root"] = "."
        portable_evidence = f"external-evidence/{execution_id}"
        execution["evidence_directory"] = portable_evidence
        sandbox = execution.setdefault("sandbox", {})
        if sandbox.get("engine_path"):
            sandbox["engine_path"] = basename(sandbox["engine_path"])
        portable_argv = []
        for value in execution.get("command_argv", []):
            argument = str(value)
            if original_root:
                argument = argument.replace(original_root, ".")
            if original_evidence:
                argument = argument.replace(original_evidence, portable_evidence)
            portable_argv.append(argument)
        execution["command_argv"] = portable_argv
    return snapshot


def analysis_state_sha256(analysis: dict[str, Any], *, portable: bool = False) -> str:
    """Hash the governed analysis state, optionally after portable redaction."""

    snapshot = _portable_analysis_snapshot(analysis) if portable else analysis
    return canonical_json_sha256(snapshot)


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
        return _package_verification_result(archive, findings, 0, "", container="zip")

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
                for name in sorted(
                    (LEGACY_REVIEW_PACKAGE_FILES | {"manifest.json"}) - names
                ):
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
                    with (
                        bundle.open(entry, "r") as source_file,
                        target.open("wb") as target_file,
                    ):
                        while chunk := source_file.read(1024 * 1024):
                            written += len(chunk)
                            if (
                                written > entry.file_size
                                or written > MAX_ARCHIVE_FILE_BYTES
                            ):
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
        if result.get("assurance_work_queue"):
            result["assurance_work_queue"]["path"] = f"{archive}!/assurance-work.json"
        return result
    finally:
        shutil.rmtree(staging)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_file_bounded(path: Path, *, limit: int) -> tuple[str, int]:
    """Hash a regular file without buffering or reading beyond the package limit."""

    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise ValueError(f"file exceeds the {limit}-byte verification limit")
            digest.update(chunk)
    return digest.hexdigest(), size


def _read_bounded_bytes(path: Path, *, limit: int) -> bytes:
    """Read bytes while enforcing the limit during I/O."""

    raw = bytearray()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            raw.extend(chunk)
            if len(raw) > limit:
                raise ValueError(f"file exceeds the {limit}-byte verification limit")
    return bytes(raw)


def _read_bounded_utf8(path: Path, *, limit: int) -> str:
    """Read UTF-8 text while enforcing the byte limit during I/O."""

    try:
        return _read_bounded_bytes(path, limit=limit).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"file is not valid UTF-8: {exc}") from exc


def _canonical_text_sha256_bounded(path: Path, *, limit: int) -> tuple[str, int]:
    """Hash UTF-8 text after portable CRLF/CR-to-LF normalization."""

    normalized_text = _read_bounded_utf8(path, limit=limit).replace("\r\n", "\n")
    normalized_bytes = normalized_text.replace("\r", "\n").encode("utf-8")
    return hashlib.sha256(normalized_bytes).hexdigest(), len(normalized_bytes)


def _read_bounded_json(path: Path, *, limit: int) -> Any:
    """Read UTF-8 JSON while enforcing the byte limit during I/O."""

    try:
        return json.loads(_read_bounded_utf8(path, limit=limit))
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"file is not valid JSON: {exc}") from exc


def _read_bounded_json_object(path: Path, *, limit: int) -> dict[str, Any]:
    """Read a bounded UTF-8 JSON object."""

    document = _read_bounded_json(path, limit=limit)
    if not isinstance(document, dict):
        raise ValueError("JSON root is not an object")
    return document


def _verify_analysis_structure(
    analysis: dict[str, Any] | None,
    *,
    max_depth: int = MAX_ANALYSIS_JSON_DEPTH,
    max_nodes: int = MAX_ANALYSIS_JSON_NODES,
    unavailable_reason: str = "",
) -> dict[str, Any]:
    """Bound JSON complexity iteratively before hashing or projection work."""

    checks = {
        "json_object": analysis is not None,
        "depth_limit": analysis is not None,
        "node_limit": analysis is not None,
        "core_contract": analysis is not None,
    }
    errors: list[dict[str, str]] = []
    node_count = 0
    observed_depth = 0
    if analysis is None:
        errors.append(
            {
                "code": "analysis_structure.unavailable",
                "message": unavailable_reason
                or "analysis.json is unavailable or invalid.",
                "path": "analysis.json",
            }
        )
    else:
        metrics = bounded_json_structure_metrics(
            analysis,
            max_depth=max_depth,
            max_nodes=max_nodes,
        )
        node_count = int(metrics["node_count"])
        observed_depth = int(metrics["max_depth"])
        if not metrics["depth_within_limit"]:
            checks["depth_limit"] = False
            errors.append(
                {
                    "code": "analysis_structure.depth_limit",
                    "message": (
                        f"JSON depth exceeds the {max_depth}-level verification limit."
                    ),
                    "path": "analysis.json",
                }
            )
        if not metrics["node_within_limit"]:
            checks["node_limit"] = False
            errors.append(
                {
                    "code": "analysis_structure.node_limit",
                    "message": (
                        f"JSON structure exceeds the {max_nodes}-node verification limit."
                    ),
                    "path": "analysis.json",
                }
            )
        contract_errors = (
            _analysis_core_contract_errors(analysis)
            if checks["node_limit"]
            else [
                {
                    "code": "analysis_structure.core_contract_unchecked",
                    "message": (
                        "Core container types were not inspected after the node limit "
                        "was exceeded."
                    ),
                    "path": "analysis.json",
                }
            ]
        )
        if contract_errors:
            checks["core_contract"] = False
            errors.extend(contract_errors)
    return {
        "format": ANALYSIS_STRUCTURE_VERIFICATION_FORMAT,
        "valid": all(checks.values()),
        "checks": checks,
        "errors": errors,
        "node_count": node_count,
        "max_depth": observed_depth,
        "limits": {"max_nodes": max_nodes, "max_depth": max_depth},
        "notice": (
            "Structural bounds and core container checks protect verification availability; "
            "passing them does not establish analysis correctness, completeness, schema "
            "conformance, or engineering approval."
        ),
    }


def _analysis_core_contract_errors(
    analysis: dict[str, Any], *, max_errors: int = 50
) -> list[dict[str, str]]:
    """Validate projection-critical container types without imposing a new schema."""

    errors: list[dict[str, str]] = []
    missing = object()

    def add(path: str, expected: str) -> None:
        if len(errors) < max_errors:
            errors.append(
                {
                    "code": "analysis_structure.core_contract",
                    "message": f"{path} must be {expected}.",
                    "path": "analysis.json",
                }
            )

    def value_at(path: tuple[str, ...]) -> Any:
        value: Any = analysis
        for segment in path:
            if not isinstance(value, dict) or segment not in value:
                return missing
            value = value[segment]
        return value

    required_objects: tuple[tuple[str, ...], ...] = (("project",), ("context",))
    optional_objects: tuple[tuple[str, ...], ...] = tuple(
        (field,)
        for field in (
            "generator",
            "summary",
            "methodology",
            "assurance",
            "sfta",
            "guidance",
            "runtime_evidence",
            "system_context",
            "repository_inventory",
            "adapter_runs",
            "run_manifest",
        )
    ) + (
        ("project", "baseline"),
        ("context", "project"),
        ("context", "analysis"),
        ("context", "scan"),
        ("context", "risk"),
        ("context", "quality"),
        ("run_manifest", "repository"),
        ("run_manifest", "resolved_inputs"),
        ("run_manifest", "tool"),
        ("run_manifest", "environment"),
        ("run_manifest", "guidance"),
        ("run_manifest", "adapters"),
        ("run_manifest", "cache"),
    )
    required_lists: tuple[tuple[str, ...], ...] = (("items",), ("components",))
    optional_lists: tuple[tuple[str, ...], ...] = tuple(
        (field,)
        for field in ("history", "warnings", "suggestions", "generated_summaries")
    )
    object_list_paths: tuple[tuple[str, ...], ...] = (
        ("items",),
        ("components",),
        ("history",),
        ("assurance", "obligations"),
        ("assurance", "executions"),
        ("assurance", "evidence_artifacts"),
        ("runtime_evidence", "imports"),
        ("runtime_evidence", "spans"),
        ("runtime_evidence", "edges"),
        ("context", "requirements"),
        ("context", "hazards"),
        ("context", "system_interfaces"),
        ("context", "contracts"),
        ("context", "fault_trees"),
        ("context", "component_mappings"),
        ("context", "reviewers"),
        ("context", "dependencies"),
        ("context", "common_causes"),
        ("context", "custom_rules"),
        ("methodology", "basis"),
        ("guidance", "sources"),
        ("guidance", "profiles"),
        ("guidance", "citations"),
        ("guidance", "rule_mappings"),
        ("sfta", "trees"),
        ("repository_inventory", "entries"),
        ("repository_inventory", "regions"),
        ("adapter_runs", "runs"),
        ("system_context", "fields"),
        ("run_manifest", "models"),
        ("run_manifest", "prompts"),
        ("run_manifest", "commands"),
        ("run_manifest", "events"),
        ("run_manifest", "review_decisions"),
        ("run_manifest", "waivers"),
        ("run_manifest", "risk_acceptances"),
        ("run_manifest", "adapters", "adapters"),
    )
    for path in required_objects:
        if not isinstance(value_at(path), dict):
            add(".".join(path), "an object")
    for path in optional_objects:
        value = value_at(path)
        if value is not missing and not isinstance(value, dict):
            add(".".join(path), "an object")
    for path in required_lists:
        if not isinstance(value_at(path), list):
            add(".".join(path), "an array")
    for path in optional_lists:
        value = value_at(path)
        if value is not missing and not isinstance(value, list):
            add(".".join(path), "an array")
    for path in object_list_paths:
        value = value_at(path)
        if value is missing:
            continue
        if not isinstance(value, list):
            add(".".join(path), "an array of objects")
            continue
        if any(not isinstance(entry, dict) for entry in value):
            add(".".join(path), "an array containing only objects")
    items = value_at(("items",))
    if isinstance(items, list):
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            for field in ("source", "component", "scanner", "review"):
                value = item.get(field, missing)
                if value is not missing and not isinstance(value, dict):
                    add(f"items[{index}].{field}", "an object")
            scanner = item.get("scanner")
            if isinstance(scanner, dict):
                citations = scanner.get("citations", missing)
                if citations is not missing and (
                    not isinstance(citations, list)
                    or any(not isinstance(entry, dict) for entry in citations)
                ):
                    add(f"items[{index}].scanner.citations", "an array of objects")
                elif isinstance(citations, list):
                    for citation_index, citation in enumerate(citations):
                        if not isinstance(citation, dict):
                            continue
                        for field in ("citation_id", "rule_id", "source_id"):
                            value = citation.get(field, missing)
                            if value is not missing and not isinstance(value, str):
                                add(
                                    f"items[{index}].scanner.citations"
                                    f"[{citation_index}].{field}",
                                    "a string",
                                )
            review = item.get("review")
            if isinstance(review, dict):
                linked_hazards = review.get("linked_hazards", missing)
                if linked_hazards is not missing and (
                    not isinstance(linked_hazards, list)
                    or any(not isinstance(value, str) for value in linked_hazards)
                ):
                    add(f"items[{index}].review.linked_hazards", "an array of strings")
    fault_trees = value_at(("context", "fault_trees"))
    if isinstance(fault_trees, list):
        for index, tree in enumerate(fault_trees):
            if not isinstance(tree, dict):
                continue
            for field in ("gates", "events"):
                value = tree.get(field, missing)
                if value is not missing and (
                    not isinstance(value, list)
                    or any(not isinstance(entry, dict) for entry in value)
                ):
                    add(
                        f"context.fault_trees[{index}].{field}",
                        "an array of objects",
                    )
    guidance = value_at(("guidance",))
    if isinstance(guidance, dict):
        guidance_string_fields = {
            "sources": ("id",),
            "profiles": ("id",),
            "citations": ("id", "source_id"),
            "rule_mappings": ("id", "citation_id"),
        }
        guidance_string_lists = {
            "profiles": ("source_ids",),
            "rule_mappings": ("profile_ids",),
        }
        for collection, fields in guidance_string_fields.items():
            values = guidance.get(collection, [])
            if not isinstance(values, list):
                continue
            for index, entry in enumerate(values):
                if not isinstance(entry, dict):
                    continue
                for field in fields:
                    value = entry.get(field, missing)
                    if value is not missing and not isinstance(value, str):
                        add(f"guidance.{collection}[{index}].{field}", "a string")
                for field in guidance_string_lists.get(collection, ()):
                    value = entry.get(field, missing)
                    if value is not missing and (
                        not isinstance(value, list)
                        or any(not isinstance(item, str) for item in value)
                    ):
                        add(
                            f"guidance.{collection}[{index}].{field}",
                            "an array of strings",
                        )
    context = value_at(("context",))
    if isinstance(context, dict):
        try:
            normalize_config(
                {field: context[field] for field in DEFAULT_CONFIG if field in context}
            )
        except (KeyError, TypeError, ValueError) as exc:
            detail = str(exc).replace("\r", " ").replace("\n", " ")[:500]
            add(
                "context",
                "a valid resolved SFMEA configuration"
                + (f" ({detail})" if detail else ""),
            )
    return errors


def _verify_analysis_diagnostics(
    package: Path,
    listed: set[str],
    analysis: dict[str, Any] | None,
    producer_version: str,
) -> dict[str, Any]:
    """Reconcile deterministic diagnostic views with packaged analysis."""

    checks = {name: False for name in ANALYSIS_DIAGNOSTIC_FILES}
    errors: list[dict[str, str]] = []
    if analysis is None:
        errors.append(
            {
                "code": "analysis_diagnostics.analysis_unavailable",
                "message": (
                    "Diagnostic projections cannot be reconciled because analysis.json "
                    "is unavailable or invalid."
                ),
                "path": "analysis.json",
            }
        )
    else:
        expected = {
            "summary": analysis.get("summary", {}),
            "validation": validate_analysis(
                analysis,
                legacy_sfta_id_wildcard=not _package_version_at_least(
                    producer_version, SFTA_EXACT_SELECTOR_VERSION
                ),
            ),
            "system_context": analysis.get("system_context", {}),
            "repository_inventory": analysis.get("repository_inventory", {}),
            "adapter_runs": analysis.get("adapter_runs", {}),
        }
        for name, filename in ANALYSIS_DIAGNOSTIC_FILES.items():
            path = package / filename
            try:
                if filename not in listed:
                    raise ValueError("artifact is not recorded in the manifest")
                if path.is_symlink() or not path.is_file():
                    raise ValueError("artifact is not a regular file")
                if path.stat().st_size > MAX_ARCHIVE_FILE_BYTES:
                    raise ValueError("artifact exceeds the 100 MB verification limit")
                actual = _read_bounded_json_object(path, limit=MAX_ARCHIVE_FILE_BYTES)
                if name == "validation":
                    actual_generated_at = actual.pop("generated_at", None)
                    expected[name].pop("generated_at", None)
                    checks[name] = bool(
                        isinstance(actual_generated_at, str)
                        and actual_generated_at
                        and actual == expected[name]
                    )
                else:
                    checks[name] = actual == expected[name]
                if not checks[name]:
                    raise ValueError(
                        "content is not the deterministic projection of analysis.json"
                    )
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                errors.append(
                    {
                        "code": f"analysis_diagnostics.{name}",
                        "message": f"Diagnostic projection failed reconciliation: {exc}.",
                        "path": filename,
                    }
                )
    return {
        "format": ANALYSIS_DIAGNOSTICS_VERIFICATION_FORMAT,
        "valid": all(checks.values()),
        "checks": checks,
        "errors": errors,
        "artifact_count": len(checks),
        "notice": (
            "Diagnostic reconciliation establishes exact derivation from packaged analysis; "
            "it does not establish analysis completeness, correctness, or approval."
        ),
    }


def _verify_guidance_traceability(
    package: Path,
    listed: set[str],
    analysis: dict[str, Any] | None,
) -> dict[str, Any]:
    """Reconcile guidance and citation artifacts with packaged analysis."""

    checks = {
        "traceability_projection": False,
        "citation_catalog_projection": False,
        "cross_artifact_consistency": False,
    }
    errors: list[dict[str, str]] = []
    trace_document: dict[str, Any] | None = None
    citation_document: list[Any] | None = None
    if analysis is None:
        errors.append(
            {
                "code": "guidance_traceability.analysis_unavailable",
                "message": (
                    "Guidance projections cannot be reconciled because analysis.json "
                    "is unavailable or invalid."
                ),
                "path": "analysis.json",
            }
        )
    else:
        expected = guidance_traceability(analysis)
        trace_path = package / "guidance-traceability.json"
        citation_path = package / "citations.json"
        try:
            if "guidance-traceability.json" not in listed:
                raise ValueError("artifact is not recorded in the manifest")
            if trace_path.is_symlink() or not trace_path.is_file():
                raise ValueError("artifact is not a regular file")
            trace_document = _read_bounded_json_object(
                trace_path, limit=MAX_ARCHIVE_FILE_BYTES
            )
            checks["traceability_projection"] = trace_document == expected
            if not checks["traceability_projection"]:
                raise ValueError(
                    "content is not the deterministic projection of analysis.json"
                )
        except (OSError, ValueError) as exc:
            errors.append(
                {
                    "code": "guidance_traceability.traceability_projection",
                    "message": f"Guidance traceability failed reconciliation: {exc}.",
                    "path": "guidance-traceability.json",
                }
            )
        try:
            if "citations.json" not in listed:
                raise ValueError("artifact is not recorded in the manifest")
            if citation_path.is_symlink() or not citation_path.is_file():
                raise ValueError("artifact is not a regular file")
            loaded_citations = _read_bounded_json(
                citation_path, limit=MAX_ARCHIVE_FILE_BYTES
            )
            if not isinstance(loaded_citations, list):
                raise ValueError("JSON root is not an array")
            citation_document = loaded_citations
            checks["citation_catalog_projection"] = citation_document == expected.get(
                "citations", []
            )
            if not checks["citation_catalog_projection"]:
                raise ValueError(
                    "content is not the deterministic citation projection of analysis.json"
                )
        except (OSError, ValueError) as exc:
            errors.append(
                {
                    "code": "guidance_traceability.citation_catalog_projection",
                    "message": f"Citation catalog failed reconciliation: {exc}.",
                    "path": "citations.json",
                }
            )
        checks["cross_artifact_consistency"] = bool(
            trace_document is not None
            and citation_document is not None
            and trace_document.get("citations") == citation_document
        )
        if not checks["cross_artifact_consistency"]:
            errors.append(
                {
                    "code": "guidance_traceability.cross_artifact_consistency",
                    "message": (
                        "The standalone citation catalog and full guidance trace disagree."
                    ),
                    "path": "citations.json",
                }
            )
    return {
        "format": GUIDANCE_TRACEABILITY_VERIFICATION_FORMAT,
        "valid": all(checks.values()),
        "checks": checks,
        "errors": errors,
        "artifact_count": 2,
        "citation_count": len(citation_document or []),
        "finding_link_count": len((trace_document or {}).get("finding_links", [])),
        "notice": (
            "Guidance reconciliation establishes artifact derivation and consistency; it "
            "does not establish regulatory applicability, compliance, or approval."
        ),
    }


def _verify_sfta_projection(
    package: Path,
    listed: set[str],
    analysis: dict[str, Any] | None,
    producer_version: str,
) -> dict[str, Any]:
    """Reconcile top-down SFTA and its gap register with packaged analysis."""

    checks = {
        "model_projection": False,
        "gap_register_projection": False,
        "gap_count_consistency": False,
    }
    errors: list[dict[str, str]] = []
    actual_model: dict[str, Any] | None = None
    actual_rows: list[dict[str, str]] | None = None
    expected_model: dict[str, Any] | None = None
    expected_rows: list[dict[str, str]] = []
    if analysis is None:
        errors.append(
            {
                "code": "sfta_projection.analysis_unavailable",
                "message": (
                    "SFTA projections cannot be reconciled because analysis.json is "
                    "unavailable or invalid."
                ),
                "path": "analysis.json",
            }
        )
    else:
        expected_model = build_sfta(
            copy.deepcopy(analysis),
            legacy_id_wildcard=not _package_version_at_least(
                producer_version, SFTA_EXACT_SELECTOR_VERSION
            ),
        )
        expected_rows = [
            {field: str(row.get(field, "")) for field in SFTA_GAP_FIELDS}
            for row in sfta_gap_rows(expected_model)
        ]
        model_path = package / "sfta.json"
        gaps_path = package / "sfta-gaps.csv"
        try:
            if "sfta.json" not in listed:
                raise ValueError("artifact is not recorded in the manifest")
            if model_path.is_symlink() or not model_path.is_file():
                raise ValueError("artifact is not a regular file")
            actual_model = _read_bounded_json_object(
                model_path, limit=MAX_ARCHIVE_FILE_BYTES
            )
            checks["model_projection"] = actual_model == expected_model
            if not checks["model_projection"]:
                raise ValueError(
                    "content is not the deterministic SFTA projection of analysis.json"
                )
        except (OSError, ValueError) as exc:
            errors.append(
                {
                    "code": "sfta_projection.model_projection",
                    "message": f"SFTA model failed reconciliation: {exc}.",
                    "path": "sfta.json",
                }
            )
        try:
            if "sfta-gaps.csv" not in listed:
                raise ValueError("artifact is not recorded in the manifest")
            if gaps_path.is_symlink() or not gaps_path.is_file():
                raise ValueError("artifact is not a regular file")
            reader = csv.DictReader(
                io.StringIO(
                    _read_bounded_utf8(gaps_path, limit=MAX_ARCHIVE_FILE_BYTES),
                    newline="",
                )
            )
            if tuple(reader.fieldnames or ()) != SFTA_GAP_FIELDS:
                raise ValueError("CSV header does not match the SFTA gap contract")
            actual_rows = list(reader)
            checks["gap_register_projection"] = actual_rows == expected_rows
            if not checks["gap_register_projection"]:
                raise ValueError(
                    "rows are not the deterministic SFTA gap projection of analysis.json"
                )
        except (OSError, csv.Error, ValueError) as exc:
            errors.append(
                {
                    "code": "sfta_projection.gap_register_projection",
                    "message": f"SFTA gap register failed reconciliation: {exc}.",
                    "path": "sfta-gaps.csv",
                }
            )
        actual_reconciliation = (
            actual_model.get("reconciliation", {})
            if isinstance(actual_model, dict)
            else {}
        )
        actual_gap_count = sum(
            len(actual_reconciliation.get(name, []))
            if isinstance(actual_reconciliation.get(name, []), list)
            else 0
            for name in (
                "top_down_uncovered_events",
                "bottom_up_unmapped_findings",
                "hazard_link_mismatches",
            )
        )
        checks["gap_count_consistency"] = bool(
            actual_rows is not None
            and actual_gap_count == len(actual_rows) == len(expected_rows)
        )
        if not checks["gap_count_consistency"]:
            errors.append(
                {
                    "code": "sfta_projection.gap_count_consistency",
                    "message": "SFTA model and flat gap-register counts disagree.",
                    "path": "sfta-gaps.csv",
                }
            )
    return {
        "format": SFTA_PROJECTION_VERIFICATION_FORMAT,
        "valid": all(checks.values()),
        "checks": checks,
        "errors": errors,
        "artifact_count": 2,
        "tree_count": len((expected_model or {}).get("trees", [])),
        "gap_count": len(expected_rows),
        "notice": (
            "SFTA reconciliation establishes deterministic artifact consistency; it does "
            "not establish fault-tree completeness, causal sufficiency, or approval."
        ),
    }


def _verify_evidence_catalog(
    package: Path,
    listed: set[str],
    analysis: dict[str, Any] | None,
) -> dict[str, Any]:
    """Reconcile execution and evidence-artifact inventory with packaged analysis."""

    checks = {
        "semantic_projection": False,
        "baseline_binding": False,
        "execution_inventory": False,
        "evidence_artifact_inventory": False,
    }
    errors: list[dict[str, str]] = []
    document: dict[str, Any] | None = None
    expected: dict[str, Any] | None = None
    if analysis is None:
        errors.append(
            {
                "code": "evidence_catalog.analysis_unavailable",
                "message": (
                    "Evidence catalog cannot be reconciled because analysis.json is "
                    "unavailable or invalid."
                ),
                "path": "analysis.json",
            }
        )
    else:
        expected = evidence_catalog_document(analysis)
        path = package / "evidence-catalog.json"
        try:
            if "evidence-catalog.json" not in listed:
                raise ValueError("artifact is not recorded in the manifest")
            if path.is_symlink() or not path.is_file():
                raise ValueError("artifact is not a regular file")
            document = _read_bounded_json_object(path, limit=MAX_ARCHIVE_FILE_BYTES)
        except (OSError, ValueError) as exc:
            errors.append(
                {
                    "code": "evidence_catalog.structure",
                    "message": f"Evidence catalog cannot be read: {exc}.",
                    "path": "evidence-catalog.json",
                }
            )
        if document is not None:
            checks.update(
                {
                    "semantic_projection": document == expected,
                    "baseline_binding": document.get("baseline_id")
                    == expected["baseline_id"],
                    "execution_inventory": document.get("executions")
                    == expected["executions"],
                    "evidence_artifact_inventory": document.get("evidence_artifacts")
                    == expected["evidence_artifacts"],
                }
            )
            messages = {
                "semantic_projection": (
                    "Evidence catalog is not the deterministic projection of analysis.json."
                ),
                "baseline_binding": "Evidence catalog baseline does not match analysis.json.",
                "execution_inventory": (
                    "Evidence catalog execution inventory does not match analysis.json."
                ),
                "evidence_artifact_inventory": (
                    "Evidence catalog artifact inventory does not match analysis.json."
                ),
            }
            errors.extend(
                {
                    "code": f"evidence_catalog.{name}",
                    "message": messages[name],
                    "path": "evidence-catalog.json",
                }
                for name, passed in checks.items()
                if not passed
            )
    return {
        "format": EVIDENCE_CATALOG_VERIFICATION_FORMAT,
        "valid": all(checks.values()),
        "checks": checks,
        "errors": errors,
        "artifact_count": 1,
        "execution_count": len((expected or {}).get("executions", [])),
        "evidence_artifact_count": len((expected or {}).get("evidence_artifacts", [])),
        "notice": (
            "Catalog reconciliation establishes inventory consistency with packaged analysis; "
            "raw external evidence still requires separate transfer and verification."
        ),
    }


def _verify_interchange_artifacts(
    package: Path,
    listed: set[str],
    analysis: dict[str, Any] | None,
    generated_at: str,
    producer_version: str,
) -> dict[str, Any]:
    """Reconcile SARIF and CycloneDX exports with packaged analysis."""

    checks = {
        "sarif_projection": False,
        "cyclonedx_projection": False,
        "baseline_consistency": False,
    }
    errors: list[dict[str, str]] = []
    actual_sarif: dict[str, Any] | None = None
    actual_cyclonedx: dict[str, Any] | None = None
    if analysis is None:
        errors.append(
            {
                "code": "interchange_artifacts.analysis_unavailable",
                "message": (
                    "Interchange artifacts cannot be reconciled because analysis.json "
                    "is unavailable or invalid."
                ),
                "path": "analysis.json",
            }
        )
    else:
        expected_sarif = sarif_document(analysis, tool_version=producer_version)
        expected_cyclonedx = cyclonedx_document(
            analysis,
            generated_at=generated_at,
            tool_version=producer_version,
        )
        for filename, check_name, expected, label in (
            (
                "findings.sarif",
                "sarif_projection",
                expected_sarif,
                "SARIF finding exchange",
            ),
            (
                "components.cdx.json",
                "cyclonedx_projection",
                expected_cyclonedx,
                "CycloneDX component inventory",
            ),
        ):
            path = package / filename
            try:
                if filename not in listed:
                    raise ValueError("artifact is not recorded in the manifest")
                if path.is_symlink() or not path.is_file():
                    raise ValueError("artifact is not a regular file")
                actual = _read_bounded_json_object(path, limit=MAX_ARCHIVE_FILE_BYTES)
                if check_name == "sarif_projection":
                    actual_sarif = actual
                else:
                    actual_cyclonedx = actual
                checks[check_name] = actual == expected
                if not checks[check_name]:
                    raise ValueError(
                        "content is not the deterministic projection of analysis.json"
                    )
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                errors.append(
                    {
                        "code": f"interchange_artifacts.{check_name}",
                        "message": f"{label} failed reconciliation: {exc}.",
                        "path": filename,
                    }
                )

        baseline_id = str(analysis.get("project", {}).get("baseline", {}).get("id", ""))
        sarif_baseline = ""
        if actual_sarif is not None:
            runs = actual_sarif.get("runs", [])
            if isinstance(runs, list) and runs and isinstance(runs[0], dict):
                automation = runs[0].get("automationDetails", {})
                if isinstance(automation, dict):
                    sarif_baseline = str(automation.get("id", ""))
        cyclonedx_baseline = ""
        if actual_cyclonedx is not None:
            metadata = actual_cyclonedx.get("metadata", {})
            component = (
                metadata.get("component", {}) if isinstance(metadata, dict) else {}
            )
            if isinstance(component, dict):
                cyclonedx_baseline = str(component.get("version", ""))
        checks["baseline_consistency"] = bool(
            actual_sarif is not None
            and actual_cyclonedx is not None
            and sarif_baseline == baseline_id
            and cyclonedx_baseline == (baseline_id or "unversioned")
        )
        if not checks["baseline_consistency"]:
            errors.append(
                {
                    "code": "interchange_artifacts.baseline_consistency",
                    "message": (
                        "SARIF and CycloneDX baseline declarations do not agree with "
                        "analysis.json."
                    ),
                    "path": "findings.sarif",
                }
            )

    sarif_results: list[Any] = []
    if actual_sarif is not None:
        runs = actual_sarif.get("runs", [])
        if isinstance(runs, list) and runs and isinstance(runs[0], dict):
            values = runs[0].get("results", [])
            if isinstance(values, list):
                sarif_results = values
    cyclonedx_components: list[Any] = []
    if actual_cyclonedx is not None:
        values = actual_cyclonedx.get("components", [])
        if isinstance(values, list):
            cyclonedx_components = values
    return {
        "format": INTERCHANGE_ARTIFACTS_VERIFICATION_FORMAT,
        "valid": all(checks.values()),
        "checks": checks,
        "errors": errors,
        "artifact_count": 2,
        "sarif_result_count": len(sarif_results),
        "cyclonedx_component_count": len(cyclonedx_components),
        "notice": (
            "Interchange reconciliation establishes deterministic derivation and shared "
            "baseline identity; it does not establish downstream tool interpretation, "
            "standards conformance, or engineering approval."
        ),
    }


def _verify_review_views(
    package: Path,
    listed: set[str],
    analysis: dict[str, Any] | None,
    producer_version: str,
) -> dict[str, Any]:
    """Regenerate the human-review exports and compare their exact bytes."""

    checks = {
        "worksheet_projection": False,
        "system_views_projection": False,
        "audit_projection": False,
        "guidance_csv_projection": False,
        "assurance_views_projection": False,
    }
    errors: list[dict[str, str]] = []
    legacy_sfta_id_wildcard = not _package_version_at_least(
        producer_version, SFTA_EXACT_SELECTOR_VERSION
    )
    include_repository_accounting = _package_version_at_least(
        producer_version, RECONCILED_INVENTORY_VIEWS_VERSION
    )
    artifact_specs: tuple[
        tuple[str, str, Callable[..., Any], dict[str, Any]], ...
    ] = (
        (
            "worksheet.csv",
            "worksheet_projection",
            export_csv,
            {"legacy_sfta_id_wildcard": legacy_sfta_id_wildcard},
        ),
        (
            "worksheet.md",
            "worksheet_projection",
            export_markdown,
            {"legacy_sfta_id_wildcard": legacy_sfta_id_wildcard},
        ),
        (
            "inventory.md",
            "system_views_projection",
            export_inventory,
            {"include_repository_accounting": include_repository_accounting},
        ),
        (
            "architecture.md",
            "system_views_projection",
            export_architecture,
            {"format": "markdown"},
        ),
        (
            "traceability.md",
            "system_views_projection",
            export_traceability,
            {"format": "markdown"},
        ),
        (
            "coverage.md",
            "system_views_projection",
            export_coverage,
            {
                "format": "markdown",
                "include_repository_accounting": include_repository_accounting,
            },
        ),
        ("audit.csv", "audit_projection", export_audit, {}),
        (
            "guidance-traceability.csv",
            "guidance_csv_projection",
            export_guidance_traceability,
            {"format": "csv"},
        ),
        (
            "assurance-register.csv",
            "assurance_views_projection",
            export_assurance_register,
            {"format": "csv"},
        ),
        (
            "assurance-register.md",
            "assurance_views_projection",
            export_assurance_register,
            {"format": "markdown"},
        ),
    )
    if analysis is None:
        errors.append(
            {
                "code": "review_views.analysis_unavailable",
                "message": (
                    "Review views cannot be reconciled because analysis.json is "
                    "unavailable or invalid."
                ),
                "path": "analysis.json",
            }
        )
    else:
        checks = {name: True for name in checks}
        review_snapshot = copy.deepcopy(analysis)
        with tempfile.TemporaryDirectory(prefix="pysfmea-review-views-") as root:
            expected_root = Path(root)
            for filename, check_name, exporter, options in artifact_specs:
                actual_path = package / filename
                expected_path = expected_root / filename
                try:
                    if filename not in listed:
                        raise ValueError("artifact is not recorded in the manifest")
                    if actual_path.is_symlink() or not actual_path.is_file():
                        raise ValueError("artifact is not a regular file")
                    exporter(review_snapshot, expected_path, **options)
                    expected_hash, expected_size = _canonical_text_sha256_bounded(
                        expected_path, limit=MAX_ARCHIVE_FILE_BYTES
                    )
                    actual_hash, actual_size = _canonical_text_sha256_bounded(
                        actual_path, limit=MAX_ARCHIVE_FILE_BYTES
                    )
                    matched = (
                        actual_size == expected_size and actual_hash == expected_hash
                    )
                    checks[check_name] = checks[check_name] and matched
                    if not matched:
                        raise ValueError(
                            "bytes are not the deterministic projection of analysis.json"
                        )
                except Exception as exc:
                    checks[check_name] = False
                    errors.append(
                        {
                            "code": f"review_views.{check_name}",
                            "message": f"Review view failed reconciliation: {exc}.",
                            "path": filename,
                        }
                    )
    analysis_items = (analysis or {}).get("items", [])
    if not isinstance(analysis_items, list):
        analysis_items = []
    active_findings = [
        value
        for value in analysis_items
        if isinstance(value, dict)
        if value.get("source_status", "active") == "active"
    ]
    analysis_components = (analysis or {}).get("components", [])
    if not isinstance(analysis_components, list):
        analysis_components = []
    return {
        "format": REVIEW_VIEWS_VERIFICATION_FORMAT,
        "valid": all(checks.values()),
        "checks": checks,
        "errors": errors,
        "artifact_count": len(artifact_specs),
        "finding_count": len(active_findings),
        "component_count": len(analysis_components),
        "notice": (
            "Review-view reconciliation establishes exact derivation from packaged "
            "analysis; it does not establish that reviewer decisions, ratings, controls, "
            "or risk acceptance are correct or approved."
        ),
    }


def _verify_package_provenance(
    package: Path,
    listed: set[str],
    analysis: dict[str, Any] | None,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Reconcile package-time audit provenance and reviewer instructions."""

    checks = {
        "run_manifest_projection": False,
        "readme_projection": False,
        "timestamp_consistency": False,
        "baseline_consistency": False,
    }
    errors: list[dict[str, str]] = []
    actual_run_manifest: dict[str, Any] | None = None
    generated_at = str(manifest.get("generated_at", ""))
    exporter = manifest.get("exporter", {})
    producer_version = (
        str(exporter.get("version", "")) if isinstance(exporter, dict) else ""
    )
    expected_run_manifest: dict[str, Any] = {}
    if analysis is None:
        errors.append(
            {
                "code": "package_provenance.analysis_unavailable",
                "message": (
                    "Package provenance cannot be reconciled because analysis.json is "
                    "unavailable or invalid."
                ),
                "path": "analysis.json",
            }
        )
    else:
        expected_run_manifest = current_audit_manifest(
            copy.deepcopy(analysis),
            generated_at=generated_at,
            tool_version=producer_version,
        )
        run_manifest_path = package / "run-manifest.json"
        try:
            if "run-manifest.json" not in listed:
                raise ValueError("artifact is not recorded in the manifest")
            if run_manifest_path.is_symlink() or not run_manifest_path.is_file():
                raise ValueError("artifact is not a regular file")
            actual_run_manifest = _read_bounded_json_object(
                run_manifest_path, limit=MAX_ARCHIVE_FILE_BYTES
            )
            checks["run_manifest_projection"] = (
                actual_run_manifest == expected_run_manifest
            )
            if not checks["run_manifest_projection"]:
                raise ValueError(
                    "content is not the deterministic package-time audit projection"
                )
        except Exception as exc:
            errors.append(
                {
                    "code": "package_provenance.run_manifest_projection",
                    "message": f"Run manifest failed reconciliation: {exc}.",
                    "path": "run-manifest.json",
                }
            )

        expected_readme = _review_package_readme(
            analysis,
            portable=bool(manifest.get("portable", False)),
            generated_at=generated_at,
            exporter_version=producer_version,
        )
        readme_path = package / "README.md"
        try:
            if "README.md" not in listed:
                raise ValueError("artifact is not recorded in the manifest")
            if readme_path.is_symlink() or not readme_path.is_file():
                raise ValueError("artifact is not a regular file")
            checks["readme_projection"] = _read_bounded_utf8(
                readme_path, limit=MAX_ARCHIVE_FILE_BYTES
            ).replace("\r\n", "\n").replace("\r", "\n") == expected_readme.replace(
                "\r\n", "\n"
            ).replace("\r", "\n")
            if not checks["readme_projection"]:
                raise ValueError(
                    "content is not the deterministic package handoff projection"
                )
        except Exception as exc:
            errors.append(
                {
                    "code": "package_provenance.readme_projection",
                    "message": f"Package README failed reconciliation: {exc}.",
                    "path": "README.md",
                }
            )

        checks["timestamp_consistency"] = bool(
            actual_run_manifest is not None
            and generated_at
            and actual_run_manifest.get("generated_at") == generated_at
        )
        scan_manifest = (
            actual_run_manifest.get("scan_manifest", {})
            if actual_run_manifest is not None
            else {}
        )
        repository = (
            scan_manifest.get("repository", {})
            if isinstance(scan_manifest, dict)
            else {}
        )
        analysis_baseline = str(
            analysis.get("project", {}).get("baseline", {}).get("id", "")
        )
        checks["baseline_consistency"] = bool(
            isinstance(repository, dict)
            and str(repository.get("baseline_id", "")) == analysis_baseline
            and str(manifest.get("baseline_id", "")) == analysis_baseline
        )
        for name, message, path in (
            (
                "timestamp_consistency",
                "Run-manifest and package generation timestamps disagree.",
                "run-manifest.json",
            ),
            (
                "baseline_consistency",
                "Run-manifest, package, and analysis baselines disagree.",
                "run-manifest.json",
            ),
        ):
            if not checks[name]:
                errors.append(
                    {
                        "code": f"package_provenance.{name}",
                        "message": message,
                        "path": path,
                    }
                )

    return {
        "format": PACKAGE_PROVENANCE_VERIFICATION_FORMAT,
        "valid": all(checks.values()),
        "checks": checks,
        "errors": errors,
        "artifact_count": 2,
        "review_decision_count": len(expected_run_manifest.get("review_decisions", [])),
        "execution_count": len(expected_run_manifest.get("test_executions", [])),
        "notice": (
            "Provenance reconciliation establishes deterministic audit and handoff "
            "consistency; it does not authenticate an author, approve a review decision, "
            "or establish certification evidence."
        ),
    }


def verify_review_package(source: str | Path) -> dict[str, Any]:
    """Return a structured package verdict even if semantic verification aborts."""

    supplied = Path(source).expanduser().absolute()
    try:
        return _verify_review_package(supplied)
    except Exception as exc:
        finding = {
            "rule_id": "package.semantic_verification_aborted",
            "level": "error",
            "message": (
                "Package semantic verification stopped safely after an unexpected "
                f"{type(exc).__name__}; inspect analysis.json container and scalar types."
            ),
            "path": "analysis.json",
        }
        return _package_verification_result(
            supplied,
            [finding],
            0,
            "",
            container="zip" if supplied.suffix.lower() == ".zip" else "directory",
        )


def package_publication_error_result(
    destination: str | Path,
    error: Exception,
    *,
    archive: bool = False,
    phase: str = "generation",
) -> dict[str, Any]:
    """Return a path-safe verification verdict for publication failures."""

    supplied = Path(destination).expanduser().absolute()
    failure = classify_publication_failure(error, phase=phase)
    finding = {
        "rule_id": failure.rule_id,
        "level": "error",
        "message": failure.message,
        "path": "",
    }
    result = _package_verification_result(
        supplied,
        [finding],
        0,
        "",
        container="zip" if archive else "directory",
    )
    result["notice"] = (
        "Publication did not complete and this verdict does not describe a newly "
        "published package; use the stable publication failure identity and catalog "
        "metadata for remediation and retry decisions."
    )
    result["publication"] = {
        "status": "not_published",
        "phase": phase,
        "catalog_format": PUBLICATION_FAILURE_CATALOG_FORMAT,
        "catalog_algorithm": PUBLICATION_FAILURE_CATALOG_ALGORITHM,
        "catalog_canonicalization": PUBLICATION_FAILURE_CATALOG_CANONICALIZATION,
        "catalog_sha256": PUBLICATION_FAILURE_CATALOG_SHA256,
        "failure_code": failure.code,
        "failure_rule_id": failure.rule_id,
        "next_action": failure.next_action,
        "retry_policy": failure.retry_policy,
    }
    return result


def _verify_review_package(source: str | Path) -> dict[str, Any]:
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
        add(
            "package.directory", "error", f"Package directory does not exist: {package}"
        )
        return _package_verification_result(package, findings, 0, "")
    manifest_path = package / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        add(
            "package.manifest_missing",
            "error",
            "A regular manifest.json file is required.",
        )
        return _package_verification_result(package, findings, 0, "")
    try:
        manifest_raw = _read_bounded_bytes(manifest_path, limit=5_000_000)
        manifest = json.loads(manifest_raw.decode("utf-8"))
        manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        add("package.manifest_invalid", "error", f"Manifest cannot be read: {exc}")
        return _package_verification_result(package, findings, 0, "")
    if not isinstance(manifest, dict):
        add("package.manifest_invalid", "error", "Manifest root must be a JSON object.")
        return _package_verification_result(package, findings, 0, "")
    package_format = str(manifest.get("format", ""))
    if package_format != REVIEW_PACKAGE_FORMAT:
        add(
            "package.format_unsupported",
            "error",
            f"Unsupported or missing package format: {package_format or '<blank>'}",
        )
    entries = manifest.get("files", [])
    if not isinstance(entries, list) or len(entries) > MAX_ARCHIVE_ENTRIES:
        add(
            "package.file_list_invalid",
            "error",
            f"Manifest files must be a list with at most {MAX_ARCHIVE_ENTRIES} entries.",
        )
        result = _package_verification_result(package, findings, 0, package_format)
        result["manifest_sha256"] = manifest_sha256
        return result

    schema_catalog_declaration = manifest.get("schema_catalog")
    schema_bundle_declared = schema_catalog_declaration is not None
    required_files = (
        REVIEW_PACKAGE_FILES
        if _package_requires_assurance_work_queue(manifest)
        else LEGACY_REVIEW_PACKAGE_FILES
    )

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
    raw_capabilities = manifest.get("capabilities")
    required_capabilities = _required_package_capabilities(manifest)
    declaration_required = bool(required_capabilities)
    capabilities_valid = bool(
        isinstance(raw_capabilities, list)
        and all(
            isinstance(value, str) and value in REVIEW_PACKAGE_CAPABILITIES
            for value in raw_capabilities
        )
        and len(raw_capabilities) == len(set(raw_capabilities))
    )
    if raw_capabilities is None and declaration_required:
        add(
            "package.capabilities_missing",
            "error",
            "Current package provenance requires an explicit capability declaration.",
            "manifest.json",
        )
    elif raw_capabilities is not None and not capabilities_valid:
        add(
            "package.capabilities_invalid",
            "error",
            "Manifest capabilities must be unique supported identifiers.",
            "manifest.json",
        )
    elif declaration_required and set(raw_capabilities or []) != required_capabilities:
        add(
            "package.capabilities_incomplete",
            "error",
            "Current package provenance does not declare every required capability.",
            "manifest.json",
        )
    state_digest = manifest.get("analysis_state_sha256", "")
    state_digest_valid = (
        isinstance(state_digest, str)
        and len(state_digest) == 64
        and all(character in "0123456789abcdefABCDEF" for character in state_digest)
    )
    if not state_digest:
        add(
            "package.analysis_state_digest_missing",
            "warning",
            "Manifest predates exact governed-analysis state binding; refresh the package.",
        )
    elif not state_digest_valid:
        add(
            "package.analysis_state_digest_invalid",
            "error",
            "Manifest governed-analysis state digest is not a SHA-256 value.",
        )

    listed: set[str] = set()
    checked = 0
    observed_total = 0
    declared_total = 0
    total_limit_reported = False
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            add(
                "package.file_entry_invalid",
                "error",
                f"Manifest file entry {index} must be an object.",
            )
            continue
        relative_name = entry.get("path", "")
        if (
            not isinstance(relative_name, str)
            or not relative_name
            or "\\" in relative_name
        ):
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
            or any(
                character not in "0123456789abcdefABCDEF" for character in expected_hash
            )
        ):
            add(
                "package.file_metadata_invalid",
                "error",
                "Manifest file size or SHA-256 value is invalid.",
                relative_name,
            )
            continue
        declared_total += expected_size
        if expected_size > MAX_ARCHIVE_FILE_BYTES:
            add(
                "package.file_limit",
                "error",
                f"Manifested file exceeds the {MAX_ARCHIVE_FILE_BYTES}-byte limit.",
                relative_name,
            )
            continue
        if declared_total > MAX_ARCHIVE_TOTAL_BYTES and not total_limit_reported:
            add(
                "package.total_limit",
                "error",
                f"Manifested files exceed the {MAX_ARCHIVE_TOTAL_BYTES}-byte total limit.",
            )
            total_limit_reported = True
        try:
            observed_size = target.stat().st_size
            if observed_size > MAX_ARCHIVE_FILE_BYTES:
                add(
                    "package.file_limit",
                    "error",
                    f"Package file exceeds the {MAX_ARCHIVE_FILE_BYTES}-byte limit.",
                    relative_name,
                )
                continue
            if observed_total + observed_size > MAX_ARCHIVE_TOTAL_BYTES:
                if not total_limit_reported:
                    add(
                        "package.total_limit",
                        "error",
                        f"Package files exceed the {MAX_ARCHIVE_TOTAL_BYTES}-byte total limit.",
                    )
                    total_limit_reported = True
                continue
            actual_hash, actual_size = _sha256_file_bounded(
                target, limit=MAX_ARCHIVE_FILE_BYTES
            )
        except (OSError, ValueError) as exc:
            add(
                "package.file_unreadable",
                "error",
                f"Manifested file cannot be read: {exc}",
                relative_name,
            )
            continue
        if observed_total + actual_size > MAX_ARCHIVE_TOTAL_BYTES:
            if not total_limit_reported:
                add(
                    "package.total_limit",
                    "error",
                    f"Package files exceed the {MAX_ARCHIVE_TOTAL_BYTES}-byte total limit.",
                )
                total_limit_reported = True
            continue
        observed_total += actual_size
        checked += 1
        if actual_size != expected_size:
            add(
                "package.size_mismatch",
                "error",
                f"Expected {expected_size} bytes but found {actual_size}.",
                relative_name,
            )
        if actual_hash.lower() != expected_hash.lower():
            add(
                "package.checksum_mismatch",
                "error",
                "SHA-256 checksum does not match the manifest.",
                relative_name,
            )

    for relative_name in sorted(required_files - listed):
        add(
            "package.required_file_missing",
            "error",
            "Required review artifact is not recorded in the manifest.",
            relative_name,
        )
    for relative_name in sorted(listed - REVIEW_PACKAGE_ALLOWED_FILES):
        add(
            "package.file_unrecognized",
            "error",
            "Manifest records a file that is not part of this package format.",
            relative_name,
        )

    actual_files: set[str] = set()
    try:
        for index, path in enumerate(package.iterdir(), start=1):
            relative_name = path.name
            if index > MAX_ARCHIVE_ENTRIES + 1:
                add(
                    "package.entry_limit",
                    "error",
                    f"Package directory contains more than {MAX_ARCHIVE_ENTRIES + 1} root entries.",
                )
                break
            if path.is_symlink():
                add(
                    "package.symlink",
                    "error",
                    "Package entries must not be symbolic links.",
                    relative_name,
                )
            elif path.is_file() and relative_name != "manifest.json":
                actual_files.add(relative_name)
            elif path.is_dir():
                add(
                    "package.entry_type",
                    "error",
                    "Review-package entries must be root-level regular files.",
                    relative_name,
                )
            elif relative_name != "manifest.json":
                add(
                    "package.entry_type",
                    "error",
                    "Review-package entry is not a regular file.",
                    relative_name,
                )
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

    schema_verification: dict[str, Any] = {}
    schema_files_listed = REVIEW_PACKAGE_SCHEMA_FILES & listed
    if schema_bundle_declared or schema_files_listed:
        if "schema-catalog.json" not in schema_files_listed:
            add(
                "package.schema_bundle_incomplete",
                "error",
                "The offline schema bundle must include schema-catalog.json.",
                "schema-catalog.json",
            )
        else:
            try:
                from .schema_registry import SCHEMA_CATALOG_FILENAME
                from .schemas import (
                    SCHEMA_CATALOG_FORMAT,
                    verify_schema_bundle_documents,
                )

                schema_documents: dict[str, Any] = {}
                for filename in sorted(schema_files_listed):
                    schema_path = package / filename
                    if schema_path.stat().st_size > 2_000_000:
                        raise ValueError(f"schema file exceeds 2 MB: {filename}")
                    document = _read_bounded_json_object(schema_path, limit=2_000_000)
                    schema_documents[filename] = document
                schema_verification = verify_schema_bundle_documents(schema_documents)
                for error in schema_verification["errors"]:
                    add(
                        f"package.{error['code']}",
                        "error",
                        error["message"],
                        error["path"],
                    )
                if not isinstance(schema_catalog_declaration, dict):
                    add(
                        "package.schema_catalog_declaration_missing",
                        "warning",
                        "Schema files are present without manifest catalog metadata.",
                        SCHEMA_CATALOG_FILENAME,
                    )
                else:
                    catalog_document = schema_documents[SCHEMA_CATALOG_FILENAME]
                    declaration_valid = (
                        schema_catalog_declaration.get("format")
                        == SCHEMA_CATALOG_FORMAT
                        and schema_catalog_declaration.get("path")
                        == SCHEMA_CATALOG_FILENAME
                        and schema_catalog_declaration.get("schema_count")
                        == schema_verification["schema_count"]
                        and schema_catalog_declaration.get("canonical_sha256")
                        == canonical_json_sha256(catalog_document)
                    )
                    if not declaration_valid:
                        add(
                            "package.schema_catalog_declaration_invalid",
                            "error",
                            "Manifest schema-catalog metadata does not match the packaged catalog.",
                            SCHEMA_CATALOG_FILENAME,
                        )
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                add(
                    "package.schema_bundle_invalid",
                    "error",
                    f"Offline schema bundle cannot be verified: {exc}",
                    "schema-catalog.json",
                )

    packaged_analysis: dict[str, Any] | None = None
    analysis_structure_verification: dict[str, Any] = {}
    analysis_path = package / "analysis.json"
    if (
        "analysis.json" in listed
        and analysis_path.is_file()
        and not analysis_path.is_symlink()
    ):
        try:
            analysis = _read_bounded_json_object(
                analysis_path, limit=MAX_ARCHIVE_FILE_BYTES
            )
            analysis_structure_verification = _verify_analysis_structure(analysis)
            if not analysis_structure_verification["valid"]:
                failed = ", ".join(
                    name
                    for name, passed in analysis_structure_verification[
                        "checks"
                    ].items()
                    if not passed
                )
                contract_invalid = not analysis_structure_verification["checks"].get(
                    "core_contract", True
                )
                add(
                    (
                        "package.analysis_contract_invalid"
                        if contract_invalid
                        else "package.analysis_structure_limit"
                    ),
                    "error",
                    "Packaged analysis cannot enter semantic verification: "
                    f"{failed or 'unknown'}.",
                    "analysis.json",
                )
            else:
                packaged_analysis = analysis
            if packaged_analysis is None:
                raise ValueError("analysis structure exceeds safe verification limits")
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
            if (
                state_digest_valid
                and analysis_state_sha256(analysis) != state_digest.lower()
            ):
                add(
                    "package.analysis_state_digest_mismatch",
                    "error",
                    "Packaged analysis does not match the manifest governed-state digest.",
                    "analysis.json",
                )
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            if not analysis_structure_verification:
                analysis_structure_verification = _verify_analysis_structure(
                    None, unavailable_reason=f"Packaged analysis cannot be read: {exc}"
                )
                add(
                    "package.analysis_invalid",
                    "error",
                    f"Packaged analysis cannot be read: {exc}",
                    "analysis.json",
                )
    if not analysis_structure_verification:
        analysis_structure_verification = _verify_analysis_structure(
            None,
            unavailable_reason=(
                "analysis.json is missing, unlisted, symbolic, or not a regular file."
            ),
        )
    queue_verification: dict[str, Any] = {}
    packaged_work_queue: dict[str, Any] | None = None
    queue_path = package / "assurance-work.json"
    if (
        "assurance-work.json" in listed
        and queue_path.is_file()
        and not queue_path.is_symlink()
    ):
        try:
            queue_verification = verify_assurance_work_queue_file(
                queue_path, analysis=packaged_analysis
            )
            packaged_work_queue = _read_bounded_json_object(
                queue_path, limit=MAX_ARCHIVE_FILE_BYTES
            )
            if packaged_analysis is None:
                add(
                    "package.assurance_work_queue_binding_unchecked",
                    "error",
                    "Packaged work queue cannot be reconciled because analysis.json is invalid.",
                    "assurance-work.json",
                )
            elif not queue_verification["valid"]:
                failed = ", ".join(queue_verification["failed_checks"]) or "unknown"
                add(
                    "package.assurance_work_queue_invalid",
                    "error",
                    "Packaged work queue failed exact analysis reconciliation: "
                    f"{failed}.",
                    "assurance-work.json",
                )
        except (OSError, UnicodeError, ValueError) as exc:
            add(
                "package.assurance_work_queue_invalid",
                "error",
                f"Packaged work queue cannot be verified: {exc}",
                "assurance-work.json",
            )
    register_verification: dict[str, Any] = {}
    if _package_requires_assurance_register_projection(manifest):
        register_path = package / "assurance-register.json"
        if (
            "assurance-register.json" in listed
            and register_path.is_file()
            and not register_path.is_symlink()
            and packaged_analysis is not None
            and packaged_work_queue is not None
        ):
            try:
                register_document = _read_bounded_json_object(
                    register_path, limit=MAX_ARCHIVE_FILE_BYTES
                )
                register_verification = verify_assurance_register(
                    register_document,
                    analysis=packaged_analysis,
                    standalone_work_queue=packaged_work_queue,
                )
                if not register_verification["valid"]:
                    failed = ", ".join(
                        name
                        for name, passed in register_verification["checks"].items()
                        if not passed
                    )
                    add(
                        "package.assurance_register_invalid",
                        "error",
                        "Packaged assurance register failed exact reconciliation: "
                        f"{failed or 'unknown'}.",
                        "assurance-register.json",
                    )
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                add(
                    "package.assurance_register_invalid",
                    "error",
                    f"Packaged assurance register cannot be verified: {exc}",
                    "assurance-register.json",
                )
        else:
            add(
                "package.assurance_register_unchecked",
                "error",
                "Assurance register reconciliation requires intact analysis and work-queue artifacts.",
                "assurance-register.json",
            )
    diagnostics_verification: dict[str, Any] = {}
    if _package_requires_analysis_diagnostics_projection(manifest):
        diagnostics_verification = _verify_analysis_diagnostics(
            package,
            listed,
            packaged_analysis,
            str(exporter.get("version", "")) if isinstance(exporter, dict) else "",
        )
        if not diagnostics_verification["valid"]:
            failed = ", ".join(
                name
                for name, passed in diagnostics_verification["checks"].items()
                if not passed
            )
            add(
                "package.analysis_diagnostics_invalid",
                "error",
                "Packaged analysis diagnostics failed exact reconciliation: "
                f"{failed or 'unknown'}.",
                "analysis.json",
            )
    guidance_verification: dict[str, Any] = {}
    if _package_requires_guidance_traceability_projection(manifest):
        guidance_verification = _verify_guidance_traceability(
            package, listed, packaged_analysis
        )
        if not guidance_verification["valid"]:
            failed = ", ".join(
                name
                for name, passed in guidance_verification["checks"].items()
                if not passed
            )
            add(
                "package.guidance_traceability_invalid",
                "error",
                "Packaged guidance traceability failed exact reconciliation: "
                f"{failed or 'unknown'}.",
                "guidance-traceability.json",
            )
    sfta_verification: dict[str, Any] = {}
    if _package_requires_sfta_projection(manifest):
        sfta_verification = _verify_sfta_projection(
            package,
            listed,
            packaged_analysis,
            str(exporter.get("version", "")) if isinstance(exporter, dict) else "",
        )
        if not sfta_verification["valid"]:
            failed = ", ".join(
                name
                for name, passed in sfta_verification["checks"].items()
                if not passed
            )
            add(
                "package.sfta_projection_invalid",
                "error",
                "Packaged SFTA artifacts failed exact reconciliation: "
                f"{failed or 'unknown'}.",
                "sfta.json",
            )
    evidence_verification: dict[str, Any] = {}
    if _package_requires_evidence_catalog_projection(manifest):
        evidence_verification = _verify_evidence_catalog(
            package, listed, packaged_analysis
        )
        if not evidence_verification["valid"]:
            failed = ", ".join(
                name
                for name, passed in evidence_verification["checks"].items()
                if not passed
            )
            add(
                "package.evidence_catalog_invalid",
                "error",
                "Packaged evidence catalog failed exact reconciliation: "
                f"{failed or 'unknown'}.",
                "evidence-catalog.json",
            )
    interchange_verification: dict[str, Any] = {}
    if _package_requires_interchange_artifacts_projection(manifest):
        interchange_verification = _verify_interchange_artifacts(
            package,
            listed,
            packaged_analysis,
            str(manifest.get("generated_at", "")),
            str(exporter.get("version", "")) if isinstance(exporter, dict) else "",
        )
        if not interchange_verification["valid"]:
            failed = ", ".join(
                name
                for name, passed in interchange_verification["checks"].items()
                if not passed
            )
            add(
                "package.interchange_artifacts_invalid",
                "error",
                "Packaged interchange artifacts failed exact reconciliation: "
                f"{failed or 'unknown'}.",
                "findings.sarif",
            )
    review_views_verification: dict[str, Any] = {}
    if _package_requires_review_views_projection(manifest):
        review_views_verification = _verify_review_views(
            package,
            listed,
            packaged_analysis,
            str(exporter.get("version", "")) if isinstance(exporter, dict) else "",
        )
        if not review_views_verification["valid"]:
            failed = ", ".join(
                name
                for name, passed in review_views_verification["checks"].items()
                if not passed
            )
            add(
                "package.review_views_invalid",
                "error",
                "Packaged review views failed exact reconciliation: "
                f"{failed or 'unknown'}.",
                "worksheet.csv",
            )
    provenance_verification: dict[str, Any] = {}
    if _package_requires_provenance_projection(manifest):
        provenance_verification = _verify_package_provenance(
            package, listed, packaged_analysis, manifest
        )
        if not provenance_verification["valid"]:
            failed = ", ".join(
                name
                for name, passed in provenance_verification["checks"].items()
                if not passed
            )
            add(
                "package.provenance_projection_invalid",
                "error",
                "Packaged audit provenance failed exact reconciliation: "
                f"{failed or 'unknown'}.",
                "run-manifest.json",
            )
    result = _package_verification_result(package, findings, checked, package_format)
    result["capabilities"] = (
        list(raw_capabilities)
        if capabilities_valid and isinstance(raw_capabilities, list)
        else []
    )
    result["schema_catalog"] = schema_verification
    result["analysis_structure"] = analysis_structure_verification
    result["assurance_work_queue"] = queue_verification
    result["assurance_register"] = register_verification
    result["analysis_diagnostics"] = diagnostics_verification
    result["guidance_traceability"] = guidance_verification
    result["sfta_projection"] = sfta_verification
    result["evidence_catalog"] = evidence_verification
    result["interchange_artifacts"] = interchange_verification
    result["review_views"] = review_views_verification
    result["package_provenance"] = provenance_verification
    result["binding"] = {
        "baseline_id": str(manifest.get("baseline_id", "")),
        "analysis_schema_version": str(manifest.get("analysis_schema_version", "")),
        "analysis_state_sha256": str(state_digest),
        "portable": bool(manifest.get("portable", False)),
        "source_analysis": str(manifest.get("source_analysis", "")),
    }
    result["manifest_sha256"] = manifest_sha256
    return result


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
        "verification_format": REVIEW_PACKAGE_VERIFICATION_FORMAT,
        "verifier": {"name": "PySFMEA", "version": __version__},
        "package": str(package),
        "container": container,
        "format": package_format,
        "valid": errors == 0,
        "checked_files": checked,
        "counts": {"error": errors, "warning": warnings},
        "findings": findings,
        "notice": "Integrity verification proves recorded bytes and provenance consistency, not engineering approval or semantic correctness.",
    }
