"""Completeness checks for a governed SFMEA review workflow."""

from __future__ import annotations

import fnmatch
import hashlib
import json
from collections import Counter
from datetime import date
from typing import Any

from .config import DEFAULT_CONFIG
from .guidance import (
    APPLICABILITY_TYPES,
    MAPPING_STRENGTHS,
    RELATIONSHIP_TYPES,
    analysis_guidance_profiles,
    guidance_bundle,
    mapping_review_expiry_audit,
)
from .integrity import verify_run_manifest_integrity
from .model import calculate_rpn, utc_now
from .repository_inventory import (
    SNAPSHOT_SOURCES,
    derive_repository_inventory_summary,
    repository_inventory_summary_mismatches,
)
from .sfta import build_sfta

LEVELS = {"error", "warning", "information"}


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def validate_analysis(
    analysis: dict[str, Any], *, legacy_sfta_id_wildcard: bool = False
) -> dict[str, Any]:
    """Return review-quality findings without changing *analysis*."""

    quality = dict(DEFAULT_CONFIG["quality"])
    quality.update(analysis.get("context", {}).get("quality", {}))
    risk = analysis.get("context", {}).get("risk", {})
    severity_categories = set(risk.get("severity_categories", []))
    hazards = {
        hazard.get("id")
        for hazard in analysis.get("context", {}).get("hazards", [])
        if isinstance(hazard, dict) and hazard.get("id")
    }
    findings: list[dict[str, Any]] = []

    def add(
        rule_id: str,
        level: str,
        message: str,
        *,
        item: dict[str, Any] | None = None,
        field: str = "",
    ) -> None:
        findings.append(
            {
                "rule_id": rule_id,
                "level": level,
                "message": message,
                "item_id": (item or {}).get("id", ""),
                "component": (item or {}).get("component", {}).get("qualname", ""),
                "field": field,
            }
        )

    manifest_verification = verify_run_manifest_integrity(analysis)
    for failure in manifest_verification["failures"]:
        add(
            str(failure["code"]),
            "error",
            str(failure["message"]),
            field=str(failure["field"]),
        )

    project_context = analysis.get("context", {}).get("project", {})
    try:
        active_guidance_profiles = analysis_guidance_profiles(analysis)
    except ValueError as exc:
        active_guidance_profiles = ["core_sfmea"]
        add(
            "guidance.invalid_profile_selection",
            "error",
            str(exc),
            field="guidance.active_profiles",
        )
    supplied_guidance = analysis.get("guidance", {})
    if not isinstance(supplied_guidance, dict):
        add(
            "guidance.invalid_catalog",
            "error",
            "The guidance catalog is not an object.",
            field="guidance",
        )
        supplied_guidance = {}
    else:
        catalog_fields = [
            "schema_version",
            "catalog_version",
            "retrieved_at",
            "sources",
            "profiles",
            "citations",
            "rule_mappings",
        ]
        if "organizational_packs" in supplied_guidance:
            catalog_fields.append("organizational_packs")
        supplied_material = {key: supplied_guidance.get(key) for key in catalog_fields}
        if supplied_guidance.get("catalog_sha256") != _digest(supplied_material):
            add(
                "guidance.catalog_integrity_mismatch",
                "error",
                "The embedded guidance catalog digest does not match its content.",
                field="guidance.catalog_sha256",
            )
        elif not supplied_guidance.get("organizational_packs"):
            expected_guidance = guidance_bundle(active_guidance_profiles)
            if (
                supplied_guidance.get("catalog_sha256")
                != expected_guidance["catalog_sha256"]
            ):
                add(
                    "guidance.catalog_drift",
                    "warning",
                    "The embedded guidance catalog differs from the catalog supplied by this PySFMEA version.",
                    field="guidance.catalog_sha256",
                )
    known_citations = {
        citation["id"] for citation in supplied_guidance.get("citations", [])
    }
    applicability = analysis.get("context", {}).get("guidance_applicability", [])
    if not isinstance(applicability, list) or any(
        not isinstance(value, dict) for value in applicability
    ):
        add(
            "guidance.invalid_applicability_decisions",
            "error",
            "Guidance applicability decisions must be an array of governed records.",
            field="context.guidance_applicability",
        )
        applicability = []
    decided_profiles = {
        value.get("profile_id")
        for value in applicability
        if isinstance(value.get("profile_id"), str)
        and value.get("rationale")
        and value.get("selected_by")
        and value.get("effective_date")
    }
    missing_applicability = sorted(set(active_guidance_profiles) - decided_profiles)
    if missing_applicability:
        add(
            "guidance.missing_applicability_decision",
            "warning",
            "Active guidance profiles lack a named project applicability decision: "
            + ", ".join(missing_applicability)
            + ".",
            field="context.guidance_applicability",
        )
    review_expiry = mapping_review_expiry_audit(
        analysis,
        bundle=supplied_guidance,
        active_profiles=active_guidance_profiles,
    )
    if review_expiry["expired_mapping_review_ids"]:
        add(
            "guidance.expired_mapping_review",
            "warning",
            f"{len(review_expiry['expired_mapping_review_ids'])} active guidance mapping "
            f"review(s) expired before the {review_expiry['audit_as_of']} analysis audit date.",
            field="guidance.rule_mappings.review.expires_at",
        )
    if review_expiry["invalid_mapping_review_expiry_ids"]:
        add(
            "guidance.invalid_mapping_review_expiry",
            "error",
            "Active guidance mapping review expiry dates must use YYYY-MM-DD.",
            field="guidance.rule_mappings.review.expires_at",
        )
    analysis_context = analysis.get("context", {}).get("analysis", {})
    if quality["require_project_context"]:
        for field in ("purpose", "boundary", "operating_context"):
            if not project_context.get(field):
                add(
                    f"project.missing_{field}",
                    "error",
                    f"Project {field.replace('_', ' ')} is not configured.",
                    field=f"project.{field}",
                )
    system_context = analysis.get("system_context", {})
    if system_context.get("schema_version") != "pysfmea-system-context-1":
        add(
            "context.missing_manifest",
            "error",
            "The resolved system-context manifest is missing or uses an unsupported schema.",
            field="system_context",
        )
    else:
        context_material = {
            key: system_context.get(key)
            for key in (
                "resolved",
                "fields",
                "status",
                "completeness_percent",
                "missing_required",
                "missing_recommended",
                "unresolved_questions",
                "limitations",
            )
        }
        if system_context.get("context_sha256") != _digest(context_material):
            add(
                "context.integrity_mismatch",
                "error",
                "The resolved system-context digest does not match its content.",
                field="system_context.context_sha256",
            )
        for field in system_context.get("missing_recommended", []):
            add(
                "context.unresolved_recommended_field",
                "information",
                f"Recommended system context remains unresolved: {str(field).replace('_', ' ')}.",
                field=f"system_context.resolved.{field}",
            )
    repository_inventory = analysis.get("repository_inventory", {})
    if (
        not isinstance(repository_inventory, dict)
        or repository_inventory.get("schema_version")
        != "pysfmea-repository-inventory-1"
    ):
        add(
            "coverage.missing_repository_inventory",
            "error",
            "The repository artifact inventory is missing or uses an unsupported schema.",
            field="repository_inventory",
        )
    else:
        entries = repository_inventory.get("entries", [])
        regions = repository_inventory.get("regions", [])
        derived_inventory_summary: dict[str, Any] | None = None
        inventory_material = {
            key: repository_inventory.get(key)
            for key in ("entries", "regions", "truncated")
        }
        if repository_inventory.get("inventory_sha256") != _digest(inventory_material):
            add(
                "coverage.inventory_integrity_mismatch",
                "error",
                "The repository inventory digest does not match its content.",
                field="repository_inventory.inventory_sha256",
            )
        records_are_valid = (
            isinstance(entries, list)
            and isinstance(regions, list)
            and all(isinstance(entry, dict) for entry in entries)
            and all(isinstance(region, dict) for region in regions)
        )
        if not records_are_valid:
            add(
                "coverage.invalid_inventory_records",
                "error",
                "Repository inventory entries and regions must be object-valued lists; rescan to rebuild the inventory.",
                field="repository_inventory",
            )
        else:
            invalid_sources = Counter(
                source
                if isinstance(source, str) and source
                else "<missing-or-non-text>"
                for source in (entry.get("snapshot_source") for entry in entries)
                if not isinstance(source, str) or source not in SNAPSHOT_SOURCES
            )
            if invalid_sources:
                rendered = ", ".join(
                    f"{source} ({count})"
                    for source, count in sorted(invalid_sources.items())
                )
                add(
                    "coverage.invalid_snapshot_provenance",
                    "error",
                    "Repository inventory contains unsupported or missing snapshot provenance: "
                    f"{rendered}. Rescan with the current PySFMEA version.",
                    field="repository_inventory.entries",
                )
            expected_summary = derive_repository_inventory_summary(repository_inventory)
            if expected_summary is None:
                add(
                    "coverage.invalid_inventory_records",
                    "error",
                    "Repository inventory records are missing the status, kind, or snapshot provenance needed for coverage accounting; rescan to rebuild the inventory.",
                    field="repository_inventory.entries",
                )
            else:
                derived_inventory_summary = expected_summary
                mismatches = repository_inventory_summary_mismatches(
                    repository_inventory, expected_summary
                )
                if mismatches:
                    add(
                        "coverage.inventory_summary_mismatch",
                        "error",
                        "Repository inventory summary does not reconcile with its entries and regions "
                        f"({', '.join(mismatches)}); rescan to rebuild derived coverage accounting.",
                        field="repository_inventory.summary",
                    )
        if repository_inventory.get("truncated"):
            add(
                "coverage.inventory_truncated",
                "warning",
                "Repository artifact inventory reached its bounded safety limit.",
                field="repository_inventory.truncated",
            )
        opaque_or_unresolved = (
            derived_inventory_summary.get("opaque_or_unresolved", 0)
            if derived_inventory_summary is not None
            else 0
        )
        if opaque_or_unresolved:
            add(
                "coverage.opaque_or_unresolved_artifacts",
                "information",
                f"{opaque_or_unresolved} repository artifact(s) or region(s) are opaque or unresolved.",
                field="repository_inventory.summary.opaque_or_unresolved",
            )
    adapter_runs = analysis.get("adapter_runs", {})
    if adapter_runs.get("schema_version") != "pysfmea-adapter-run-ledger-1":
        add(
            "provenance.missing_adapter_run_ledger",
            "error",
            "The adapter execution/contribution ledger is missing or unsupported.",
            field="adapter_runs",
        )
    elif adapter_runs.get("ledger_sha256") != _digest(
        {"runs": adapter_runs.get("runs", [])}
    ):
        add(
            "provenance.adapter_ledger_integrity_mismatch",
            "error",
            "The adapter-run ledger digest does not match its content.",
            field="adapter_runs.ledger_sha256",
        )
    if not hazards:
        add(
            "project.no_hazards",
            "information",
            "No project hazards are configured; confirm that hazard linkage is outside this analysis scope.",
            field="hazards",
        )
    if not analysis_context.get("ground_rules"):
        add(
            "analysis.no_ground_rules",
            "error",
            "No SFMEA ground rules are configured.",
            field="analysis.ground_rules",
        )
    if not analysis_context.get("revision"):
        add(
            "analysis.no_revision",
            "error",
            "No analysis revision or lifecycle baseline name is configured.",
            field="analysis.revision",
        )
    baseline = analysis.get("project", {}).get("baseline", {})
    if not baseline.get("id") or not baseline.get("source_digest"):
        add(
            "analysis.missing_source_baseline",
            "error",
            "The analysis does not identify a reproducible source/configuration baseline.",
            field="project.baseline",
        )
    elif baseline.get("vcs", {}).get("dirty") is True:
        add(
            "analysis.dirty_worktree",
            "warning",
            "The scan was produced from a Git worktree with uncommitted or untracked changes.",
            field="project.baseline.vcs",
        )
    configured_reviewer_records = analysis.get("context", {}).get("reviewers", [])
    if not configured_reviewer_records:
        add(
            "analysis.no_reviewers",
            "error",
            "No cross-functional reviewers are identified.",
            field="reviewers",
        )
    elif (
        len({reviewer.get("role", "") for reviewer in configured_reviewer_records}) < 2
    ):
        add(
            "analysis.insufficient_review_diversity",
            "warning",
            "The configured review team represents fewer than two distinct roles.",
            field="reviewers",
        )
    for hazard in analysis.get("context", {}).get("hazards", []):
        if not hazard.get("description"):
            add(
                "catalog.hazard_missing_description",
                "error",
                f"Hazard {hazard.get('id', '<missing ID>')} has no description.",
                field="hazards",
            )
        if not hazard.get("end_effect"):
            add(
                "catalog.hazard_missing_end_effect",
                "error",
                f"Hazard {hazard.get('id', '<missing ID>')} has no system/end effect.",
                field="hazards",
            )
    for requirement in analysis.get("context", {}).get("requirements", []):
        if not requirement.get("text"):
            add(
                "catalog.requirement_missing_text",
                "error",
                f"Requirement {requirement.get('id', '<missing ID>')} has no requirement text.",
                field="requirements",
            )
        if not requirement.get("source"):
            add(
                "catalog.requirement_missing_source",
                "warning",
                f"Requirement {requirement.get('id', '<missing ID>')} has no authoritative source.",
                field="requirements",
            )
    for interface in analysis.get("context", {}).get("system_interfaces", []):
        interface_id = interface.get("id", "<missing ID>")
        if not interface.get("source") or not interface.get("target"):
            add(
                "catalog.interface_missing_endpoint",
                "error",
                f"System interface {interface_id} has an incomplete source/target boundary.",
                field="system_interfaces",
            )
        if not interface.get("description"):
            add(
                "catalog.interface_missing_description",
                "warning",
                f"System interface {interface_id} has no functional description.",
                field="system_interfaces",
            )
    if not analysis.get("context", {}).get("component_mappings"):
        add(
            "analysis.no_architecture_mapping",
            "warning",
            "No components are mapped to requirements, hazards, or subsystems.",
            field="component_mappings",
        )
    for warning in analysis.get("warnings", []):
        add(
            "scan.warning",
            quality["scan_warning_level"],
            f"Scanner warning for {warning.get('path', 'unknown path')}: {warning.get('message', '')}",
        )
    if not analysis.get("components"):
        add(
            "analysis.no_components",
            "error",
            "The analysis contains no scanned or configured components.",
            field="components",
        )
    if not analysis.get("items"):
        add(
            "analysis.no_failure_modes",
            "error",
            "The analysis contains no candidate or manually added failure modes.",
            field="items",
        )
    items_by_id = {
        str(item.get("id", "")): item
        for item in analysis.get("items", [])
        if isinstance(item, dict) and item.get("id")
    }
    assurance = analysis.get("assurance", {})
    obligations = (
        assurance.get("obligations", []) if isinstance(assurance, dict) else []
    )
    executions_by_id = {
        str(value.get("id", "")): value
        for value in assurance.get("executions", [])
        if isinstance(value, dict) and value.get("id")
    }
    obligations_by_finding: dict[str, list[dict[str, Any]]] = {}
    for obligation in obligations:
        if not isinstance(obligation, dict):
            continue
        finding_id = str(obligation.get("finding_id", ""))
        item = items_by_id.get(finding_id)
        obligations_by_finding.setdefault(finding_id, []).append(obligation)
        if item is None:
            add(
                "assurance.unknown_finding",
                "error",
                f"Verification obligation {obligation.get('id', '')} references an unknown finding: {finding_id}.",
                field="assurance.obligations.finding_id",
            )
            continue
        if not obligation.get("acceptance_criteria") or not obligation.get("oracles"):
            add(
                "assurance.incomplete_contract",
                "error",
                f"Verification obligation {obligation.get('id', '')} lacks acceptance criteria or observable oracles.",
                item=item,
                field="assurance.obligations",
            )
        if obligation.get("baseline_id") != analysis.get("project", {}).get(
            "baseline", {}
        ).get("id", ""):
            add(
                "assurance.stale_baseline",
                "warning",
                f"Verification obligation {obligation.get('id', '')} is tied to a different analysis baseline.",
                item=item,
                field="assurance.obligations.baseline_id",
            )
        status = obligation.get("assurance_status")
        if status in {"verified", "closed"}:
            executions = [
                executions_by_id.get(execution_id, {})
                for execution_id in obligation.get("executions", [])
            ]
            review = obligation.get("review", {})
            sufficient_execution = any(
                execution.get("status") == "passed"
                and any(
                    evidence_review.get("decision") == "sufficient"
                    for evidence_review in execution.get("reviews", [])
                    if isinstance(evidence_review, dict)
                )
                for execution in executions
            )
            if (
                obligation.get("evidence_status") != "sufficient"
                or not sufficient_execution
                or not review.get("reviewer")
                or not review.get("rationale")
            ):
                add(
                    "assurance.unsupported_verification",
                    "error",
                    f"Verification obligation {obligation.get('id', '')} is {status} without sufficient executions and an evidence-sufficiency review.",
                    item=item,
                    field="assurance.obligations.assurance_status",
                )
        if status == "closed" and not obligation.get("review", {}).get(
            "acceptance_approved_by"
        ):
            add(
                "assurance.unapproved_closure",
                "error",
                f"Verification obligation {obligation.get('id', '')} is closed without named approval.",
                item=item,
                field="assurance.obligations.review.acceptance_approved_by",
            )
    for execution in executions_by_id.values():
        obligation = next(
            (
                value
                for value in obligations
                if value.get("id") == execution.get("obligation_id")
            ),
            None,
        )
        item = items_by_id.get(str(execution.get("finding_id", "")))
        if obligation is None or item is None:
            add(
                "assurance.execution_trace_broken",
                "error",
                f"Execution {execution.get('id', '')} does not trace to a known obligation and finding.",
                field="assurance.executions",
            )
            continue
        if execution.get("baseline_id") != analysis.get("project", {}).get(
            "baseline", {}
        ).get("id", ""):
            add(
                "assurance.execution_stale",
                "warning",
                f"Execution {execution.get('id', '')} belongs to an older baseline.",
                item=item,
                field="assurance.executions.baseline_id",
            )
        if not execution.get("reviews"):
            add(
                "assurance.execution_unreviewed",
                "information",
                f"Execution {execution.get('id', '')} awaits independent evidence review.",
                item=item,
                field="assurance.executions.reviews",
            )
    for finding_id, item in items_by_id.items():
        if item.get("source_status", "active") != "active":
            continue
        count = len(obligations_by_finding.get(finding_id, []))
        if count != 1:
            add(
                "assurance.obligation_cardinality",
                "error",
                f"Active finding requires exactly one verification obligation; found {count}.",
                item=item,
                field="assurance.obligations",
            )
    gap_count = sum(
        bool(obligation.get("planning_gaps"))
        for obligation in obligations
        if isinstance(obligation, dict)
        and obligation.get("source_status", "active") == "active"
    )
    if gap_count:
        add(
            "assurance.planning_gaps",
            "information",
            f"{gap_count} active verification obligation(s) require effect or control definition before approval.",
            field="assurance.obligations.planning_gaps",
        )
    for suggestion in analysis.get("suggestions", []):
        for citation_id in suggestion.get("proposed_citation_ids", []):
            if citation_id not in known_citations:
                add(
                    "guidance.unknown_suggested_citation",
                    "error",
                    f"Machine suggestion {suggestion.get('id', '')} references an unknown guidance citation: {citation_id}.",
                    field="suggestions.proposed_citation_ids",
                )
        if suggestion.get("status") == "stale":
            add(
                "discovery.stale_suggestion",
                "warning",
                f"Machine suggestion {suggestion.get('id', '')} was generated against an older baseline.",
                field="suggestions",
            )
        elif suggestion.get("status") == "proposed":
            add(
                "discovery.unreviewed_suggestion",
                "information",
                f"Machine suggestion {suggestion.get('id', '')} awaits explicit review.",
                field="suggestions",
            )
    for summary in analysis.get("generated_summaries", []):
        if summary.get("stale"):
            add(
                "discovery.stale_summary",
                "warning",
                f"Generated summary {summary.get('id', '')} was produced for an older baseline.",
                field="generated_summaries",
            )
    runtime_spans = analysis.get("runtime_evidence", {}).get("spans", [])
    unmapped_runtime = sum(not span.get("component_id") for span in runtime_spans)
    if unmapped_runtime:
        add(
            "runtime.unmapped_spans",
            "warning",
            f"{unmapped_runtime} imported runtime span(s) are not mapped to scanned components.",
            field="runtime_evidence",
        )
    current_baseline_id = analysis.get("project", {}).get("baseline", {}).get("id", "")
    stale_trace_imports = sum(
        value.get("baseline_id") != current_baseline_id
        for value in analysis.get("runtime_evidence", {}).get("imports", [])
    )
    if stale_trace_imports:
        add(
            "runtime.stale_trace_baseline",
            "warning",
            f"{stale_trace_imports} runtime trace import(s) were captured for an older source baseline.",
            field="runtime_evidence",
        )
    incomplete_instrumentation = sum(
        isinstance(value.get("instrumentation"), dict)
        and value["instrumentation"].get("declared") is True
        and value["instrumentation"].get("status") != "complete_declared_and_observed"
        for value in analysis.get("runtime_evidence", {}).get("imports", [])
    )
    if incomplete_instrumentation:
        add(
            "runtime.incomplete_instrumentation_scope",
            "warning",
            f"{incomplete_instrumentation} runtime trace import(s) declare instrumentation "
            "scope that was not completely observed.",
            field="runtime_evidence",
        )

    seen_component_ids: set[str] = set()
    for component in analysis.get("components", []):
        component_id = component.get("id", "")
        if not component_id or component_id in seen_component_ids:
            add(
                "analysis.duplicate_or_missing_component_id",
                "error",
                "Component ID is missing or duplicated.",
                field="components",
            )
        seen_component_ids.add(component_id)
    seen_ids: set[str] = set()
    component_ids = seen_component_ids
    observed_hazards: set[str] = set()
    observed_requirements: set[str] = set()
    mapped_interfaces = {
        interface
        for component in analysis.get("components", [])
        for interface in component.get("interface_ids", [])
    }
    code_component_refs = [
        f"{component.get('source', {}).get('path', '')}:{component.get('qualname', '')}"
        for component in analysis.get("components", [])
        if component.get("kind") not in {"environment", "common_cause"}
    ]
    for mapping in analysis.get("context", {}).get("component_mappings", []):
        if not any(
            fnmatch.fnmatchcase(reference, mapping.get("pattern", ""))
            for reference in code_component_refs
        ):
            add(
                "trace.unmatched_component_mapping",
                "warning",
                f"Component mapping pattern matches no scanned component: {mapping.get('pattern', '')}",
                field="component_mappings",
            )
    for critical in analysis.get("context", {}).get("critical_functions", []):
        if not any(
            fnmatch.fnmatchcase(reference, critical.get("pattern", ""))
            for reference in code_component_refs
        ):
            add(
                "trace.unmatched_critical_function",
                "error",
                f"Critical-function pattern matches no scanned component: {critical.get('pattern', '')}",
                field="critical_functions",
            )
    for component in analysis.get("components", []):
        if (
            component.get("kind") == "common_cause"
            and len(component.get("affected_component_ids", [])) < 2
        ):
            add(
                "analysis.incomplete_common_cause",
                "warning",
                f"{component.get('qualname', 'Common cause')} affects fewer than two scanned components.",
                field="common_causes",
            )
    for item in analysis.get("items", []):
        item_id = item.get("id", "")
        if not item_id or item_id in seen_ids:
            add(
                "analysis.duplicate_or_missing_id",
                "error",
                "Item ID is missing or duplicated.",
                item=item,
            )
        seen_ids.add(item_id)
        citation_links = item.get("scanner", {}).get("citations", [])
        if not isinstance(citation_links, list):
            add(
                "guidance.invalid_finding_citations",
                "error",
                "Finding citations must be a list.",
                item=item,
                field="scanner.citations",
            )
            citation_links = []
        for link in citation_links:
            if not isinstance(link, dict):
                add(
                    "guidance.invalid_finding_citation",
                    "error",
                    "A finding citation is not an object.",
                    item=item,
                    field="scanner.citations",
                )
                continue
            citation_id = str(link.get("citation_id", ""))
            if citation_id not in known_citations:
                add(
                    "guidance.unknown_citation",
                    "error",
                    f"Finding references an unknown guidance citation: {citation_id or '<missing ID>'}.",
                    item=item,
                    field="scanner.citations",
                )
            if link.get("relationship") not in RELATIONSHIP_TYPES:
                add(
                    "guidance.invalid_relationship",
                    "error",
                    f"Finding citation {citation_id or '<missing ID>'} has an invalid relationship.",
                    item=item,
                    field="scanner.citations",
                )
            if link.get("strength") not in MAPPING_STRENGTHS:
                add(
                    "guidance.invalid_strength",
                    "error",
                    f"Finding citation {citation_id or '<missing ID>'} has an invalid mapping strength.",
                    item=item,
                    field="scanner.citations",
                )
            if link.get("applicability") not in APPLICABILITY_TYPES:
                add(
                    "guidance.invalid_applicability",
                    "error",
                    f"Finding citation {citation_id or '<missing ID>'} has invalid applicability metadata.",
                    item=item,
                    field="scanner.citations",
                )
        review = item.get("review", {})
        disposition = review.get("disposition", "unreviewed")
        status = review.get("status", "draft")
        active = item.get("source_status", "active") == "active"
        if item.get("source_status", "active") not in {"active", "removed"}:
            add(
                "integrity.invalid_source_status",
                "error",
                f"Invalid source status: {item.get('source_status')!r}",
                item=item,
                field="source_status",
            )
        if item.get("source_change", "") not in {
            "new",
            "changed",
            "impacted",
            "moved",
            "unchanged",
            "removed",
            "manual",
            "legacy",
        }:
            add(
                "integrity.invalid_source_change",
                "error",
                f"Invalid source-change classification: {item.get('source_change')!r}",
                item=item,
                field="source_change",
            )
        if item.get("component_id") and item.get("component_id") not in component_ids:
            add(
                "integrity.unknown_component",
                "error",
                "Failure-mode record references an unknown component.",
                item=item,
                field="component_id",
            )
        if disposition not in {
            "unreviewed",
            "accepted",
            "rejected",
            "needs_information",
        }:
            add(
                "integrity.invalid_disposition",
                "error",
                f"Invalid review disposition: {disposition!r}",
                item=item,
                field="disposition",
            )
        if status not in {
            "draft",
            "in_review",
            "action_required",
            "verified",
            "closed",
        }:
            add(
                "integrity.invalid_status",
                "error",
                f"Invalid workflow status: {status!r}",
                item=item,
                field="status",
            )
        for rating in (
            "severity",
            "occurrence",
            "detection",
            "post_action_severity",
            "post_action_occurrence",
            "post_action_detection",
        ):
            value = review.get(rating)
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= 10
            ):
                add(
                    "integrity.invalid_rating",
                    "error",
                    f"{rating.replace('_', ' ').title()} must be an integer from 1 through 10.",
                    item=item,
                    field=rating,
                )
        for date_field in ("target_date", "approval_date"):
            value = review.get(date_field)
            if value:
                try:
                    date.fromisoformat(value)
                except (TypeError, ValueError):
                    add(
                        "integrity.invalid_date",
                        "error",
                        f"{date_field.replace('_', ' ').title()} must use YYYY-MM-DD.",
                        item=item,
                        field=date_field,
                    )
        for category_field in ("severity_category", "post_action_severity_category"):
            value = review.get(category_field, "")
            if value and (not severity_categories or value not in severity_categories):
                add(
                    "integrity.invalid_severity_category",
                    "error",
                    f"{category_field.replace('_', ' ').title()} is not in the configured scale.",
                    item=item,
                    field=category_field,
                )

        if active and review.get("revalidation_required"):
            add(
                "review.revalidation_required",
                "error",
                "The reviewed item must be revalidated against the current source.",
                item=item,
                field="revalidation_required",
            )
        if (
            active
            and review.get("reviewed_at")
            and not review.get("revalidation_required")
        ):
            fingerprint_pairs = (
                ("validated_fingerprint", "source_fingerprint"),
                ("validated_context_fingerprint", "context_fingerprint"),
                (
                    "validated_analysis_context_fingerprint",
                    "analysis_context_fingerprint",
                ),
            )
            for validated_field, scanner_field in fingerprint_pairs:
                current = item.get("scanner", {}).get(scanner_field, "")
                validated = review.get(validated_field, "")
                if current and validated != current:
                    add(
                        "review.stale_validation_fingerprint",
                        "error",
                        "Review validation evidence does not match the current analysis context.",
                        item=item,
                        field=validated_field,
                    )
                    break
            current_baseline_id = baseline.get("id", "")
            if (
                current_baseline_id
                and review.get("validated_baseline_id") != current_baseline_id
            ):
                add(
                    "review.stale_validation_baseline",
                    "error",
                    "Review validation evidence does not match the current repository baseline.",
                    item=item,
                    field="validated_baseline_id",
                )
        if active and disposition == "unreviewed":
            add(
                "review.unreviewed",
                quality["unreviewed_level"],
                "Candidate has not received a review disposition.",
                item=item,
                field="disposition",
            )
        elif active and disposition == "needs_information":
            add(
                "review.needs_information",
                "warning",
                "Review is waiting for additional information.",
                item=item,
                field="disposition",
            )
        elif (
            active
            and disposition == "rejected"
            and quality["require_rejection_rationale"]
        ):
            if not review.get("disposition_rationale"):
                add(
                    "review.missing_rejection_rationale",
                    "error",
                    "Rejected scanner candidate has no disposition rationale.",
                    item=item,
                    field="disposition_rationale",
                )

        unknown_hazards = set(review.get("linked_hazards", [])) - hazards
        observed_hazards.update(review.get("linked_hazards", []))
        if "hazards" in analysis.get("context", {}) and unknown_hazards:
            add(
                "trace.unknown_hazard",
                "error",
                "Unknown linked hazard ID(s): " + ", ".join(sorted(unknown_hazards)),
                item=item,
                field="linked_hazards",
            )
        requirements = {
            requirement.get("id")
            for requirement in analysis.get("context", {}).get("requirements", [])
            if isinstance(requirement, dict) and requirement.get("id")
        }
        linked_requirements = {
            value.strip()
            for line in str(review.get("requirement", "")).splitlines()
            for value in line.split(",")
            if value.strip()
        }
        unknown_requirements = linked_requirements - requirements
        observed_requirements.update(linked_requirements)
        if requirements and unknown_requirements:
            add(
                "trace.unknown_requirement",
                "error",
                "Unknown requirement ID(s): " + ", ".join(sorted(unknown_requirements)),
                item=item,
                field="requirement",
            )
        configured_reviewers = {
            reviewer.get("name")
            for reviewer in analysis.get("context", {}).get("reviewers", [])
            if isinstance(reviewer, dict) and reviewer.get("name")
        }
        if (
            active
            and disposition != "unreviewed"
            and quality["require_reviewer_for_decision"]
            and not review.get("reviewer")
        ):
            add(
                "review.missing_reviewer",
                "error",
                "A review disposition requires a named reviewer.",
                item=item,
                field="reviewer",
            )
        if (
            configured_reviewers
            and (review.get("reviewed_at") or disposition != "unreviewed")
            and review.get("reviewer") not in configured_reviewers
        ):
            add(
                "review.unidentified_reviewer",
                "error",
                "The latest reviewer is not in the configured review team.",
                item=item,
                field="reviewer",
            )

        if disposition == "accepted":
            if (
                not item.get("component_id")
                or item.get("component_id") not in component_ids
            ):
                add(
                    "accepted.unassigned_component",
                    "error",
                    "Accepted failure mode is not assigned to a known analysis component.",
                    item=item,
                    field="component_id",
                )
            for field, label in (
                ("function", "intended function"),
                ("failure_mode", "failure mode"),
                ("end_effect", "system/end effect"),
            ):
                if not review.get(field):
                    add(
                        f"accepted.missing_{field}",
                        "error",
                        f"Accepted failure mode is missing its {label}.",
                        item=item,
                        field=field,
                    )
            if quality["require_requirement_for_accepted"] and not review.get(
                "requirement"
            ):
                add(
                    "accepted.missing_requirement",
                    "error",
                    "Accepted failure mode has no requirement or trace identifier.",
                    item=item,
                    field="requirement",
                )
            if quality["require_hazard_for_accepted"] and not review.get(
                "linked_hazards"
            ):
                add(
                    "accepted.missing_hazard",
                    "error",
                    "Accepted failure mode is not linked to a project hazard.",
                    item=item,
                    field="linked_hazards",
                )
            if quality["require_severity_for_accepted"] and (
                (risk.get("method") == "sod_rpn" and review.get("severity") is None)
                or (
                    review.get("severity") is None
                    and not review.get("severity_category")
                )
            ):
                add(
                    "accepted.missing_severity",
                    "error",
                    "Accepted failure mode has no severity rating.",
                    item=item,
                    field="severity",
                )
            if quality["require_next_higher_effect_for_accepted"] and not review.get(
                "next_higher_effect"
            ):
                add(
                    "accepted.missing_next_higher_effect",
                    "error",
                    "Accepted failure mode has no next-higher-level effect.",
                    item=item,
                    field="next_higher_effect",
                )
            if quality["require_local_effect_for_accepted"] and not review.get(
                "local_effect"
            ):
                add(
                    "accepted.missing_local_effect",
                    "error",
                    "Accepted failure mode has no local component effect.",
                    item=item,
                    field="local_effect",
                )
            if quality["require_causes_for_accepted"] and not review.get("causes"):
                add(
                    "accepted.missing_causes",
                    "error",
                    "Accepted failure mode has no documented potential cause.",
                    item=item,
                    field="causes",
                )
            if quality["require_rating_rationales"] and (
                review.get("severity") is not None or review.get("severity_category")
            ):
                if not review.get("severity_rationale"):
                    add(
                        "accepted.missing_severity_rationale",
                        "error",
                        "Severity rating has no rationale.",
                        item=item,
                        field="severity_rationale",
                    )
            if risk.get("method") == "sod_rpn":
                for rating in ("occurrence", "detection"):
                    if review.get(rating) is None:
                        add(
                            f"accepted.missing_{rating}",
                            "error",
                            f"The configured S/O/D method requires a {rating} rating.",
                            item=item,
                            field=rating,
                        )
                    elif quality["require_rating_rationales"] and not review.get(
                        f"{rating}_rationale"
                    ):
                        add(
                            f"accepted.missing_{rating}_rationale",
                            "error",
                            f"{rating.title()} rating has no rationale.",
                            item=item,
                            field=f"{rating}_rationale",
                        )
            if quality["require_controls_for_accepted"] and not (
                review.get("prevention_controls") or review.get("detection_controls")
            ):
                add(
                    "accepted.missing_controls",
                    "error",
                    "Accepted failure mode has no existing prevention or detection controls.",
                    item=item,
                    field="prevention_controls",
                )

        if status == "action_required":
            if quality["require_action_description_for_action"] and not review.get(
                "recommended_actions"
            ):
                add(
                    "action.missing_description",
                    "error",
                    "Action-required item has no recommended action description.",
                    item=item,
                    field="recommended_actions",
                )
            if quality["require_owner_for_action"] and not review.get("owner"):
                add(
                    "action.missing_owner",
                    "error",
                    "Action-required item has no owner.",
                    item=item,
                    field="owner",
                )
            if quality["require_target_date_for_action"] and not review.get(
                "target_date"
            ):
                add(
                    "action.missing_target_date",
                    "error",
                    "Action-required item has no target date.",
                    item=item,
                    field="target_date",
                )

        if status in {"verified", "closed"}:
            if disposition != "accepted":
                add(
                    "closure.not_accepted",
                    "error",
                    "Verified or closed items must have an accepted disposition.",
                    item=item,
                    field="disposition",
                )
            if quality["require_verification_for_verified"] and not review.get(
                "verification_evidence"
            ):
                add(
                    "closure.missing_verification",
                    "error",
                    "Verified or closed item has no verification evidence.",
                    item=item,
                    field="verification_evidence",
                )
        if status == "closed" and quality["require_approval_for_closed"]:
            threshold = quality["approval_severity_threshold"]
            severities = (
                review.get("severity"),
                review.get("post_action_severity"),
            )
            severity_categories_for_item = (
                review.get("severity_category"),
                review.get("post_action_severity_category"),
            )
            approval_required = any(
                isinstance(severity, int)
                and not isinstance(severity, bool)
                and severity >= threshold
                for severity in severities
            )
            approval_required = approval_required or bool(
                set(severity_categories_for_item)
                & set(quality["approval_severity_categories"])
            )
            if approval_required:
                if not review.get("approved_by") or not review.get("approval_date"):
                    add(
                        "closure.missing_approval",
                        "error",
                        f"Closed item at or above severity {threshold} lacks named, dated approval.",
                        item=item,
                        field="approved_by",
                    )
                elif (
                    configured_reviewers
                    and review.get("approved_by") not in configured_reviewers
                ):
                    add(
                        "closure.unidentified_approver",
                        "error",
                        "The named risk approver is not in the configured review team.",
                        item=item,
                        field="approved_by",
                    )
        if status == "closed" and quality["require_actions_taken_for_closed"]:
            if not review.get("actions_taken"):
                add(
                    "closure.missing_action_resolution",
                    "error",
                    "Closed item does not record actions taken or an explicit no-action resolution.",
                    item=item,
                    field="actions_taken",
                )
        if status == "closed" and quality["require_post_action_assessment_for_closed"]:
            has_post_severity = review.get("post_action_severity") is not None
            if risk.get("method") != "sod_rpn":
                has_post_severity = has_post_severity or bool(
                    review.get("post_action_severity_category")
                )
            required_residual = [] if has_post_severity else ["post_action_severity"]
            if risk.get("method") == "sod_rpn":
                required_residual.extend(
                    ["post_action_occurrence", "post_action_detection"]
                )
            missing_residual = [
                field for field in required_residual if review.get(field) is None
            ]
            if missing_residual:
                add(
                    "closure.missing_post_action_assessment",
                    "error",
                    "Closed item lacks the configured residual/post-action assessment.",
                    item=item,
                    field=missing_residual[0],
                )
            if quality["require_rating_rationales"]:
                residual_rationales = []
                if has_post_severity and not review.get(
                    "post_action_severity_rationale"
                ):
                    residual_rationales.append("post_action_severity_rationale")
                if risk.get("method") == "sod_rpn":
                    for rating in ("occurrence", "detection"):
                        if review.get(
                            f"post_action_{rating}"
                        ) is not None and not review.get(
                            f"post_action_{rating}_rationale"
                        ):
                            residual_rationales.append(
                                f"post_action_{rating}_rationale"
                            )
                if residual_rationales:
                    add(
                        "closure.missing_post_action_rationale",
                        "error",
                        "Closed item has residual ratings without supporting rationale.",
                        item=item,
                        field=residual_rationales[0],
                    )
        if (
            any(
                review.get(field) is not None
                for field in (
                    "post_action_severity",
                    "post_action_occurrence",
                    "post_action_detection",
                )
            )
            and calculate_rpn(item, post_action=True) is None
            and risk.get("method") == "sod_rpn"
        ):
            add(
                "residual.incomplete_ratings",
                "warning",
                "Post-action S/O/D assessment is incomplete.",
                item=item,
                field="post_action_severity",
            )

    for hazard_id in sorted(hazards - observed_hazards):
        add(
            "trace.unlinked_hazard",
            "warning",
            f"Configured hazard {hazard_id} is not linked to any failure-mode record.",
            field="hazards",
        )
    configured_requirements = {
        requirement.get("id")
        for requirement in analysis.get("context", {}).get("requirements", [])
        if isinstance(requirement, dict) and requirement.get("id")
    }
    for requirement_id in sorted(configured_requirements - observed_requirements):
        add(
            "trace.unlinked_requirement",
            "warning",
            f"Configured requirement {requirement_id} is not linked to any failure-mode record.",
            field="requirements",
        )
    configured_interfaces = {
        interface.get("id")
        for interface in analysis.get("context", {}).get("system_interfaces", [])
        if isinstance(interface, dict) and interface.get("id")
    }
    for interface_id in sorted(configured_interfaces - mapped_interfaces):
        add(
            "trace.unmapped_system_interface",
            "warning",
            f"Configured system interface {interface_id} is not mapped to a scanned component.",
            field="system_interfaces",
        )

    sfta = build_sfta(analysis, legacy_id_wildcard=legacy_sfta_id_wildcard)
    for tree in sfta.get("trees", []):
        if tree.get("source") == "generated_placeholder":
            add(
                "sfta.missing_top_down_decomposition",
                "warning",
                f"Hazard {tree.get('hazard_id')} has no explicit Software Fault Tree decomposition.",
                field="fault_trees",
            )
    reconciliation = sfta.get("reconciliation", {})
    for gap in reconciliation.get("top_down_uncovered_events", []):
        add(
            "sfta.uncovered_top_down_event",
            "warning",
            f"Fault-tree event {gap.get('event_id')} has no correlated bottom-up finding.",
            field="sfta.reconciliation.top_down_uncovered_events",
        )
    item_by_id = {value.get("id"): value for value in analysis.get("items", [])}
    bottom_up_gaps = reconciliation.get("bottom_up_unmapped_findings", [])
    if bottom_up_gaps:
        sample_ids = [
            str(value.get("finding_id", ""))
            for value in bottom_up_gaps[:5]
            if isinstance(value, dict) and value.get("finding_id")
        ]
        add(
            "sfta.unmapped_bottom_up_finding",
            "warning",
            (
                f"{len(bottom_up_gaps)} hazard-linked findings are not correlated to an event "
                "in the hazard's fault tree. Review the complete SFTA reconciliation register; "
                f"sample finding IDs: {', '.join(sample_ids) or 'unavailable'}."
            ),
            item=item_by_id.get(sample_ids[0]) if sample_ids else None,
            field="sfta.reconciliation.bottom_up_unmapped_findings",
        )
    for gap in reconciliation.get("hazard_link_mismatches", []):
        add(
            "sfta.hazard_link_mismatch",
            "error",
            f"Fault-tree event {gap.get('event_id')} correlates a finding that is not linked to hazard {gap.get('hazard_id')}.",
            item=item_by_id.get(gap.get("finding_id")),
            field="linked_hazards",
        )

    counts = Counter(finding["level"] for finding in findings)
    return {
        "generated_at": utc_now(),
        "counts": {
            level: counts.get(level, 0) for level in ("error", "warning", "information")
        },
        "findings": findings,
    }


def review_queue(
    analysis: dict[str, Any],
    *,
    limit: int = 25,
    minimum_priority: str = "low",
    group_families: bool = False,
    max_per_component: int | None = None,
    balance_priorities: bool = False,
) -> list[dict[str, Any]]:
    """Return a bounded, optionally family-grouped human review queue."""

    if minimum_priority not in {"high", "medium", "low"}:
        raise ValueError("minimum_priority must be high, medium, or low")
    if max_per_component is not None and (
        not isinstance(max_per_component, int)
        or isinstance(max_per_component, bool)
        or max_per_component < 1
    ):
        raise ValueError("max_per_component must be a positive integer or null")

    report = validate_analysis(analysis)
    findings_by_item: dict[str, list[dict[str, Any]]] = {}
    for finding in report["findings"]:
        if finding["item_id"]:
            findings_by_item.setdefault(finding["item_id"], []).append(finding)
    priority_rank = {"high": 0, "medium": 1, "low": 2, "manual": 3}
    priority_threshold = priority_rank[minimum_priority]
    change_rank = {"changed": 0, "impacted": 1, "moved": 2, "new": 3, "manual": 4}
    candidates = []
    for item in analysis.get("items", []):
        if item.get("source_status", "active") != "active":
            continue
        review = item.get("review", {})
        findings = findings_by_item.get(item.get("id", ""), [])
        errors = sum(finding["level"] == "error" for finding in findings)
        blocking_errors = sum(
            finding["level"] == "error"
            and finding.get("rule_id") not in {"review.unreviewed"}
            for finding in findings
        )
        warnings = sum(finding["level"] == "warning" for finding in findings)
        if (
            review.get("status") == "closed"
            and not errors
            and not review.get("revalidation_required")
        ):
            continue
        screening_priority = item.get("scanner", {}).get("screening_priority", "")
        if (
            screening_priority != "manual"
            and priority_rank.get(screening_priority, 9) > priority_threshold
        ):
            continue
        component_id = str(item.get("component_id", ""))
        failure_class = str(item.get("scanner", {}).get("failure_class", ""))
        candidates.append(
            {
                "id": item.get("id", ""),
                "component_id": component_id,
                "component": item.get("component", {}).get("qualname", ""),
                "failure_class": failure_class,
                "rule_id": item.get("scanner", {}).get("rule_id", ""),
                "failure_mode": review.get("failure_mode")
                or item.get("scanner", {}).get("failure_mode", ""),
                "path": item.get("source", {}).get("path", ""),
                "line": item.get("source", {}).get("line", 0) or 0,
                "source_change": item.get("source_change", ""),
                "screening_priority": item.get("scanner", {}).get(
                    "screening_priority", ""
                ),
                "disposition": review.get("disposition", ""),
                "hazard_linked": bool(review.get("linked_hazards")),
                "status": review.get("status", ""),
                "revalidation_required": bool(review.get("revalidation_required")),
                "errors": errors,
                "blocking_errors": blocking_errors,
                "warnings": warnings,
                "finding_rules": [finding["rule_id"] for finding in findings],
                "_family_key": (component_id, failure_class),
                "_rank": (
                    0 if review.get("revalidation_required") else 1,
                    0 if blocking_errors else 1,
                    change_rank.get(item.get("source_change", ""), 9),
                    priority_rank.get(
                        item.get("scanner", {}).get("screening_priority", ""), 9
                    ),
                    item.get("source", {}).get("path", ""),
                    item.get("source", {}).get("line", 0) or 0,
                ),
            }
        )
    candidates.sort(key=lambda value: value["_rank"])
    if group_families:
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for candidate in candidates:
            grouped.setdefault(candidate["_family_key"], []).append(candidate)
        candidates = []
        for family in grouped.values():
            representative = family[0]
            family_material = [
                representative["component_id"],
                representative["failure_class"],
            ]
            representative["family_id"] = (
                "REVIEW-FAMILY-" + _digest(family_material)[:12].upper()
            )
            representative["family_size"] = len(family)
            representative["family_rule_ids"] = sorted(
                {str(value["rule_id"]) for value in family}
            )
            representative["family_finding_ids"] = [
                str(value["id"]) for value in family
            ]
            candidates.append(representative)
        candidates.sort(key=lambda value: value["_rank"])
    similarity_clusters: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for candidate in candidates:
        similarity_clusters.setdefault(
            (str(candidate["path"]), str(candidate["failure_class"])), []
        ).append(candidate)
    for (path, failure_class), cluster in similarity_clusters.items():
        cluster_id = "REVIEW-CLUSTER-" + _digest([path, failure_class])[:12].upper()
        cluster_finding_ids = sorted(
            {
                str(finding_id)
                for value in cluster
                for finding_id in value.get("family_finding_ids", [value["id"]])
            }
        )
        for candidate in cluster:
            candidate["review_cluster_id"] = cluster_id
            candidate["review_cluster_size"] = len(cluster_finding_ids)
            candidate["review_cluster_finding_ids"] = cluster_finding_ids[:100]
            candidate["review_cluster_finding_ids_omitted"] = max(
                0, len(cluster_finding_ids) - 100
            )
    if max_per_component is not None:
        selected: list[dict[str, Any]] = []
        component_counts: Counter[str] = Counter()
        for candidate in candidates:
            protected = bool(
                candidate["revalidation_required"]
                or candidate["screening_priority"] == "manual"
                or candidate["hazard_linked"]
            )
            component_id = candidate["component_id"]
            if not protected and component_counts[component_id] >= max_per_component:
                continue
            selected.append(candidate)
            if not protected:
                component_counts[component_id] += 1
        candidates = selected
    diversified: list[dict[str, Any]] = []
    tiers: dict[tuple[Any, ...], dict[str, list[dict[str, Any]]]] = {}
    for candidate in candidates:
        tier = tuple(candidate["_rank"][:4])
        tiers.setdefault(tier, {}).setdefault(candidate["component_id"], []).append(
            candidate
        )
    for tier in sorted(tiers):
        component_buckets = tiers[tier]
        component_order = sorted(
            component_buckets,
            key=lambda component_id: component_buckets[component_id][0]["_rank"],
        )
        max_rounds = max(len(values) for values in component_buckets.values())
        for round_index in range(max_rounds):
            for component_id in component_order:
                bucket = component_buckets[component_id]
                if round_index >= len(bucket):
                    continue
                candidate = bucket[round_index]
                candidate["diversity_round"] = round_index + 1
                reasons = [f"priority:{candidate['screening_priority']}"]
                if candidate["revalidation_required"]:
                    reasons.insert(0, "revalidation_required")
                if candidate["blocking_errors"]:
                    reasons.insert(0, "validation_error")
                if candidate["hazard_linked"]:
                    reasons.insert(0, "hazard_linked")
                if candidate["screening_priority"] == "manual":
                    reasons.insert(0, "manual_priority")
                reasons.append(f"component_diversity_round:{round_index + 1}")
                candidate["selection_reasons"] = reasons
                diversified.append(candidate)
    candidates = diversified
    if balance_priorities and limit > 0:
        # Preserve ranked order while reserving bounded representation for every
        # priority that survived the caller's explicit priority floor.
        selected_ids: set[str] = set()
        balanced: list[dict[str, Any]] = []
        protected_candidates = [
            value
            for value in candidates
            if value["revalidation_required"]
            or value["blocking_errors"]
            or value["hazard_linked"]
            or value["screening_priority"] == "manual"
        ]
        for candidate in protected_candidates[:limit]:
            balanced.append(candidate)
            selected_ids.add(str(candidate["id"]))
        present_priorities = [
            priority
            for priority in ("high", "medium", "low")
            if any(
                value["screening_priority"] == priority
                and str(value["id"]) not in selected_ids
                for value in candidates
            )
        ]
        reserve = max(1, limit // 10)
        for priority in present_priorities:
            added = 0
            for candidate in candidates:
                if len(balanced) >= limit or added >= reserve:
                    break
                candidate_id = str(candidate["id"])
                if (
                    candidate_id in selected_ids
                    or candidate["screening_priority"] != priority
                ):
                    continue
                candidate.setdefault("selection_reasons", []).append(
                    f"priority_reserve:{priority}"
                )
                balanced.append(candidate)
                selected_ids.add(candidate_id)
                added += 1
        for candidate in candidates:
            if len(balanced) >= limit:
                break
            candidate_id = str(candidate["id"])
            if candidate_id not in selected_ids:
                balanced.append(candidate)
                selected_ids.add(candidate_id)
        candidates = balanced
    for value in candidates:
        value.pop("_rank", None)
        value.pop("_family_key", None)
    return candidates[:limit]
