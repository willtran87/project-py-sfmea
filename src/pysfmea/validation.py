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
from .model import calculate_rpn, stable_id, utc_now
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


def _hierarchy_ancestors(
    node_id: str, node_by_id: dict[str, dict[str, Any]]
) -> set[str]:
    """Return bounded ancestors for validation without trusting the supplied graph."""

    ancestors: set[str] = set()
    cursor = str(node_by_id.get(node_id, {}).get("parent_id", ""))
    while cursor and cursor not in ancestors:
        ancestors.add(cursor)
        cursor = str(node_by_id.get(cursor, {}).get("parent_id", ""))
    return ancestors


def validate_analysis(
    analysis: dict[str, Any], *, legacy_sfta_id_wildcard: bool = False
) -> dict[str, Any]:
    """Return review-quality findings without changing *analysis*."""

    quality = dict(DEFAULT_CONFIG["quality"])
    quality.update(analysis.get("context", {}).get("quality", {}))
    risk = analysis.get("context", {}).get("risk", {})
    severity_categories = set(risk.get("severity_categories", []))
    hazards: set[str] = {
        str(hazard.get("id"))
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
    data_flow = analysis.get("interprocedural_data_flow")
    if data_flow is not None:
        data_flow_valid = isinstance(data_flow, dict)
        edges = data_flow.get("edges", []) if data_flow_valid else []
        summary = data_flow.get("summary", {}) if data_flow_valid else {}
        data_flow_valid = (
            data_flow_valid
            and data_flow.get("format") == "pysfmea-interprocedural-data-flow-1"
            and isinstance(edges, list)
            and isinstance(summary, dict)
        )
        data_flow_edge_ids: list[str] = []
        inbound_by_component: dict[str, set[str]] = {
            str(identifier): set() for identifier in component_ids
        }
        outbound_by_component: dict[str, set[str]] = {
            str(identifier): set() for identifier in component_ids
        }
        if data_flow_valid:
            for edge in edges:
                if not isinstance(edge, dict):
                    data_flow_valid = False
                    continue
                edge_id = str(edge.get("id", ""))
                caller_id = str(edge.get("caller_component_id", ""))
                callee_id = str(edge.get("callee_component_id", ""))
                dimensions = edge.get("flow_dimensions", {})
                arguments = edge.get("arguments", [])
                result_flow = edge.get("result_flow", {})
                if (
                    not edge_id
                    or caller_id not in component_ids
                    or callee_id not in component_ids
                    or edge.get("resolution")
                    not in {"unique_static_target", "ambiguous_static_candidates"}
                    or not isinstance(arguments, list)
                    or not all(isinstance(value, dict) for value in arguments)
                    or not isinstance(result_flow, dict)
                    or not isinstance(dimensions, dict)
                    or set(dimensions)
                    != {"parameter", "return", "attribute", "container"}
                    or not all(isinstance(value, bool) for value in dimensions.values())
                ):
                    data_flow_valid = False
                data_flow_edge_ids.append(edge_id)
                if caller_id in outbound_by_component:
                    outbound_by_component[caller_id].add(edge_id)
                if callee_id in inbound_by_component:
                    inbound_by_component[callee_id].add(edge_id)
            embedded = summary.get("embedded_edges")
            omitted = summary.get("edges_omitted")
            resolved = summary.get("resolved_call_edges")
            if (
                len(data_flow_edge_ids) != len(set(data_flow_edge_ids))
                or not all(
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 0
                    for value in (embedded, omitted, resolved)
                )
                or embedded != len(edges)
                or resolved != embedded + omitted
                or summary.get("truncated") != bool(omitted)
            ):
                data_flow_valid = False
            for component in analysis.get("components", []):
                if not isinstance(component, dict):
                    data_flow_valid = False
                    continue
                component_id = str(component.get("id", ""))
                index = component.get("data_flow", {})
                if not isinstance(index, dict):
                    data_flow_valid = False
                    continue
                inbound = index.get("inbound_edge_ids", [])
                outbound = index.get("outbound_edge_ids", [])
                if (
                    not isinstance(inbound, list)
                    or not isinstance(outbound, list)
                    or any(
                        value not in inbound_by_component.get(component_id, set())
                        for value in inbound
                    )
                    or any(
                        value not in outbound_by_component.get(component_id, set())
                        for value in outbound
                    )
                ):
                    data_flow_valid = False
        if not data_flow_valid:
            add(
                "analysis.invalid_interprocedural_data_flow",
                "error",
                "Interprocedural data-flow structure, counts, relationships, or component indexes are inconsistent.",
                field="interprocedural_data_flow",
            )
    alias_flow = analysis.get("alias_object_flow")
    if alias_flow is not None:
        alias_flow_valid = isinstance(alias_flow, dict)
        alias_records = alias_flow.get("records", []) if alias_flow_valid else []
        alias_summary = alias_flow.get("summary", {}) if alias_flow_valid else {}
        alias_flow_valid = (
            alias_flow_valid
            and alias_flow.get("format") == "pysfmea-alias-object-flow-1"
            and isinstance(alias_records, list)
            and isinstance(alias_summary, dict)
        )
        alias_ids: list[str] = []
        if alias_flow_valid:
            for record in alias_records:
                if not isinstance(record, dict):
                    alias_flow_valid = False
                    continue
                identifier = str(record.get("id", ""))
                alias_ids.append(identifier)
                if (
                    not identifier
                    or str(record.get("component_id", "")) not in component_ids
                    or record.get("binding_kind")
                    not in {
                        "local_alias_or_value_binding",
                        "attribute_write",
                        "container_write",
                        "destructuring_or_expression_binding",
                    }
                    or not str(record.get("target", ""))
                    or not isinstance(record.get("source"), dict)
                ):
                    alias_flow_valid = False
            embedded = alias_summary.get("embedded_bindings")
            omitted = alias_summary.get("bindings_omitted")
            discovered = alias_summary.get("bindings_discovered")
            if (
                len(alias_ids) != len(set(alias_ids))
                or not all(
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 0
                    for value in (embedded, omitted, discovered)
                )
                or embedded != len(alias_records)
                or discovered != embedded + omitted
                or alias_summary.get("truncated") != bool(omitted)
            ):
                alias_flow_valid = False
        if not alias_flow_valid:
            add(
                "analysis.invalid_alias_object_flow",
                "error",
                "Alias/object-flow structure, counts, or component relationships are inconsistent.",
                field="alias_object_flow",
            )
    concurrency = analysis.get("concurrency_model")
    if concurrency is not None:
        concurrency_valid = isinstance(concurrency, dict)
        operations = concurrency.get("operations", []) if concurrency_valid else []
        relations = concurrency.get("relations", []) if concurrency_valid else []
        summary = concurrency.get("summary", {}) if concurrency_valid else {}
        concurrency_valid = (
            concurrency_valid
            and concurrency.get("format") == "pysfmea-concurrency-model-1"
            and isinstance(operations, list)
            and isinstance(relations, list)
            and isinstance(summary, dict)
        )
        operation_ids: list[str] = []
        relation_ids: list[str] = []
        operations_by_component: dict[str, list[str]] = {
            str(identifier): [] for identifier in component_ids
        }
        relations_by_component: dict[str, list[str]] = {
            str(identifier): [] for identifier in component_ids
        }
        allowed_categories = {
            "task_spawn",
            "task_join_or_wait",
            "cancellation_or_timeout",
            "synchronization",
            "await_completion",
        }
        allowed_relation_kinds = {
            "lexical_program_order",
            "await_completion_before_next_operation",
            "spawn_to_later_join_candidate",
        }
        if concurrency_valid:
            for operation in operations:
                if not isinstance(operation, dict):
                    concurrency_valid = False
                    continue
                identifier = str(operation.get("id", ""))
                component_id = str(operation.get("component_id", ""))
                categories = operation.get("categories", [])
                operation_ids.append(identifier)
                if component_id in operations_by_component:
                    operations_by_component[component_id].append(identifier)
                if (
                    not identifier
                    or component_id not in component_ids
                    or not isinstance(categories, list)
                    or not categories
                    or len(categories) != len(set(categories))
                    or any(value not in allowed_categories for value in categories)
                    or not isinstance(operation.get("line"), int)
                    or isinstance(operation.get("line"), bool)
                    or int(operation.get("line", -1)) < 0
                    or not isinstance(operation.get("order"), int)
                    or isinstance(operation.get("order"), bool)
                    or int(operation.get("order", -1)) < 0
                ):
                    concurrency_valid = False
            known_operation_ids = set(operation_ids)
            for relation in relations:
                if not isinstance(relation, dict):
                    concurrency_valid = False
                    continue
                identifier = str(relation.get("id", ""))
                component_id = str(relation.get("component_id", ""))
                source_id = str(relation.get("source_operation_id", ""))
                target_id = str(relation.get("target_operation_id", ""))
                relation_ids.append(identifier)
                if component_id in relations_by_component:
                    relations_by_component[component_id].append(identifier)
                if (
                    not identifier
                    or component_id not in component_ids
                    or source_id not in known_operation_ids
                    or target_id not in known_operation_ids
                    or source_id == target_id
                    or relation.get("kind") not in allowed_relation_kinds
                ):
                    concurrency_valid = False
            operation_values = (
                summary.get("operations_discovered"),
                summary.get("operations_embedded"),
                summary.get("operations_omitted"),
            )
            relation_values = (
                summary.get("relations_discovered"),
                summary.get("relations_embedded"),
                summary.get("relations_omitted"),
            )
            expected_operation_categories = dict(
                sorted(
                    Counter(
                        category
                        for operation in operations
                        for category in operation.get("categories", [])
                    ).items()
                )
            )
            expected_relation_kinds = dict(
                sorted(
                    Counter(str(value.get("kind", "")) for value in relations).items()
                )
            )
            if (
                len(operation_ids) != len(set(operation_ids))
                or len(relation_ids) != len(set(relation_ids))
                or not all(
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 0
                    for value in (*operation_values, *relation_values)
                )
                or operation_values[1] != len(operations)
                or operation_values[0] != operation_values[1] + operation_values[2]
                or relation_values[1] != len(relations)
                or relation_values[0] != relation_values[1] + relation_values[2]
                or summary.get("truncated")
                != bool(operation_values[2] or relation_values[2])
                or summary.get("operation_categories") != expected_operation_categories
                or summary.get("relation_kinds") != expected_relation_kinds
            ):
                concurrency_valid = False
            for component in analysis.get("components", []):
                if not isinstance(component, dict):
                    concurrency_valid = False
                    continue
                component_id = str(component.get("id", ""))
                index = component.get("concurrency", {})
                expected_operations = operations_by_component.get(component_id, [])
                expected_relations = relations_by_component.get(component_id, [])
                if (
                    not isinstance(index, dict)
                    or index.get("operation_ids") != expected_operations[:1_000]
                    or index.get("operations_omitted")
                    != max(0, len(expected_operations) - 1_000)
                    or index.get("relation_ids") != expected_relations[:2_000]
                    or index.get("relations_omitted")
                    != max(0, len(expected_relations) - 2_000)
                ):
                    concurrency_valid = False
        if not concurrency_valid:
            add(
                "analysis.invalid_concurrency_model",
                "error",
                "Concurrency operations, relations, counts, or component indexes are inconsistent.",
                field="concurrency_model",
            )
    control_flow_model = analysis.get("static_control_flow_model")
    if control_flow_model is not None:
        control_flow_valid = isinstance(control_flow_model, dict)
        decisions = (
            control_flow_model.get("decisions", []) if control_flow_valid else []
        )
        control_flow_summary = (
            control_flow_model.get("summary", {}) if control_flow_valid else {}
        )
        control_flow_valid = (
            control_flow_valid
            and control_flow_model.get("format")
            == "pysfmea-static-control-flow-model-2"
            and isinstance(decisions, list)
            and isinstance(control_flow_summary, dict)
            and control_flow_model.get("limits")
            == {
                "records_per_component": 10_000,
                "decisions": 100_000,
                "expression_depth": 20,
                "integer_bits": 4_096,
                "sequence_length": 4_096,
                "power_exponent": 64,
                "shift": 1_024,
            }
        )
        decision_ids: list[str] = []
        decisions_by_component: dict[str, list[str]] = {
            str(identifier): [] for identifier in component_ids
        }
        components_by_id = {
            str(value.get("id", "")): value
            for value in analysis.get("components", [])
            if isinstance(value, dict)
        }
        if control_flow_valid:
            allowed_kinds = {
                "if_statement",
                "if_expression",
                "while_statement",
                "boolean_short_circuit",
                "empty_for_loop",
                "nonempty_for_loop",
                "match_case_pattern",
                "match_case_guard",
                "try_else_clause",
                "statement_sequence_termination",
            }
            allowed_bases = {
                "literal_truth",
                "literal_comparison",
                "bounded_literal_expression",
                "static_boolean_expression",
                "type_checking_guard",
                "empty_literal_iterable",
                "empty_bounded_literal_iterable",
                "nonempty_iteration_terminal_body",
                "direct_terminal_statement",
                "statically_selected_terminal_block",
                "all_conditional_branches_terminal",
                "context_block_terminal",
                "empty_iteration_else_terminal",
                "false_loop_else_terminal",
                "static_pattern_match",
                "static_pattern_mismatch",
                "irrefutable_pattern",
                "statically_selected_match_case_terminal",
                "exhaustive_match_cases_terminal",
                "static_true_loop_without_break",
                "try_body_cannot_fall_through",
                "terminal_finally_block",
                "all_try_paths_terminal",
            }
            for decision in decisions:
                if not isinstance(decision, dict):
                    control_flow_valid = False
                    continue
                identifier = str(decision.get("id", ""))
                component_id = str(decision.get("component_id", ""))
                component = components_by_id.get(component_id, {})
                source = component.get("source", {})
                decision_ids.append(identifier)
                if component_id in decisions_by_component:
                    decisions_by_component[component_id].append(identifier)
                raw_records = component.get("control_flow_decisions", [])
                raw_match = next(
                    (
                        value
                        for value in raw_records
                        if isinstance(value, dict)
                        and str(value.get("id", "")) == identifier
                    ),
                    None,
                )
                raw_projection = {
                    key: value
                    for key, value in decision.items()
                    if key not in {"component_id", "component_reference"}
                }
                if (
                    not identifier
                    or component_id not in component_ids
                    or not isinstance(decision.get("decision"), bool)
                    or decision.get("kind") not in allowed_kinds
                    or decision.get("basis") not in allowed_bases
                    or not isinstance(decision.get("line"), int)
                    or isinstance(decision.get("line"), bool)
                    or int(decision.get("line", 0)) <= 0
                    or not isinstance(decision.get("column"), int)
                    or isinstance(decision.get("column"), bool)
                    or int(decision.get("column", 0)) < 0
                    or not isinstance(decision.get("end_column"), int)
                    or isinstance(decision.get("end_column"), bool)
                    or int(decision.get("end_column", 0)) < int(
                        decision.get("column", 0)
                    )
                    or not isinstance(decision.get("pruned_operand_count"), int)
                    or isinstance(decision.get("pruned_operand_count"), bool)
                    or int(decision.get("pruned_operand_count", 0)) < 0
                    or not isinstance(decision.get("pruned_statement_count"), int)
                    or isinstance(decision.get("pruned_statement_count"), bool)
                    or int(decision.get("pruned_statement_count", 0)) < 0
                    or not isinstance(decision.get("decisive_operand_index"), int)
                    or isinstance(decision.get("decisive_operand_index"), bool)
                    or int(decision.get("decisive_operand_index", 0)) < 0
                    or raw_match != raw_projection
                    or identifier
                    != stable_id(
                        "STATIC-CONTROL-FLOW",
                        str(source.get("path", "")),
                        str(component.get("qualname", "")),
                        str(decision.get("kind", "")),
                        str(decision.get("line", 0)),
                        str(decision.get("column", 0)),
                        str(decision.get("end_column", 0)),
                        str(decision.get("expression", "")),
                        str(decision.get("decision")),
                        str(decision.get("selected_branch", "")),
                    )
                ):
                    control_flow_valid = False
            source_records = sum(
                len(value.get("control_flow_decisions", []))
                for value in components_by_id.values()
                if isinstance(value.get("control_flow_decisions", []), list)
            )
            source_omitted = sum(
                int(value.get("control_flow_decisions_omitted", 0))
                for value in components_by_id.values()
                if isinstance(value.get("control_flow_decisions_omitted", 0), int)
                and not isinstance(
                    value.get("control_flow_decisions_omitted", 0), bool
                )
                and int(value.get("control_flow_decisions_omitted", 0)) >= 0
            )
            expected_omitted = source_omitted + source_records - len(decisions)
            expected_kinds = dict(
                sorted(Counter(str(value.get("kind", "")) for value in decisions).items())
            )
            expected_bases = dict(
                sorted(Counter(str(value.get("basis", "")) for value in decisions).items())
            )
            summary_integers = (
                control_flow_summary.get("decisions_discovered"),
                control_flow_summary.get("decisions_embedded"),
                control_flow_summary.get("decisions_omitted"),
                control_flow_summary.get("true_decisions"),
                control_flow_summary.get("false_decisions"),
                control_flow_summary.get("pruned_operands"),
                control_flow_summary.get("pruned_statements"),
            )
            if (
                len(decision_ids) != len(set(decision_ids))
                or not all(
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 0
                    for value in summary_integers
                )
                or control_flow_summary.get("decisions_discovered") != source_records
                or control_flow_summary.get("decisions_embedded") != len(decisions)
                or control_flow_summary.get("decisions_omitted") != expected_omitted
                or control_flow_summary.get("true_decisions")
                != sum(value.get("decision") is True for value in decisions)
                or control_flow_summary.get("false_decisions")
                != sum(value.get("decision") is False for value in decisions)
                or control_flow_summary.get("pruned_operands")
                != sum(int(value.get("pruned_operand_count", 0)) for value in decisions)
                or control_flow_summary.get("pruned_statements")
                != sum(
                    int(value.get("pruned_statement_count", 0))
                    for value in decisions
                )
                or control_flow_summary.get("decision_kinds") != expected_kinds
                or control_flow_summary.get("decision_bases") != expected_bases
                or control_flow_summary.get("truncated") != bool(expected_omitted)
            ):
                control_flow_valid = False
            for component_id, component in components_by_id.items():
                expected = decisions_by_component.get(component_id, [])
                index = component.get("static_control_flow", {})
                if (
                    not isinstance(index, dict)
                    or index.get("decision_ids") != expected[:1_000]
                    or index.get("decisions_omitted")
                    != max(0, len(expected) - 1_000)
                ):
                    control_flow_valid = False
        if not control_flow_valid:
            add(
                "analysis.invalid_static_control_flow_model",
                "error",
                "Static control-flow decisions, counts, source projections, or component indexes are inconsistent.",
                field="static_control_flow_model",
            )
    exception_model = analysis.get("exception_propagation")
    if exception_model is not None:
        exception_valid = isinstance(exception_model, dict)
        raises = exception_model.get("raises", []) if exception_valid else []
        handlers = exception_model.get("handlers", []) if exception_valid else []
        finalizers = exception_model.get("finalizers", []) if exception_valid else []
        exception_edges = exception_model.get("edges", []) if exception_valid else []
        summary = exception_model.get("summary", {}) if exception_valid else {}
        exception_valid = (
            exception_valid
            and exception_model.get("format") == "pysfmea-exception-propagation-3"
            and isinstance(raises, list)
            and isinstance(handlers, list)
            and isinstance(finalizers, list)
            and isinstance(exception_edges, list)
            and isinstance(summary, dict)
        )
        raise_ids: list[str] = []
        handler_ids: list[str] = []
        finalizer_ids: list[str] = []
        exception_edge_ids: list[str] = []
        raises_by_component: dict[str, list[str]] = {
            str(identifier): [] for identifier in component_ids
        }
        handlers_by_component: dict[str, list[str]] = {
            str(identifier): [] for identifier in component_ids
        }
        finalizers_by_component: dict[str, list[str]] = {
            str(identifier): [] for identifier in component_ids
        }
        exception_inbound_by_component: dict[str, list[str]] = {
            str(identifier): [] for identifier in component_ids
        }
        exception_outbound_by_component: dict[str, list[str]] = {
            str(identifier): [] for identifier in component_ids
        }
        exception_records_by_caller: dict[str, list[dict[str, Any]]] = {
            str(identifier): [] for identifier in component_ids
        }
        components = [
            value for value in analysis.get("components", []) if isinstance(value, dict)
        ]
        exception_components_by_id = {
            str(value.get("id", "")): value for value in components if value.get("id")
        }
        allowed_actions = {
            "reraises",
            "raises_explicitly",
            "translates",
            "control_flow_exit",
            "suppresses",
            "records_or_logs",
            "continues_after_handler",
        }
        allowed_dispositions = {
            "may_propagate",
            "indeterminate_handler_match",
            "caught_and_reraised",
            "caught_and_translates",
            "caught_and_raises_explicitly",
            "caught_and_exits_control_flow",
            "caught_and_suppresses",
            "caught_and_continues",
            "caught_with_mixed_handler_outcome",
            "caught_with_conditional_reraise",
            "caught_with_conditional_translation",
            "caught_with_conditional_explicit_raise",
            "caught_with_conditional_control_flow_exit",
            "caught_with_indeterminate_handler_outcome",
            "suppressed_by_finally_control_flow",
            "replaced_by_finally_exception",
        }
        propagating_dispositions = {
            "may_propagate",
            "indeterminate_handler_match",
            "caught_and_reraised",
            "caught_with_conditional_reraise",
            "caught_with_indeterminate_handler_outcome",
            "caught_with_mixed_handler_outcome",
        }
        allowed_match_kinds = {
            "no_handler_match",
            "exact_type",
            "builtin_subclass",
            "project_subclass",
            "base_exception_catch_all",
            "indeterminate_dynamic_type",
            "indeterminate_handler_order",
        }
        definite_match_kinds = {
            "exact_type",
            "builtin_subclass",
            "project_subclass",
            "base_exception_catch_all",
        }
        allowed_handler_outcome_kinds = {
            "fallthrough",
            "reraise",
            "raise",
            "return",
            "break",
            "continue",
            "indeterminate",
        }
        if exception_valid:
            for record in raises:
                if not isinstance(record, dict):
                    exception_valid = False
                    continue
                identifier = str(record.get("id", ""))
                component_id = str(record.get("component_id", ""))
                raise_ids.append(identifier)
                if component_id in raises_by_component:
                    raises_by_component[component_id].append(identifier)
                if (
                    not identifier
                    or component_id not in component_ids
                    or not str(record.get("exception_type", ""))
                    or not isinstance(record.get("bare_reraise"), bool)
                    or not isinstance(record.get("reraises_active_handler"), bool)
                    or record.get("bare_reraise")
                    and record.get("reraises_active_handler") is not True
                    or record.get("reraises_active_handler") is True
                    and record.get("exception_type") != "active_handler_exception"
                    or not isinstance(record.get("control_context"), list)
                ):
                    exception_valid = False
            for record in handlers:
                if not isinstance(record, dict):
                    exception_valid = False
                    continue
                identifier = str(record.get("id", ""))
                component_id = str(record.get("component_id", ""))
                exception_types = record.get("exception_types", [])
                actions = record.get("actions", [])
                outcomes = record.get("outcomes", [])
                outcome_kinds = record.get("outcome_kinds", [])
                normalized_outcomes = {
                    (
                        str(value.get("kind", "")),
                        str(value.get("exception_type", "")),
                    )
                    for value in outcomes
                    if isinstance(value, dict)
                }
                expected_outcome_kinds = sorted(
                    value[0] for value in normalized_outcomes
                )
                expected_outcome_kinds = sorted(set(expected_outcome_kinds))
                outcomes_truncated = record.get("outcomes_truncated")
                expected_certainty = (
                    "indeterminate"
                    if outcomes_truncated is True
                    or "indeterminate" in expected_outcome_kinds
                    else "uniform"
                    if len(normalized_outcomes) == 1
                    else "conditional"
                )
                handler_ids.append(identifier)
                if component_id in handlers_by_component:
                    handlers_by_component[component_id].append(identifier)
                if (
                    not identifier
                    or component_id not in component_ids
                    or not isinstance(exception_types, list)
                    or not exception_types
                    or not all(
                        isinstance(value, str) and value for value in exception_types
                    )
                    or not isinstance(actions, list)
                    or not actions
                    or any(value not in allowed_actions for value in actions)
                    or not isinstance(outcomes, list)
                    or not outcomes
                    or len(outcomes) > 250
                    or len(outcomes)
                    != len(
                        {
                            (
                                value.get("kind"),
                                value.get("exception_type"),
                                value.get("line"),
                            )
                            for value in outcomes
                            if isinstance(value, dict)
                        }
                    )
                    or any(
                        not isinstance(value, dict)
                        or value.get("kind") not in allowed_handler_outcome_kinds
                        or not isinstance(value.get("exception_type"), str)
                        or bool(value.get("exception_type"))
                        != (value.get("kind") in {"raise", "reraise"})
                        or value.get("kind") == "reraise"
                        and value.get("exception_type") != "active_handler_exception"
                        or not isinstance(value.get("line"), int)
                        or isinstance(value.get("line"), bool)
                        or int(value.get("line", -1)) < 0
                        or value.get("kind") != "fallthrough"
                        and int(value.get("line", 0)) <= 0
                        for value in outcomes
                    )
                    or outcome_kinds != expected_outcome_kinds
                    or not isinstance(outcomes_truncated, bool)
                    or record.get("outcome_certainty") != expected_certainty
                    or not isinstance(record.get("may_reraise_original"), bool)
                    or record.get("may_reraise_original")
                    != ("reraise" in expected_outcome_kinds)
                    or ("reraises" in actions) != ("reraise" in expected_outcome_kinds)
                    or ("raises_explicitly" in actions)
                    != ("raise" in expected_outcome_kinds)
                    or ("control_flow_exit" in actions)
                    != bool(
                        set(expected_outcome_kinds) & {"return", "break", "continue"}
                    )
                    or ("translates" in actions)
                    != bool(record.get("translated_exception_types", []))
                    or record.get("handler_kind") not in {"standard", "exception_group"}
                    or not isinstance(record.get("handler_index"), int)
                    or isinstance(record.get("handler_index"), bool)
                    or int(record.get("handler_index", -1)) < 0
                ):
                    exception_valid = False
            allowed_finalizer_actions = {
                "returns",
                "raises",
                "breaks",
                "continues",
                "records_or_logs",
            }
            allowed_finalizer_terminal_bases = {
                "uniform_safe_terminal_outcome",
                "evaluated_return_expression",
                "uniform_nonterminal_outcome",
                "conditional_or_fallthrough_outcomes",
                "indeterminate_or_truncated_outcomes",
            }
            for record in finalizers:
                if not isinstance(record, dict):
                    exception_valid = False
                    continue
                identifier = str(record.get("id", ""))
                component_id = str(record.get("component_id", ""))
                actions = record.get("actions", [])
                outcomes = record.get("outcomes", [])
                outcome_kinds = record.get("outcome_kinds", [])
                normalized_outcomes = {
                    (
                        str(value.get("kind", "")),
                        str(value.get("exception_type", "")),
                    )
                    for value in outcomes
                    if isinstance(value, dict)
                }
                expected_outcome_kinds = sorted(
                    {value[0] for value in normalized_outcomes}
                )
                outcomes_truncated = record.get("outcomes_truncated")
                expected_certainty = (
                    "indeterminate"
                    if outcomes_truncated is True
                    or "indeterminate" in expected_outcome_kinds
                    else "uniform"
                    if len(normalized_outcomes) == 1
                    else "conditional"
                )
                terminal_kind = str(record.get("terminal_kind", ""))
                terminal_exception_type = str(record.get("terminal_exception_type", ""))
                terminal_basis = str(record.get("terminal_basis", ""))
                component_record = exception_components_by_id.get(component_id, {})
                component_path = str(component_record.get("source", {}).get("path", ""))
                component_qualname = str(component_record.get("qualname", ""))
                finalizer_ids.append(identifier)
                if component_id in finalizers_by_component:
                    finalizers_by_component[component_id].append(identifier)
                if (
                    not identifier
                    or component_id not in component_ids
                    or record.get("component_reference")
                    != f"{component_path}:{component_qualname}"
                    or not isinstance(actions, list)
                    or any(value not in allowed_finalizer_actions for value in actions)
                    or not isinstance(outcomes, list)
                    or not outcomes
                    or len(outcomes) > 250
                    or len(outcomes)
                    != len(
                        {
                            (
                                value.get("kind"),
                                value.get("exception_type"),
                                value.get("line"),
                            )
                            for value in outcomes
                            if isinstance(value, dict)
                        }
                    )
                    or any(
                        not isinstance(value, dict)
                        or value.get("kind") not in allowed_handler_outcome_kinds
                        or not isinstance(value.get("exception_type"), str)
                        or bool(value.get("exception_type"))
                        != (value.get("kind") in {"raise", "reraise"})
                        or value.get("kind") == "reraise"
                        and value.get("exception_type") != "active_handler_exception"
                        or not isinstance(value.get("line"), int)
                        or isinstance(value.get("line"), bool)
                        or int(value.get("line", -1)) < 0
                        or value.get("kind") != "fallthrough"
                        and int(value.get("line", 0)) <= 0
                        for value in outcomes
                    )
                    or outcome_kinds != expected_outcome_kinds
                    or not isinstance(outcomes_truncated, bool)
                    or record.get("outcome_certainty") != expected_certainty
                    or terminal_kind
                    not in {"none", "return", "raise", "reraise", "break", "continue"}
                    or not isinstance(record.get("unconditional_terminal"), bool)
                    or record.get("unconditional_terminal") != (terminal_kind != "none")
                    or bool(terminal_exception_type)
                    != (terminal_kind in {"raise", "reraise"})
                    or terminal_kind == "reraise"
                    and terminal_exception_type != "active_handler_exception"
                    or terminal_basis not in allowed_finalizer_terminal_bases
                    or (terminal_kind != "none")
                    != (terminal_basis == "uniform_safe_terminal_outcome")
                    or terminal_kind != "none"
                    and normalized_outcomes
                    != {(terminal_kind, terminal_exception_type)}
                    or terminal_basis == "evaluated_return_expression"
                    and normalized_outcomes != {("return", "")}
                    or terminal_basis == "uniform_nonterminal_outcome"
                    and normalized_outcomes != {("fallthrough", "")}
                    or terminal_basis == "conditional_or_fallthrough_outcomes"
                    and expected_certainty != "conditional"
                    or terminal_basis == "indeterminate_or_truncated_outcomes"
                    and expected_certainty != "indeterminate"
                    or record.get("authority")
                    != "bounded_branch_aware_static_finally_outcome_candidate"
                    or not isinstance(record.get("try_line"), int)
                    or isinstance(record.get("try_line"), bool)
                    or int(record.get("try_line", 0)) <= 0
                    or not isinstance(record.get("line"), int)
                    or isinstance(record.get("line"), bool)
                    or int(record.get("line", 0)) <= 0
                    or identifier
                    != stable_id(
                        "EXCEPTION-FINALIZER",
                        component_path,
                        component_qualname,
                        str(record.get("try_line", 0)),
                        str(record.get("line", 0)),
                        terminal_kind,
                        terminal_exception_type,
                    )
                ):
                    exception_valid = False
            known_handler_ids = set(handler_ids)
            known_finalizer_ids = set(finalizer_ids)
            handlers_by_id = {
                str(value.get("id", "")): value
                for value in handlers
                if isinstance(value, dict) and value.get("id")
            }
            finalizers_by_id = {
                str(value.get("id", "")): value
                for value in finalizers
                if isinstance(value, dict) and value.get("id")
            }
            for edge in exception_edges:
                if not isinstance(edge, dict):
                    exception_valid = False
                    continue
                identifier = str(edge.get("id", ""))
                caller_id = str(edge.get("caller_component_id", ""))
                callee_id = str(edge.get("callee_component_id", ""))
                edge_handler_ids = edge.get("handler_ids", [])
                disposition = edge.get("disposition")
                selected_handler_id = str(edge.get("selected_handler_id", ""))
                handler_actions = edge.get("handler_actions", [])
                handler_outcomes = edge.get("handler_outcomes", [])
                handler_outcome_certainty = str(
                    edge.get("handler_outcome_certainty", "")
                )
                handler_may_reraise_original = edge.get("handler_may_reraise_original")
                finalizer_id = str(edge.get("finalizer_id", ""))
                finalizer_terminal_kind = str(edge.get("finalizer_terminal_kind", ""))
                finalizer_exception_type = str(edge.get("finalizer_exception_type", ""))
                match_kind = edge.get("match_kind")
                call_site = edge.get("call_site", {})
                exception_edge_ids.append(identifier)
                if caller_id in exception_inbound_by_component:
                    exception_inbound_by_component[caller_id].append(identifier)
                    exception_records_by_caller[caller_id].append(edge)
                if callee_id in exception_outbound_by_component:
                    exception_outbound_by_component[callee_id].append(identifier)
                if (
                    not identifier
                    or caller_id not in component_ids
                    or callee_id not in component_ids
                    or not str(edge.get("exception_type", ""))
                    or disposition not in allowed_dispositions
                    or edge.get("resolution")
                    not in {"unique_static_target", "ambiguous_static_candidates"}
                    or not isinstance(edge_handler_ids, list)
                    or any(value not in known_handler_ids for value in edge_handler_ids)
                    or selected_handler_id
                    and selected_handler_id not in known_handler_ids
                    or bool(edge_handler_ids) != (match_kind != "no_handler_match")
                    or bool(selected_handler_id)
                    and selected_handler_id not in edge_handler_ids
                    or not isinstance(handler_actions, list)
                    or any(value not in allowed_actions for value in handler_actions)
                    or bool(selected_handler_id)
                    and handler_actions
                    != handlers_by_id.get(selected_handler_id, {}).get("actions", [])
                    or not isinstance(handler_outcomes, list)
                    or bool(selected_handler_id)
                    and handler_outcomes
                    != handlers_by_id.get(selected_handler_id, {}).get("outcomes", [])
                    or not selected_handler_id
                    and handler_outcomes
                    or bool(selected_handler_id) != bool(handler_outcome_certainty)
                    or bool(selected_handler_id)
                    and handler_outcome_certainty
                    != handlers_by_id.get(selected_handler_id, {}).get(
                        "outcome_certainty", ""
                    )
                    or not isinstance(handler_may_reraise_original, bool)
                    or bool(selected_handler_id)
                    and handler_may_reraise_original
                    != handlers_by_id.get(selected_handler_id, {}).get(
                        "may_reraise_original", False
                    )
                    or not selected_handler_id
                    and handler_may_reraise_original
                    or finalizer_id
                    and finalizer_id not in known_finalizer_ids
                    or bool(finalizer_id) != bool(finalizer_terminal_kind)
                    or bool(finalizer_exception_type)
                    != (finalizer_terminal_kind in {"raise", "reraise"})
                    or bool(finalizer_id)
                    and finalizer_terminal_kind
                    != finalizers_by_id.get(finalizer_id, {}).get("terminal_kind", "")
                    or bool(finalizer_id)
                    and finalizer_exception_type
                    != finalizers_by_id.get(finalizer_id, {}).get(
                        "terminal_exception_type", ""
                    )
                    or (finalizer_terminal_kind == "raise")
                    != (disposition == "replaced_by_finally_exception")
                    or disposition == "suppressed_by_finally_control_flow"
                    and finalizer_terminal_kind not in {"return", "break", "continue"}
                    or match_kind not in allowed_match_kinds
                    or bool(selected_handler_id) != (match_kind in definite_match_kinds)
                    or disposition == "may_propagate"
                    and match_kind != "no_handler_match"
                    or disposition == "indeterminate_handler_match"
                    and match_kind
                    not in {
                        "indeterminate_dynamic_type",
                        "indeterminate_handler_order",
                    }
                    or not isinstance(edge.get("propagates_original"), bool)
                    or edge.get("propagates_original")
                    != (disposition in propagating_dispositions)
                    or not isinstance(call_site, dict)
                    or identifier
                    != stable_id(
                        "EXCEPTION-PROPAGATION",
                        str(edge.get("caller_reference", "")),
                        str(edge.get("callee_reference", "")),
                        str(call_site.get("line", 0)),
                        str(call_site.get("order", 0)),
                        str(edge.get("exception_type", "")),
                        str(disposition),
                    )
                ):
                    exception_valid = False
            source_raise_count = sum(
                len(value.get("exception_raises", []))
                for value in components
                if isinstance(value.get("exception_raises", []), list)
            )
            source_handler_count = sum(
                len(value.get("exception_handlers", []))
                for value in components
                if isinstance(value.get("exception_handlers", []), list)
            )
            source_finalizer_count = sum(
                len(value.get("exception_finalizers", []))
                for value in components
                if isinstance(value.get("exception_finalizers", []), list)
            )
            per_component_omitted = sum(
                int(value.get("exception_records_omitted", 0))
                for value in components
                if isinstance(value.get("exception_records_omitted", 0), int)
                and not isinstance(value.get("exception_records_omitted", 0), bool)
                and int(value.get("exception_records_omitted", 0)) >= 0
            )
            edge_values = (
                summary.get("propagation_edges_discovered"),
                summary.get("propagation_edges_embedded"),
                summary.get("propagation_edges_omitted"),
            )
            integer_summary_values = (
                summary.get("raise_records_discovered"),
                summary.get("raise_records_embedded"),
                summary.get("handler_records_discovered"),
                summary.get("handler_records_embedded"),
                summary.get("handlers_may_reraise_original"),
                summary.get("finalizer_records_discovered"),
                summary.get("finalizer_records_embedded"),
                summary.get("unconditional_terminal_finalizers"),
                summary.get("source_records_omitted"),
                *edge_values,
                summary.get("locally_caught_raise_candidates"),
                summary.get("locally_rethrown_raise_candidates"),
                summary.get("local_raises_suppressed_by_finally"),
                summary.get("local_raises_replaced_by_finally"),
                summary.get("outgoing_exception_types"),
                summary.get("fixed_point_iterations"),
                summary.get("project_exception_types_indexed"),
            )
            disposition_counts = summary.get("edge_dispositions", {})
            match_kind_counts = summary.get("handler_match_kinds", {})
            outcome_certainty_counts = summary.get("handler_outcome_certainties", {})
            expected_source_omitted = (
                per_component_omitted
                + source_raise_count
                - len(raises)
                + source_handler_count
                - len(handlers)
                + source_finalizer_count
                - len(finalizers)
            )
            if (
                len(raise_ids) != len(set(raise_ids))
                or len(handler_ids) != len(set(handler_ids))
                or len(finalizer_ids) != len(set(finalizer_ids))
                or len(exception_edge_ids) != len(set(exception_edge_ids))
                or not all(
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 0
                    for value in integer_summary_values
                )
                or summary.get("raise_records_discovered") != source_raise_count
                or summary.get("raise_records_embedded") != len(raises)
                or summary.get("handler_records_discovered") != source_handler_count
                or summary.get("handler_records_embedded") != len(handlers)
                or summary.get("handlers_may_reraise_original")
                != sum(
                    value.get("may_reraise_original") is True
                    for value in handlers
                    if isinstance(value, dict)
                )
                or not isinstance(outcome_certainty_counts, dict)
                or set(outcome_certainty_counts)
                - {"uniform", "conditional", "indeterminate"}
                or outcome_certainty_counts
                != dict(
                    sorted(
                        Counter(
                            str(value.get("outcome_certainty", "indeterminate"))
                            for value in handlers
                            if isinstance(value, dict)
                        ).items()
                    )
                )
                or summary.get("finalizer_records_discovered") != source_finalizer_count
                or summary.get("finalizer_records_embedded") != len(finalizers)
                or summary.get("unconditional_terminal_finalizers")
                != sum(
                    value.get("unconditional_terminal") is True
                    for value in finalizers
                    if isinstance(value, dict)
                )
                or summary.get("source_records_omitted") != expected_source_omitted
                or edge_values[1] != len(exception_edges)
                or edge_values[0] != edge_values[1] + edge_values[2]
                or not isinstance(disposition_counts, dict)
                or set(disposition_counts) - allowed_dispositions
                or any(
                    not isinstance(value, int) or isinstance(value, bool) or value < 0
                    for value in disposition_counts.values()
                )
                or sum(disposition_counts.values()) != edge_values[0]
                or edge_values[2] == 0
                and disposition_counts
                != dict(
                    sorted(
                        Counter(
                            str(value.get("disposition", ""))
                            for value in exception_edges
                        ).items()
                    )
                )
                or not isinstance(match_kind_counts, dict)
                or set(match_kind_counts) - allowed_match_kinds
                or any(
                    not isinstance(value, int) or isinstance(value, bool) or value < 0
                    for value in match_kind_counts.values()
                )
                or sum(match_kind_counts.values()) != edge_values[0]
                or edge_values[2] == 0
                and match_kind_counts
                != dict(
                    sorted(
                        Counter(
                            str(value.get("match_kind", ""))
                            for value in exception_edges
                        ).items()
                    )
                )
                or summary.get("truncated")
                != bool(expected_source_omitted or edge_values[2])
            ):
                exception_valid = False
            for component in components:
                component_id = str(component.get("id", ""))
                index = component.get("exception_flow", {})
                expected_raises = raises_by_component.get(component_id, [])
                expected_handlers = handlers_by_component.get(component_id, [])
                expected_finalizers = finalizers_by_component.get(component_id, [])
                expected_inbound: list[str] = exception_inbound_by_component.get(
                    component_id, []
                )
                expected_outbound: list[str] = exception_outbound_by_component.get(
                    component_id, []
                )
                expected_records = exception_records_by_caller.get(component_id, [])
                expected_types = sorted(
                    {
                        str(value.get("exception_type", "unknown"))
                        for value in expected_records
                    }
                )
                expected_dispositions = dict(
                    sorted(
                        Counter(
                            str(value.get("disposition", "unknown"))
                            for value in expected_records
                        ).items()
                    )
                )
                if (
                    not isinstance(index, dict)
                    or index.get("raise_ids") != expected_raises[:1_000]
                    or index.get("raises_omitted")
                    != max(0, len(expected_raises) - 1_000)
                    or index.get("handler_ids") != expected_handlers[:1_000]
                    or index.get("handlers_omitted")
                    != max(0, len(expected_handlers) - 1_000)
                    or index.get("finalizer_ids") != expected_finalizers[:1_000]
                    or index.get("finalizers_omitted")
                    != max(0, len(expected_finalizers) - 1_000)
                    or index.get("incoming_edge_ids") != expected_inbound[:2_000]
                    or index.get("incoming_edges_omitted")
                    != max(0, len(expected_inbound) - 2_000)
                    or index.get("outgoing_edge_ids") != expected_outbound[:2_000]
                    or index.get("outgoing_edges_omitted")
                    != max(0, len(expected_outbound) - 2_000)
                    or index.get("incoming_dispositions") != expected_dispositions
                    or index.get("incoming_exception_types") != expected_types[:1_000]
                    or index.get("incoming_exception_types_omitted")
                    != max(0, len(expected_types) - 1_000)
                    or index.get("propagating_incoming_edges")
                    != sum(
                        bool(value.get("propagates_original"))
                        for value in expected_records
                    )
                    or index.get("indeterminate_incoming_edges")
                    != sum(
                        value.get("disposition") == "indeterminate_handler_match"
                        for value in expected_records
                    )
                ):
                    exception_valid = False
        if not exception_valid:
            add(
                "analysis.invalid_exception_propagation",
                "error",
                "Exception raise, handler, finalizer, propagation, count, or component-index records are inconsistent.",
                field="exception_propagation",
            )
    state_model = analysis.get("state_machine_model")
    if state_model is not None:
        state_valid = isinstance(state_model, dict)
        states = state_model.get("states", []) if state_valid else []
        guards = state_model.get("guards", []) if state_valid else []
        transitions = state_model.get("transitions", []) if state_valid else []
        state_summary = state_model.get("summary", {}) if state_valid else {}
        state_valid = (
            state_valid
            and state_model.get("format") == "pysfmea-state-machine-model-1"
            and isinstance(states, list)
            and isinstance(guards, list)
            and isinstance(transitions, list)
            and isinstance(state_summary, dict)
        )
        state_ids: list[str] = []
        guard_ids: list[str] = []
        transition_ids: list[str] = []
        guards_by_component: dict[str, list[str]] = {
            str(identifier): [] for identifier in component_ids
        }
        transitions_by_component: dict[str, list[str]] = {
            str(identifier): [] for identifier in component_ids
        }
        if state_valid:
            for state in states:
                if not isinstance(state, dict):
                    state_valid = False
                    continue
                identifier = str(state.get("id", ""))
                state_ids.append(identifier)
                if (
                    not identifier
                    or str(state.get("component_id", "")) not in component_ids
                    or not str(state.get("state_variable", ""))
                    or not str(state.get("state_expression", ""))
                ):
                    state_valid = False
            for guard in guards:
                if not isinstance(guard, dict):
                    state_valid = False
                    continue
                identifier = str(guard.get("id", ""))
                component_id = str(guard.get("component_id", ""))
                guard_ids.append(identifier)
                if component_id in guards_by_component:
                    guards_by_component[component_id].append(identifier)
                if (
                    not identifier
                    or component_id not in component_ids
                    or guard.get("kind") not in {"if", "while"}
                    or not str(guard.get("expression", ""))
                    or not isinstance(guard.get("state_variables"), list)
                ):
                    state_valid = False
            known_state_ids = set(state_ids)
            known_guard_ids = set(guard_ids)
            for transition in transitions:
                if not isinstance(transition, dict):
                    state_valid = False
                    continue
                identifier = str(transition.get("id", ""))
                component_id = str(transition.get("component_id", ""))
                linked_guards = transition.get("guard_ids", [])
                transition_ids.append(identifier)
                if component_id in transitions_by_component:
                    transitions_by_component[component_id].append(identifier)
                if (
                    not identifier
                    or component_id not in component_ids
                    or not str(transition.get("state_variable", ""))
                    or not str(transition.get("target_state_expression", ""))
                    or transition.get("target_state_id") not in known_state_ids
                    or not isinstance(linked_guards, list)
                    or any(value not in known_guard_ids for value in linked_guards)
                ):
                    state_valid = False
            components = [
                value
                for value in analysis.get("components", [])
                if isinstance(value, dict)
            ]
            source_guards = sum(
                len(value.get("state_guards", []))
                for value in components
                if isinstance(value.get("state_guards", []), list)
            )
            source_transitions = sum(
                len(value.get("state_transitions", []))
                for value in components
                if isinstance(value.get("state_transitions", []), list)
            )
            component_omissions = sum(
                int(value.get("state_records_omitted", 0))
                for value in components
                if isinstance(value.get("state_records_omitted", 0), int)
                and not isinstance(value.get("state_records_omitted", 0), bool)
                and int(value.get("state_records_omitted", 0)) >= 0
            )
            expected_omitted = (
                component_omissions
                + source_guards
                - len(guards)
                + source_transitions
                - len(transitions)
            )
            state_summary_values = (
                state_summary.get("guards_discovered"),
                state_summary.get("guards_embedded"),
                state_summary.get("transitions_discovered"),
                state_summary.get("transitions_embedded"),
                state_summary.get("state_nodes"),
                state_summary.get("source_records_omitted"),
                state_summary.get("guarded_transitions"),
            )
            if (
                len(state_ids) != len(set(state_ids))
                or len(guard_ids) != len(set(guard_ids))
                or len(transition_ids) != len(set(transition_ids))
                or not all(
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 0
                    for value in state_summary_values
                )
                or state_summary.get("guards_discovered") != source_guards
                or state_summary.get("guards_embedded") != len(guards)
                or state_summary.get("transitions_discovered") != source_transitions
                or state_summary.get("transitions_embedded") != len(transitions)
                or state_summary.get("state_nodes") != len(states)
                or state_summary.get("source_records_omitted") != expected_omitted
                or state_summary.get("guarded_transitions")
                != sum(bool(value.get("guard_ids")) for value in transitions)
                or state_summary.get("truncated") != bool(expected_omitted)
            ):
                state_valid = False
            for component in components:
                component_id = str(component.get("id", ""))
                index = component.get("state_machine", {})
                expected_guards = guards_by_component.get(component_id, [])
                expected_transitions = transitions_by_component.get(component_id, [])
                if (
                    not isinstance(index, dict)
                    or index.get("guard_ids") != expected_guards[:1_000]
                    or index.get("guards_omitted")
                    != max(0, len(expected_guards) - 1_000)
                    or index.get("transition_ids") != expected_transitions[:1_000]
                    or index.get("transitions_omitted")
                    != max(0, len(expected_transitions) - 1_000)
                ):
                    state_valid = False
        if not state_valid:
            add(
                "analysis.invalid_state_machine_model",
                "error",
                "State, guard, transition, count, or component-index records are inconsistent.",
                field="state_machine_model",
            )
    resilience = analysis.get("resilience_semantics")
    if resilience is not None:
        resilience_valid = isinstance(resilience, dict)
        resilience_operations = (
            resilience.get("operations", []) if resilience_valid else []
        )
        transactions = resilience.get("transactions", []) if resilience_valid else []
        effects = resilience.get("effects", []) if resilience_valid else []
        timing_relations = (
            resilience.get("timing_relations", []) if resilience_valid else []
        )
        retry_paths = resilience.get("retry_paths", []) if resilience_valid else []
        breakers = resilience.get("circuit_breakers", []) if resilience_valid else []
        resources = resilience.get("resources", []) if resilience_valid else []
        resilience_summary = resilience.get("summary", {}) if resilience_valid else {}
        resilience_valid = (
            resilience_valid
            and resilience.get("format") == "pysfmea-resilience-semantics-1"
            and all(
                isinstance(value, list)
                for value in (
                    resilience_operations,
                    transactions,
                    effects,
                    timing_relations,
                    retry_paths,
                    breakers,
                    resources,
                )
            )
            and isinstance(resilience_summary, dict)
        )
        component_references = {
            f"{value.get('source', {}).get('path', '')}:{value.get('qualname', '')}": str(
                value.get("id", "")
            )
            for value in analysis.get("components", [])
            if isinstance(value, dict)
            and value.get("kind") not in {"environment", "common_cause"}
        }
        resilience_operation_ids: list[str] = []
        resilience_operations_by_component: dict[str, list[str]] = {
            str(identifier): [] for identifier in component_ids
        }
        allowed_categories = {
            "transaction_begin",
            "transaction_commit",
            "transaction_rollback",
            "transaction_savepoint",
            "persistence_write",
            "side_effect",
            "message_or_external_side_effect",
            "compensation",
            "idempotency_control",
            "idempotency_key",
            "filesystem_side_effect",
            "subprocess_side_effect",
            "retry",
            "retry_backoff",
            "temporal_budget",
            "resource_bound",
            "resource_growth_candidate",
        }
        if resilience_valid:
            for operation in resilience_operations:
                if not isinstance(operation, dict):
                    resilience_valid = False
                    continue
                identifier = str(operation.get("id", ""))
                component_id = str(operation.get("component_id", ""))
                categories = operation.get("categories", [])
                resilience_operation_ids.append(identifier)
                if component_id in resilience_operations_by_component:
                    resilience_operations_by_component[component_id].append(identifier)
                if (
                    not identifier
                    or component_id not in component_ids
                    or not isinstance(categories, list)
                    or not categories
                    or any(value not in allowed_categories for value in categories)
                    or len(categories) != len(set(categories))
                ):
                    resilience_valid = False
            known_operation_ids = set(resilience_operation_ids)
            for transaction in transactions:
                if not isinstance(transaction, dict):
                    resilience_valid = False
                    continue
                operation_links = transaction.get("operation_ids", [])
                if (
                    str(transaction.get("component_id", "")) not in component_ids
                    or not isinstance(operation_links, list)
                    or any(
                        value not in known_operation_ids for value in operation_links
                    )
                    or not isinstance(transaction.get("consistency_risks"), list)
                    or not isinstance(transaction.get("compensation_observed"), bool)
                ):
                    resilience_valid = False
            for effect in effects:
                if not isinstance(effect, dict):
                    resilience_valid = False
                    continue
                if (
                    str(effect.get("component_reference", ""))
                    not in component_references
                    or not isinstance(effect.get("direct_effects"), list)
                    or not isinstance(effect.get("transitive_effects"), list)
                    or not isinstance(effect.get("idempotency_controls"), list)
                    or not isinstance(effect.get("unprotected_retry_side_effect"), bool)
                    or not isinstance(effect.get("retry_factor"), int)
                    or isinstance(effect.get("retry_factor"), bool)
                    or int(effect.get("retry_factor", 0)) < 1
                ):
                    resilience_valid = False
            for relation in timing_relations:
                if not isinstance(relation, dict):
                    resilience_valid = False
                    continue
                if (
                    str(relation.get("caller_reference", ""))
                    not in component_references
                    or str(relation.get("callee_reference", ""))
                    not in component_references
                    or relation.get("status")
                    not in {
                        "callee_budget_exceeds_caller",
                        "bounded_compatible_literals",
                        "incomplete_budget_chain",
                    }
                ):
                    resilience_valid = False
            for retry_path in retry_paths:
                if not isinstance(retry_path, dict):
                    resilience_valid = False
                    continue
                path = retry_path.get("path", [])
                factor = retry_path.get("amplification_factor_upper_candidate")
                if (
                    str(retry_path.get("origin_component_reference", ""))
                    not in component_references
                    or not isinstance(path, list)
                    or not path
                    or any(value not in component_references for value in path)
                    or not isinstance(factor, int)
                    or isinstance(factor, bool)
                    or factor < 1
                    or not isinstance(retry_path.get("cycle_detected"), bool)
                    or not isinstance(retry_path.get("depth_limited"), bool)
                    or not isinstance(retry_path.get("search_truncated"), bool)
                    or not isinstance(retry_path.get("search_states"), int)
                    or isinstance(retry_path.get("search_states"), bool)
                    or int(retry_path.get("search_states", 0)) < 1
                ):
                    resilience_valid = False
            breaker_ids: list[str] = []
            for breaker in breakers:
                if not isinstance(breaker, dict):
                    resilience_valid = False
                    continue
                breaker_ids.append(str(breaker.get("id", "")))
                if (
                    not breaker_ids[-1]
                    or not str(breaker.get("scope", ""))
                    or not all(
                        isinstance(breaker.get(field), list)
                        for field in (
                            "roles",
                            "states",
                            "threshold_expressions",
                            "cooldown_expressions",
                            "synchronization",
                            "scope_keys",
                            "fallback_indicators",
                            "semantic_gaps",
                        )
                    )
                ):
                    resilience_valid = False
            for resource in resources:
                if not isinstance(resource, dict):
                    resilience_valid = False
                    continue
                if (
                    str(resource.get("component_id", "")) not in component_ids
                    or not isinstance(resource.get("bounded_resources"), list)
                    or not isinstance(resource.get("unbounded_growth_candidates"), list)
                    or not isinstance(resource.get("recursive_call_candidate"), bool)
                ):
                    resilience_valid = False
            resilience_summary_values = (
                resilience_summary.get("operations_discovered"),
                resilience_summary.get("operations_embedded"),
                resilience_summary.get("operations_omitted"),
                resilience_summary.get("transaction_components"),
                resilience_summary.get("transaction_risks"),
                resilience_summary.get("effect_components"),
                resilience_summary.get("retry_paths"),
                resilience_summary.get("timing_relations"),
                resilience_summary.get("breaker_models"),
                resilience_summary.get("resource_risks"),
            )
            if (
                len(resilience_operation_ids) != len(set(resilience_operation_ids))
                or len(breaker_ids) != len(set(breaker_ids))
                or not all(
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 0
                    for value in resilience_summary_values
                )
                or resilience_summary.get("operations_embedded")
                != len(resilience_operations)
                or resilience_summary.get("operations_discovered")
                != len(resilience_operations)
                + resilience_summary.get("operations_omitted", 0)
                or resilience_summary.get("transaction_components")
                != sum(bool(value.get("operation_ids")) for value in transactions)
                or resilience_summary.get("transaction_risks")
                != sum(
                    len(value.get("consistency_risks", [])) for value in transactions
                )
                or resilience_summary.get("effect_components")
                != sum(bool(value.get("transitive_effects")) for value in effects)
                or resilience_summary.get("retry_paths") != len(retry_paths)
                or resilience_summary.get("timing_relations") != len(timing_relations)
                or resilience_summary.get("breaker_models") != len(breakers)
                or resilience_summary.get("resource_risks")
                != sum(
                    len(value.get("unbounded_growth_candidates", []))
                    for value in resources
                )
                or resilience_summary.get("truncated")
                != bool(resilience_summary.get("operations_omitted"))
            ):
                resilience_valid = False
            for component in analysis.get("components", []):
                if not isinstance(component, dict):
                    resilience_valid = False
                    continue
                component_id = str(component.get("id", ""))
                index = component.get("resilience_semantics", {})
                expected = resilience_operations_by_component.get(component_id, [])
                if (
                    not isinstance(index, dict)
                    or index.get("operation_ids") != expected[:2_000]
                    or index.get("operations_omitted") != max(0, len(expected) - 2_000)
                ):
                    resilience_valid = False
        if not resilience_valid:
            add(
                "analysis.invalid_resilience_semantics",
                "error",
                "Transaction, effect, timing, retry, breaker, resource, count, or component-index records are inconsistent.",
                field="resilience_semantics",
            )
    authorization = analysis.get("authorization_scope_flow")
    if authorization is not None:
        authorization_valid = isinstance(authorization, dict)
        auth_components = (
            authorization.get("components", []) if authorization_valid else []
        )
        auth_edges = authorization.get("edges", []) if authorization_valid else []
        auth_summary = authorization.get("summary", {}) if authorization_valid else {}
        authorization_valid = (
            authorization_valid
            and authorization.get("format") == "pysfmea-authorization-scope-flow-1"
            and isinstance(auth_components, list)
            and isinstance(auth_edges, list)
            and isinstance(auth_summary, dict)
        )
        allowed_dimensions = {
            "identity",
            "tenant",
            "role_or_permission",
            "scope_or_claim",
            "credential",
        }
        auth_edge_ids: list[str] = []
        auth_edges_by_component: dict[str, list[str]] = {
            str(identifier): [] for identifier in component_ids
        }
        if authorization_valid:
            auth_component_ids: list[str] = []
            for component in auth_components:
                if not isinstance(component, dict):
                    authorization_valid = False
                    continue
                component_id = str(component.get("component_id", ""))
                dimensions = component.get("context_dimensions", [])
                controls = component.get("controls", [])
                risks = component.get("risks", [])
                auth_component_ids.append(component_id)
                if (
                    component_id not in component_ids
                    or not isinstance(dimensions, list)
                    or any(value not in allowed_dimensions for value in dimensions)
                    or len(dimensions) != len(set(dimensions))
                    or not isinstance(controls, list)
                    or not all(isinstance(value, dict) for value in controls)
                    or not isinstance(risks, list)
                    or not all(isinstance(value, str) and value for value in risks)
                    or not isinstance(component.get("boundary"), bool)
                    or not isinstance(component.get("sensitive_side_effect"), bool)
                ):
                    authorization_valid = False
            known_data_flow_ids = {
                str(value.get("id", ""))
                for value in analysis.get("interprocedural_data_flow", {}).get(
                    "edges", []
                )
                if isinstance(value, dict)
            }
            for edge in auth_edges:
                if not isinstance(edge, dict):
                    authorization_valid = False
                    continue
                identifier = str(edge.get("id", ""))
                caller_id = str(edge.get("caller_component_id", ""))
                callee_id = str(edge.get("callee_component_id", ""))
                dimensions = edge.get("dimensions", [])
                auth_edge_ids.append(identifier)
                if caller_id in auth_edges_by_component:
                    auth_edges_by_component[caller_id].append(identifier)
                if callee_id in auth_edges_by_component:
                    auth_edges_by_component[callee_id].append(identifier)
                if (
                    not identifier
                    or caller_id not in component_ids
                    or callee_id not in component_ids
                    or edge.get("data_flow_edge_id") not in known_data_flow_ids
                    or not isinstance(dimensions, list)
                    or not dimensions
                    or any(value not in allowed_dimensions for value in dimensions)
                    or not isinstance(edge.get("bindings"), list)
                ):
                    authorization_valid = False
            edge_values = (
                auth_summary.get("flow_edges_discovered"),
                auth_summary.get("flow_edges_embedded"),
                auth_summary.get("flow_edges_omitted"),
            )
            authorization_summary_values = (
                auth_summary.get("components"),
                auth_summary.get("components_with_context"),
                auth_summary.get("components_with_controls"),
                auth_summary.get("risk_candidates"),
                *edge_values,
            )
            if (
                len(auth_component_ids) != len(set(auth_component_ids))
                or len(auth_edge_ids) != len(set(auth_edge_ids))
                or not all(
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 0
                    for value in authorization_summary_values
                )
                or auth_summary.get("components") != len(auth_components)
                or auth_summary.get("components_with_context")
                != sum(
                    bool(value.get("context_dimensions")) for value in auth_components
                )
                or auth_summary.get("components_with_controls")
                != sum(bool(value.get("controls")) for value in auth_components)
                or auth_summary.get("risk_candidates")
                != sum(len(value.get("risks", [])) for value in auth_components)
                or edge_values[1] != len(auth_edges)
                or edge_values[0] != edge_values[1] + edge_values[2]
                or auth_summary.get("truncated") != bool(edge_values[2])
            ):
                authorization_valid = False
            for component in analysis.get("components", []):
                if not isinstance(component, dict):
                    authorization_valid = False
                    continue
                component_id = str(component.get("id", ""))
                index = component.get("authorization_scope_flow", {})
                expected = auth_edges_by_component.get(component_id, [])
                if (
                    not isinstance(index, dict)
                    or index.get("edge_ids") != expected[:2_000]
                    or index.get("edges_omitted") != max(0, len(expected) - 2_000)
                ):
                    authorization_valid = False
        if not authorization_valid:
            add(
                "analysis.invalid_authorization_scope_flow",
                "error",
                "Authorization context, controls, flow edges, counts, or component indexes are inconsistent.",
                field="authorization_scope_flow",
            )
    contract_model = analysis.get("contract_semantics")
    if contract_model is not None:
        contract_valid = isinstance(contract_model, dict)
        contract_operations = (
            contract_model.get("operations", []) if contract_valid else []
        )
        contract_types = contract_model.get("types", []) if contract_valid else []
        compatibility = (
            contract_model.get("compatibility", []) if contract_valid else []
        )
        evolution = contract_model.get("evolution", []) if contract_valid else []
        contract_summary = contract_model.get("summary", {}) if contract_valid else {}
        contract_valid = (
            contract_valid
            and contract_model.get("format") == "pysfmea-contract-semantics-1"
            and isinstance(contract_operations, list)
            and isinstance(contract_types, list)
            and isinstance(compatibility, list)
            and isinstance(evolution, list)
            and isinstance(contract_summary, dict)
        )
        contract_operation_ids: list[str] = []
        type_ids: list[str] = []
        compatibility_ids: list[str] = []
        evolution_ids: list[str] = []
        operation_ids_by_component: dict[str, list[str]] = {
            str(identifier): [] for identifier in component_ids
        }
        compatibility_ids_by_component: dict[str, list[str]] = {
            str(identifier): [] for identifier in component_ids
        }
        known_contract_ids = {
            str(value.get("id", ""))
            for value in analysis.get("context", {}).get("contracts", [])
            if isinstance(value, dict)
        }
        component_ids_by_source_path: dict[str, list[str]] = {}
        for component in analysis.get("components", []):
            if isinstance(component, dict):
                component_ids_by_source_path.setdefault(
                    str(component.get("source", {}).get("path", "")), []
                ).append(str(component.get("id", "")))
        if contract_valid:
            for operation in contract_operations:
                if not isinstance(operation, dict):
                    contract_valid = False
                    continue
                identifier = str(operation.get("id", ""))
                contract_operation_ids.append(identifier)
                for component_id in component_ids_by_source_path.get(
                    str(operation.get("contract_path", "")), []
                ):
                    operation_ids_by_component[component_id].append(identifier)
                if (
                    not identifier
                    or operation.get("contract_id") not in known_contract_ids
                    or not str(operation.get("operation", ""))
                    or not isinstance(operation.get("request"), dict)
                    or not isinstance(operation.get("responses"), list)
                    or not isinstance(operation.get("semantic_sha256"), str)
                    or len(str(operation.get("semantic_sha256", ""))) != 64
                ):
                    contract_valid = False
            for contract_type in contract_types:
                if not isinstance(contract_type, dict):
                    contract_valid = False
                    continue
                identifier = str(contract_type.get("id", ""))
                type_ids.append(identifier)
                if (
                    not identifier
                    or contract_type.get("contract_id") not in known_contract_ids
                    or not str(contract_type.get("name", ""))
                    or not isinstance(contract_type.get("required"), list)
                    or not isinstance(contract_type.get("properties"), list)
                    or not isinstance(contract_type.get("semantic_sha256"), str)
                    or len(str(contract_type.get("semantic_sha256", ""))) != 64
                ):
                    contract_valid = False
            known_operation_ids = set(contract_operation_ids)
            for record in compatibility:
                if not isinstance(record, dict):
                    contract_valid = False
                    continue
                identifier = str(record.get("id", ""))
                compatibility_ids.append(identifier)
                python_ids = record.get("python_component_ids", [])
                if isinstance(python_ids, list):
                    for component_id in python_ids:
                        if str(component_id) in compatibility_ids_by_component:
                            compatibility_ids_by_component[str(component_id)].append(
                                identifier
                            )
                if (
                    not identifier
                    or record.get("status")
                    not in {"review_required", "compatible_static_shape"}
                    or (
                        "contract_operation_id" in record
                        and record.get("contract_operation_id")
                        not in known_operation_ids
                    )
                    or not isinstance(python_ids, list)
                    or any(value not in component_ids for value in python_ids)
                ):
                    contract_valid = False
            for record in evolution:
                if not isinstance(record, dict):
                    contract_valid = False
                    continue
                identifier = str(record.get("id", ""))
                evolution_ids.append(identifier)
                if (
                    not identifier
                    or record.get("kind")
                    not in {"operation_evolution", "type_evolution"}
                    or record.get("from_contract_id") not in known_contract_ids
                    or record.get("to_contract_id") not in known_contract_ids
                    or not str(record.get("subject", ""))
                    or not isinstance(record.get("changes"), dict)
                    or not isinstance(record.get("breaking_change_candidates"), list)
                ):
                    contract_valid = False
            operation_values = (
                contract_summary.get("operations_discovered"),
                contract_summary.get("operations_embedded"),
                contract_summary.get("operations_omitted"),
            )
            type_values = (
                contract_summary.get("types_discovered"),
                contract_summary.get("types_embedded"),
                contract_summary.get("types_omitted"),
            )
            contract_summary_values = (
                contract_summary.get("contracts"),
                *operation_values,
                *type_values,
                contract_summary.get("compatibility_records"),
                contract_summary.get("evolution_records_discovered"),
                contract_summary.get("evolution_records_embedded"),
                contract_summary.get("evolution_records_omitted"),
                contract_summary.get("breaking_change_candidates"),
                contract_summary.get("review_required"),
            )
            expected_kinds = dict(
                sorted(
                    Counter(
                        str(value.get("kind", ""))
                        for value in analysis.get("context", {}).get("contracts", [])
                        if isinstance(value, dict)
                    ).items()
                )
            )
            if (
                len(contract_operation_ids) != len(set(contract_operation_ids))
                or len(type_ids) != len(set(type_ids))
                or len(compatibility_ids) != len(set(compatibility_ids))
                or len(evolution_ids) != len(set(evolution_ids))
                or not all(
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and value >= 0
                    for value in contract_summary_values
                )
                or contract_summary.get("contracts") != len(known_contract_ids)
                or contract_summary.get("contract_kinds") != expected_kinds
                or operation_values[1] != len(contract_operations)
                or operation_values[0] != operation_values[1] + operation_values[2]
                or type_values[1] != len(contract_types)
                or type_values[0] != type_values[1] + type_values[2]
                or contract_summary.get("compatibility_records") != len(compatibility)
                or contract_summary.get("evolution_records_embedded") != len(evolution)
                or contract_summary.get("evolution_records_discovered")
                != len(evolution) + contract_summary.get("evolution_records_omitted", 0)
                or contract_summary.get("breaking_change_candidates")
                != sum(
                    bool(value.get("breaking_change_candidates")) for value in evolution
                )
                or contract_summary.get("review_required")
                != sum(
                    value.get("status") == "review_required" for value in compatibility
                )
                or contract_summary.get("truncated")
                != bool(
                    operation_values[2]
                    or type_values[2]
                    or contract_summary.get("evolution_records_omitted")
                )
            ):
                contract_valid = False
            for component in analysis.get("components", []):
                if not isinstance(component, dict):
                    contract_valid = False
                    continue
                component_id = str(component.get("id", ""))
                index = component.get("contract_semantics", {})
                if (
                    not isinstance(index, dict)
                    or index.get("operation_ids")
                    != operation_ids_by_component.get(component_id, [])[:1_000]
                    or index.get("compatibility_ids")
                    != compatibility_ids_by_component.get(component_id, [])[:1_000]
                ):
                    contract_valid = False
        if not contract_valid:
            add(
                "analysis.invalid_contract_semantics",
                "error",
                "Contract operations, types, compatibility records, counts, or component indexes are inconsistent.",
                field="contract_semantics",
            )
    deployment = analysis.get("deployment_topology")
    if deployment is not None:
        deployment_valid = isinstance(deployment, dict)
        nodes = deployment.get("nodes", []) if deployment_valid else []
        edges = deployment.get("edges", []) if deployment_valid else []
        placements = deployment.get("placements", []) if deployment_valid else []
        summary = deployment.get("summary", {}) if deployment_valid else {}
        deployment_valid = (
            deployment_valid
            and deployment.get("format") == "pysfmea-deployment-topology-1"
            and all(isinstance(value, list) for value in (nodes, edges, placements))
            and isinstance(summary, dict)
        )
        node_ids: list[str] = []
        deployment_edge_ids: list[str] = []
        placement_by_component: dict[str, dict[str, Any]] = {}
        if deployment_valid:
            inventory_entries = {
                str(value.get("path", "")): str(value.get("sha256", ""))
                for value in analysis.get("repository_inventory", {}).get("entries", [])
                if isinstance(value, dict)
            }
            for node in nodes:
                if not isinstance(node, dict):
                    deployment_valid = False
                    continue
                node_id = str(node.get("id", ""))
                path = str(node.get("artifact_path", ""))
                node_ids.append(node_id)
                if (
                    not node_id
                    or not node.get("kind")
                    or not node.get("name")
                    or not path
                    or (
                        path != "configuration.project.deployment_environments"
                        and (
                            path not in inventory_entries
                            or node.get("artifact_sha256") != inventory_entries[path]
                        )
                    )
                ):
                    deployment_valid = False
            known_node_ids = set(node_ids)
            for edge in edges:
                if not isinstance(edge, dict):
                    deployment_valid = False
                    continue
                edge_id = str(edge.get("id", ""))
                deployment_edge_ids.append(edge_id)
                if (
                    not edge_id
                    or edge.get("source_node_id") not in known_node_ids
                    or edge.get("target_node_id") not in known_node_ids
                    or not edge.get("kind")
                    or edge.get("artifact_path") not in inventory_entries
                ):
                    deployment_valid = False
            expected_code_components = {
                str(value.get("id", ""))
                for value in analysis.get("components", [])
                if isinstance(value, dict)
                and value.get("kind") not in {"environment", "common_cause"}
            }
            for placement in placements:
                if not isinstance(placement, dict):
                    deployment_valid = False
                    continue
                component_id = str(placement.get("component_id", ""))
                placement_nodes = placement.get("node_ids", [])
                if (
                    component_id in placement_by_component
                    or component_id not in expected_code_components
                    or not isinstance(placement_nodes, list)
                    or len(placement_nodes) != len(set(placement_nodes))
                    or any(value not in known_node_ids for value in placement_nodes)
                    or placement.get("status")
                    != ("candidate_placement" if placement_nodes else "unplaced")
                ):
                    deployment_valid = False
                placement_by_component[component_id] = placement
            deployment_count_fields = (
                "nodes_discovered",
                "nodes_embedded",
                "nodes_omitted",
                "edges_discovered",
                "edges_embedded",
                "edges_omitted",
                "components",
                "placed_components",
                "unplaced_components",
            )
            if (
                len(node_ids) != len(set(node_ids))
                or len(deployment_edge_ids) != len(set(deployment_edge_ids))
                or set(placement_by_component) != expected_code_components
                or not all(
                    isinstance(summary.get(field), int)
                    and not isinstance(summary.get(field), bool)
                    and int(summary.get(field, -1)) >= 0
                    for field in deployment_count_fields
                )
                or summary.get("nodes_embedded") != len(nodes)
                or summary.get("nodes_discovered")
                != len(nodes) + summary.get("nodes_omitted", 0)
                or summary.get("edges_embedded") != len(edges)
                or summary.get("edges_discovered")
                != len(edges) + summary.get("edges_omitted", 0)
                or summary.get("components") != len(placements)
                or summary.get("placed_components")
                != sum(bool(value.get("node_ids")) for value in placements)
                or summary.get("unplaced_components")
                != sum(not value.get("node_ids") for value in placements)
                or summary.get("truncated")
                != bool(summary.get("nodes_omitted") or summary.get("edges_omitted"))
            ):
                deployment_valid = False
            for component in analysis.get("components", []):
                if not isinstance(component, dict):
                    deployment_valid = False
                    continue
                component_id = str(component.get("id", ""))
                expected = placement_by_component.get(component_id, {}).get(
                    "node_ids", []
                )
                index = component.get("deployment_topology", {})
                if (
                    not isinstance(index, dict)
                    or index.get("node_ids") != expected[:1_000]
                    or index.get("nodes_omitted") != max(0, len(expected) - 1_000)
                    or index.get("status")
                    != ("candidate_placement" if expected else "unplaced")
                ):
                    deployment_valid = False
        if not deployment_valid:
            add(
                "analysis.invalid_deployment_topology",
                "error",
                "Deployment nodes, edges, provenance, counts, placements, or component indexes are inconsistent.",
                field="deployment_topology",
            )
    shared_fate = analysis.get("shared_fate_analysis")
    if shared_fate is not None:
        shared_fate_valid = isinstance(shared_fate, dict)
        regions = shared_fate.get("regions", []) if shared_fate_valid else []
        summary = shared_fate.get("summary", {}) if shared_fate_valid else {}
        shared_fate_valid = (
            shared_fate_valid
            and shared_fate.get("format") == "pysfmea-shared-fate-analysis-1"
            and isinstance(regions, list)
            and isinstance(summary, dict)
        )
        region_ids: list[str] = []
        regions_by_component: dict[str, list[str]] = {
            str(identifier): [] for identifier in component_ids
        }
        if shared_fate_valid:
            for region in regions:
                if not isinstance(region, dict):
                    shared_fate_valid = False
                    continue
                region_id = str(region.get("id", ""))
                affected = region.get("affected_component_ids", [])
                region_ids.append(region_id)
                if (
                    not region_id
                    or region.get("kind")
                    not in {"deployment_node", "subsystem", "external_dependency"}
                    or not region.get("key")
                    or not isinstance(affected, list)
                    or affected != sorted(set(affected))
                    or len(affected) < 2
                    or any(value not in component_ids for value in affected)
                ):
                    shared_fate_valid = False
                for component_id in affected:
                    if str(component_id) in regions_by_component:
                        regions_by_component[str(component_id)].append(region_id)
            shared_fate_count_fields = (
                "regions",
                "regions_discovered",
                "regions_omitted",
                "affected_components",
            )
            if (
                len(region_ids) != len(set(region_ids))
                or not all(
                    isinstance(summary.get(field), int)
                    and not isinstance(summary.get(field), bool)
                    and int(summary.get(field, -1)) >= 0
                    for field in shared_fate_count_fields
                )
                or summary.get("regions") != len(regions)
                or summary.get("regions_discovered")
                != len(regions) + summary.get("regions_omitted", 0)
                or summary.get("affected_components")
                != len(
                    {
                        value
                        for region in regions
                        for value in region.get("affected_component_ids", [])
                    }
                )
                or summary.get("by_kind")
                != dict(sorted(Counter(value.get("kind") for value in regions).items()))
                or summary.get("truncated") != bool(summary.get("regions_omitted"))
            ):
                shared_fate_valid = False
            for component in analysis.get("components", []):
                if not isinstance(component, dict):
                    shared_fate_valid = False
                    continue
                component_id = str(component.get("id", ""))
                expected = regions_by_component.get(component_id, [])
                index = component.get("shared_fate", {})
                if (
                    not isinstance(index, dict)
                    or index.get("region_ids") != expected[:1_000]
                    or index.get("regions_omitted") != max(0, len(expected) - 1_000)
                ):
                    shared_fate_valid = False
        if not shared_fate_valid:
            add(
                "analysis.invalid_shared_fate_analysis",
                "error",
                "Shared-fate regions, counts, affected components, or component indexes are inconsistent.",
                field="shared_fate_analysis",
            )
    hierarchy = analysis.get("architecture_hierarchy")
    if hierarchy is not None:
        hierarchy_valid = isinstance(hierarchy, dict)
        nodes = hierarchy.get("nodes", []) if hierarchy_valid else []
        memberships = hierarchy.get("memberships", []) if hierarchy_valid else []
        summary = hierarchy.get("summary", {}) if hierarchy_valid else {}
        hierarchy_valid = (
            hierarchy_valid
            and hierarchy.get("format") == "pysfmea-architecture-hierarchy-1"
            and isinstance(nodes, list)
            and isinstance(memberships, list)
            and isinstance(summary, dict)
        )
        node_by_id: dict[str, dict[str, Any]] = {}
        membership_by_component: dict[str, dict[str, Any]] = {}
        if hierarchy_valid:
            for node in nodes:
                if not isinstance(node, dict):
                    hierarchy_valid = False
                    continue
                node_id = str(node.get("id", ""))
                if not node_id or node_id in node_by_id:
                    hierarchy_valid = False
                node_by_id[node_id] = node
                if (
                    node.get("kind")
                    not in {"repository", "subsystem", "source_package"}
                    or not node.get("path")
                    or not isinstance(node.get("component_ids"), list)
                    or node.get("component_ids")
                    != sorted(set(node.get("component_ids", [])))
                    or any(
                        value not in component_ids
                        for value in node.get("component_ids", [])
                    )
                    or not all(
                        isinstance(node.get(trace_kind), dict)
                        and all(
                            isinstance(node[trace_kind].get(field), list)
                            and node[trace_kind].get(field)
                            == sorted(set(node[trace_kind].get(field, [])))
                            for field in ("requirements", "hazards", "interfaces")
                        )
                        for trace_kind in ("direct_trace", "effective_trace")
                    )
                ):
                    hierarchy_valid = False
            roots = [value for value in nodes if not value.get("parent_id")]
            if len(roots) != 1 or roots[0].get("kind") != "repository":
                hierarchy_valid = False
            for node in nodes:
                parent_id = str(node.get("parent_id", ""))
                if parent_id and parent_id not in node_by_id:
                    hierarchy_valid = False
                visited: set[str] = set()
                cursor = str(node.get("id", ""))
                while cursor:
                    if cursor in visited:
                        hierarchy_valid = False
                        break
                    visited.add(cursor)
                    cursor = str(node_by_id.get(cursor, {}).get("parent_id", ""))
            expected_code_components = {
                str(value.get("id", ""))
                for value in analysis.get("components", [])
                if isinstance(value, dict)
                and value.get("kind") not in {"environment", "common_cause"}
            }
            for membership in memberships:
                if not isinstance(membership, dict):
                    hierarchy_valid = False
                    continue
                component_id = str(membership.get("component_id", ""))
                member_nodes = membership.get("node_ids", [])
                if (
                    component_id in membership_by_component
                    or component_id not in expected_code_components
                    or not isinstance(member_nodes, list)
                    or member_nodes != sorted(set(member_nodes))
                    or not member_nodes
                    or any(value not in node_by_id for value in member_nodes)
                ):
                    hierarchy_valid = False
                membership_by_component[component_id] = membership
            children: dict[str, list[str]] = {value: [] for value in node_by_id}
            for node_id, node in node_by_id.items():
                parent_id = str(node.get("parent_id", ""))
                if parent_id in children:
                    children[parent_id].append(node_id)
            ancestors_by_node = {
                node_id: _hierarchy_ancestors(node_id, node_by_id)
                for node_id in node_by_id
            }
            expected_components_by_node: dict[str, set[str]] = {
                node_id: set() for node_id in node_by_id
            }
            for component_id, membership in membership_by_component.items():
                for member_node_id in membership.get("node_ids", []):
                    for affected_node_id in {
                        member_node_id,
                        *ancestors_by_node.get(member_node_id, set()),
                    }:
                        expected_components_by_node[affected_node_id].add(component_id)
            for node_id, node in node_by_id.items():
                expected_components = expected_components_by_node[node_id]
                if node.get("component_ids") != sorted(expected_components):
                    hierarchy_valid = False
                expected_effective = {
                    field: sorted(
                        set(node.get("direct_trace", {}).get(field, []))
                        | {
                            value
                            for child_id in children.get(node_id, [])
                            for value in node_by_id[child_id]
                            .get("effective_trace", {})
                            .get(field, [])
                        }
                    )
                    for field in ("requirements", "hazards", "interfaces")
                }
                if node.get("effective_trace") != expected_effective:
                    hierarchy_valid = False
            if (
                set(membership_by_component) != expected_code_components
                or summary.get("nodes") != len(nodes)
                or summary.get("memberships") != len(memberships)
                or summary.get("subsystem_nodes")
                != sum(value.get("kind") == "subsystem" for value in nodes)
                or summary.get("source_package_nodes")
                != sum(value.get("kind") == "source_package" for value in nodes)
                or summary.get("unmapped_to_subsystem")
                != sum(
                    not any(
                        node_by_id[value].get("kind") == "subsystem"
                        for value in membership.get("node_ids", [])
                    )
                    for membership in memberships
                )
                or not isinstance(summary.get("nodes_omitted"), int)
                or isinstance(summary.get("nodes_omitted"), bool)
                or summary.get("nodes_omitted", -1) < 0
                or summary.get("truncated") != bool(summary.get("nodes_omitted"))
            ):
                hierarchy_valid = False
            for component in analysis.get("components", []):
                if not isinstance(component, dict):
                    hierarchy_valid = False
                    continue
                component_id = str(component.get("id", ""))
                expected = membership_by_component.get(component_id, {}).get(
                    "node_ids", []
                )
                index = component.get("architecture_hierarchy", {})
                if (
                    not isinstance(index, dict)
                    or index.get("node_ids") != expected[:1_000]
                    or index.get("nodes_omitted") != max(0, len(expected) - 1_000)
                ):
                    hierarchy_valid = False
        if not hierarchy_valid:
            add(
                "analysis.invalid_architecture_hierarchy",
                "error",
                "Architecture nodes, inheritance, trace aggregation, counts, memberships, or component indexes are inconsistent.",
                field="architecture_hierarchy",
            )
    graphify = analysis.get("graphify_reconciliation")
    if graphify is not None:
        graphify_valid = isinstance(graphify, dict)
        source = graphify.get("source", {}) if graphify_valid else {}
        summary = graphify.get("summary", {}) if graphify_valid else {}
        edges = graphify.get("edges", []) if graphify_valid else []
        graphify_valid = (
            graphify_valid
            and graphify.get("format") == "pysfmea-graphify-reconciliation-1"
            and isinstance(source, dict)
            and isinstance(summary, dict)
            and isinstance(edges, list)
            and isinstance(source.get("sha256"), str)
            and len(source.get("sha256", "")) == 64
            and isinstance(source.get("bytes"), int)
            and not isinstance(source.get("bytes"), bool)
            and source.get("bytes", -1) >= 0
            and isinstance(graphify.get("authority"), str)
        )
        expected_correlated = 0
        expected_leads = 0
        if graphify_valid:
            for edge in edges:
                if not isinstance(edge, dict):
                    graphify_valid = False
                    continue
                source_component_id = str(edge.get("source_component_id", ""))
                target_component_id = str(edge.get("target_component_id", ""))
                relation = str(edge.get("relation", ""))
                reconciliation = str(edge.get("reconciliation", ""))
                if (
                    not str(edge.get("id", ""))
                    or source_component_id not in component_ids
                    or target_component_id not in component_ids
                    or not relation
                    or reconciliation
                    not in {
                        "corroborated",
                        "graphify_only_review_lead",
                        "outside_native_call_comparison",
                    }
                ):
                    graphify_valid = False
                if relation == "calls" and reconciliation == "corroborated":
                    expected_correlated += 1
                if (
                    relation == "calls"
                    and reconciliation == "graphify_only_review_lead"
                ):
                    expected_leads += 1
            count_fields = (
                "nodes_discovered",
                "edges_discovered",
                "mapped_nodes",
                "mapped_edges",
                "edges_embedded",
                "edges_omitted",
                "call_edges_between_mapped_components",
                "corroborated_call_edges",
                "graphify_only_call_review_leads",
                "native_call_edges",
            )
            if (
                not all(
                    isinstance(summary.get(field), int)
                    and not isinstance(summary.get(field), bool)
                    and summary.get(field, -1) >= 0
                    for field in count_fields
                )
                or summary.get("edges_embedded") != len(edges)
                or summary.get("mapped_edges")
                != len(edges) + summary.get("edges_omitted", 0)
                or summary.get("corroborated_call_edges") != expected_correlated
                or summary.get("graphify_only_call_review_leads") != expected_leads
                or summary.get("truncated") != bool(summary.get("edges_omitted"))
                or not isinstance(graphify.get("reconciliation_sha256"), str)
                or len(graphify.get("reconciliation_sha256", "")) != 64
            ):
                graphify_valid = False
            expected_digest = _digest(
                {
                    "source_sha256": source.get("sha256", ""),
                    "summary": {
                        "nodes_discovered": summary.get("nodes_discovered"),
                        "edges_discovered": summary.get("edges_discovered"),
                        "mapped_edges": summary.get("mapped_edges"),
                        "corroborated_call_edges": summary.get(
                            "corroborated_call_edges"
                        ),
                        "graphify_only_call_review_leads": summary.get(
                            "graphify_only_call_review_leads"
                        ),
                    },
                    "edges": edges,
                }
            )
            if graphify.get("reconciliation_sha256") != expected_digest:
                graphify_valid = False
        if not graphify_valid:
            add(
                "analysis.invalid_graphify_reconciliation",
                "error",
                "Graphify provenance, mapped edges, reconciliation labels, or summary counts are inconsistent.",
                field="graphify_reconciliation",
            )
    observed_hazards: set[str] = set()
    observed_requirements: set[str] = set()
    mapped_interfaces: set[str] = {
        str(interface)
        for component in analysis.get("components", [])
        if isinstance(component, dict)
        for interface in component.get("interface_ids", [])
        if isinstance(interface, str) and interface
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
    configured_requirements: set[str] = {
        str(requirement.get("id"))
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
    configured_interfaces: set[str] = {
        str(interface.get("id"))
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
    interface_reconciliation = analysis.get("interface_reconciliation", {})
    disposition_reconciliation = (
        interface_reconciliation.get("disposition_reconciliation", {})
        if isinstance(interface_reconciliation, dict)
        else {}
    )
    stale_dispositions = disposition_reconciliation.get("unmatched_endpoint_ids", [])
    if isinstance(stale_dispositions, list) and stale_dispositions:
        sample = ", ".join(str(value) for value in stale_dispositions[:5])
        add(
            "interface.stale_reviewed_disposition",
            "warning",
            f"{len(stale_dispositions)} reviewed interface dispositions no longer match a discovered endpoint; sample: {sample}.",
            field="interface_dispositions",
        )
    confirmed_defects = [
        value
        for value in analysis.get("context", {}).get("interface_dispositions", [])
        if isinstance(value, dict)
        and value.get("decision") in {"confirmed_defect", "confirmed_mismatch"}
    ]
    if confirmed_defects:
        sample = ", ".join(
            str(value.get("endpoint_id", "")) for value in confirmed_defects[:5]
        )
        add(
            "interface.confirmed_reviewed_defect",
            "error",
            f"{len(confirmed_defects)} reviewed interface dispositions confirm a defect or mismatch; sample: {sample}.",
            field="interface_dispositions",
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
