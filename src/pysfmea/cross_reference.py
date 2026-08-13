"""Deterministic cross-scanner and assurance relationship fabric."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .architecture import architecture_graph
from .assurance import (
    ASSURANCE_WORK_NEXT_ACTIONS,
    ASSURANCE_WORK_STATES,
    assurance_work_queue,
    ensure_assurance_register,
)
from .file_publication import atomic_publish_text
from .guidance import guidance_traceability
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .model import stable_id
from .sfta import build_sfta
from .synthesis import suggestion_relationships
from .validation import validate_analysis
from .version import __version__

CROSS_REFERENCE_FORMAT = "pysfmea-cross-reference-index-1"
CROSS_REFERENCE_VERIFICATION_FORMAT = "pysfmea-cross-reference-verification-1"
CROSS_REFERENCE_VERIFICATION_CHECKS = (
    "format",
    "content_integrity",
    "entity_identity",
    "relationship_integrity",
    "fusion_integrity",
    "semantic_profile_integrity",
    "verification_readiness_integrity",
    "review_governance_integrity",
    "adapter_provenance_integrity",
    "repository_provenance_integrity",
    "machine_assistance_integrity",
    "finding_chain_integrity",
    "review_lead_integrity",
    "summary_reconciliation",
    "analysis_binding",
    "exact_regeneration",
)
MAX_CROSS_REFERENCE_BYTES = 200_000_000
MAX_CROSS_REFERENCE_JSON_DEPTH = 100
MAX_CROSS_REFERENCE_JSON_NODES = 5_000_000
MAX_ENTITIES = 200_000
MAX_RELATIONSHIPS = 500_000
MAX_FUSIONS = 100_000
MAX_CHAINS = 100_000
MAX_REVIEW_LEADS = 100_000

SEMANTIC_EXPOSURE_DIMENSIONS = (
    "data_flow",
    "alias_object_flow",
    "concurrency",
    "exception_propagation",
    "state_machine",
    "authorization_scope",
    "contract_semantics",
    "deployment_topology",
    "shared_fate",
    "architecture_hierarchy",
)

COMPOUND_EXPOSURE_PRIORITIES = {
    "authorization_context_crosses_data_flow": "high",
    "concurrent_state_transition": "high",
    "exception_during_state_transition": "high",
    "exception_near_resilience_or_side_effect_semantics": "high",
    "shared_fate_on_declared_deployment": "high",
    "contract_at_interface_boundary": "medium",
    "contract_carries_interprocedural_data": "medium",
    "authorization_context_at_contract_boundary": "high",
    "state_or_concurrency_near_resilience_semantics": "medium",
}

VERIFICATION_EVIDENCE_POSTURES = (
    "verified_with_sufficient_evidence",
    "risk_accepted_not_verification_evidence",
    "not_applicable",
    "execution_failed",
    "reviewed_execution_recorded",
    "execution_review_pending",
    "execution_recorded",
    "implementation_registered",
    "candidate_tests_and_coverage",
    "candidate_tests_only",
    "coverage_observation_only",
    "no_verification_signal",
)

VERIFICATION_EVIDENCE_SIGNAL_NAMES = (
    "finding_accepted",
    "source_current",
    "assigned_owner",
    "named_reviewer",
    "candidate_test_links",
    "coverage_observation",
    "implementation_registered",
    "execution_recorded",
    "passing_execution_recorded",
    "independent_execution_review",
    "evidence_artifact_recorded",
    "evidence_sufficient",
    "terminal_verification",
)

READINESS_GAP_PRIORITIES = {
    "accepted_finding_without_owner": "high",
    "accepted_finding_without_reviewer": "high",
    "accepted_finding_requires_revalidation": "high",
    "accepted_finding_without_test_candidate": "medium",
    "accepted_finding_without_registered_implementation": "medium",
    "implemented_test_without_execution": "medium",
    "failed_or_incomplete_execution": "high",
    "passing_execution_without_independent_review": "high",
    "sufficient_evidence_without_terminal_verification": "medium",
    "coverage_without_test_or_execution_evidence": "low",
}

VERIFICATION_READINESS_STATE_ACTIONS = {
    **dict(zip(ASSURANCE_WORK_STATES, ASSURANCE_WORK_NEXT_ACTIONS)),
    "historical": "none",
    "revalidation_required": "revalidate_finding",
    "awaiting_finding_review": "review_finding",
    "outside_accepted_assurance_scope": "none",
}

REVIEW_GOVERNANCE_STATES = (
    "historical",
    "revalidation_required",
    "blocked_by_validation",
    "awaiting_finding_review",
    "needs_information",
    "accepted_assurance_work",
    "accepted_resolved",
    "rejected",
)


def _quality_diagnostic_raw_id(
    value: dict[str, Any], *, occurrence: int = 1
) -> str:
    return stable_id(
        "QUALITY-DIAGNOSTIC",
        str(value.get("rule_id", "")),
        str(value.get("level", "")),
        str(value.get("item_id", "")),
        str(value.get("field", "")),
        str(value.get("message", "")),
        str(occurrence),
    )


def _review_governance_state(
    *,
    source_status: str,
    revalidation_required: bool,
    blocking_error_count: int,
    disposition: str,
    readiness_state: str,
    readiness_next_action: str,
) -> tuple[str, str]:
    if source_status != "active":
        return "historical", "none"
    if revalidation_required:
        return "revalidation_required", "revalidate_finding"
    if blocking_error_count:
        return "blocked_by_validation", "resolve_quality_gate_diagnostics"
    if disposition == "unreviewed":
        return "awaiting_finding_review", "review_finding"
    if disposition == "needs_information":
        return "needs_information", "collect_missing_information"
    if disposition == "accepted":
        if readiness_state == "resolved":
            return "accepted_resolved", "none"
        return "accepted_assurance_work", readiness_next_action
    return "rejected", "none"


def _text_values(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def _safe_int(value: object, default: int = 0) -> int:
    if not isinstance(value, (str, int, float)):
        return default
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _entity_id(kind: str, raw_id: object) -> str:
    return f"{kind}:{raw_id}"


def _relation_id(source: str, target: str, kind: str, channel: str) -> str:
    return stable_id("XREL", source, target, kind, channel)


def _classification(channels: set[str]) -> str:
    if channels == {"native_ast", "graphify_static", "runtime_observed"}:
        return "observed_multi_source"
    if channels == {"native_ast", "runtime_observed"}:
        return "observed_native"
    if channels == {"graphify_static", "runtime_observed"}:
        return "observed_graphify_gap"
    if channels == {"native_ast", "graphify_static"}:
        return "multi_static"
    if channels == {"runtime_observed"}:
        return "runtime_only_review_lead"
    if channels == {"graphify_static"}:
        return "graphify_only_review_lead"
    return "native_static_only"


def _compound_exposure_kinds(
    semantic_dimensions: dict[str, Any], chain_dimensions: dict[str, Any]
) -> list[str]:
    exposures: set[str] = set()
    if semantic_dimensions.get("authorization_scope") and semantic_dimensions.get(
        "data_flow"
    ):
        exposures.add("authorization_context_crosses_data_flow")
    if semantic_dimensions.get("concurrency") and semantic_dimensions.get(
        "state_machine"
    ):
        exposures.add("concurrent_state_transition")
    if semantic_dimensions.get("exception_propagation") and semantic_dimensions.get(
        "state_machine"
    ):
        exposures.add("exception_during_state_transition")
    if semantic_dimensions.get("deployment_topology") and semantic_dimensions.get(
        "shared_fate"
    ):
        exposures.add("shared_fate_on_declared_deployment")
    if semantic_dimensions.get("contract_semantics") and chain_dimensions.get(
        "interfaces"
    ):
        exposures.add("contract_at_interface_boundary")
    if semantic_dimensions.get("contract_semantics") and semantic_dimensions.get(
        "data_flow"
    ):
        exposures.add("contract_carries_interprocedural_data")
    if semantic_dimensions.get("authorization_scope") and semantic_dimensions.get(
        "contract_semantics"
    ):
        exposures.add("authorization_context_at_contract_boundary")
    if semantic_dimensions.get("exception_propagation") and chain_dimensions.get(
        "timing_and_resilience"
    ):
        exposures.add("exception_near_resilience_or_side_effect_semantics")
    if (
        semantic_dimensions.get("concurrency")
        or semantic_dimensions.get("state_machine")
    ) and chain_dimensions.get("timing_and_resilience"):
        exposures.add("state_or_concurrency_near_resilience_semantics")
    return sorted(exposures)


def _candidate_test_paths(value: object) -> list[str]:
    """Normalize scanner lists and legacy comma-joined obligation candidates."""

    paths: set[str] = set()
    for candidate in _text_values(value):
        for path in candidate.split(","):
            normalized = path.strip().replace("\\", "/")
            if normalized:
                paths.add(normalized)
    return sorted(paths)


def _verification_evidence_posture(
    *,
    assurance_statuses: set[str],
    evidence_statuses: set[str],
    implementation_registered: bool,
    candidate_tests: bool,
    coverage_observed: bool,
    executions: list[dict[str, Any]],
) -> str:
    latest = executions[-1] if executions else {}
    latest_status = str(latest.get("status", ""))
    independently_reviewed = bool(latest.get("reviews"))
    if assurance_statuses & {"verified", "closed"} and "sufficient" in evidence_statuses:
        return "verified_with_sufficient_evidence"
    if "accepted_risk" in assurance_statuses:
        return "risk_accepted_not_verification_evidence"
    if assurance_statuses and assurance_statuses <= {"not_applicable", "retired"}:
        return "not_applicable"
    if latest_status in {"failed", "timeout", "error"}:
        return "execution_failed"
    if latest_status == "passed" and independently_reviewed:
        return "reviewed_execution_recorded"
    if latest_status == "passed":
        return "execution_review_pending"
    if executions:
        return "execution_recorded"
    if implementation_registered:
        return "implementation_registered"
    if candidate_tests and coverage_observed:
        return "candidate_tests_and_coverage"
    if candidate_tests:
        return "candidate_tests_only"
    if coverage_observed:
        return "coverage_observation_only"
    return "no_verification_signal"


def build_cross_reference_index(
    analysis: dict[str, Any],
    *,
    assurance_register: dict[str, Any] | None = None,
    guidance_trace: dict[str, Any] | None = None,
    sfta_model: dict[str, Any] | None = None,
    architecture: dict[str, Any] | None = None,
    validation_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Fuse independently derived relationships without overstating their authority."""

    assurance = assurance_register or ensure_assurance_register(analysis)
    analysis_sha256 = canonical_json_sha256(analysis)
    guidance = guidance_trace or guidance_traceability(analysis)
    sfta = sfta_model or build_sfta(analysis)
    graph = architecture or architecture_graph(analysis)
    validation = validation_report or validate_analysis(analysis)

    entities: dict[str, dict[str, Any]] = {}
    relationships: dict[str, dict[str, Any]] = {}
    omitted: Counter[str] = Counter()

    def add_entity(
        kind: str,
        raw_id: object,
        label: object = "",
        *,
        authority: str = "derived_reference",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        entity_id = _entity_id(kind, raw_id)
        if entity_id not in entities:
            if len(entities) >= MAX_ENTITIES:
                omitted["entities"] += 1
                return entity_id
            entities[entity_id] = {
                "id": entity_id,
                "raw_id": str(raw_id),
                "kind": kind,
                "label": str(label or raw_id),
                "authority": authority,
                "metadata": metadata or {},
            }
        return entity_id

    def add_relation(
        source: str,
        target: str,
        kind: str,
        channel: str,
        *,
        authority: str,
        evidence_ids: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        relation_id = _relation_id(source, target, kind, channel)
        if source not in entities or target not in entities:
            omitted["relationships_missing_bounded_entity"] += 1
            return ""
        if relation_id not in relationships:
            if len(relationships) >= MAX_RELATIONSHIPS:
                omitted["relationships"] += 1
                return relation_id
            relationships[relation_id] = {
                "id": relation_id,
                "source": source,
                "target": target,
                "kind": kind,
                "channel": channel,
                "authority": authority,
                "evidence_ids": sorted(set(evidence_ids or [])),
                "metadata": metadata or {},
            }
        else:
            relationships[relation_id]["evidence_ids"] = sorted(
                {
                    *relationships[relation_id]["evidence_ids"],
                    *(evidence_ids or []),
                }
            )
        return relation_id

    components = {
        str(value.get("id", "")): value
        for value in analysis.get("components", [])
        if isinstance(value, dict) and value.get("id")
    }
    component_reference_to_id = {
        f"{component.get('source', {}).get('path', '')}:{component.get('qualname', '')}": raw_id
        for raw_id, component in components.items()
    }
    for raw_id, component in components.items():
        add_entity(
            "component",
            raw_id,
            component.get("qualname", raw_id),
            authority="repository_static_analysis",
            metadata={
                "kind": component.get("kind", ""),
                "path": component.get("source", {}).get("path", ""),
            },
        )

    analysis_scope_entity = add_entity(
        "analysis_scope",
        analysis_sha256,
        analysis.get("project", {}).get("name") or analysis_sha256[:12],
        authority="exact_governed_analysis_state",
        metadata={
            "analysis_state_sha256": analysis_sha256,
            "baseline_id": str(
                analysis.get("project", {}).get("baseline", {}).get("id", "")
            ),
        },
    )
    adapter_ledger = analysis.get("adapter_runs", {})
    if not isinstance(adapter_ledger, dict):
        adapter_ledger = {}
    adapter_runs = [
        value
        for value in adapter_ledger.get("runs", [])
        if isinstance(value, dict) and value.get("adapter_id")
    ]
    adapter_ledger_raw_id = str(adapter_ledger.get("ledger_sha256", "")) or stable_id(
        "ADAPTER-LEDGER", analysis_sha256
    )
    adapter_ledger_entity = add_entity(
        "adapter_ledger",
        adapter_ledger_raw_id,
        "adapter execution ledger",
        authority="integrity_bound_adapter_execution_ledger",
        metadata={
            "ledger_sha256": str(adapter_ledger.get("ledger_sha256", "")),
            "schema_version": str(adapter_ledger.get("schema_version", "")),
            "run_count": len(adapter_runs),
        },
    )
    run_manifest = analysis.get("run_manifest", {})
    if not isinstance(run_manifest, dict):
        run_manifest = {}
    run_manifest_raw_id = str(run_manifest.get("id", "")) or stable_id(
        "RUN-MANIFEST", analysis_sha256
    )
    run_manifest_entity = add_entity(
        "run_manifest",
        run_manifest_raw_id,
        run_manifest.get("id") or "run manifest",
        authority="integrity_bound_scan_reproducibility_manifest",
        metadata={
            "manifest_sha256": str(run_manifest.get("manifest_sha256", "")),
            "resolved_inputs_sha256": str(
                run_manifest.get("resolved_inputs_sha256", "")
            ),
            "adapter_run_ledger_sha256": str(
                run_manifest.get("resolved_inputs", {}).get(
                    "adapter_run_ledger_sha256", ""
                )
            ),
        },
    )
    configuration_digest = str(
        run_manifest.get("resolved_inputs", {}).get("configuration_digest", "")
    )
    configuration_path = str(
        run_manifest.get("tool", {}).get("settings", {}).get("config_file", "")
    )
    configuration_input_entity = ""
    analysis_input_relationship_ids: set[str] = set()
    if configuration_digest or configuration_path:
        configuration_input_entity = add_entity(
            "configuration_input",
            configuration_digest or stable_id("CONFIGURATION-INPUT", configuration_path),
            configuration_path or "resolved project configuration",
            authority="run_manifest_bound_resolved_configuration_input",
            metadata={
                "path": configuration_path,
                "sha256": configuration_digest,
                "source_label": "sfmea.toml",
            },
        )
        relation_id = add_relation(
            run_manifest_entity,
            configuration_input_entity,
            "binds_configuration_input",
            "analysis_input",
            authority="run_manifest_bound_resolved_configuration_input",
        )
        if relation_id in relationships:
            analysis_input_relationship_ids.add(relation_id)
    adapter_core_relationship_ids: set[str] = set()
    for source, target, kind, channel, authority in (
        (
            analysis_scope_entity,
            run_manifest_entity,
            "has_run_manifest",
            "run_manifest",
            "exact_analysis_reproducibility_binding",
        ),
        (
            analysis_scope_entity,
            adapter_ledger_entity,
            "has_adapter_ledger",
            "adapter_ledger",
            "exact_analysis_adapter_ledger_binding",
        ),
        (
            run_manifest_entity,
            adapter_ledger_entity,
            "binds_adapter_ledger",
            "run_manifest",
            "manifest_recorded_adapter_ledger_digest",
        ),
    ):
        relation_id = add_relation(
            source,
            target,
            kind,
            channel,
            authority=authority,
        )
        if relation_id in relationships:
            adapter_core_relationship_ids.add(relation_id)
    adapter_run_entities_by_id: dict[str, str] = {}
    for run in adapter_runs:
        adapter_id = str(run.get("adapter_id", ""))
        adapter_entity = add_entity(
            "adapter_run",
            adapter_id,
            adapter_id,
            authority="integrity_bound_adapter_execution_record",
            metadata={
                "adapter_id": adapter_id,
                "adapter_version": str(run.get("adapter_version", "")),
                "status": str(run.get("status", "")),
                "reason": str(run.get("reason", "")),
                "input_sha256": str(run.get("input_sha256", "")),
                "output_sha256": str(run.get("output_sha256", "")),
                "contribution_count": _safe_int(run.get("contribution_count", 0)),
            },
        )
        adapter_run_entities_by_id[adapter_id] = adapter_entity
        relation_id = add_relation(
            adapter_ledger_entity,
            adapter_entity,
            "records_adapter_run",
            "adapter_ledger",
            authority="integrity_bound_adapter_execution_record",
        )
        if relation_id in relationships:
            adapter_core_relationship_ids.add(relation_id)

    repository_inventory = analysis.get("repository_inventory", {})
    if not isinstance(repository_inventory, dict):
        repository_inventory = {}
    inventory_entries = [
        value
        for value in repository_inventory.get("entries", [])
        if isinstance(value, dict) and value.get("path")
    ]
    inventory_regions = [
        value
        for value in repository_inventory.get("regions", [])
        if isinstance(value, dict) and value.get("path")
    ]
    repository_inventory_raw_id = str(
        repository_inventory.get("inventory_sha256", "")
    ) or stable_id("REPOSITORY-INVENTORY", analysis_sha256)
    repository_inventory_entity = add_entity(
        "repository_inventory",
        repository_inventory_raw_id,
        "repository inventory",
        authority="integrity_bound_repository_inventory",
        metadata={
            "inventory_sha256": str(
                repository_inventory.get("inventory_sha256", "")
            ),
            "schema_version": str(repository_inventory.get("schema_version", "")),
            "truncated": bool(repository_inventory.get("truncated")),
            "artifact_count": len(inventory_entries),
            "region_count": len(inventory_regions),
        },
    )
    repository_provenance_relationship_ids: set[str] = set()
    repository_provenance_relationship_ids.update(analysis_input_relationship_ids)
    relation_id = add_relation(
        analysis_scope_entity,
        repository_inventory_entity,
        "has_repository_inventory",
        "repository_inventory",
        authority="exact_analysis_repository_inventory_binding",
    )
    if relation_id in relationships:
        repository_provenance_relationship_ids.add(relation_id)

    repository_artifact_entities_by_path: dict[str, str] = {}
    repository_artifact_records_by_path: dict[str, dict[str, Any]] = {}
    opaque_repository_artifact_entity_ids: set[str] = set()
    for entry in inventory_entries:
        path = str(entry.get("path", ""))
        artifact_entity = add_entity(
            "repository_artifact",
            path,
            path,
            authority="integrity_bound_repository_inventory_entry",
            metadata={
                "path": path,
                "kind": str(entry.get("kind", "")),
                "status": str(entry.get("status", "")),
                "analysis_depth": str(entry.get("analysis_depth", "")),
                "reason": str(entry.get("reason", "")),
                "size": _safe_int(entry.get("size", 0)),
                "sha256": str(entry.get("sha256", "")),
                "snapshot_source": str(entry.get("snapshot_source", "")),
                "adapter_ids": sorted(set(_text_values(entry.get("adapter_ids")))),
            },
        )
        if artifact_entity not in entities:
            omitted["repository_artifacts"] += 1
            continue
        repository_artifact_entities_by_path[path] = artifact_entity
        repository_artifact_records_by_path[path] = entry
        if entry.get("status") == "opaque":
            opaque_repository_artifact_entity_ids.add(artifact_entity)
        relation_id = add_relation(
            repository_inventory_entity,
            artifact_entity,
            "accounts_for_repository_artifact",
            "repository_inventory",
            authority="integrity_bound_repository_inventory_entry",
        )
        if relation_id in relationships:
            repository_provenance_relationship_ids.add(relation_id)

    repository_region_entity_ids: set[str] = set()
    for region in inventory_regions:
        path = str(region.get("path", ""))
        region_entity = add_entity(
            "repository_region",
            path,
            path,
            authority="declared_repository_inventory_exclusion",
            metadata={
                "path": path,
                "status": str(region.get("status", "")),
                "reason": str(region.get("reason", "")),
            },
        )
        if region_entity not in entities:
            omitted["repository_regions"] += 1
            continue
        repository_region_entity_ids.add(region_entity)
        relation_id = add_relation(
            repository_inventory_entity,
            region_entity,
            "excludes_repository_region",
            "repository_inventory",
            authority="declared_repository_inventory_exclusion",
        )
        if relation_id in relationships:
            repository_provenance_relationship_ids.add(relation_id)

    context_dependencies = [
        value
        for value in analysis.get("context", {}).get("dependencies", [])
        if isinstance(value, dict) and value.get("name")
    ]
    dependency_source_artifact_entities = {
        repository_artifact_entities_by_path[source]
        for source in {
            str(value.get("source", "")) for value in context_dependencies
        }
        if source in repository_artifact_entities_by_path
    }
    component_source_relationship_ids: dict[str, set[str]] = defaultdict(set)
    component_source_artifact_entities: dict[str, set[str]] = defaultdict(set)
    component_configuration_input_entities: dict[str, set[str]] = defaultdict(set)
    configured_component_ids: set[str] = set()
    unaccounted_component_ids: list[str] = []
    for component_id, component in components.items():
        source_path = str(component.get("source", {}).get("path", ""))
        artifact_entities = {
            repository_artifact_entities_by_path[source_path]
        } if source_path in repository_artifact_entities_by_path else set()
        if (
            not artifact_entities
            and component.get("kind") == "environment"
            and "runtime_environment" in _text_values(component.get("signals"))
        ):
            artifact_entities = set(dependency_source_artifact_entities)
        if (
            not artifact_entities
            and component.get("kind") == "common_cause"
            and configuration_input_entity
        ):
            component_configuration_input_entities[component_id].add(
                configuration_input_entity
            )
            configured_component_ids.add(component_id)
            relation_id = add_relation(
                _entity_id("component", component_id),
                configuration_input_entity,
                "configured_by_analysis_input",
                "analysis_input",
                authority="run_manifest_bound_project_configuration",
            )
            if relation_id in relationships:
                component_source_relationship_ids[component_id].add(relation_id)
                analysis_input_relationship_ids.add(relation_id)
                repository_provenance_relationship_ids.add(relation_id)
            continue
        if not artifact_entities:
            unaccounted_component_ids.append(component_id)
            continue
        component_source_artifact_entities[component_id].update(artifact_entities)
        for artifact_entity in sorted(artifact_entities):
            relation_id = add_relation(
                _entity_id("component", component_id),
                artifact_entity,
                "defined_in_repository_artifact",
                "repository_inventory",
                authority=(
                    "exact_component_source_path_to_inventory_entry"
                    if len(artifact_entities) == 1
                    and source_path in repository_artifact_entities_by_path
                    else "aggregate_environment_component_to_dependency_manifests"
                ),
            )
            if relation_id in relationships:
                component_source_relationship_ids[component_id].add(relation_id)
                repository_provenance_relationship_ids.add(relation_id)

    dependency_entity_ids: set[str] = set()
    for dependency in context_dependencies:
        dependency_raw_id = (
            "dependency:"
            + str(dependency.get("source", ""))
            + ":"
            + str(dependency.get("name", ""))
        )
        dependency_entity = add_entity(
            "dependency",
            dependency_raw_id,
            dependency.get("specification") or dependency.get("name"),
            authority="bounded_dependency_manifest_inventory",
            metadata={
                "name": str(dependency.get("name", "")),
                "specification": str(dependency.get("specification", "")),
                "source": str(dependency.get("source", "")),
                "evidence_type": str(dependency.get("evidence_type", "")),
                "sha256": str(dependency.get("sha256", "")),
            },
        )
        if dependency_entity not in entities:
            omitted["dependencies"] += 1
            continue
        dependency_entity_ids.add(dependency_entity)
        source_artifact = repository_artifact_entities_by_path.get(
            str(dependency.get("source", "")), ""
        )
        if source_artifact:
            relation_id = add_relation(
                dependency_entity,
                source_artifact,
                "declared_by_repository_artifact",
                "dependency_inventory",
                authority="bounded_dependency_manifest_inventory",
            )
            if relation_id in relationships:
                repository_provenance_relationship_ids.add(relation_id)

    contract_entity_ids: set[str] = set()
    for contract in analysis.get("context", {}).get("contracts", []):
        if not isinstance(contract, dict):
            continue
        contract_raw_id = str(
            contract.get("id") or contract.get("path") or contract.get("source") or ""
        )
        if not contract_raw_id:
            continue
        contract_entity = add_entity(
            "contract",
            contract_raw_id,
            contract.get("name") or contract_raw_id,
            authority="project_configured_contract_reference",
            metadata={
                "path": str(contract.get("path", "")),
                "source": str(contract.get("source", "")),
            },
        )
        if contract_entity not in entities:
            omitted["contracts"] += 1
            continue
        contract_entity_ids.add(contract_entity)
        source_path = str(contract.get("path") or contract.get("source") or "")
        source_artifact = repository_artifact_entities_by_path.get(source_path, "")
        if source_artifact:
            relation_id = add_relation(
                contract_entity,
                source_artifact,
                "declared_by_repository_artifact",
                "contract_inventory",
                authority="project_configured_contract_reference",
            )
            if relation_id in relationships:
                repository_provenance_relationship_ids.add(relation_id)
    diagnostic_entities_by_finding: dict[str, list[str]] = defaultdict(list)
    diagnostic_records_by_finding: dict[str, list[dict[str, Any]]] = defaultdict(list)
    global_diagnostic_entity_ids: list[str] = []
    global_diagnostic_relationship_ids: list[str] = []
    diagnostic_occurrences: Counter[tuple[str, str, str, str, str]] = Counter()
    diagnostic_entity_by_object_id: dict[int, str] = {}
    for diagnostic in validation.get("findings", []):
        if not isinstance(diagnostic, dict) or not diagnostic.get("rule_id"):
            continue
        diagnostic_key = (
            str(diagnostic.get("rule_id", "")),
            str(diagnostic.get("level", "")),
            str(diagnostic.get("item_id", "")),
            str(diagnostic.get("field", "")),
            str(diagnostic.get("message", "")),
        )
        diagnostic_occurrences[diagnostic_key] += 1
        raw_id = _quality_diagnostic_raw_id(
            diagnostic, occurrence=diagnostic_occurrences[diagnostic_key]
        )
        diagnostic_entity = add_entity(
            "quality_gate_diagnostic",
            raw_id,
            diagnostic.get("rule_id") or raw_id,
            authority="deterministic_quality_gate_diagnostic",
            metadata={
                "rule_id": str(diagnostic.get("rule_id", "")),
                "level": str(diagnostic.get("level", "")),
                "field": str(diagnostic.get("field", "")),
                "item_id": str(diagnostic.get("item_id", "")),
                "message": str(diagnostic.get("message", "")),
                "scope": "finding" if diagnostic.get("item_id") else "analysis",
                "occurrence": diagnostic_occurrences[diagnostic_key],
            },
        )
        if diagnostic_entity not in entities:
            omitted["quality_gate_diagnostics"] += 1
            continue
        diagnostic_entity_by_object_id[id(diagnostic)] = diagnostic_entity
        finding_id = str(diagnostic.get("item_id", ""))
        if finding_id:
            diagnostic_entities_by_finding[finding_id].append(diagnostic_entity)
            diagnostic_records_by_finding[finding_id].append(diagnostic)
            continue
        global_diagnostic_entity_ids.append(diagnostic_entity)
        relation_id = add_relation(
            analysis_scope_entity,
            diagnostic_entity,
            "has_analysis_quality_gate_diagnostic",
            "validation",
            authority="deterministic_analysis_scope_quality_gate_diagnostic",
        )
        if relation_id in relationships:
            global_diagnostic_relationship_ids.append(relation_id)

    context = analysis.get("context", {})
    for kind, collection in (
        ("requirement", context.get("requirements", [])),
        ("hazard", context.get("hazards", [])),
        ("interface", context.get("system_interfaces", [])),
    ):
        for value in collection:
            if isinstance(value, dict) and value.get("id"):
                add_entity(
                    kind,
                    value["id"],
                    value.get("name") or value.get("description") or value["id"],
                    authority="project_configuration",
                )

    citation_by_id = {
        str(value.get("id", "")): value
        for value in guidance.get("citations", [])
        if isinstance(value, dict) and value.get("id")
    }
    for raw_id, citation in citation_by_id.items():
        locator = citation.get("locator", {})
        locator_label = ""
        if isinstance(locator, dict):
            locator_label = " · ".join(
                str(locator.get(field, ""))
                for field in ("section", "heading", "page")
                if locator.get(field)
            )
        add_entity(
            "citation",
            raw_id,
            locator_label or citation.get("title") or raw_id,
            authority="versioned_guidance_catalog",
            metadata={"source_id": citation.get("source_id", "")},
        )

    component_pair_evidence: dict[tuple[str, str], dict[str, list[str]]] = defaultdict(
        lambda: defaultdict(list)
    )
    channel_map = {
        "internal_call": ("native_ast", "repository_static_analysis"),
        "graphify_static_call": ("graphify_static", "external_static_analysis"),
        "observed_runtime": ("runtime_observed", "bounded_runtime_observation"),
    }
    for edge in graph.get("edges", []):
        if not isinstance(edge, dict) or edge.get("kind") not in channel_map:
            continue
        source_raw = str(edge.get("source", ""))
        target_raw = str(edge.get("target", ""))
        if source_raw not in components or target_raw not in components:
            continue
        channel, authority = channel_map[str(edge["kind"])]
        evidence = str(edge.get("trace_id") or edge.get("evidence") or channel)
        relation_id = add_relation(
            _entity_id("component", source_raw),
            _entity_id("component", target_raw),
            "component_call",
            channel,
            authority=authority,
            evidence_ids=[evidence],
        )
        if relation_id:
            component_pair_evidence[(source_raw, target_raw)][channel].append(
                relation_id
            )

    fusions: list[dict[str, Any]] = []
    for (source, target), channel_relations in sorted(component_pair_evidence.items()):
        if len(fusions) >= MAX_FUSIONS:
            omitted["fusions"] += 1
            continue
        channels = set(channel_relations)
        classification = _classification(channels)
        fusions.append(
            {
                "id": stable_id("XFUS", source, target),
                "source_component_id": source,
                "target_component_id": target,
                "channels": sorted(channels),
                "classification": classification,
                "corroboration_count": len(channels),
                "runtime_observed": "runtime_observed" in channels,
                "relationship_ids": sorted(
                    {
                        relation_id
                        for values in channel_relations.values()
                        for relation_id in values
                    }
                ),
                "notice": (
                    "Runtime presence proves only that this edge occurred in the imported "
                    "bounded trace; static or multi-source agreement does not prove completeness."
                ),
            }
        )

    obligations = {
        str(value.get("id", "")): value
        for value in assurance.get("obligations", [])
        if isinstance(value, dict) and value.get("id")
    }
    obligations_by_finding: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for obligation_id, obligation in obligations.items():
        add_entity(
            "obligation",
            obligation_id,
            obligation.get("title")
            or obligation.get("verification_method")
            or obligation_id,
            authority="deterministic_assurance_planner",
            metadata={
                "status": obligation.get("assurance_status", ""),
                "evidence_status": obligation.get("evidence_status", ""),
            },
        )
        obligations_by_finding[str(obligation.get("finding_id", ""))].append(obligation)

    artifacts = {
        str(value.get("id", "")): value
        for value in assurance.get("evidence_artifacts", [])
        if isinstance(value, dict) and value.get("id")
    }
    for artifact_id, artifact in artifacts.items():
        add_entity(
            "evidence",
            artifact_id,
            artifact.get("path") or artifact.get("kind") or artifact_id,
            authority="recorded_evidence_artifact",
        )

    resilience = analysis.get("resilience_semantics", {})
    resilience_entities_by_component: dict[str, list[str]] = defaultdict(list)
    timing_relationships_by_component: dict[str, list[str]] = defaultdict(list)
    for operation in resilience.get("operations", []):
        if not isinstance(operation, dict) or not operation.get("id"):
            continue
        operation_id = str(operation["id"])
        component_id = str(operation.get("component_id", ""))
        operation_entity = add_entity(
            "resilience_operation",
            operation_id,
            operation.get("reference") or operation_id,
            authority=str(
                operation.get(
                    "authority", "bounded_static_resilience_semantic_operation"
                )
            ),
            metadata={
                "categories": _text_values(operation.get("categories")),
                "declared_timeout": operation.get("declared_timeout"),
                "resource_bound": operation.get("resource_bound"),
            },
        )
        if component_id in components:
            resilience_entities_by_component[component_id].append(operation_entity)
            add_relation(
                _entity_id("component", component_id),
                operation_entity,
                "has_resilience_operation",
                "resilience_semantics",
                authority="bounded_static_resilience_semantics",
            )
    for effect in resilience.get("effects", []):
        if not isinstance(effect, dict):
            continue
        reference = str(effect.get("component_reference", ""))
        component_id = component_reference_to_id.get(reference, "")
        direct_effects = _text_values(effect.get("direct_effects"))
        transitive_effects = _text_values(effect.get("transitive_effects"))
        retry_factor = _safe_int(effect.get("retry_factor", 1), 1)
        if not component_id or not (
            direct_effects
            or transitive_effects
            or retry_factor > 1
            or effect.get("unprotected_retry_side_effect")
        ):
            continue
        effect_id = stable_id("RESILIENCE-EFFECT", component_id)
        effect_entity = add_entity(
            "resilience_effect_summary",
            effect_id,
            reference or effect_id,
            authority=str(
                effect.get(
                    "authority",
                    "bounded_interprocedural_effect_summary_not_runtime_exactly_once_proof",
                )
            ),
            metadata={
                "direct_effects": direct_effects,
                "transitive_effects": transitive_effects,
                "retry_factor": retry_factor,
                "unprotected_retry_side_effect": bool(
                    effect.get("unprotected_retry_side_effect")
                ),
            },
        )
        resilience_entities_by_component[component_id].append(effect_entity)
        add_relation(
            _entity_id("component", component_id),
            effect_entity,
            "has_resilience_effect_summary",
            "resilience_semantics",
            authority="bounded_static_resilience_semantics",
        )
    for transaction in resilience.get("transactions", []):
        if not isinstance(transaction, dict):
            continue
        component_id = str(transaction.get("component_id", ""))
        operation_ids = _text_values(transaction.get("operation_ids"))
        risks = _text_values(transaction.get("consistency_risks"))
        if component_id not in components or not (operation_ids or risks):
            continue
        transaction_id = stable_id("TRANSACTION-SUMMARY", component_id)
        transaction_entity = add_entity(
            "transaction_summary",
            transaction_id,
            transaction.get("component_reference") or transaction_id,
            authority=str(
                transaction.get(
                    "authority",
                    "lexical_transaction_and_consistency_summary_not_runtime_atomicity_proof",
                )
            ),
            metadata={
                "operation_ids": operation_ids,
                "consistency_risks": risks,
                "open_transaction_depth_at_exit": transaction.get(
                    "open_transaction_depth_at_exit"
                ),
                "compensation_observed": bool(transaction.get("compensation_observed")),
            },
        )
        resilience_entities_by_component[component_id].append(transaction_entity)
        add_relation(
            _entity_id("component", component_id),
            transaction_entity,
            "has_transaction_summary",
            "resilience_semantics",
            authority="bounded_static_resilience_semantics",
        )
    for resource in resilience.get("resources", []):
        if not isinstance(resource, dict):
            continue
        component_id = str(resource.get("component_id", ""))
        bounded = resource.get("bounded_resources", [])
        unbounded = resource.get("unbounded_growth_candidates", [])
        if component_id not in components or not (
            bounded or unbounded or resource.get("recursive_call_candidate")
        ):
            continue
        resource_id = stable_id("RESOURCE-SUMMARY", component_id)
        resource_entity = add_entity(
            "resource_summary",
            resource_id,
            resource.get("component_reference") or resource_id,
            authority=str(
                resource.get(
                    "authority",
                    "static_resource_bound_candidates_not_symbolic_complexity_proof",
                )
            ),
            metadata={
                "bounded_resource_count": len(bounded)
                if isinstance(bounded, list)
                else 0,
                "unbounded_growth_candidate_count": len(unbounded)
                if isinstance(unbounded, list)
                else 0,
                "recursive_call_candidate": bool(
                    resource.get("recursive_call_candidate")
                ),
            },
        )
        resilience_entities_by_component[component_id].append(resource_entity)
        add_relation(
            _entity_id("component", component_id),
            resource_entity,
            "has_resource_summary",
            "resilience_semantics",
            authority="bounded_static_resilience_semantics",
        )
    for timing in resilience.get("timing_relations", []):
        if not isinstance(timing, dict):
            continue
        caller_id = component_reference_to_id.get(
            str(timing.get("caller_reference", "")), ""
        )
        callee_id = component_reference_to_id.get(
            str(timing.get("callee_reference", "")), ""
        )
        if not caller_id or not callee_id:
            continue
        relation_id = add_relation(
            _entity_id("component", caller_id),
            _entity_id("component", callee_id),
            "has_timing_budget_relation",
            "resilience_semantics",
            authority=str(
                timing.get(
                    "authority",
                    "same-unit-literal_budget_constraint_not_end_to_end_latency_proof",
                )
            ),
            metadata={
                "model_id": str(timing.get("id", "")),
                "status": str(timing.get("status", "")),
                "caller_budget": timing.get("caller_budget"),
                "callee_budget": timing.get("callee_budget"),
            },
        )
        if relation_id:
            timing_relationships_by_component[caller_id].append(relation_id)
            timing_relationships_by_component[callee_id].append(relation_id)
    for index, retry in enumerate(resilience.get("retry_paths", [])):
        if not isinstance(retry, dict):
            continue
        path_references = _text_values(retry.get("path"))
        retry_id = stable_id(
            "RETRY-PATH",
            str(retry.get("origin_component_reference", "")),
            str(index),
            *path_references,
        )
        retry_entity = add_entity(
            "retry_path",
            retry_id,
            " → ".join(path_references) or retry_id,
            authority=str(
                retry.get(
                    "authority",
                    "static_nested_retry_upper_candidate_not_runtime_attempt_count_proof",
                )
            ),
            metadata={
                "amplification_factor_upper_candidate": retry.get(
                    "amplification_factor_upper_candidate"
                ),
                "cycle_detected": bool(retry.get("cycle_detected")),
                "search_truncated": bool(retry.get("search_truncated")),
            },
        )
        for reference in path_references:
            component_id = component_reference_to_id.get(reference, "")
            if not component_id:
                continue
            resilience_entities_by_component[component_id].append(retry_entity)
            add_relation(
                _entity_id("component", component_id),
                retry_entity,
                "participates_in_retry_path",
                "resilience_semantics",
                authority="bounded_static_retry_path_candidate",
            )
    for breaker in resilience.get("circuit_breakers", []):
        if not isinstance(breaker, dict) or not breaker.get("id"):
            continue
        breaker_entity = add_entity(
            "circuit_breaker_model",
            breaker["id"],
            breaker.get("scope") or breaker["id"],
            authority=str(
                breaker.get(
                    "authority",
                    "class_scope_static_breaker_semantics_not_effectiveness_or_transition_proof",
                )
            ),
            metadata={
                "roles": _text_values(breaker.get("roles")),
                "states": _text_values(breaker.get("states")),
                "semantic_gaps": _text_values(breaker.get("semantic_gaps")),
            },
        )
        scope = str(breaker.get("scope", ""))
        for component_id, component in components.items():
            qualname = str(component.get("qualname", ""))
            if qualname != scope and not qualname.startswith(scope + "."):
                continue
            resilience_entities_by_component[component_id].append(breaker_entity)
            add_relation(
                _entity_id("component", component_id),
                breaker_entity,
                "participates_in_circuit_breaker_model",
                "resilience_semantics",
                authority="bounded_static_breaker_semantics",
            )

    semantic_entities_by_component: dict[str, set[str]] = defaultdict(set)
    semantic_relationships_by_component: dict[str, set[str]] = defaultdict(set)
    semantic_dimensions_by_component: dict[str, set[str]] = defaultdict(set)

    def semantic_metadata(record: dict[str, Any]) -> dict[str, Any]:
        """Retain decision-useful bounded fields without duplicating complete models."""

        fields = (
            "kind",
            "status",
            "resolution",
            "disposition",
            "categories",
            "dimensions",
            "risks",
            "gaps",
            "exception_type",
            "state_variable",
            "target_state_expression",
            "operation",
            "component_reference",
            "line",
            "path",
            "node_ids",
            "affected_component_ids",
        )
        metadata: dict[str, Any] = {}
        for field in fields:
            value = record.get(field)
            if value in (None, "", [], {}):
                continue
            if isinstance(value, (str, int, float, bool)):
                metadata[field] = value
                continue
            if isinstance(value, list):
                scalar_values = [
                    item
                    for item in value
                    if isinstance(item, (str, int, float, bool))
                ]
                metadata[field] = scalar_values[:100]
                if len(scalar_values) > 100:
                    metadata[f"{field}_omitted"] = len(scalar_values) - 100
        return metadata

    def link_semantic_record(
        component_id: str,
        dimension: str,
        record_kind: str,
        raw_id: object,
        record: dict[str, Any],
        *,
        role: str = "record",
        label: object = "",
        authority: str = "bounded_static_semantic_projection",
    ) -> None:
        if component_id not in components or not raw_id:
            return
        entity_id = add_entity(
            record_kind,
            raw_id,
            label or record.get("component_reference") or raw_id,
            authority=str(record.get("authority") or authority),
            metadata=semantic_metadata(record),
        )
        if entity_id not in entities:
            return
        semantic_entities_by_component[component_id].add(entity_id)
        semantic_dimensions_by_component[component_id].add(dimension)
        relation_id = add_relation(
            _entity_id("component", component_id),
            entity_id,
            f"has_{dimension}_{role}",
            dimension,
            authority=str(record.get("authority") or authority),
        )
        if relation_id in relationships:
            semantic_relationships_by_component[component_id].add(relation_id)

    data_flow = analysis.get("interprocedural_data_flow", {})
    for edge in data_flow.get("edges", []):
        if not isinstance(edge, dict) or not edge.get("id"):
            continue
        link_semantic_record(
            str(edge.get("caller_component_id", "")),
            "data_flow",
            "data_flow_edge",
            edge["id"],
            edge,
            role="outbound_edge",
            label=f"{edge.get('caller_reference', '')} → {edge.get('callee_reference', '')}",
        )
        link_semantic_record(
            str(edge.get("callee_component_id", "")),
            "data_flow",
            "data_flow_edge",
            edge["id"],
            edge,
            role="inbound_edge",
            label=f"{edge.get('caller_reference', '')} → {edge.get('callee_reference', '')}",
        )

    alias_flow = analysis.get("alias_object_flow", {})
    for index, record in enumerate(alias_flow.get("records", [])):
        if not isinstance(record, dict):
            continue
        record_id = record.get("id") or stable_id(
            "ALIAS-XREF",
            str(record.get("component_id", "")),
            str(record.get("target", "")),
            str(record.get("line", 0)),
            str(index),
        )
        link_semantic_record(
            str(record.get("component_id", "")),
            "alias_object_flow",
            "alias_object_binding",
            record_id,
            record,
            label=record.get("target") or record_id,
        )

    concurrency = analysis.get("concurrency_model", {})
    for operation in concurrency.get("operations", []):
        if isinstance(operation, dict) and operation.get("id"):
            link_semantic_record(
                str(operation.get("component_id", "")),
                "concurrency",
                "concurrency_operation",
                operation["id"],
                operation,
                label=operation.get("reference") or operation["id"],
            )
    for relation in concurrency.get("relations", []):
        if isinstance(relation, dict) and relation.get("id"):
            link_semantic_record(
                str(relation.get("component_id", "")),
                "concurrency",
                "concurrency_relation",
                relation["id"],
                relation,
                label=relation.get("kind") or relation["id"],
            )

    exception_model = analysis.get("exception_propagation", {})
    for collection, record_kind, role in (
        ("raises", "exception_raise", "raise"),
        ("handlers", "exception_handler", "handler"),
    ):
        for record in exception_model.get(collection, []):
            if isinstance(record, dict) and record.get("id"):
                link_semantic_record(
                    str(record.get("component_id", "")),
                    "exception_propagation",
                    record_kind,
                    record["id"],
                    record,
                    role=role,
                    label=record.get("exception_type")
                    or record.get("component_reference")
                    or record["id"],
                )
    for edge in exception_model.get("edges", []):
        if not isinstance(edge, dict) or not edge.get("id"):
            continue
        label = (
            f"{edge.get('exception_type', 'exception')} · "
            f"{edge.get('disposition', 'propagation candidate')}"
        )
        link_semantic_record(
            str(edge.get("caller_component_id", "")),
            "exception_propagation",
            "exception_propagation_edge",
            edge["id"],
            edge,
            role="incoming_edge",
            label=label,
        )
        link_semantic_record(
            str(edge.get("callee_component_id", "")),
            "exception_propagation",
            "exception_propagation_edge",
            edge["id"],
            edge,
            role="outgoing_edge",
            label=label,
        )

    state_model = analysis.get("state_machine_model", {})
    for collection, record_kind, role in (
        ("states", "state_candidate", "state"),
        ("guards", "state_guard", "guard"),
        ("transitions", "state_transition", "transition"),
    ):
        for record in state_model.get(collection, []):
            if isinstance(record, dict) and record.get("id"):
                link_semantic_record(
                    str(record.get("component_id", "")),
                    "state_machine",
                    record_kind,
                    record["id"],
                    record,
                    role=role,
                    label=record.get("target_state_expression")
                    or record.get("state_expression")
                    or record.get("component_reference")
                    or record["id"],
                )

    authorization = analysis.get("authorization_scope_flow", {})
    for record in authorization.get("components", []):
        if not isinstance(record, dict):
            continue
        if not any(
            record.get(field)
            for field in ("context_dimensions", "controls", "risks", "boundary")
        ):
            continue
        component_id = str(record.get("component_id", ""))
        link_semantic_record(
            component_id,
            "authorization_scope",
            "authorization_context",
            stable_id("AUTH-CONTEXT-XREF", component_id),
            {
                **record,
                "dimensions": _text_values(record.get("context_dimensions")),
            },
            label=record.get("component_reference") or component_id,
        )
    for edge in authorization.get("edges", []):
        if not isinstance(edge, dict) or not edge.get("id"):
            continue
        for role, field in (
            ("outbound_edge", "caller_component_id"),
            ("inbound_edge", "callee_component_id"),
        ):
            link_semantic_record(
                str(edge.get(field, "")),
                "authorization_scope",
                "authorization_scope_edge",
                edge["id"],
                edge,
                role=role,
                label=", ".join(_text_values(edge.get("dimensions"))) or edge["id"],
            )

    contract_model = analysis.get("contract_semantics", {})
    contract_records: dict[str, tuple[str, dict[str, Any]]] = {}
    for collection, record_kind in (
        ("operations", "contract_operation"),
        ("compatibility", "contract_compatibility"),
    ):
        for record in contract_model.get(collection, []):
            if isinstance(record, dict) and record.get("id"):
                contract_records[str(record["id"])] = (record_kind, record)
    for component_id, component in components.items():
        index = component.get("contract_semantics", {})
        if not isinstance(index, dict):
            continue
        for role, field in (
            ("operation", "operation_ids"),
            ("compatibility", "compatibility_ids"),
        ):
            for record_id in _text_values(index.get(field)):
                record_kind, record = contract_records.get(
                    record_id, (f"contract_{role}", {"id": record_id})
                )
                link_semantic_record(
                    component_id,
                    "contract_semantics",
                    record_kind,
                    record_id,
                    record,
                    role=role,
                    label=record.get("operation")
                    or record.get("kind")
                    or record_id,
                    authority="governed_local_contract_semantics",
                )

    deployment = analysis.get("deployment_topology", {})
    deployment_nodes = {
        str(record.get("id", "")): record
        for record in deployment.get("nodes", [])
        if isinstance(record, dict) and record.get("id")
    }
    for placement in deployment.get("placements", []):
        if not isinstance(placement, dict):
            continue
        component_id = str(placement.get("component_id", ""))
        for node_id in _text_values(placement.get("node_ids")):
            record = deployment_nodes.get(node_id, {"id": node_id})
            link_semantic_record(
                component_id,
                "deployment_topology",
                "deployment_node",
                node_id,
                record,
                role="candidate_placement",
                label=record.get("name") or record.get("path") or node_id,
                authority="declared_static_deployment_candidate",
            )

    shared_fate = analysis.get("shared_fate_analysis", {})
    for region in shared_fate.get("regions", []):
        if not isinstance(region, dict) or not region.get("id"):
            continue
        for component_id in _text_values(region.get("affected_component_ids")):
            link_semantic_record(
                component_id,
                "shared_fate",
                "shared_fate_region",
                region["id"],
                region,
                role="affected_component",
                label=region.get("key") or region.get("kind") or region["id"],
            )

    hierarchy = analysis.get("architecture_hierarchy", {})
    hierarchy_nodes = {
        str(record.get("id", "")): record
        for record in hierarchy.get("nodes", [])
        if isinstance(record, dict) and record.get("id")
    }
    for membership in hierarchy.get("memberships", []):
        if not isinstance(membership, dict):
            continue
        component_id = str(membership.get("component_id", ""))
        for node_id in _text_values(membership.get("node_ids")):
            record = hierarchy_nodes.get(node_id, {"id": node_id})
            link_semantic_record(
                component_id,
                "architecture_hierarchy",
                "architecture_node",
                node_id,
                record,
                role="membership",
                label=record.get("path") or record.get("name") or node_id,
                authority="deterministic_architecture_hierarchy_membership",
            )

    semantic_profiles: list[dict[str, Any]] = []
    semantic_profile_by_component: dict[str, dict[str, Any]] = {}
    for component_id in sorted(components):
        dimensions = {
            dimension: dimension in semantic_dimensions_by_component[component_id]
            for dimension in SEMANTIC_EXPOSURE_DIMENSIONS
        }
        profile_raw_id = stable_id("SEMANTIC-PROFILE", component_id)
        profile_entity_id = add_entity(
            "semantic_profile",
            profile_raw_id,
            components[component_id].get("qualname") or component_id,
            authority="deterministic_cross_analyzer_semantic_profile",
            metadata={
                "populated_dimensions": [
                    dimension for dimension, populated in dimensions.items() if populated
                ]
            },
        )
        profile_relation_id = add_relation(
            _entity_id("component", component_id),
            profile_entity_id,
            "has_semantic_exposure_profile",
            "cross_reference",
            authority="deterministic_cross_analyzer_semantic_profile",
        )
        entity_ids = sorted(semantic_entities_by_component[component_id])
        relationship_ids = sorted(semantic_relationships_by_component[component_id])
        if profile_relation_id in relationships:
            relationship_ids.append(profile_relation_id)
        profile = {
            "id": profile_entity_id,
            "component_id": component_id,
            "dimensions": dimensions,
            "entity_ids": entity_ids,
            "relationship_ids": sorted(set(relationship_ids)),
            "populated_dimension_count": sum(dimensions.values()),
            "notice": (
                "The profile joins bounded static analyzer records by stable component identity; "
                "co-location is a review aid, not proof of reachability, causality, or defect."
            ),
        }
        semantic_profiles.append(profile)
        semantic_profile_by_component[component_id] = profile

    executions = {
        str(value.get("id", "")): value
        for value in assurance.get("executions", [])
        if isinstance(value, dict) and value.get("id")
    }
    for execution_id, execution in executions.items():
        execution_entity = add_entity(
            "execution",
            execution_id,
            execution.get("status") or execution_id,
            authority="recorded_execution",
            metadata={
                "status": str(execution.get("status", "")),
                "independently_reviewed": bool(execution.get("reviews")),
            },
        )
        obligation_id = str(execution.get("obligation_id", ""))
        if obligation_id in obligations:
            add_relation(
                _entity_id("obligation", obligation_id),
                execution_entity,
                "has_execution",
                "assurance_register",
                authority="recorded_execution",
            )

    work_queue = assurance_work_queue(analysis)
    work_queue_by_finding = {
        str(value.get("finding_id", "")): value
        for value in work_queue.get("items", [])
        if isinstance(value, dict) and value.get("finding_id")
    }
    test_candidate_entities_by_component: dict[str, set[str]] = defaultdict(set)
    coverage_entities_by_component: dict[str, set[str]] = defaultdict(set)
    readiness_relationships_by_component: dict[str, set[str]] = defaultdict(set)
    for component_id, component in components.items():
        for test_path in _candidate_test_paths(component.get("test_references")):
            test_entity = add_entity(
                "test_candidate",
                stable_id("TEST-CANDIDATE", test_path),
                test_path,
                authority="textual_static_test_reference_not_execution_or_adequacy_evidence",
                metadata={"path": test_path, "source": "component_test_reference"},
            )
            test_candidate_entities_by_component[component_id].add(test_entity)
            relation_id = add_relation(
                _entity_id("component", component_id),
                test_entity,
                "has_static_test_candidate",
                "test_reference",
                authority="textual_static_test_reference_not_execution_or_adequacy_evidence",
            )
            if relation_id in relationships:
                readiness_relationships_by_component[component_id].add(relation_id)
        coverage = component.get("coverage")
        if isinstance(coverage, dict):
            coverage_id = stable_id("COVERAGE-OBSERVATION", component_id)
            coverage_entity = add_entity(
                "coverage_observation",
                coverage_id,
                component.get("qualname") or coverage_id,
                authority="coverage_py_observed_line_and_branch_execution_not_test_adequacy",
                metadata={
                    field: coverage.get(field)
                    for field in (
                        "line_percent",
                        "covered_lines",
                        "missing_lines",
                        "branch_percent",
                        "covered_branches",
                        "missing_branches",
                    )
                    if coverage.get(field) is not None
                },
            )
            coverage_entities_by_component[component_id].add(coverage_entity)
            relation_id = add_relation(
                _entity_id("component", component_id),
                coverage_entity,
                "has_coverage_observation",
                "coverage_py",
                authority="observed_execution_lines_and_branches_not_control_effectiveness",
            )
            if relation_id in relationships:
                readiness_relationships_by_component[component_id].add(relation_id)

    obligation_test_candidate_entities: dict[str, set[str]] = defaultdict(set)
    obligation_implemented_test_entities: dict[str, set[str]] = defaultdict(set)
    obligation_assignment_entities: dict[str, set[str]] = defaultdict(set)
    readiness_relationships_by_obligation: dict[str, set[str]] = defaultdict(set)
    for obligation_id, obligation in obligations.items():
        component_id = str(obligation.get("component_id", ""))
        for test_path in _candidate_test_paths(obligation.get("existing_test_candidates")):
            test_entity = add_entity(
                "test_candidate",
                stable_id("TEST-CANDIDATE", test_path),
                test_path,
                authority="textual_static_test_reference_not_execution_or_adequacy_evidence",
                metadata={"path": test_path, "source": "obligation_existing_candidate"},
            )
            obligation_test_candidate_entities[obligation_id].add(test_entity)
            if component_id in components:
                test_candidate_entities_by_component[component_id].add(test_entity)
            relation_id = add_relation(
                _entity_id("obligation", obligation_id),
                test_entity,
                "has_static_test_candidate",
                "assurance_planner",
                authority="candidate_link_not_implemented_test_or_execution_evidence",
            )
            if relation_id in relationships:
                readiness_relationships_by_obligation[obligation_id].add(relation_id)
        automation = obligation.get("automation", {})
        if not isinstance(automation, dict):
            automation = {}
        implemented_path = str(automation.get("implemented_test_path", "")).strip()
        implementation_status = str(
            automation.get("implementation_status", "not_implemented")
        )
        if implementation_status == "implemented" and implemented_path:
            test_sha256 = str(automation.get("test_sha256", ""))
            implementation_entity = add_entity(
                "implemented_test",
                stable_id(
                    "IMPLEMENTED-TEST", obligation_id, implemented_path, test_sha256
                ),
                implemented_path,
                authority="registered_content_bound_test_implementation_not_execution_evidence",
                metadata={
                    "path": implemented_path,
                    "test_sha256": test_sha256,
                    "implementation_origin": str(
                        automation.get("implementation_origin", "")
                    ),
                },
            )
            obligation_implemented_test_entities[obligation_id].add(
                implementation_entity
            )
            relation_id = add_relation(
                _entity_id("obligation", obligation_id),
                implementation_entity,
                "implemented_by_test",
                "assurance_register",
                authority="registered_content_bound_test_implementation_not_execution_evidence",
            )
            if relation_id in relationships:
                readiness_relationships_by_obligation[obligation_id].add(relation_id)
        review = obligation.get("review", {})
        if not isinstance(review, dict):
            review = {}
        for role, field in (("owner", "owner"), ("reviewer", "reviewer")):
            participant = str(review.get(field, "")).strip()
            if not participant:
                continue
            participant_entity = add_entity(
                f"assurance_{role}",
                stable_id(f"ASSURANCE-{role.upper()}", participant),
                participant,
                authority="recorded_assurance_assignment",
            )
            obligation_assignment_entities[obligation_id].add(participant_entity)
            relation_id = add_relation(
                _entity_id("obligation", obligation_id),
                participant_entity,
                f"assigned_{role}",
                "assurance_register",
                authority="recorded_assurance_assignment_not_independence_or_approval_proof",
            )
            if relation_id in relationships:
                readiness_relationships_by_obligation[obligation_id].add(relation_id)

    sfta_nodes_by_finding: dict[str, list[str]] = defaultdict(list)
    for tree in sfta.get("trees", []):
        if not isinstance(tree, dict):
            continue
        tree_id = str(tree.get("id", ""))
        tree_entity = add_entity(
            "sfta_tree",
            tree_id,
            tree.get("hazard_id") or tree_id,
            authority=str(tree.get("source", "derived_sfta")),
        )
        for node in tree.get("nodes", []):
            if not isinstance(node, dict):
                continue
            qualified_id = f"{tree_id}:{node.get('id', '')}"
            node_entity = add_entity(
                "sfta_event",
                qualified_id,
                node.get("description") or node.get("id") or qualified_id,
                authority=str(tree.get("source", "derived_sfta")),
            )
            add_relation(
                tree_entity,
                node_entity,
                "contains_event",
                "sfta",
                authority=str(tree.get("source", "derived_sfta")),
            )
            for finding_id in _text_values(node.get("linked_finding_ids")):
                sfta_nodes_by_finding[finding_id].append(qualified_id)

    finding_chains: list[dict[str, Any]] = []
    verification_readiness_profiles: list[dict[str, Any]] = []
    review_governance_profiles: list[dict[str, Any]] = []
    unaccounted_finding_ids: list[str] = []
    for item in analysis.get("items", []):
        if not isinstance(item, dict) or not item.get("id"):
            continue
        if len(finding_chains) >= MAX_CHAINS:
            omitted["finding_chains"] += 1
            continue
        finding_id = str(item["id"])
        component_id = str(item.get("component_id", ""))
        finding_entity = add_entity(
            "finding",
            finding_id,
            item.get("review", {}).get("failure_mode")
            or item.get("scanner", {}).get("failure_mode")
            or finding_id,
            authority="candidate_requires_engineering_review",
            metadata={
                "disposition": item.get("review", {}).get("disposition", "unreviewed"),
                "priority": item.get("scanner", {}).get("screening_priority", ""),
                "source_status": item.get("source_status", "active"),
                "source_change": item.get("source_change", ""),
                "workflow_status": item.get("review", {}).get("status", "draft"),
                "revalidation_required": bool(
                    item.get("review", {}).get("revalidation_required")
                ),
            },
        )
        component_entity = _entity_id("component", component_id)
        if component_id in components:
            add_relation(
                component_entity,
                finding_entity,
                "has_failure_mode",
                "sfmea",
                authority="candidate_requires_engineering_review",
            )

        source_path = str(item.get("source", {}).get("path", ""))
        source_artifact_entities = {
            repository_artifact_entities_by_path[source_path]
        } if source_path in repository_artifact_entities_by_path else set()
        if not source_artifact_entities:
            source_artifact_entities = set(
                component_source_artifact_entities.get(component_id, set())
            )
        source_configuration_entities = set(
            component_configuration_input_entities.get(component_id, set())
        )
        source_artifact_entity = (
            sorted(source_artifact_entities)[0] if source_artifact_entities else ""
        )
        source_configuration_input_entity = (
            sorted(source_configuration_entities)[0]
            if source_configuration_entities
            else ""
        )
        source_provenance_relationship_ids = set(
            component_source_relationship_ids.get(component_id, set())
        )
        for artifact_entity in sorted(source_artifact_entities):
            relation_id = add_relation(
                finding_entity,
                artifact_entity,
                "originates_from_repository_artifact",
                "repository_inventory",
                authority=(
                    "exact_finding_source_path_to_inventory_entry"
                    if len(source_artifact_entities) == 1
                    and source_path in repository_artifact_entities_by_path
                    else "aggregate_environment_finding_to_dependency_manifests"
                ),
            )
            if relation_id in relationships:
                source_provenance_relationship_ids.add(relation_id)
                repository_provenance_relationship_ids.add(relation_id)
        if source_configuration_input_entity:
            relation_id = add_relation(
                finding_entity,
                source_configuration_input_entity,
                "originates_from_analysis_input",
                "analysis_input",
                authority="run_manifest_bound_project_configuration",
            )
            if relation_id in relationships:
                source_provenance_relationship_ids.add(relation_id)
                analysis_input_relationship_ids.add(relation_id)
                repository_provenance_relationship_ids.add(relation_id)
        if not source_artifact_entities and not source_configuration_input_entity:
            unaccounted_finding_ids.append(finding_id)
        source_artifact_record = (
            entities[source_artifact_entity].get("metadata", {})
            if source_artifact_entity
            else {}
        )
        source_adapter_ids = sorted(
            {
                adapter_id
                for artifact_entity in source_artifact_entities
                for adapter_id in _text_values(
                    entities[artifact_entity].get("metadata", {}).get("adapter_ids")
                )
            }
        )

        requirements = sorted(
            set(_text_values(item.get("component", {}).get("requirement_ids")))
        )
        hazards = sorted(
            set(_text_values(item.get("review", {}).get("linked_hazards")))
        )
        citation_ids = sorted(
            {
                str(value.get("citation_id", ""))
                for value in item.get("scanner", {}).get("citations", [])
                if isinstance(value, dict) and value.get("citation_id")
            }
        )
        if not citation_ids:
            citation_ids = sorted(
                set(_text_values(item.get("scanner", {}).get("citation_ids")))
            )
        finding_obligations = obligations_by_finding.get(finding_id, [])
        evidence_ids: set[str] = set()
        execution_ids: set[str] = set()
        for requirement_id in requirements:
            add_relation(
                finding_entity,
                add_entity("requirement", requirement_id),
                "traces_to_requirement",
                "project_mapping",
                authority="project_configuration",
            )
        for hazard_id in hazards:
            add_relation(
                finding_entity,
                add_entity("hazard", hazard_id),
                "may_contribute_to_hazard",
                "engineering_review",
                authority="reviewed_or_inherited_hazard_link",
            )
        for citation_id in citation_ids:
            add_relation(
                finding_entity,
                add_entity("citation", citation_id),
                "supported_by_guidance",
                "guidance_mapping",
                authority="guidance_relevance_not_noncompliance",
            )
        for obligation in finding_obligations:
            obligation_id = str(obligation.get("id", ""))
            add_relation(
                finding_entity,
                _entity_id("obligation", obligation_id),
                "generates_obligation",
                "assurance_planner",
                authority="deterministic_assurance_planner",
            )
            for artifact_id in _text_values(obligation.get("evidence_artifact_ids")):
                evidence_ids.add(artifact_id)
                add_relation(
                    _entity_id("obligation", obligation_id),
                    add_entity("evidence", artifact_id),
                    "requires_or_records_evidence",
                    "assurance_register",
                    authority="recorded_evidence_reference",
                )
            for execution_id, execution in executions.items():
                if str(execution.get("obligation_id", "")) == obligation_id:
                    execution_ids.add(execution_id)
        for qualified_id in sorted(set(sfta_nodes_by_finding.get(finding_id, []))):
            add_relation(
                _entity_id("sfta_event", qualified_id),
                finding_entity,
                "correlates_to_finding",
                "sfta_reconciliation",
                authority="configured_or_derived_sfta_correlation",
            )
        dimensions = {
            "component": component_id in components,
            "source_provenance": bool(
                source_artifact_entities or source_configuration_input_entity
            ),
            "requirements": bool(requirements),
            "hazards": bool(hazards),
            "guidance": bool(citation_ids),
            "verification": bool(finding_obligations),
            "evidence": bool(evidence_ids or execution_ids),
            "sfta": bool(sfta_nodes_by_finding.get(finding_id)),
        }
        scanner = item.get("scanner", {})
        upstream_paths = [
            [
                component_reference_to_id[reference]
                for reference in _text_values(path)
                if reference in component_reference_to_id
            ]
            for path in scanner.get("upstream_paths", [])
            if isinstance(path, list)
        ]
        upstream_paths = [path for path in upstream_paths if path]
        cascade_component_ids = sorted(
            {component for path in upstream_paths for component in path}
        )
        resilience_entity_ids = sorted(
            set(resilience_entities_by_component.get(component_id, []))
        )
        timing_relation_ids = sorted(
            set(timing_relationships_by_component.get(component_id, []))
        )
        obligation_ids = sorted(
            str(value.get("id", "")) for value in finding_obligations
        )
        test_candidate_entity_ids = sorted(
            {
                *test_candidate_entities_by_component.get(component_id, set()),
                *(
                    entity_id
                    for obligation_id in obligation_ids
                    for entity_id in obligation_test_candidate_entities.get(
                        obligation_id, set()
                    )
                ),
            }
        )
        coverage_entity_ids = sorted(
            coverage_entities_by_component.get(component_id, set())
        )
        implemented_test_entity_ids = sorted(
            {
                entity_id
                for obligation_id in obligation_ids
                for entity_id in obligation_implemented_test_entities.get(
                    obligation_id, set()
                )
            }
        )
        assignment_entity_ids = {
            entity_id
            for obligation_id in obligation_ids
            for entity_id in obligation_assignment_entities.get(obligation_id, set())
        }
        readiness_relationship_ids = {
            *readiness_relationships_by_component.get(component_id, set()),
            *(
                relationship_id
                for obligation_id in obligation_ids
                for relationship_id in readiness_relationships_by_obligation.get(
                    obligation_id, set()
                )
            ),
        }
        review = item.get("review", {})
        if not isinstance(review, dict):
            review = {}
        for role, field in (("owner", "owner"), ("reviewer", "reviewer")):
            participant = str(review.get(field, "")).strip()
            if not participant:
                continue
            participant_entity = add_entity(
                f"finding_{role}",
                stable_id(f"FINDING-{role.upper()}", participant),
                participant,
                authority="recorded_finding_review_assignment",
            )
            assignment_entity_ids.add(participant_entity)
            relation_id = add_relation(
                finding_entity,
                participant_entity,
                f"assigned_{role}",
                "sfmea_review",
                authority="recorded_review_assignment_not_independence_or_approval_proof",
            )
            if relation_id in relationships:
                readiness_relationship_ids.add(relation_id)
        finding_executions = [
            execution
            for execution_id, execution in executions.items()
            if execution_id in execution_ids
        ]
        assurance_statuses = {
            str(value.get("assurance_status", ""))
            for value in finding_obligations
            if value.get("assurance_status")
        }
        evidence_statuses = {
            str(value.get("evidence_status", ""))
            for value in finding_obligations
            if value.get("evidence_status")
        }
        implementation_registered = bool(implemented_test_entity_ids)
        evidence_posture = _verification_evidence_posture(
            assurance_statuses=assurance_statuses,
            evidence_statuses=evidence_statuses,
            implementation_registered=implementation_registered,
            candidate_tests=bool(test_candidate_entity_ids),
            coverage_observed=bool(coverage_entity_ids),
            executions=finding_executions,
        )
        disposition = str(review.get("disposition", "unreviewed"))
        work_item = work_queue_by_finding.get(finding_id, {})
        if item.get("source_status", "active") != "active":
            lifecycle_state = "historical"
            next_action_id = "none"
            blockers: list[str] = []
        elif review.get("revalidation_required"):
            lifecycle_state = "revalidation_required"
            next_action_id = "revalidate_finding"
            blockers = ["reviewed finding requires revalidation against current source"]
        elif work_item:
            lifecycle_state = str(work_item.get("state", "contract_gap"))
            next_action_id = str(work_item.get("next_action_id", ""))
            blockers = _text_values(work_item.get("blockers"))
        elif disposition == "unreviewed":
            lifecycle_state = "awaiting_finding_review"
            next_action_id = "review_finding"
            blockers = ["finding disposition is unreviewed"]
        else:
            lifecycle_state = "outside_accepted_assurance_scope"
            next_action_id = "none"
            blockers = [
                f"finding disposition {disposition!r} is outside the accepted assurance workflow"
            ]
        owner_present = any(
            entity_id.startswith(("finding_owner:", "assurance_owner:"))
            for entity_id in assignment_entity_ids
        )
        reviewer_present = any(
            entity_id.startswith(("finding_reviewer:", "assurance_reviewer:"))
            for entity_id in assignment_entity_ids
        )
        latest_execution = finding_executions[-1] if finding_executions else {}
        passing_execution = str(latest_execution.get("status", "")) == "passed"
        independently_reviewed_execution = bool(latest_execution.get("reviews"))
        readiness_gaps: set[str] = set()
        if (
            disposition == "accepted"
            and item.get("source_status", "active") == "active"
            and lifecycle_state != "resolved"
        ):
            if not owner_present:
                readiness_gaps.add("accepted_finding_without_owner")
            if not reviewer_present:
                readiness_gaps.add("accepted_finding_without_reviewer")
            if review.get("revalidation_required"):
                readiness_gaps.add("accepted_finding_requires_revalidation")
            if not test_candidate_entity_ids and not implementation_registered:
                readiness_gaps.add("accepted_finding_without_test_candidate")
            if not implementation_registered:
                readiness_gaps.add(
                    "accepted_finding_without_registered_implementation"
                )
            if implementation_registered and not finding_executions:
                readiness_gaps.add("implemented_test_without_execution")
            if str(latest_execution.get("status", "")) in {
                "failed",
                "timeout",
                "error",
            }:
                readiness_gaps.add("failed_or_incomplete_execution")
            if passing_execution and not independently_reviewed_execution:
                readiness_gaps.add(
                    "passing_execution_without_independent_review"
                )
            if (
                "sufficient" in evidence_statuses
                and not assurance_statuses & {"verified", "closed"}
            ):
                readiness_gaps.add(
                    "sufficient_evidence_without_terminal_verification"
                )
            if (
                coverage_entity_ids
                and not test_candidate_entity_ids
                and not implementation_registered
                and not finding_executions
            ):
                readiness_gaps.add(
                    "coverage_without_test_or_execution_evidence"
                )
        readiness_profile_raw_id = stable_id(
            "VERIFICATION-READINESS", finding_id
        )
        readiness_profile_entity = add_entity(
            "verification_readiness_profile",
            readiness_profile_raw_id,
            finding_id,
            authority="deterministic_assurance_evidence_readiness_projection",
            metadata={
                "lifecycle_state": lifecycle_state,
                "evidence_posture": evidence_posture,
                "next_action_id": next_action_id,
                "readiness_gaps": sorted(readiness_gaps),
            },
        )
        relation_id = add_relation(
            finding_entity,
            readiness_profile_entity,
            "has_verification_readiness_profile",
            "cross_reference",
            authority="deterministic_assurance_evidence_readiness_projection",
        )
        if relation_id in relationships:
            readiness_relationship_ids.add(relation_id)
        readiness_targets = {
            *test_candidate_entity_ids,
            *coverage_entity_ids,
            *implemented_test_entity_ids,
            *assignment_entity_ids,
            *(_entity_id("obligation", value) for value in obligation_ids),
            *(_entity_id("execution", value) for value in execution_ids),
            *(_entity_id("evidence", value) for value in evidence_ids),
        }
        for target_entity_id in sorted(readiness_targets):
            if target_entity_id not in entities:
                continue
            relation_id = add_relation(
                readiness_profile_entity,
                target_entity_id,
                "considers_readiness_evidence",
                "verification_readiness",
                authority="typed_reference_preserving_source_evidence_authority",
                metadata={"target_kind": target_entity_id.split(":", 1)[0]},
            )
            if relation_id in relationships:
                readiness_relationship_ids.add(relation_id)
        evidence_signals = {
            "finding_accepted": disposition == "accepted",
            "source_current": bool(
                item.get("source_status", "active") == "active"
                and not review.get("revalidation_required")
            ),
            "assigned_owner": owner_present,
            "named_reviewer": reviewer_present,
            "candidate_test_links": bool(test_candidate_entity_ids),
            "coverage_observation": bool(coverage_entity_ids),
            "implementation_registered": implementation_registered,
            "execution_recorded": bool(finding_executions),
            "passing_execution_recorded": passing_execution,
            "independent_execution_review": independently_reviewed_execution,
            "evidence_artifact_recorded": bool(evidence_ids),
            "evidence_sufficient": "sufficient" in evidence_statuses,
            "terminal_verification": bool(
                assurance_statuses & {"verified", "closed"}
            ),
        }
        dimensions["verification_readiness"] = any(
            evidence_signals[field]
            for field in (
                "assigned_owner",
                "named_reviewer",
                "candidate_test_links",
                "coverage_observation",
                "implementation_registered",
                "execution_recorded",
                "evidence_artifact_recorded",
            )
        )
        readiness_profile = {
            "id": readiness_profile_entity,
            "finding_id": finding_id,
            "component_id": component_id,
            "source_status": str(item.get("source_status", "active")),
            "finding_disposition": disposition,
            "lifecycle_state": lifecycle_state,
            "next_action_id": next_action_id,
            "blockers": blockers,
            "evidence_posture": evidence_posture,
            "evidence_signals": evidence_signals,
            "readiness_gaps": sorted(readiness_gaps),
            "test_candidate_entity_ids": test_candidate_entity_ids,
            "coverage_entity_ids": coverage_entity_ids,
            "implemented_test_entity_ids": implemented_test_entity_ids,
            "assignment_entity_ids": sorted(assignment_entity_ids),
            "obligation_ids": obligation_ids,
            "execution_ids": sorted(execution_ids),
            "evidence_artifact_ids": sorted(evidence_ids),
            "relationship_ids": sorted(readiness_relationship_ids),
            "latest_execution_id": str(latest_execution.get("id", "")),
            "latest_execution_status": str(latest_execution.get("status", "")),
            "notice": (
                "Test references and coverage are candidate or observed-execution signals only. "
                "Only governed, current, reviewed evidence can support verification; execution "
                "evidence requires independent review. This profile does not approve work or "
                "accept risk."
            ),
        }
        verification_readiness_profiles.append(readiness_profile)
        diagnostic_entity_ids = sorted(
            set(diagnostic_entities_by_finding.get(finding_id, []))
        )
        diagnostic_records = diagnostic_records_by_finding.get(finding_id, [])
        diagnostic_counts = dict(
            sorted(
                Counter(
                    str(value.get("level", "unknown"))
                    for value in diagnostic_records
                ).items()
            )
        )
        blocking_diagnostic_entity_ids = sorted(
            {
                diagnostic_entity
                for diagnostic_entity, diagnostic in zip(
                    diagnostic_entities_by_finding.get(finding_id, []),
                    diagnostic_records,
                )
                if diagnostic.get("level") == "error"
                and diagnostic.get("rule_id") != "review.unreviewed"
            }
        )
        governance_state, governance_next_action = _review_governance_state(
            source_status=str(item.get("source_status", "active")),
            revalidation_required=bool(review.get("revalidation_required")),
            blocking_error_count=len(blocking_diagnostic_entity_ids),
            disposition=disposition,
            readiness_state=lifecycle_state,
            readiness_next_action=next_action_id,
        )
        governance_raw_id = stable_id("REVIEW-GOVERNANCE", finding_id)
        governance_profile_entity = add_entity(
            "review_governance_profile",
            governance_raw_id,
            finding_id,
            authority="deterministic_quality_gate_and_lifecycle_projection",
            metadata={
                "state": governance_state,
                "next_action_id": governance_next_action,
                "source_change": str(item.get("source_change", "")),
                "blocking_error_count": len(blocking_diagnostic_entity_ids),
            },
        )
        governance_relationship_ids: set[str] = set()
        relation_id = add_relation(
            finding_entity,
            governance_profile_entity,
            "has_review_governance_profile",
            "cross_reference",
            authority="deterministic_quality_gate_and_lifecycle_projection",
        )
        if relation_id in relationships:
            governance_relationship_ids.add(relation_id)
        for diagnostic_entity_id in diagnostic_entity_ids:
            relation_id = add_relation(
                governance_profile_entity,
                diagnostic_entity_id,
                "has_finding_quality_gate_diagnostic",
                "validation",
                authority="deterministic_finding_scope_quality_gate_diagnostic",
            )
            if relation_id in relationships:
                governance_relationship_ids.add(relation_id)
        governance_profile = {
            "id": governance_profile_entity,
            "finding_id": finding_id,
            "component_id": component_id,
            "source_status": str(item.get("source_status", "active")),
            "source_change": str(item.get("source_change", "")),
            "screening_priority": str(
                item.get("scanner", {}).get("screening_priority", "")
            ),
            "finding_disposition": disposition,
            "workflow_status": str(review.get("status", "draft")),
            "revalidation_required": bool(review.get("revalidation_required")),
            "state": governance_state,
            "next_action_id": governance_next_action,
            "readiness_profile_id": readiness_profile_entity,
            "diagnostic_entity_ids": diagnostic_entity_ids,
            "blocking_diagnostic_entity_ids": blocking_diagnostic_entity_ids,
            "diagnostic_counts": diagnostic_counts,
            "relationship_ids": sorted(governance_relationship_ids),
            "notice": (
                "Quality-gate diagnostics are deterministic workflow findings, not proof of a "
                "software failure. Global analysis-scope diagnostics remain separate from "
                "finding-local review state."
            ),
        }
        review_governance_profiles.append(governance_profile)
        dimensions["quality_governance"] = bool(
            diagnostic_entity_ids
            or review.get("revalidation_required")
            or item.get("source_change")
            or disposition != "unreviewed"
        )
        dimensions["cascade_analysis"] = bool(upstream_paths)
        dimensions["timing_and_resilience"] = bool(
            resilience_entity_ids or timing_relation_ids
        )
        finding_chains.append(
            {
                "finding_id": finding_id,
                "component_id": component_id,
                "source_status": item.get("source_status", "active"),
                "source_repository_artifact_entity_id": source_artifact_entity,
                "source_repository_artifact_entity_ids": sorted(
                    source_artifact_entities
                ),
                "source_configuration_input_entity_id": (
                    source_configuration_input_entity
                ),
                "source_repository_path": source_path,
                "source_repository_status": str(
                    source_artifact_record.get("status", "")
                    if len(source_artifact_entities) == 1
                    else "multiple"
                    if source_artifact_entities
                    else "configured"
                ),
                "source_analysis_depth": str(
                    source_artifact_record.get("analysis_depth", "")
                    if len(source_artifact_entities) == 1
                    else "aggregate_dependency_manifests"
                    if source_artifact_entities
                    else "project_configuration"
                ),
                "source_snapshot_sha256": str(
                    source_artifact_record.get("sha256", "")
                    if len(source_artifact_entities) == 1
                    else configuration_digest
                    if source_configuration_input_entity
                    else ""
                ),
                "source_adapter_ids": source_adapter_ids,
                "source_provenance_relationship_ids": sorted(
                    source_provenance_relationship_ids
                ),
                "requirement_ids": requirements,
                "hazard_ids": hazards,
                "citation_ids": citation_ids,
                "obligation_ids": obligation_ids,
                "evidence_artifact_ids": sorted(evidence_ids),
                "execution_ids": sorted(execution_ids),
                "sfta_event_ids": sorted(
                    set(sfta_nodes_by_finding.get(finding_id, []))
                ),
                "cascade_component_ids": cascade_component_ids,
                "cascade_paths": upstream_paths,
                "cascade_path_analysis": (
                    scanner.get("upstream_path_analysis", {})
                    if isinstance(scanner.get("upstream_path_analysis"), dict)
                    else {}
                ),
                "resilience_entity_ids": resilience_entity_ids,
                "timing_relationship_ids": timing_relation_ids,
                "verification_readiness_profile_id": readiness_profile_entity,
                "test_candidate_entity_ids": test_candidate_entity_ids,
                "coverage_entity_ids": coverage_entity_ids,
                "implemented_test_entity_ids": implemented_test_entity_ids,
                "assignment_entity_ids": sorted(assignment_entity_ids),
                "readiness_relationship_ids": sorted(readiness_relationship_ids),
                "verification_lifecycle_state": lifecycle_state,
                "verification_evidence_posture": evidence_posture,
                "verification_next_action_id": next_action_id,
                "verification_readiness_gaps": sorted(readiness_gaps),
                "review_governance_profile_id": governance_profile_entity,
                "quality_diagnostic_entity_ids": diagnostic_entity_ids,
                "blocking_quality_diagnostic_entity_ids": (
                    blocking_diagnostic_entity_ids
                ),
                "review_governance_relationship_ids": sorted(
                    governance_relationship_ids
                ),
                "review_governance_state": governance_state,
                "review_next_action_id": governance_next_action,
                "quality_diagnostic_counts": diagnostic_counts,
                "source_change": str(item.get("source_change", "")),
                "revalidation_required": bool(review.get("revalidation_required")),
                "dimensions": dimensions,
                "linkage_completeness_percent": round(
                    100 * sum(dimensions.values()) / len(dimensions), 1
                ),
                "notice": (
                    "Linkage completeness measures populated relationship dimensions; "
                    "it is not risk acceptance, verification success, or compliance."
                ),
            }
        )

    reconciliation = analysis.get("interface_reconciliation", {})
    server_routes = {
        str(value.get("id", "")): value
        for value in reconciliation.get("server_routes", [])
        if isinstance(value, dict) and value.get("id")
    }
    clients = {
        str(value.get("id", "")): value
        for value in reconciliation.get("client_endpoints", [])
        if isinstance(value, dict) and value.get("id")
    }
    for route_id, route in server_routes.items():
        route_entity = add_entity(
            "server_route",
            route_id,
            route.get("normalized_path") or route_id,
            authority="repository_static_analysis",
        )
        component_id = str(route.get("component_id", ""))
        if component_id in components:
            add_relation(
                route_entity,
                _entity_id("component", component_id),
                "implemented_by_component",
                "interface_reconciliation",
                authority="repository_static_analysis",
            )
    for client_id, client in clients.items():
        add_entity(
            "client_endpoint",
            client_id,
            client.get("normalized_path") or client.get("literal") or client_id,
            authority="bounded_literal_analysis",
        )
    for match in reconciliation.get("matches", []):
        if not isinstance(match, dict):
            continue
        client_id = str(match.get("client_endpoint_id", ""))
        route_id = str(match.get("server_route_id", ""))
        if client_id in clients and route_id in server_routes:
            add_relation(
                _entity_id("client_endpoint", client_id),
                _entity_id("server_route", route_id),
                "matches_server_route",
                "interface_reconciliation",
                authority="exact_normalized_static_path_match",
            )

    inbound_fusions: dict[str, list[str]] = defaultdict(list)
    outbound_fusions: dict[str, list[str]] = defaultdict(list)
    for fusion in fusions:
        inbound_fusions[fusion["target_component_id"]].append(fusion["id"])
        outbound_fusions[fusion["source_component_id"]].append(fusion["id"])
    routes_by_component: dict[str, list[str]] = defaultdict(list)
    clients_by_route: dict[str, list[str]] = defaultdict(list)
    for route_id, route in server_routes.items():
        component_id = str(route.get("component_id", ""))
        if component_id:
            routes_by_component[component_id].append(
                _entity_id("server_route", route_id)
            )
    for match in reconciliation.get("matches", []):
        if (
            isinstance(match, dict)
            and match.get("server_route_id")
            and match.get("client_endpoint_id")
        ):
            clients_by_route[str(match["server_route_id"])].append(
                _entity_id("client_endpoint", match["client_endpoint_id"])
            )
    for chain in finding_chains:
        component_id = chain["component_id"]
        route_entities = sorted(set(routes_by_component.get(component_id, [])))
        client_entities = sorted(
            {
                client_entity
                for route_entity in route_entities
                for client_entity in clients_by_route.get(
                    route_entity.removeprefix("server_route:"), []
                )
            }
        )
        chain["interface_entity_ids"] = [*route_entities, *client_entities]
        chain["inbound_fusion_ids"] = sorted(set(inbound_fusions.get(component_id, [])))
        chain["outbound_fusion_ids"] = sorted(
            set(outbound_fusions.get(component_id, []))
        )
        chain["dimensions"]["interfaces"] = bool(chain["interface_entity_ids"])
        chain["dimensions"]["component_relationships"] = bool(
            chain["inbound_fusion_ids"] or chain["outbound_fusion_ids"]
        )
        semantic_profile = semantic_profile_by_component.get(component_id)
        semantic_dimensions = (
            semantic_profile.get("dimensions", {})
            if isinstance(semantic_profile, dict)
            else {dimension: False for dimension in SEMANTIC_EXPOSURE_DIMENSIONS}
        )
        semantic_entity_ids = (
            [semantic_profile["id"], *semantic_profile.get("entity_ids", [])]
            if isinstance(semantic_profile, dict)
            else []
        )
        semantic_relationship_ids = (
            list(semantic_profile.get("relationship_ids", []))
            if isinstance(semantic_profile, dict)
            else []
        )
        chain["semantic_profile_id"] = (
            str(semantic_profile.get("id", ""))
            if isinstance(semantic_profile, dict)
            else ""
        )
        chain["semantic_dimensions"] = semantic_dimensions
        chain["semantic_entity_ids"] = sorted(set(semantic_entity_ids))
        chain["semantic_relationship_ids"] = sorted(
            set(semantic_relationship_ids)
        )
        chain["compound_exposure_kinds"] = _compound_exposure_kinds(
            semantic_dimensions, chain["dimensions"]
        )
        chain["dimensions"]["semantic_exposure"] = bool(
            semantic_profile
            and int(semantic_profile.get("populated_dimension_count", 0)) > 0
        )
        chain["linkage_completeness_percent"] = round(
            100 * sum(chain["dimensions"].values()) / len(chain["dimensions"]),
            1,
        )

    # Machine-generated suggestions and summaries remain non-authoritative claims, but their
    # provenance and deterministic lexical relationships are still useful review evidence.
    machine_suggestion_profiles: list[dict[str, Any]] = []
    machine_summary_profiles: list[dict[str, Any]] = []
    machine_assistance_relationship_ids: set[str] = set()
    machine_claim_relationship_ids: set[str] = set()
    machine_entities_by_finding: dict[str, set[str]] = defaultdict(set)
    machine_relationships_by_finding: dict[str, set[str]] = defaultdict(set)
    unresolved_machine_evidence_references: list[str] = []
    unresolved_machine_citation_references: list[str] = []
    unresolved_machine_entity_ids: set[str] = set()
    suggestion_entity_by_raw_id: dict[str, str] = {}
    finding_ids = {str(value.get("finding_id", "")) for value in finding_chains}

    def resolve_machine_evidence(raw_id: str) -> str:
        if raw_id in finding_ids:
            return _entity_id("finding", raw_id)
        if raw_id in components:
            return _entity_id("component", raw_id)
        return ""

    for suggestion in analysis.get("suggestions", []):
        if not isinstance(suggestion, dict) or not suggestion.get("id"):
            continue
        suggestion_id = str(suggestion["id"])
        component_id = str(suggestion.get("component_id", ""))
        provenance = suggestion.get("provenance", {})
        if not isinstance(provenance, dict):
            provenance = {}
        content = suggestion.get("content", {})
        if not isinstance(content, dict):
            content = {}
        suggestion_entity = add_entity(
            "machine_suggestion",
            suggestion_id,
            content.get("failure_mode") or suggestion_id,
            authority="machine_generated_claim_requires_human_review",
            metadata={
                "status": str(suggestion.get("status", "proposed")),
                "confidence": str(suggestion.get("confidence", "low")),
                "origin": str(suggestion.get("origin", "machine_suggestion")),
                "provider": str(provenance.get("provider", "")),
                "model": str(provenance.get("model", "")),
                "prompt_version": str(provenance.get("prompt_version", "")),
                "baseline_id": str(provenance.get("baseline_id", "")),
                "response_hash": str(provenance.get("response_hash", "")),
                "reviewer": str(suggestion.get("reviewer", "")),
            },
        )
        suggestion_entity_by_raw_id[suggestion_id] = suggestion_entity
        suggestion_relationship_id_set: set[str] = set()
        suggestion_evidence_entity_ids: set[str] = set()
        suggestion_citation_entity_ids: set[str] = set()
        suggestion_unresolved_evidence_ids: list[str] = []
        suggestion_unresolved_citation_ids: list[str] = []
        if component_id in components:
            relation_id = add_relation(
                suggestion_entity,
                _entity_id("component", component_id),
                "proposes_failure_mode_for",
                "machine_assistance",
                authority="machine_generated_claim_requires_human_review",
            )
            if relation_id in relationships:
                suggestion_relationship_id_set.add(relation_id)
                machine_assistance_relationship_ids.add(relation_id)
        for evidence_id in _text_values(suggestion.get("evidence_ids")):
            evidence_entity = resolve_machine_evidence(evidence_id)
            if not evidence_entity:
                suggestion_unresolved_evidence_ids.append(evidence_id)
                unresolved_machine_evidence_references.append(
                    f"{suggestion_id}:{evidence_id}"
                )
                unresolved_machine_entity_ids.add(suggestion_entity)
                continue
            suggestion_evidence_entity_ids.add(evidence_entity)
            relation_id = add_relation(
                suggestion_entity,
                evidence_entity,
                "grounded_in_supplied_evidence",
                "machine_assistance",
                authority="provider_selected_allowlisted_evidence_reference",
            )
            if relation_id in relationships:
                suggestion_relationship_id_set.add(relation_id)
                machine_assistance_relationship_ids.add(relation_id)
                if evidence_id in finding_ids:
                    machine_entities_by_finding[evidence_id].add(suggestion_entity)
                    machine_relationships_by_finding[evidence_id].add(relation_id)
        for citation_id in _text_values(suggestion.get("proposed_citation_ids")):
            citation_entity = _entity_id("citation", citation_id)
            if citation_entity not in entities:
                suggestion_unresolved_citation_ids.append(citation_id)
                unresolved_machine_citation_references.append(
                    f"{suggestion_id}:{citation_id}"
                )
                unresolved_machine_entity_ids.add(suggestion_entity)
                continue
            suggestion_citation_entity_ids.add(citation_entity)
            relation_id = add_relation(
                suggestion_entity,
                citation_entity,
                "proposes_guidance_reference",
                "machine_assistance",
                authority="machine_proposed_guidance_relevance_requires_human_review",
            )
            if relation_id in relationships:
                suggestion_relationship_id_set.add(relation_id)
                machine_assistance_relationship_ids.add(relation_id)
        materialized_finding_id = str(suggestion.get("materialized_item_id", ""))
        materialized_finding_entity = ""
        if materialized_finding_id in finding_ids:
            materialized_finding_entity = _entity_id(
                "finding", materialized_finding_id
            )
            relation_id = add_relation(
                suggestion_entity,
                materialized_finding_entity,
                "materialized_as_unreviewed_finding",
                "machine_assistance",
                authority="human_accepted_suggestion_preserving_machine_provenance",
            )
            if relation_id in relationships:
                suggestion_relationship_id_set.add(relation_id)
                machine_assistance_relationship_ids.add(relation_id)
                machine_entities_by_finding[materialized_finding_id].add(
                    suggestion_entity
                )
                machine_relationships_by_finding[materialized_finding_id].add(
                    relation_id
                )
        machine_suggestion_profiles.append(
            {
                "id": suggestion_entity,
                "suggestion_id": suggestion_id,
                "component_id": component_id,
                "status": str(suggestion.get("status", "proposed")),
                "confidence": str(suggestion.get("confidence", "low")),
                "evidence_entity_ids": sorted(suggestion_evidence_entity_ids),
                "citation_entity_ids": sorted(suggestion_citation_entity_ids),
                "materialized_finding_entity_id": materialized_finding_entity,
                "claim_relationship_ids": [],
                "relationship_ids": sorted(suggestion_relationship_id_set),
                "unresolved_evidence_ids": sorted(
                    set(suggestion_unresolved_evidence_ids)
                ),
                "unresolved_citation_ids": sorted(
                    set(suggestion_unresolved_citation_ids)
                ),
                "notice": (
                    "This is a machine-generated claim and evidence-link projection. Human "
                    "acceptance materializes an unreviewed finding; it does not approve the "
                    "claim, citation, risk, or evidence sufficiency."
                ),
            }
        )

    claim_entity_by_raw_id = {
        **{finding_id: _entity_id("finding", finding_id) for finding_id in finding_ids},
        **suggestion_entity_by_raw_id,
    }
    claim_relationships = suggestion_relationships(analysis)
    relation_kind_by_collection = {
        "duplicates": "lexically_duplicates_claim",
        "contradictions": "lexically_contradicts_claim",
        "divergences": "lexically_diverges_from_claim",
    }
    claim_relationships_by_suggestion: dict[str, set[str]] = defaultdict(set)
    claim_lead_subjects: dict[str, set[str]] = defaultdict(set)
    for collection, relation_kind in relation_kind_by_collection.items():
        for record in claim_relationships.get(collection, []):
            if not isinstance(record, dict):
                continue
            left_raw_id = str(record.get("left_id", ""))
            right_raw_id = str(record.get("right_id", ""))
            left_entity = claim_entity_by_raw_id.get(left_raw_id, "")
            right_entity = claim_entity_by_raw_id.get(right_raw_id, "")
            if not left_entity or not right_entity:
                continue
            field = str(record.get("field", "failure_mode"))
            relation_id = add_relation(
                left_entity,
                right_entity,
                relation_kind,
                f"machine_claim_comparison:{field}",
                authority="bounded_deterministic_lexical_comparison_review_lead",
                evidence_ids=_text_values(record.get("evidence_overlap")),
                metadata={
                    key: record[key]
                    for key in ("field", "similarity", "reason", "classification")
                    if key in record
                },
            )
            if relation_id not in relationships:
                continue
            machine_claim_relationship_ids.add(relation_id)
            machine_assistance_relationship_ids.add(relation_id)
            claim_lead_subjects[collection].update({left_entity, right_entity})
            for raw_id in (left_raw_id, right_raw_id):
                if raw_id in suggestion_entity_by_raw_id:
                    claim_relationships_by_suggestion[raw_id].add(relation_id)
                if raw_id in finding_ids:
                    other_entity = right_entity if raw_id == left_raw_id else left_entity
                    machine_entities_by_finding[raw_id].add(other_entity)
                    machine_relationships_by_finding[raw_id].add(relation_id)
    for profile in machine_suggestion_profiles:
        suggestion_id = str(profile["suggestion_id"])
        claim_relation_ids = claim_relationships_by_suggestion.get(
            suggestion_id, set()
        )
        profile["claim_relationship_ids"] = sorted(claim_relation_ids)
        profile["relationship_ids"] = sorted(
            {*_text_values(profile.get("relationship_ids")), *claim_relation_ids}
        )

    component_id_by_qualname = {
        str(component.get("qualname", "")): component_id
        for component_id, component in components.items()
        if component.get("qualname")
    }
    stale_machine_summary_entity_ids: set[str] = set()
    for summary_record in analysis.get("generated_summaries", []):
        if not isinstance(summary_record, dict) or not summary_record.get("id"):
            continue
        summary_id = str(summary_record["id"])
        group_by = str(summary_record.get("group_by", "project"))
        key = str(summary_record.get("key", ""))
        summary_entity = add_entity(
            "machine_summary",
            summary_id,
            summary_record.get("summary") or summary_id,
            authority="machine_generated_summary_requires_human_review",
            metadata={
                "group_by": group_by,
                "key": key,
                "stale": bool(summary_record.get("stale")),
                "provider": str(summary_record.get("provider", "")),
                "model": str(summary_record.get("model", "")),
                "prompt_version": str(summary_record.get("prompt_version", "")),
                "baseline_id": str(summary_record.get("baseline_id", "")),
                "response_hash": str(summary_record.get("response_hash", "")),
            },
        )
        if summary_record.get("stale"):
            stale_machine_summary_entity_ids.add(summary_entity)
        scope_entity = ""
        if group_by == "project":
            scope_entity = analysis_scope_entity
        elif group_by == "component":
            component_id = key if key in components else component_id_by_qualname.get(key, "")
            if component_id:
                scope_entity = _entity_id("component", component_id)
        elif group_by == "hazard" and _entity_id("hazard", key) in entities:
            scope_entity = _entity_id("hazard", key)
        elif group_by == "subsystem" and key:
            scope_entity = add_entity(
                "subsystem",
                key,
                key,
                authority="repository_static_subsystem_grouping",
            )
        summary_relationship_id_set: set[str] = set()
        if scope_entity:
            relation_id = add_relation(
                summary_entity,
                scope_entity,
                "summarizes_scope",
                "machine_assistance",
                authority="machine_generated_summary_requires_human_review",
            )
            if relation_id in relationships:
                summary_relationship_id_set.add(relation_id)
                machine_assistance_relationship_ids.add(relation_id)
        summary_evidence_entity_ids: set[str] = set()
        summary_unresolved_evidence_ids: list[str] = []
        for evidence_id in _text_values(summary_record.get("evidence_ids")):
            evidence_entity = resolve_machine_evidence(evidence_id)
            if not evidence_entity:
                summary_unresolved_evidence_ids.append(evidence_id)
                unresolved_machine_evidence_references.append(
                    f"{summary_id}:{evidence_id}"
                )
                unresolved_machine_entity_ids.add(summary_entity)
                continue
            summary_evidence_entity_ids.add(evidence_entity)
            relation_id = add_relation(
                summary_entity,
                evidence_entity,
                "summarizes_supplied_evidence",
                "machine_assistance",
                authority="provider_selected_allowlisted_evidence_reference",
            )
            if relation_id in relationships:
                summary_relationship_id_set.add(relation_id)
                machine_assistance_relationship_ids.add(relation_id)
                if evidence_id in finding_ids:
                    machine_entities_by_finding[evidence_id].add(summary_entity)
                    machine_relationships_by_finding[evidence_id].add(relation_id)
        machine_summary_profiles.append(
            {
                "id": summary_entity,
                "summary_id": summary_id,
                "group_by": group_by,
                "key": key,
                "stale": bool(summary_record.get("stale")),
                "scope_entity_id": scope_entity,
                "evidence_entity_ids": sorted(summary_evidence_entity_ids),
                "unresolved_evidence_ids": sorted(
                    set(summary_unresolved_evidence_ids)
                ),
                "relationship_ids": sorted(summary_relationship_id_set),
                "notice": (
                    "This narrative is machine generated from bounded evidence references. "
                    "It is not an engineering conclusion, approval, or risk-acceptance record."
                ),
            }
        )

    for chain in finding_chains:
        finding_id = str(chain.get("finding_id", ""))
        chain["machine_assistance_entity_ids"] = sorted(
            machine_entities_by_finding.get(finding_id, set())
        )
        chain["machine_assistance_relationship_ids"] = sorted(
            machine_relationships_by_finding.get(finding_id, set())
        )
        chain["dimensions"]["machine_assistance"] = bool(
            chain["machine_assistance_entity_ids"]
        )
        chain["linkage_completeness_percent"] = round(
            100 * sum(chain["dimensions"].values()) / len(chain["dimensions"]), 1
        )

    review_leads: list[dict[str, Any]] = []
    proposed_suggestion_entities = [
        profile["id"]
        for profile in machine_suggestion_profiles
        if profile.get("status") == "proposed"
    ]
    if proposed_suggestion_entities:
        review_leads.append(
            {
                "id": stable_id("XLEAD", "proposed_machine_suggestions"),
                "kind": "proposed_machine_suggestions",
                "priority": "medium",
                "subject_ids": proposed_suggestion_entities[:25],
                "affected_count": len(proposed_suggestion_entities),
                "subject_ids_omitted": max(0, len(proposed_suggestion_entities) - 25),
                "description": (
                    f"{len(proposed_suggestion_entities)} machine-generated suggestion(s) "
                    "await explicit human adjudication. Evidence and citations are proposed "
                    "links only and do not establish correctness or compliance."
                ),
            }
        )
    for collection, priority in (
        ("duplicates", "medium"),
        ("contradictions", "high"),
        ("divergences", "medium"),
    ):
        subjects = sorted(claim_lead_subjects.get(collection, set()))
        count = _safe_int(claim_relationships.get("summary", {}).get(collection, 0))
        if not count:
            continue
        review_leads.append(
            {
                "id": stable_id("XLEAD", "machine_claim_relationship", collection),
                "kind": f"machine_claim_{collection}",
                "priority": priority,
                "subject_ids": subjects[:25],
                "affected_count": count,
                "subject_ids_omitted": max(0, len(subjects) - 25),
                "description": (
                    f"Deterministic bounded lexical comparison identified {count} machine-"
                    f"assisted claim {collection}. Review the linked claims and source "
                    "evidence; lexical comparison does not determine which claim is correct."
                ),
            }
        )
    if stale_machine_summary_entity_ids:
        review_leads.append(
            {
                "id": stable_id("XLEAD", "stale_machine_summaries"),
                "kind": "stale_machine_summaries",
                "priority": "medium",
                "subject_ids": sorted(stale_machine_summary_entity_ids)[:25],
                "affected_count": len(stale_machine_summary_entity_ids),
                "subject_ids_omitted": max(
                    0, len(stale_machine_summary_entity_ids) - 25
                ),
                "description": (
                    "Machine-generated summaries marked stale must be regenerated or excluded "
                    "from current review decisions."
                ),
            }
        )
    unresolved_machine_entities = sorted(unresolved_machine_entity_ids)
    unresolved_machine_reference_count = len(unresolved_machine_evidence_references) + len(
        unresolved_machine_citation_references
    )
    if unresolved_machine_reference_count:
        review_leads.append(
            {
                "id": stable_id("XLEAD", "unresolved_machine_assistance_references"),
                "kind": "unresolved_machine_assistance_references",
                "priority": "high",
                "subject_ids": unresolved_machine_entities[:25],
                "affected_count": unresolved_machine_reference_count,
                "subject_ids_omitted": max(0, len(unresolved_machine_entities) - 25),
                "description": (
                    f"{unresolved_machine_reference_count} machine-assistance evidence or "
                    "citation reference(s) do not resolve to the governed fabric. Exclude them "
                    "from review decisions until their provenance is repaired."
                ),
            }
        )
    if opaque_repository_artifact_entity_ids:
        review_leads.append(
            {
                "id": stable_id("XLEAD", "opaque_repository_artifacts"),
                "kind": "repository_artifacts_without_semantic_analysis",
                "priority": "medium",
                "subject_ids": sorted(opaque_repository_artifact_entity_ids)[:25],
                "affected_count": len(opaque_repository_artifact_entity_ids),
                "subject_ids_omitted": max(
                    0, len(opaque_repository_artifact_entity_ids) - 25
                ),
                "description": (
                    f"{len(opaque_repository_artifact_entity_ids)} inventoried repository "
                    "artifact(s) have metadata-and-digest coverage but no registered semantic "
                    "analyzer. Confirm applicability or add a bounded analyzer; opacity is a "
                    "coverage condition, not evidence of a defect."
                ),
            }
        )
    if repository_inventory.get("truncated"):
        review_leads.append(
            {
                "id": stable_id("XLEAD", "repository_inventory_truncated"),
                "kind": "repository_inventory_truncated",
                "priority": "high",
                "subject_ids": [repository_inventory_entity],
                "affected_count": 1,
                "subject_ids_omitted": 0,
                "description": (
                    "The repository inventory reached a configured bound. Review the inventory "
                    "limits before treating source coverage as complete."
                ),
            }
        )
    if unaccounted_component_ids:
        review_leads.append(
            {
                "id": stable_id("XLEAD", "components_without_repository_provenance"),
                "kind": "components_without_repository_provenance",
                "priority": "high",
                "subject_ids": [
                    _entity_id("component", value)
                    for value in sorted(unaccounted_component_ids)[:25]
                ],
                "affected_count": len(unaccounted_component_ids),
                "subject_ids_omitted": max(0, len(unaccounted_component_ids) - 25),
                "description": (
                    f"{len(unaccounted_component_ids)} component(s) do not resolve to an "
                    "integrity-bound repository-inventory entry. Reconcile source paths and "
                    "inventory coverage before relying on their provenance."
                ),
            }
        )
    for fusion in fusions:
        if fusion["classification"] not in {
            "graphify_only_review_lead",
            "runtime_only_review_lead",
            "observed_graphify_gap",
        }:
            continue
        review_leads.append(
            {
                "id": stable_id("XLEAD", fusion["id"], fusion["classification"]),
                "kind": fusion["classification"],
                "priority": (
                    "high"
                    if fusion["classification"] == "observed_graphify_gap"
                    else "medium"
                ),
                "subject_ids": [
                    _entity_id("component", fusion["source_component_id"]),
                    _entity_id("component", fusion["target_component_id"]),
                ],
                "description": (
                    "Independent relationship channels disagree with the native AST call graph; "
                    "review dynamic dispatch, mapping accuracy, and scanner coverage."
                ),
            }
        )
    for value in reconciliation.get("compatibility_findings", []):
        if not isinstance(value, dict):
            continue
        subject_id = _entity_id("client_endpoint", value.get("client_endpoint_id", ""))
        review_leads.append(
            {
                "id": str(
                    value.get("id")
                    or stable_id("XLEAD", json.dumps(value, sort_keys=True))
                ),
                "kind": "interface_compatibility_gap",
                "priority": "medium",
                "subject_ids": [subject_id] if subject_id in entities else [],
                "description": str(
                    value.get("notice")
                    or "Static client/server interface compatibility requires review."
                ),
            }
        )
    dimension_priorities = {
        "component": "high",
        "source_provenance": "high",
        "guidance": "medium",
        "verification": "medium",
        "evidence": "low",
        "requirements": "low",
        "hazards": "low",
        "sfta": "low",
        "interfaces": "low",
        "component_relationships": "low",
        "cascade_analysis": "low",
        "timing_and_resilience": "low",
        "semantic_exposure": "low",
        "verification_readiness": "low",
    }
    for dimension, priority in dimension_priorities.items():
        affected = [
            value
            for value in finding_chains
            if value.get("source_status", "active") == "active"
            and not value.get("dimensions", {}).get(dimension, False)
        ]
        if not affected:
            continue
        review_leads.append(
            {
                "id": stable_id("XLEAD", "finding_chain_dimension", dimension),
                "kind": f"finding_chain_missing_{dimension}",
                "priority": priority,
                "subject_ids": [
                    _entity_id("finding", value["finding_id"])
                    for value in affected[:25]
                ],
                "affected_count": len(affected),
                "subject_ids_omitted": max(0, len(affected) - 25),
                "description": (
                    f"{len(affected)} finding chain(s) have no {dimension.replace('_', ' ')} "
                    "link. Confirm applicability and add governed traceability where required; "
                    "absence is not automatically a defect."
                ),
            }
        )
    compound_exposure_chains: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for chain in finding_chains:
        if chain.get("source_status", "active") != "active":
            continue
        for exposure_kind in _text_values(chain.get("compound_exposure_kinds")):
            compound_exposure_chains[exposure_kind].append(chain)
    for exposure_kind, affected in sorted(compound_exposure_chains.items()):
        review_leads.append(
            {
                "id": stable_id("XLEAD", "compound_semantic_exposure", exposure_kind),
                "kind": f"compound_semantic_exposure_{exposure_kind}",
                "priority": COMPOUND_EXPOSURE_PRIORITIES.get(exposure_kind, "medium"),
                "subject_ids": [
                    _entity_id("finding", chain["finding_id"])
                    for chain in affected[:25]
                ],
                "affected_count": len(affected),
                "subject_ids_omitted": max(0, len(affected) - 25),
                "description": (
                    f"{len(affected)} active finding chain(s) intersect the independently "
                    f"derived {exposure_kind.replace('_', ' ')} models. Review the exact "
                    "semantic record links; intersection is a prioritization lead, not proof "
                    "of reachability, causality, vulnerability, or failure."
                ),
            }
        )
    readiness_gap_profiles: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for profile in verification_readiness_profiles:
        for gap in _text_values(profile.get("readiness_gaps")):
            readiness_gap_profiles[gap].append(profile)
    for gap, affected in sorted(readiness_gap_profiles.items()):
        review_leads.append(
            {
                "id": stable_id("XLEAD", "verification_readiness_gap", gap),
                "kind": f"verification_readiness_gap_{gap}",
                "priority": READINESS_GAP_PRIORITIES.get(gap, "medium"),
                "subject_ids": [
                    _entity_id("finding", profile["finding_id"])
                    for profile in affected[:25]
                ],
                "affected_count": len(affected),
                "subject_ids_omitted": max(0, len(affected) - 25),
                "description": (
                    f"{len(affected)} accepted finding(s) have the verification-readiness "
                    f"gap {gap.replace('_', ' ')}. Follow the profile's exact lifecycle "
                    "state and next action; candidate tests or coverage do not constitute "
                    "verification evidence."
                ),
            }
        )
    quality_diagnostics_by_scope_rule: dict[
        tuple[str, str, str], list[dict[str, Any]]
    ] = defaultdict(list)
    for diagnostic in validation.get("findings", []):
        if not isinstance(diagnostic, dict):
            continue
        embedded_diagnostic_entity = diagnostic_entity_by_object_id.get(id(diagnostic))
        if not embedded_diagnostic_entity:
            continue
        level = str(diagnostic.get("level", ""))
        rule_id = str(diagnostic.get("rule_id", ""))
        finding_id = str(diagnostic.get("item_id", ""))
        if level not in {"error", "warning"} or not rule_id:
            continue
        if finding_id and rule_id == "review.unreviewed":
            continue
        scope = "finding" if finding_id else "analysis"
        quality_diagnostics_by_scope_rule[(scope, level, rule_id)].append(diagnostic)
    for (scope, level, rule_id), affected in sorted(
        quality_diagnostics_by_scope_rule.items()
    ):
        subject_ids = sorted(
            {
                (
                    _entity_id("finding", diagnostic.get("item_id", ""))
                    if diagnostic.get("item_id")
                    else diagnostic_entity_by_object_id[id(diagnostic)]
                )
                for diagnostic in affected
            }
        )
        review_leads.append(
            {
                "id": stable_id(
                    "XLEAD", "quality_gate_diagnostic", scope, level, rule_id
                ),
                "kind": f"quality_gate_{scope}_{rule_id}",
                "priority": "high" if level == "error" else "medium",
                "subject_ids": subject_ids[:25],
                "affected_count": len(affected),
                "subject_ids_omitted": max(0, len(subject_ids) - 25),
                "description": (
                    f"{len(affected)} {scope}-scope {level} diagnostic(s) use quality-gate "
                    f"rule {rule_id}. Resolve the governed workflow condition; the diagnostic "
                    "does not establish a software failure or control ineffectiveness."
                ),
            }
        )
    sfta_reconciliation = sfta.get("reconciliation", {})
    for key, priority in (
        ("top_down_uncovered_events", "high"),
        ("bottom_up_unmapped_findings", "medium"),
        ("hazard_link_mismatches", "high"),
    ):
        values = [
            value
            for value in sfta_reconciliation.get(key, [])
            if isinstance(value, dict)
        ]
        if not values:
            continue
        subjects = sorted(
            {
                _entity_id("finding", value["finding_id"])
                for value in values
                if value.get("finding_id")
                and _entity_id("finding", value["finding_id"]) in entities
            }
        )
        review_leads.append(
            {
                "id": stable_id("XLEAD", "sfta_reconciliation", key),
                "kind": f"sfta_{key}",
                "priority": priority,
                "subject_ids": subjects[:25],
                "affected_count": len(values),
                "subject_ids_omitted": max(0, len(subjects) - 25),
                "description": (
                    f"{len(values)} SFTA {key.replace('_', ' ')} record(s) require "
                    "engineering review. The lead is aggregated; use the complete SFTA "
                    "reconciliation register for every record."
                ),
            }
        )
    review_leads.sort(
        key=lambda value: (
            {"high": 0, "medium": 1, "low": 2}.get(value["priority"], 3),
            value["kind"],
            value["id"],
        )
    )
    if len(review_leads) > MAX_REVIEW_LEADS:
        omitted["review_leads"] += len(review_leads) - MAX_REVIEW_LEADS
        review_leads = review_leads[:MAX_REVIEW_LEADS]

    entity_ids_by_raw_id: dict[str, list[str]] = defaultdict(list)
    for entity_id, entity in entities.items():
        entity_ids_by_raw_id[str(entity.get("raw_id", ""))].append(entity_id)
    adapter_provenance_profiles: list[dict[str, Any]] = []
    adapter_relationships_by_finding: dict[str, set[str]] = defaultdict(set)
    adapter_entities_by_finding: dict[str, set[str]] = defaultdict(set)
    adapter_statuses_by_finding: dict[str, dict[str, str]] = defaultdict(dict)
    all_adapter_relationship_ids = set(adapter_core_relationship_ids)
    for run in adapter_runs:
        adapter_id = str(run.get("adapter_id", ""))
        adapter_entity = adapter_run_entities_by_id.get(adapter_id, "")
        contribution_ids = sorted(
            set(_text_values(run.get("contribution_entity_ids")))
        )
        linked_relationship_ids: set[str] = set()
        linked_contribution_ids: set[str] = set()
        for contribution_id in contribution_ids:
            targets = sorted(set(entity_ids_by_raw_id.get(contribution_id, [])))
            for target_entity_id in targets:
                if target_entity_id == adapter_entity:
                    continue
                relation_id = add_relation(
                    adapter_entity,
                    target_entity_id,
                    "contributed_entity",
                    "adapter_ledger",
                    authority="integrity_bound_adapter_contribution_identity",
                    metadata={"contribution_entity_id": contribution_id},
                )
                if relation_id not in relationships:
                    continue
                linked_relationship_ids.add(relation_id)
                all_adapter_relationship_ids.add(relation_id)
                linked_contribution_ids.add(contribution_id)
                target_entity = entities[target_entity_id]
                if target_entity.get("kind") == "finding":
                    finding_id = str(target_entity.get("raw_id", ""))
                    adapter_relationships_by_finding[finding_id].add(relation_id)
                    adapter_entities_by_finding[finding_id].add(adapter_entity)
                    adapter_statuses_by_finding[finding_id][adapter_id] = str(
                        run.get("status", "")
                    )
        adapter_provenance_profiles.append(
            {
                "id": adapter_entity,
                "adapter_id": adapter_id,
                "status": str(run.get("status", "")),
                "contribution_entity_ids": contribution_ids,
                "linked_contribution_entity_ids": sorted(linked_contribution_ids),
                "unlinked_contribution_entity_ids": sorted(
                    set(contribution_ids) - linked_contribution_ids
                ),
                "relationship_ids": sorted(linked_relationship_ids),
                "notice": (
                    "Contribution identity proves only that the recorded adapter emitted the "
                    "normalized entity ID; it does not prove analytical correctness, coverage, "
                    "or independent verification."
                ),
            }
        )
    for chain in finding_chains:
        finding_id = str(chain.get("finding_id", ""))
        chain["adapter_run_entity_ids"] = sorted(
            adapter_entities_by_finding.get(finding_id, set())
        )
        chain["adapter_provenance_relationship_ids"] = sorted(
            adapter_relationships_by_finding.get(finding_id, set())
        )
        chain["adapter_statuses"] = dict(
            sorted(adapter_statuses_by_finding.get(finding_id, {}).items())
        )
        chain["dimensions"]["tool_provenance"] = bool(
            chain["adapter_run_entity_ids"]
        )
        chain["linkage_completeness_percent"] = round(
            100 * sum(chain["dimensions"].values()) / len(chain["dimensions"]), 1
        )

    entities_list = sorted(entities.values(), key=lambda value: value["id"])
    relationships_list = sorted(relationships.values(), key=lambda value: value["id"])
    finding_chains.sort(key=lambda value: value["finding_id"])
    verification_readiness_profiles.sort(key=lambda value: value["finding_id"])
    review_governance_profiles.sort(key=lambda value: value["finding_id"])
    adapter_provenance_profiles.sort(key=lambda value: value["adapter_id"])
    machine_suggestion_profiles.sort(key=lambda value: value["suggestion_id"])
    machine_summary_profiles.sort(key=lambda value: value["summary_id"])
    classification_counts = Counter(value["classification"] for value in fusions)
    validation_findings = [
        value
        for value in validation.get("findings", [])
        if isinstance(value, dict) and id(value) in diagnostic_entity_by_object_id
    ]
    global_validation_findings = [
        value for value in validation_findings if not value.get("item_id")
    ]
    result = {
        "format": CROSS_REFERENCE_FORMAT,
        "analysis_state_sha256": analysis_sha256,
        "baseline_id": analysis.get("project", {}).get("baseline", {}).get("id", ""),
        "authority": (
            "deterministic_cross_reference_projection; preserves each source channel's "
            "authority and does not establish completeness, compliance, or risk acceptance"
        ),
        "summary": {
            "entities": len(entities_list),
            "relationships": len(relationships_list),
            "component_relationship_fusions": len(fusions),
            "semantic_profiles": len(semantic_profiles),
            "semantic_profiles_with_records": sum(
                value["populated_dimension_count"] > 0 for value in semantic_profiles
            ),
            "verification_readiness_profiles": len(
                verification_readiness_profiles
            ),
            "verification_profiles_with_signals": sum(
                any(
                    value["evidence_signals"][field]
                    for field in (
                        "assigned_owner",
                        "named_reviewer",
                        "candidate_test_links",
                        "coverage_observation",
                        "implementation_registered",
                        "execution_recorded",
                        "evidence_artifact_recorded",
                    )
                )
                for value in verification_readiness_profiles
            ),
            "review_governance_profiles": len(review_governance_profiles),
            "quality_gate_diagnostics": len(validation_findings),
            "global_quality_gate_diagnostics": len(global_validation_findings),
            "profiles_with_blocking_quality_diagnostics": sum(
                bool(value["blocking_diagnostic_entity_ids"])
                for value in review_governance_profiles
            ),
            "adapter_runs": len(adapter_provenance_profiles),
            "findings_with_tool_provenance": sum(
                bool(value.get("adapter_run_entity_ids")) for value in finding_chains
            ),
            "adapter_contribution_relationships": sum(
                len(value["relationship_ids"])
                for value in adapter_provenance_profiles
            ),
            "unlinked_adapter_contributions": sum(
                len(value["unlinked_contribution_entity_ids"])
                for value in adapter_provenance_profiles
            ),
            "repository_artifacts": len(repository_artifact_entities_by_path),
            "semantically_analyzed_repository_artifacts": sum(
                value.get("status") == "analyzed"
                for value in repository_artifact_records_by_path.values()
            ),
            "opaque_repository_artifacts": len(
                opaque_repository_artifact_entity_ids
            ),
            "excluded_repository_regions": len(repository_region_entity_ids),
            "dependency_entities": len(dependency_entity_ids),
            "contract_entities": len(contract_entity_ids),
            "components_with_repository_provenance": (
                sum(
                    bool(component_source_artifact_entities.get(component_id))
                    for component_id in components
                )
            ),
            "findings_with_repository_provenance": sum(
                bool(value.get("source_repository_artifact_entity_id"))
                for value in finding_chains
            ),
            "configured_source_components": len(configured_component_ids),
            "configured_source_findings": sum(
                bool(value.get("source_configuration_input_entity_id"))
                for value in finding_chains
            ),
            "components_with_source_provenance": (
                len(components) - len(unaccounted_component_ids)
            ),
            "findings_with_source_provenance": sum(
                bool(value.get("dimensions", {}).get("source_provenance"))
                for value in finding_chains
            ),
            "repository_provenance_relationships": len(
                repository_provenance_relationship_ids
            ),
            "machine_suggestions": len(machine_suggestion_profiles),
            "proposed_machine_suggestions": sum(
                value.get("status") == "proposed"
                for value in machine_suggestion_profiles
            ),
            "machine_summaries": len(machine_summary_profiles),
            "stale_machine_summaries": len(stale_machine_summary_entity_ids),
            "machine_claim_relationships": len(machine_claim_relationship_ids),
            "machine_assistance_relationships": len(
                machine_assistance_relationship_ids
            ),
            "machine_assistance_unresolved_evidence_references": len(
                unresolved_machine_evidence_references
            ),
            "machine_assistance_unresolved_citation_references": len(
                unresolved_machine_citation_references
            ),
            "findings_with_machine_assistance": sum(
                bool(value.get("machine_assistance_entity_ids"))
                for value in finding_chains
            ),
            "compound_exposure_chains": sum(
                bool(value.get("compound_exposure_kinds"))
                for value in finding_chains
            ),
            "finding_chains": len(finding_chains),
            "active_finding_chains": sum(
                value.get("source_status", "active") == "active"
                for value in finding_chains
            ),
            "historical_finding_chains": sum(
                value.get("source_status", "active") != "active"
                for value in finding_chains
            ),
            "review_leads": len(review_leads),
            "runtime_observed_fusions": sum(
                value["runtime_observed"] for value in fusions
            ),
            "multi_source_fusions": sum(
                value["corroboration_count"] > 1 for value in fusions
            ),
            "classifications": dict(sorted(classification_counts.items())),
            "review_leads_by_kind": dict(
                sorted(Counter(value["kind"] for value in review_leads).items())
            ),
            "semantic_dimensions": dict(
                sorted(
                    Counter(
                        dimension
                        for profile in semantic_profiles
                        for dimension, populated in profile["dimensions"].items()
                        if populated
                    ).items()
                )
            ),
            "compound_exposures_by_kind": dict(
                sorted(
                    Counter(
                        exposure
                        for chain in finding_chains
                        for exposure in chain.get("compound_exposure_kinds", [])
                    ).items()
                )
            ),
            "verification_lifecycle_states": dict(
                sorted(
                    Counter(
                        value["lifecycle_state"]
                        for value in verification_readiness_profiles
                    ).items()
                )
            ),
            "verification_evidence_postures": dict(
                sorted(
                    Counter(
                        value["evidence_posture"]
                        for value in verification_readiness_profiles
                    ).items()
                )
            ),
            "verification_readiness_gaps": dict(
                sorted(
                    Counter(
                        gap
                        for value in verification_readiness_profiles
                        for gap in value["readiness_gaps"]
                    ).items()
                )
            ),
            "quality_diagnostics_by_level": dict(
                sorted(
                    Counter(
                        str(value.get("level", "unknown"))
                        for value in validation_findings
                    ).items()
                )
            ),
            "global_quality_diagnostics_by_level": dict(
                sorted(
                    Counter(
                        str(value.get("level", "unknown"))
                        for value in global_validation_findings
                    ).items()
                )
            ),
            "review_governance_states": dict(
                sorted(
                    Counter(
                        value["state"] for value in review_governance_profiles
                    ).items()
                )
            ),
            "source_change_states": dict(
                sorted(
                    Counter(
                        value["source_change"] or "unspecified"
                        for value in review_governance_profiles
                    ).items()
                )
            ),
            "adapter_run_statuses": dict(
                sorted(
                    Counter(
                        value["status"] for value in adapter_provenance_profiles
                    ).items()
                )
            ),
            "repository_artifact_statuses": dict(
                sorted(
                    Counter(
                        str(value.get("status", "unknown"))
                        for value in repository_artifact_records_by_path.values()
                    ).items()
                )
            ),
            "machine_suggestion_statuses": dict(
                sorted(
                    Counter(
                        value["status"] for value in machine_suggestion_profiles
                    ).items()
                )
            ),
            "machine_claim_relationship_types": dict(
                sorted(
                    Counter(
                        str(relationships[value].get("kind", ""))
                        for value in machine_claim_relationship_ids
                    ).items()
                )
            ),
            "omitted_by_bound": dict(sorted(omitted.items())),
        },
        "entities": entities_list,
        "relationships": relationships_list,
        "component_relationship_fusions": fusions,
        "semantic_profiles": semantic_profiles,
        "verification_readiness_profiles": verification_readiness_profiles,
        "quality_gate_projection": {
            "analysis_scope_entity_id": analysis_scope_entity,
            "global_diagnostic_entity_ids": sorted(
                set(global_diagnostic_entity_ids)
            ),
            "global_relationship_ids": sorted(
                set(global_diagnostic_relationship_ids)
            ),
            "global_diagnostic_counts": dict(
                sorted(
                    Counter(
                        str(value.get("level", "unknown"))
                        for value in global_validation_findings
                    ).items()
                )
            ),
            "analysis_gate_state": (
                "blocked"
                if any(value.get("level") == "error" for value in validation_findings)
                else "review_required"
                if any(
                    value.get("level") == "warning" for value in validation_findings
                )
                else "clear"
            ),
            "notice": (
                "Analysis-scope diagnostics govern handoff readiness and remain separate from "
                "finding-local review state. A clear quality gate proves workflow completeness "
                "only; it does not prove correctness, safety, or compliance."
            ),
        },
        "review_governance_profiles": review_governance_profiles,
        "adapter_provenance": {
            "run_manifest_entity_id": run_manifest_entity,
            "adapter_ledger_entity_id": adapter_ledger_entity,
            "adapter_run_profiles": adapter_provenance_profiles,
            "relationship_ids": sorted(all_adapter_relationship_ids),
            "notice": (
                "Adapter provenance binds normalized contribution identities to integrity-bound "
                "run records and the scan manifest. It does not establish analytical correctness, "
                "completeness, qualification, or independence."
            ),
        },
        "repository_provenance": {
            "repository_inventory_entity_id": repository_inventory_entity,
            "configuration_input_entity_id": configuration_input_entity,
            "repository_artifact_entity_ids": sorted(
                repository_artifact_entities_by_path.values()
            ),
            "repository_region_entity_ids": sorted(repository_region_entity_ids),
            "dependency_entity_ids": sorted(dependency_entity_ids),
            "contract_entity_ids": sorted(contract_entity_ids),
            "opaque_repository_artifact_entity_ids": sorted(
                opaque_repository_artifact_entity_ids
            ),
            "unaccounted_component_ids": sorted(unaccounted_component_ids),
            "unaccounted_finding_ids": sorted(unaccounted_finding_ids),
            "configured_component_ids": sorted(configured_component_ids),
            "configured_finding_ids": sorted(
                value["finding_id"]
                for value in finding_chains
                if value.get("source_configuration_input_entity_id")
            ),
            "relationship_ids": sorted(repository_provenance_relationship_ids),
            "inventory_truncated": bool(repository_inventory.get("truncated")),
            "notice": (
                "Repository provenance binds component and finding source paths to inventoried "
                "content digests and analyzer attribution. Indexed or opaque artifacts are "
                "accounted for but not semantically analyzed; the projection does not prove "
                "source completeness, dependency safety, or analytical correctness."
            ),
        },
        "machine_assistance_provenance": {
            "suggestion_profiles": machine_suggestion_profiles,
            "summary_profiles": machine_summary_profiles,
            "claim_relationship_ids": sorted(machine_claim_relationship_ids),
            "relationship_ids": sorted(machine_assistance_relationship_ids),
            "unresolved_evidence_references": sorted(
                set(unresolved_machine_evidence_references)
            ),
            "unresolved_citation_references": sorted(
                set(unresolved_machine_citation_references)
            ),
            "stale_summary_entity_ids": sorted(stale_machine_summary_entity_ids),
            "lexical_analysis": {
                "format": str(claim_relationships.get("format", "")),
                "summary": claim_relationships.get("summary", {}),
                "notice": str(claim_relationships.get("notice", "")),
            },
            "notice": (
                "Machine suggestions and summaries are untrusted, non-authoritative review "
                "aids. Links preserve supplied evidence, proposed guidance, human "
                "materialization, and bounded lexical comparisons without approving claims, "
                "risk, evidence sufficiency, or compliance."
            ),
        },
        "finding_chains": finding_chains,
        "review_leads": review_leads,
        "limitations": [
            "Static relationships can omit dynamic dispatch, generated code, and environment wiring.",
            "Runtime relationships describe imported observations only and do not prove path completeness or absence.",
            "Guidance links express relevance to a candidate; they do not assert noncompliance.",
            "Configured hazards, requirements, interfaces, and SFTA logic retain project-supplied authority.",
            "Cascade paths, retry amplification, literal timing budgets, and circuit-breaker models are bounded static candidates, not runtime causality, latency, or control-effectiveness proof.",
            "Semantic profiles join independently bounded static models by stable component identity; compound exposure leads are intersections for review, not proof of reachability, causality, vulnerability, or failure.",
            "Verification-readiness profiles keep textual test candidates, coverage observations, registered implementations, executions, evidence review, assignments, and lifecycle decisions distinct; no lower-authority signal is promoted to verification evidence.",
            "Review-governance profiles cross-reference deterministic quality diagnostics, source change, revalidation, disposition, and assurance next actions; diagnostics are workflow conditions, not software-failure evidence.",
            "Adapter provenance links normalized contribution identities to integrity-bound adapter runs and the run manifest; tool attribution does not establish correctness, completeness, qualification, or independence.",
            "Repository provenance links source paths, inventory snapshots, dependencies, contracts, components, and findings without promoting indexed or opaque artifacts to semantic-analysis evidence.",
            "Machine-assistance provenance preserves bounded suggestion, summary, evidence, citation, materialization, and lexical-comparison links; generated text and deterministic text similarity remain review aids, not authoritative engineering conclusions.",
            "Linkage completeness is an accounting measure, not verification success or risk acceptance.",
        ],
    }
    result["content_sha256"] = canonical_json_sha256(result)
    return result


def cross_reference_markdown(index: dict[str, Any]) -> str:
    """Render a concise human-readable companion to the complete JSON index."""

    summary = index.get("summary", {})
    lines = [
        "# Cross-reference evidence fabric",
        "",
        f"Analysis SHA-256: `{index.get('analysis_state_sha256', '')}`",
        f"Content SHA-256: `{index.get('content_sha256', '')}`",
        "",
        "## Coverage",
        "",
        "| Measure | Count |",
        "|---|---:|",
    ]
    for key in (
        "entities",
        "relationships",
        "component_relationship_fusions",
        "semantic_profiles",
        "semantic_profiles_with_records",
        "verification_readiness_profiles",
        "verification_profiles_with_signals",
        "review_governance_profiles",
        "quality_gate_diagnostics",
        "global_quality_gate_diagnostics",
        "profiles_with_blocking_quality_diagnostics",
        "adapter_runs",
        "findings_with_tool_provenance",
        "adapter_contribution_relationships",
        "unlinked_adapter_contributions",
        "repository_artifacts",
        "semantically_analyzed_repository_artifacts",
        "opaque_repository_artifacts",
        "excluded_repository_regions",
        "dependency_entities",
        "contract_entities",
        "components_with_repository_provenance",
        "findings_with_repository_provenance",
        "configured_source_components",
        "configured_source_findings",
        "components_with_source_provenance",
        "findings_with_source_provenance",
        "repository_provenance_relationships",
        "machine_suggestions",
        "proposed_machine_suggestions",
        "machine_summaries",
        "stale_machine_summaries",
        "machine_claim_relationships",
        "machine_assistance_relationships",
        "machine_assistance_unresolved_evidence_references",
        "machine_assistance_unresolved_citation_references",
        "findings_with_machine_assistance",
        "compound_exposure_chains",
        "finding_chains",
        "multi_source_fusions",
        "runtime_observed_fusions",
        "review_leads",
    ):
        lines.append(f"| {key.replace('_', ' ').title()} | {summary.get(key, 0)} |")
    lines.extend(
        [
            "",
            "## Relationship consensus",
            "",
            "| Classification | Count |",
            "|---|---:|",
        ]
    )
    for key, value in summary.get("classifications", {}).items():
        lines.append(f"| {key.replace('_', ' ')} | {value} |")
    lines.extend(
        [
            "",
            "## Semantic exposure coverage",
            "",
            "| Analyzer dimension | Component profiles |",
            "|---|---:|",
        ]
    )
    for key, value in summary.get("semantic_dimensions", {}).items():
        lines.append(f"| {key.replace('_', ' ')} | {value} |")
    lines.extend(
        [
            "",
            "## Compound exposure intersections",
            "",
            "| Intersection | Finding chains |",
            "|---|---:|",
        ]
    )
    for key, value in summary.get("compound_exposures_by_kind", {}).items():
        lines.append(f"| {key.replace('_', ' ')} | {value} |")
    lines.extend(
        [
            "",
            "## Verification readiness",
            "",
            "### Lifecycle states",
            "",
            "| State | Finding profiles |",
            "|---|---:|",
        ]
    )
    for key, value in summary.get("verification_lifecycle_states", {}).items():
        lines.append(f"| {key.replace('_', ' ')} | {value} |")
    lines.extend(
        [
            "",
            "### Evidence postures",
            "",
            "| Posture | Finding profiles |",
            "|---|---:|",
        ]
    )
    for key, value in summary.get("verification_evidence_postures", {}).items():
        lines.append(f"| {key.replace('_', ' ')} | {value} |")
    lines.extend(
        [
            "",
            "Textual test links and coverage observations remain candidate or observed-execution signals; they are not verification evidence.",
        ]
    )
    lines.extend(
        [
            "",
            "## Review governance",
            "",
            f"Analysis gate state: `{index.get('quality_gate_projection', {}).get('analysis_gate_state', 'unknown')}`",
            "",
            "### Finding governance states",
            "",
            "| State | Finding profiles |",
            "|---|---:|",
        ]
    )
    for key, value in summary.get("review_governance_states", {}).items():
        lines.append(f"| {key.replace('_', ' ')} | {value} |")
    lines.extend(
        [
            "",
            "### Quality diagnostics",
            "",
            "| Level | All diagnostics | Analysis-scope diagnostics |",
            "|---|---:|---:|",
        ]
    )
    diagnostic_levels = set(summary.get("quality_diagnostics_by_level", {})) | set(
        summary.get("global_quality_diagnostics_by_level", {})
    )
    for level in sorted(diagnostic_levels):
        lines.append(
            f"| {level} | {summary.get('quality_diagnostics_by_level', {}).get(level, 0)} "
            f"| {summary.get('global_quality_diagnostics_by_level', {}).get(level, 0)} |"
        )
    lines.extend(
        [
            "",
            "Quality diagnostics express workflow completeness and consistency; they do not establish software failure, safety, or compliance.",
        ]
    )
    lines.extend(
        [
            "",
            "## Tool provenance",
            "",
            "| Adapter run status | Runs |",
            "|---|---:|",
        ]
    )
    for key, value in summary.get("adapter_run_statuses", {}).items():
        lines.append(f"| {key.replace('_', ' ')} | {value} |")
    lines.extend(
        [
            "",
            "Adapter contribution identity provides traceable tool attribution; it does not establish analytical correctness, coverage, qualification, or independence.",
        ]
    )
    lines.extend(
        [
            "",
            "## Repository source provenance",
            "",
            "| Inventory status | Artifacts |",
            "|---|---:|",
        ]
    )
    for key, value in summary.get("repository_artifact_statuses", {}).items():
        lines.append(f"| {key.replace('_', ' ')} | {value} |")
    lines.extend(
        [
            "",
            "Source-path linkage preserves inventory status and content identity; indexed or opaque files are not promoted to semantic-analysis evidence.",
        ]
    )
    lines.extend(
        [
            "",
            "## Machine-assistance provenance",
            "",
            "| Suggestion status | Suggestions |",
            "|---|---:|",
        ]
    )
    for key, value in summary.get("machine_suggestion_statuses", {}).items():
        lines.append(f"| {key.replace('_', ' ')} | {value} |")
    lines.extend(
        [
            "",
            "| Lexical relationship | Relationships |",
            "|---|---:|",
        ]
    )
    for key, value in summary.get("machine_claim_relationship_types", {}).items():
        lines.append(f"| {key.replace('_', ' ')} | {value} |")
    lines.extend(
        [
            "",
            "Generated claims, narratives, citation proposals, and lexical similarity are review aids only; they cannot approve a finding, evidence, risk, or compliance conclusion.",
        ]
    )
    lines.extend(["", "## Prioritized review leads", ""])
    leads = index.get("review_leads", [])[:100]
    if not leads:
        lines.append("No cross-source discrepancies were projected.")
    else:
        lines.extend(
            ["| Priority | Kind | Subjects | Description |", "|---|---|---|---|"]
        )
        for value in leads:
            description = str(value.get("description", "")).replace("|", "\\|")
            subjects = ", ".join(value.get("subject_ids", [])).replace("|", "\\|")
            lines.append(
                f"| {value.get('priority', '')} | {value.get('kind', '')} | {subjects} | {description} |"
            )
    lines.extend(["", "## Interpretation limits", ""])
    lines.extend(f"- {value}" for value in index.get("limitations", []))
    lines.append("")
    return "\n".join(lines)


def export_cross_reference_index(
    analysis: dict[str, Any], destination: str | Path, *, format: str = "json"
) -> Path:
    """Publish the complete JSON index or its concise Markdown projection."""

    index = build_cross_reference_index(analysis)
    if format == "json":
        content = json.dumps(index, indent=2, ensure_ascii=False) + "\n"
    elif format == "markdown":
        content = cross_reference_markdown(index)
    else:
        raise ValueError("cross-reference export format must be json or markdown")
    return atomic_publish_text(
        destination,
        content,
        label=f"cross-reference {format} export",
    )


def verify_cross_reference_file(
    source: str | Path, *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Verify bounded fabric integrity, references, accounting, and optional regeneration."""

    checks: dict[str, bool | None] = {
        name: False for name in CROSS_REFERENCE_VERIFICATION_CHECKS
    }
    if analysis is None:
        checks["analysis_binding"] = None
        checks["exact_regeneration"] = None
    errors: list[dict[str, str]] = []

    def fail(code: str, message: str) -> None:
        errors.append({"code": code, "message": message})

    try:
        document = load_bounded_json_document(
            source,
            label="cross-reference evidence fabric",
            max_bytes=MAX_CROSS_REFERENCE_BYTES,
            max_depth=MAX_CROSS_REFERENCE_JSON_DEPTH,
            max_nodes=MAX_CROSS_REFERENCE_JSON_NODES,
        )
    except ValueError as exc:
        return {
            "format": CROSS_REFERENCE_VERIFICATION_FORMAT,
            "verifier": {"name": "PySFMEA", "version": __version__},
            "path": str(Path(source).absolute()),
            "valid": False,
            "status": "invalid",
            "binding_requested": analysis is not None,
            "binding_checked": False,
            "checks": checks,
            "failed_checks": [
                name for name, passed in checks.items() if passed is False
            ],
            "unchecked_checks": [
                name for name, passed in checks.items() if passed is None
            ],
            "errors": [
                {
                    "code": "cross_reference.ingestion_failed",
                    "message": str(exc),
                }
            ],
            "notice": (
                "Verification detects corruption, inconsistent references, and optional "
                "analysis drift; it does not establish completeness or compliance."
            ),
        }
    value = document.value
    if not isinstance(value, dict):
        fail("cross_reference.invalid_shape", "The fabric root must be an object.")
    else:
        checks["format"] = value.get("format") == CROSS_REFERENCE_FORMAT
        if not checks["format"]:
            fail(
                "cross_reference.unsupported_format",
                "The fabric format is unsupported.",
            )

        supplied_digest = value.get("content_sha256")
        canonical = dict(value)
        canonical.pop("content_sha256", None)
        checks["content_integrity"] = bool(
            isinstance(supplied_digest, str)
            and re.fullmatch(r"[0-9a-f]{64}", supplied_digest)
            and supplied_digest == canonical_json_sha256(canonical)
        )
        if not checks["content_integrity"]:
            fail(
                "cross_reference.content_digest_mismatch",
                "The fabric content does not match its declared SHA-256 digest.",
            )

        entities = value.get("entities")
        entity_ids = (
            [
                str(entity.get("id", ""))
                for entity in entities
                if isinstance(entity, dict)
            ]
            if isinstance(entities, list)
            else []
        )
        checks["entity_identity"] = bool(
            isinstance(entities, list)
            and len(entity_ids) == len(entities)
            and all(entity_ids)
            and len(entity_ids) == len(set(entity_ids))
        )
        if not checks["entity_identity"]:
            fail(
                "cross_reference.entity_identity_invalid",
                "Every entity must be an object with a unique non-empty ID.",
            )
        entity_id_set = set(entity_ids)
        entity_raw_ids_by_kind: dict[str, set[str]] = defaultdict(set)
        for entity in entities or []:
            if isinstance(entity, dict):
                entity_raw_ids_by_kind[str(entity.get("kind", ""))].add(
                    str(entity.get("raw_id", ""))
                )

        relationships = value.get("relationships")
        relationship_ids = (
            [
                str(relation.get("id", ""))
                for relation in relationships
                if isinstance(relation, dict)
            ]
            if isinstance(relationships, list)
            else []
        )
        checks["relationship_integrity"] = bool(
            isinstance(relationships, list)
            and len(relationship_ids) == len(relationships)
            and all(relationship_ids)
            and len(relationship_ids) == len(set(relationship_ids))
            and all(
                isinstance(relation, dict)
                and relation.get("source") in entity_id_set
                and relation.get("target") in entity_id_set
                for relation in relationships
            )
        )
        if not checks["relationship_integrity"]:
            fail(
                "cross_reference.relationship_integrity_invalid",
                "Relationships must have unique IDs and resolve to embedded entities.",
            )
        relationship_id_set = set(relationship_ids)

        fusions = value.get("component_relationship_fusions")
        fusion_ids = (
            [
                str(fusion.get("id", ""))
                for fusion in fusions
                if isinstance(fusion, dict)
            ]
            if isinstance(fusions, list)
            else []
        )
        component_ids = {
            str(entity.get("raw_id", ""))
            for entity in entities or []
            if isinstance(entity, dict) and entity.get("kind") == "component"
        }
        relationships_by_id = {
            str(relation.get("id", "")): relation
            for relation in relationships or []
            if isinstance(relation, dict) and relation.get("id")
        }
        checks["fusion_integrity"] = bool(
            isinstance(fusions, list)
            and len(fusion_ids) == len(fusions)
            and all(fusion_ids)
            and len(fusion_ids) == len(set(fusion_ids))
            and all(
                isinstance(fusion, dict)
                and fusion.get("source_component_id") in component_ids
                and fusion.get("target_component_id") in component_ids
                and bool(_text_values(fusion.get("channels")))
                and bool(_text_values(fusion.get("relationship_ids")))
                and set(_text_values(fusion.get("relationship_ids")))
                <= relationship_id_set
                and isinstance(fusion.get("channels"), list)
                and fusion.get("corroboration_count")
                == len(set(_text_values(fusion.get("channels"))))
                and fusion.get("runtime_observed")
                == ("runtime_observed" in _text_values(fusion.get("channels")))
                and fusion.get("classification")
                == _classification(set(_text_values(fusion.get("channels"))))
                and all(
                    relationships_by_id[relation_id].get("source")
                    == _entity_id("component", fusion.get("source_component_id", ""))
                    and relationships_by_id[relation_id].get("target")
                    == _entity_id("component", fusion.get("target_component_id", ""))
                    and relationships_by_id[relation_id].get("channel")
                    in set(_text_values(fusion.get("channels")))
                    for relation_id in _text_values(fusion.get("relationship_ids"))
                    if relation_id in relationships_by_id
                )
                for fusion in fusions
            )
        )
        if not checks["fusion_integrity"]:
            fail(
                "cross_reference.fusion_integrity_invalid",
                "Fusions must resolve component endpoints and channel relationships.",
            )
        fusion_id_set = set(fusion_ids)

        semantic_profiles = value.get("semantic_profiles")
        semantic_profile_ids = (
            [
                str(profile.get("id", ""))
                for profile in semantic_profiles
                if isinstance(profile, dict)
            ]
            if isinstance(semantic_profiles, list)
            else []
        )
        semantic_profile_entity_ids = {
            str(entity.get("id", ""))
            for entity in entities or []
            if isinstance(entity, dict) and entity.get("kind") == "semantic_profile"
        }
        checks["semantic_profile_integrity"] = bool(
            isinstance(semantic_profiles, list)
            and len(semantic_profile_ids) == len(semantic_profiles)
            and all(semantic_profile_ids)
            and len(semantic_profile_ids) == len(set(semantic_profile_ids))
            and set(semantic_profile_ids) == semantic_profile_entity_ids
            and all(
                isinstance(profile, dict)
                and profile.get("component_id") in component_ids
                and isinstance(profile.get("dimensions"), dict)
                and set(profile["dimensions"]) == set(SEMANTIC_EXPOSURE_DIMENSIONS)
                and all(
                    isinstance(profile["dimensions"][dimension], bool)
                    for dimension in SEMANTIC_EXPOSURE_DIMENSIONS
                )
                and profile.get("populated_dimension_count")
                == sum(bool(populated) for populated in profile["dimensions"].values())
                and isinstance(profile.get("entity_ids"), list)
                and set(_text_values(profile.get("entity_ids"))) <= entity_id_set
                and isinstance(profile.get("relationship_ids"), list)
                and set(_text_values(profile.get("relationship_ids")))
                <= relationship_id_set
                and all(
                    relationships_by_id[relation_id].get("source")
                    == _entity_id("component", profile.get("component_id", ""))
                    for relation_id in _text_values(profile.get("relationship_ids"))
                    if relation_id in relationships_by_id
                )
                for profile in semantic_profiles
            )
        )
        if not checks["semantic_profile_integrity"]:
            fail(
                "cross_reference.semantic_profile_integrity_invalid",
                "Semantic profiles must map one-to-one to components and resolve every bounded analyzer record.",
            )
        semantic_profile_id_set = set(semantic_profile_ids)
        semantic_profiles_by_id = {
            str(profile.get("id", "")): profile
            for profile in semantic_profiles or []
            if isinstance(profile, dict) and profile.get("id")
        }

        readiness_profiles = value.get("verification_readiness_profiles")
        readiness_profile_ids = (
            [
                str(profile.get("id", ""))
                for profile in readiness_profiles
                if isinstance(profile, dict)
            ]
            if isinstance(readiness_profiles, list)
            else []
        )
        readiness_profile_entity_ids = {
            str(entity.get("id", ""))
            for entity in entities or []
            if isinstance(entity, dict)
            and entity.get("kind") == "verification_readiness_profile"
        }
        finding_entity_ids = {
            str(entity.get("raw_id", ""))
            for entity in entities or []
            if isinstance(entity, dict) and entity.get("kind") == "finding"
        }
        entities_by_id = {
            str(entity.get("id", "")): entity
            for entity in entities or []
            if isinstance(entity, dict) and entity.get("id")
        }
        readiness_profiles_by_id = {
            str(profile.get("id", "")): profile
            for profile in readiness_profiles or []
            if isinstance(profile, dict) and profile.get("id")
        }
        finding_entities_by_raw_id = {
            str(entity.get("raw_id", "")): entity
            for entity in entities or []
            if isinstance(entity, dict) and entity.get("kind") == "finding"
        }

        repository_provenance = value.get("repository_provenance")
        repository_provenance_data = (
            repository_provenance
            if isinstance(repository_provenance, dict)
            else {}
        )
        repository_inventory_entity_ids = {
            entity_id
            for entity_id, entity in entities_by_id.items()
            if entity.get("kind") == "repository_inventory"
        }
        repository_artifact_entity_ids = {
            entity_id
            for entity_id, entity in entities_by_id.items()
            if entity.get("kind") == "repository_artifact"
        }
        repository_region_entity_ids = {
            entity_id
            for entity_id, entity in entities_by_id.items()
            if entity.get("kind") == "repository_region"
        }
        dependency_entity_id_set = {
            entity_id
            for entity_id, entity in entities_by_id.items()
            if entity.get("kind") == "dependency"
        }
        contract_entity_id_set = {
            entity_id
            for entity_id, entity in entities_by_id.items()
            if entity.get("kind") == "contract"
        }
        configuration_input_entity_ids = {
            entity_id
            for entity_id, entity in entities_by_id.items()
            if entity.get("kind") == "configuration_input"
        }
        repository_channel_relationship_ids = {
            relation_id
            for relation_id, relation in relationships_by_id.items()
            if relation.get("channel")
            in {
                "repository_inventory",
                "dependency_inventory",
                "contract_inventory",
                "analysis_input",
            }
        }
        declared_repository_relationship_ids = (
            set(_text_values(repository_provenance.get("relationship_ids")))
            if isinstance(repository_provenance, dict)
            else set()
        )
        opaque_entity_ids = {
            entity_id
            for entity_id in repository_artifact_entity_ids
            if entities_by_id[entity_id].get("metadata", {}).get("status")
            == "opaque"
        }
        inventory_entity_id = (
            str(repository_provenance.get("repository_inventory_entity_id", ""))
            if isinstance(repository_provenance, dict)
            else ""
        )
        configuration_input_entity_id = (
            str(repository_provenance.get("configuration_input_entity_id", ""))
            if isinstance(repository_provenance, dict)
            else ""
        )
        repository_entity_records_valid = all(
            entity.get("raw_id") == entity.get("metadata", {}).get("path")
            and isinstance(entity.get("metadata", {}).get("size"), int)
            and entity.get("metadata", {}).get("size", -1) >= 0
            and isinstance(entity.get("metadata", {}).get("adapter_ids"), list)
            for entity in (
                entities_by_id[entity_id]
                for entity_id in repository_artifact_entity_ids
            )
        )
        configuration_entity_record_valid = bool(
            not configuration_input_entity_id
            or (
                entities_by_id.get(configuration_input_entity_id, {}).get("kind")
                == "configuration_input"
                and (
                    (
                        entities_by_id[configuration_input_entity_id]
                        .get("metadata", {})
                        .get("sha256")
                        == entities_by_id[configuration_input_entity_id].get("raw_id")
                        and re.fullmatch(
                            r"[0-9a-f]{64}",
                            str(
                                entities_by_id[configuration_input_entity_id]
                                .get("metadata", {})
                                .get("sha256", "")
                            ),
                        )
                        is not None
                    )
                    if entities_by_id[configuration_input_entity_id]
                    .get("metadata", {})
                    .get("sha256")
                    else bool(
                        entities_by_id[configuration_input_entity_id].get("raw_id")
                    )
                )
            )
        )
        repository_relationship_shapes_valid = all(
            (
                relation.get("kind") == "has_repository_inventory"
                and relation.get("target") == inventory_entity_id
                and entities_by_id.get(str(relation.get("source")), {}).get("kind")
                == "analysis_scope"
            )
            or (
                relation.get("kind") == "accounts_for_repository_artifact"
                and relation.get("source") == inventory_entity_id
                and relation.get("target") in repository_artifact_entity_ids
            )
            or (
                relation.get("kind") == "excludes_repository_region"
                and relation.get("source") == inventory_entity_id
                and relation.get("target") in repository_region_entity_ids
            )
            or (
                relation.get("kind") == "defined_in_repository_artifact"
                and entities_by_id.get(str(relation.get("source")), {}).get("kind")
                == "component"
                and relation.get("target") in repository_artifact_entity_ids
            )
            or (
                relation.get("kind") == "originates_from_repository_artifact"
                and entities_by_id.get(str(relation.get("source")), {}).get("kind")
                == "finding"
                and relation.get("target") in repository_artifact_entity_ids
            )
            or (
                relation.get("kind") == "declared_by_repository_artifact"
                and entities_by_id.get(str(relation.get("source")), {}).get("kind")
                in {"dependency", "contract"}
                and relation.get("target") in repository_artifact_entity_ids
            )
            or (
                relation.get("kind") == "binds_configuration_input"
                and entities_by_id.get(str(relation.get("source")), {}).get("kind")
                == "run_manifest"
                and relation.get("target") == configuration_input_entity_id
            )
            or (
                relation.get("kind") == "configured_by_analysis_input"
                and entities_by_id.get(str(relation.get("source")), {}).get("kind")
                == "component"
                and relation.get("target") == configuration_input_entity_id
            )
            or (
                relation.get("kind") == "originates_from_analysis_input"
                and entities_by_id.get(str(relation.get("source")), {}).get("kind")
                == "finding"
                and relation.get("target") == configuration_input_entity_id
            )
            for relation_id, relation in relationships_by_id.items()
            if relation_id in repository_channel_relationship_ids
        )
        relationship_configured_component_ids = {
            str(entities_by_id[str(relation.get("source"))].get("raw_id", ""))
            for relation in relationships_by_id.values()
            if relation.get("kind") == "configured_by_analysis_input"
            and str(relation.get("source")) in entities_by_id
        }
        relationship_configured_finding_ids = {
            str(entities_by_id[str(relation.get("source"))].get("raw_id", ""))
            for relation in relationships_by_id.values()
            if relation.get("kind") == "originates_from_analysis_input"
            and str(relation.get("source")) in entities_by_id
        }
        checks["repository_provenance_integrity"] = bool(
            isinstance(repository_provenance, dict)
            and len(repository_inventory_entity_ids) == 1
            and inventory_entity_id in repository_inventory_entity_ids
            and (
                (not configuration_input_entity_ids and not configuration_input_entity_id)
                or (
                    len(configuration_input_entity_ids) == 1
                    and configuration_input_entity_id
                    in configuration_input_entity_ids
                )
            )
            and set(
                _text_values(
                    repository_provenance.get("repository_artifact_entity_ids")
                )
            )
            == repository_artifact_entity_ids
            and set(
                _text_values(
                    repository_provenance.get("repository_region_entity_ids")
                )
            )
            == repository_region_entity_ids
            and set(_text_values(repository_provenance.get("dependency_entity_ids")))
            == dependency_entity_id_set
            and set(_text_values(repository_provenance.get("contract_entity_ids")))
            == contract_entity_id_set
            and set(
                _text_values(
                    repository_provenance.get(
                        "opaque_repository_artifact_entity_ids"
                    )
                )
            )
            == opaque_entity_ids
            and declared_repository_relationship_ids
            == repository_channel_relationship_ids
            and set(
                _text_values(repository_provenance.get("unaccounted_component_ids"))
            )
            <= component_ids
            and set(
                _text_values(repository_provenance.get("unaccounted_finding_ids"))
            )
            <= finding_entity_ids
            and set(
                _text_values(repository_provenance.get("configured_component_ids"))
            )
            == relationship_configured_component_ids
            and set(
                _text_values(repository_provenance.get("configured_finding_ids"))
            )
            == relationship_configured_finding_ids
            and set(
                _text_values(repository_provenance.get("configured_component_ids"))
            ).isdisjoint(
                _text_values(repository_provenance.get("unaccounted_component_ids"))
            )
            and set(
                _text_values(repository_provenance.get("configured_finding_ids"))
            ).isdisjoint(
                _text_values(repository_provenance.get("unaccounted_finding_ids"))
            )
            and isinstance(repository_provenance.get("inventory_truncated"), bool)
            and repository_entity_records_valid
            and configuration_entity_record_valid
            and repository_relationship_shapes_valid
        )
        if not checks["repository_provenance_integrity"]:
            fail(
                "cross_reference.repository_provenance_integrity_invalid",
                "Repository provenance must reconcile the inventory, artifact, source, dependency, contract, and exclusion relationships.",
            )

        machine_assistance = value.get("machine_assistance_provenance")
        machine_assistance_data = (
            machine_assistance if isinstance(machine_assistance, dict) else {}
        )
        suggestion_profiles = machine_assistance_data.get("suggestion_profiles")
        summary_profiles = machine_assistance_data.get("summary_profiles")
        machine_suggestion_entity_ids = {
            entity_id
            for entity_id, entity in entities_by_id.items()
            if entity.get("kind") == "machine_suggestion"
        }
        machine_summary_entity_ids = {
            entity_id
            for entity_id, entity in entities_by_id.items()
            if entity.get("kind") == "machine_summary"
        }
        machine_channel_relationship_ids = {
            relation_id
            for relation_id, relation in relationships_by_id.items()
            if relation.get("channel") == "machine_assistance"
            or str(relation.get("channel", "")).startswith(
                "machine_claim_comparison:"
            )
        }
        machine_claim_relation_ids = {
            relation_id
            for relation_id in machine_channel_relationship_ids
            if relationships_by_id[relation_id].get("kind")
            in {
                "lexically_duplicates_claim",
                "lexically_contradicts_claim",
                "lexically_diverges_from_claim",
            }
        }
        declared_machine_relationship_ids = set(
            _text_values(machine_assistance_data.get("relationship_ids"))
        )
        declared_claim_relationship_ids = set(
            _text_values(machine_assistance_data.get("claim_relationship_ids"))
        )

        def machine_suggestion_profile_valid(profile: object) -> bool:
            if not isinstance(profile, dict):
                return False
            entity_id = str(profile.get("id", ""))
            suggestion_id = str(profile.get("suggestion_id", ""))
            profile_relationship_ids = set(
                _text_values(profile.get("relationship_ids"))
            )
            expected_relationship_ids = {
                relation_id
                for relation_id in machine_channel_relationship_ids
                if relationships_by_id[relation_id].get("source") == entity_id
                or (
                    relation_id in machine_claim_relation_ids
                    and relationships_by_id[relation_id].get("target") == entity_id
                )
            }
            expected_evidence_entity_ids = {
                str(relationships_by_id[relation_id].get("target", ""))
                for relation_id in expected_relationship_ids
                if relationships_by_id[relation_id].get("kind")
                == "grounded_in_supplied_evidence"
            }
            expected_citation_entity_ids = {
                str(relationships_by_id[relation_id].get("target", ""))
                for relation_id in expected_relationship_ids
                if relationships_by_id[relation_id].get("kind")
                == "proposes_guidance_reference"
            }
            expected_materialized_entities = {
                str(relationships_by_id[relation_id].get("target", ""))
                for relation_id in expected_relationship_ids
                if relationships_by_id[relation_id].get("kind")
                == "materialized_as_unreviewed_finding"
            }
            expected_claim_relationship_ids = (
                expected_relationship_ids & machine_claim_relation_ids
            )
            materialized = str(profile.get("materialized_finding_entity_id", ""))
            metadata = entities_by_id.get(entity_id, {}).get("metadata", {})
            return bool(
                entity_id in machine_suggestion_entity_ids
                and entities_by_id[entity_id].get("raw_id") == suggestion_id
                and profile.get("component_id") in component_ids
                and metadata.get("status") == profile.get("status")
                and metadata.get("confidence") == profile.get("confidence")
                and set(_text_values(profile.get("evidence_entity_ids")))
                == expected_evidence_entity_ids
                and all(
                    entities_by_id[target].get("kind") in {"component", "finding"}
                    for target in _text_values(profile.get("evidence_entity_ids"))
                )
                and set(_text_values(profile.get("citation_entity_ids")))
                == expected_citation_entity_ids
                and all(
                    entities_by_id[target].get("kind") == "citation"
                    for target in _text_values(profile.get("citation_entity_ids"))
                )
                and (not materialized or materialized in entity_id_set)
                and (
                    not materialized
                    or entities_by_id[materialized].get("kind") == "finding"
                )
                and expected_materialized_entities
                == ({materialized} if materialized else set())
                and set(_text_values(profile.get("claim_relationship_ids")))
                == expected_claim_relationship_ids
                and profile_relationship_ids == expected_relationship_ids
                and all(
                    isinstance(raw_id, str) and raw_id
                    for raw_id in profile.get("unresolved_evidence_ids", [])
                )
                and all(
                    isinstance(raw_id, str) and raw_id
                    for raw_id in profile.get("unresolved_citation_ids", [])
                )
            )

        def machine_summary_profile_valid(profile: object) -> bool:
            if not isinstance(profile, dict):
                return False
            entity_id = str(profile.get("id", ""))
            summary_id = str(profile.get("summary_id", ""))
            scope_entity_id = str(profile.get("scope_entity_id", ""))
            profile_relationship_ids = set(
                _text_values(profile.get("relationship_ids"))
            )
            expected_relationship_ids = {
                relation_id
                for relation_id in machine_channel_relationship_ids
                if relationships_by_id[relation_id].get("source") == entity_id
            }
            expected_evidence_entity_ids = {
                str(relationships_by_id[relation_id].get("target", ""))
                for relation_id in expected_relationship_ids
                if relationships_by_id[relation_id].get("kind")
                == "summarizes_supplied_evidence"
            }
            expected_scope_entities = {
                str(relationships_by_id[relation_id].get("target", ""))
                for relation_id in expected_relationship_ids
                if relationships_by_id[relation_id].get("kind") == "summarizes_scope"
            }
            metadata = entities_by_id.get(entity_id, {}).get("metadata", {})
            return bool(
                entity_id in machine_summary_entity_ids
                and entities_by_id[entity_id].get("raw_id") == summary_id
                and profile.get("group_by")
                in {"project", "subsystem", "hazard", "component"}
                and metadata.get("group_by") == profile.get("group_by")
                and metadata.get("key") == profile.get("key")
                and metadata.get("stale") is profile.get("stale")
                and (not scope_entity_id or scope_entity_id in entity_id_set)
                and expected_scope_entities
                == ({scope_entity_id} if scope_entity_id else set())
                and set(_text_values(profile.get("evidence_entity_ids")))
                == expected_evidence_entity_ids
                and all(
                    entities_by_id[target].get("kind") in {"component", "finding"}
                    for target in _text_values(profile.get("evidence_entity_ids"))
                )
                and profile_relationship_ids == expected_relationship_ids
                and all(
                    isinstance(raw_id, str) and raw_id
                    for raw_id in profile.get("unresolved_evidence_ids", [])
                )
            )

        machine_relationship_shapes_valid = all(
            (
                relation.get("kind") == "proposes_failure_mode_for"
                and entities_by_id.get(str(relation.get("source")), {}).get("kind")
                == "machine_suggestion"
                and entities_by_id.get(str(relation.get("target")), {}).get("kind")
                == "component"
            )
            or (
                relation.get("kind") == "grounded_in_supplied_evidence"
                and entities_by_id.get(str(relation.get("source")), {}).get("kind")
                == "machine_suggestion"
                and entities_by_id.get(str(relation.get("target")), {}).get("kind")
                in {"component", "finding"}
            )
            or (
                relation.get("kind") == "proposes_guidance_reference"
                and entities_by_id.get(str(relation.get("source")), {}).get("kind")
                == "machine_suggestion"
                and entities_by_id.get(str(relation.get("target")), {}).get("kind")
                == "citation"
            )
            or (
                relation.get("kind") == "materialized_as_unreviewed_finding"
                and entities_by_id.get(str(relation.get("source")), {}).get("kind")
                == "machine_suggestion"
                and entities_by_id.get(str(relation.get("target")), {}).get("kind")
                == "finding"
            )
            or (
                relation.get("kind") == "summarizes_scope"
                and entities_by_id.get(str(relation.get("source")), {}).get("kind")
                == "machine_summary"
                and entities_by_id.get(str(relation.get("target")), {}).get("kind")
                in {"analysis_scope", "component", "hazard", "subsystem"}
            )
            or (
                relation.get("kind") == "summarizes_supplied_evidence"
                and entities_by_id.get(str(relation.get("source")), {}).get("kind")
                == "machine_summary"
                and entities_by_id.get(str(relation.get("target")), {}).get("kind")
                in {"component", "finding"}
            )
            or (
                relation.get("kind")
                in {
                    "lexically_duplicates_claim",
                    "lexically_contradicts_claim",
                    "lexically_diverges_from_claim",
                }
                and entities_by_id.get(str(relation.get("source")), {}).get("kind")
                in {"machine_suggestion", "finding"}
                and entities_by_id.get(str(relation.get("target")), {}).get("kind")
                in {"machine_suggestion", "finding"}
                and "machine_suggestion"
                in {
                    entities_by_id.get(str(relation.get("source")), {}).get("kind"),
                    entities_by_id.get(str(relation.get("target")), {}).get("kind"),
                }
            )
            for relation_id, relation in relationships_by_id.items()
            if relation_id in machine_channel_relationship_ids
        )
        expected_unresolved_evidence_references = {
            f"{profile.get('suggestion_id', '')}:{raw_id}"
            for profile in suggestion_profiles or []
            if isinstance(profile, dict)
            for raw_id in profile.get("unresolved_evidence_ids", [])
        } | {
            f"{profile.get('summary_id', '')}:{raw_id}"
            for profile in summary_profiles or []
            if isinstance(profile, dict)
            for raw_id in profile.get("unresolved_evidence_ids", [])
        }
        expected_unresolved_citation_references = {
            f"{profile.get('suggestion_id', '')}:{raw_id}"
            for profile in suggestion_profiles or []
            if isinstance(profile, dict)
            for raw_id in profile.get("unresolved_citation_ids", [])
        }
        expected_stale_summary_ids = {
            str(profile.get("id", ""))
            for profile in summary_profiles or []
            if isinstance(profile, dict) and profile.get("stale") is True
        }
        lexical_analysis = machine_assistance_data.get("lexical_analysis", {})
        lexical_summary = (
            lexical_analysis.get("summary", {})
            if isinstance(lexical_analysis, dict)
            else {}
        )
        checks["machine_assistance_integrity"] = bool(
            isinstance(machine_assistance, dict)
            and isinstance(suggestion_profiles, list)
            and isinstance(summary_profiles, list)
            and {str(profile.get("id", "")) for profile in suggestion_profiles if isinstance(profile, dict)}
            == machine_suggestion_entity_ids
            and {str(profile.get("id", "")) for profile in summary_profiles if isinstance(profile, dict)}
            == machine_summary_entity_ids
            and all(machine_suggestion_profile_valid(profile) for profile in suggestion_profiles)
            and all(machine_summary_profile_valid(profile) for profile in summary_profiles)
            and declared_machine_relationship_ids == machine_channel_relationship_ids
            and declared_claim_relationship_ids == machine_claim_relation_ids
            and set(
                machine_assistance_data.get("unresolved_evidence_references", [])
            )
            == expected_unresolved_evidence_references
            and set(
                machine_assistance_data.get("unresolved_citation_references", [])
            )
            == expected_unresolved_citation_references
            and set(_text_values(machine_assistance_data.get("stale_summary_entity_ids")))
            == expected_stale_summary_ids
            and isinstance(lexical_analysis, dict)
            and lexical_analysis.get("format")
            == "pysfmea-suggestion-relationships-1"
            and isinstance(lexical_summary, dict)
            and lexical_summary.get("claims")
            == sum(
                entity.get("metadata", {}).get("source_status", "active")
                == "active"
                for entity in finding_entities_by_raw_id.values()
            )
            + sum(
                profile.get("status") == "proposed"
                for profile in suggestion_profiles
                if isinstance(profile, dict)
            )
            and all(
                isinstance(count, int)
                and not isinstance(count, bool)
                and count >= 0
                for count in (
                    lexical_summary.get(name)
                    for name in ("duplicates", "contradictions", "divergences")
                )
            )
            and isinstance(lexical_summary.get("truncated"), bool)
            and machine_relationship_shapes_valid
        )
        if not checks["machine_assistance_integrity"]:
            fail(
                "cross_reference.machine_assistance_integrity_invalid",
                "Machine suggestions, summaries, evidence, citation, materialization, and lexical-comparison relationships must reconcile without promoting generated claims.",
            )
        verified_machine_entities_by_finding: dict[str, set[str]] = defaultdict(set)
        verified_machine_relationships_by_finding: dict[str, set[str]] = defaultdict(
            set
        )
        for relation_id in machine_channel_relationship_ids:
            relation = relationships_by_id[relation_id]
            source = str(relation.get("source", ""))
            target = str(relation.get("target", ""))
            source_kind = entities_by_id.get(source, {}).get("kind")
            target_kind = entities_by_id.get(target, {}).get("kind")
            if source_kind == "finding" and target_kind in {
                "machine_suggestion",
                "machine_summary",
            }:
                finding_id = str(entities_by_id[source].get("raw_id", ""))
                verified_machine_entities_by_finding[finding_id].add(target)
                verified_machine_relationships_by_finding[finding_id].add(
                    relation_id
                )
            elif target_kind == "finding" and source_kind in {
                "machine_suggestion",
                "machine_summary",
            }:
                finding_id = str(entities_by_id[target].get("raw_id", ""))
                verified_machine_entities_by_finding[finding_id].add(source)
                verified_machine_relationships_by_finding[finding_id].add(
                    relation_id
                )

        def readiness_profile_valid(profile: object) -> bool:
            if not isinstance(profile, dict):
                return False
            signals = profile.get("evidence_signals")
            finding_metadata = finding_entities_by_raw_id.get(
                str(profile.get("finding_id", "")), {}
            ).get("metadata", {})
            if not (
                profile.get("id") in readiness_profile_entity_ids
                and profile.get("finding_id") in finding_entity_ids
                and profile.get("component_id") in component_ids
                and isinstance(signals, dict)
                and set(signals) == set(VERIFICATION_EVIDENCE_SIGNAL_NAMES)
                and all(isinstance(signals[name], bool) for name in signals)
                and profile.get("evidence_posture")
                in VERIFICATION_EVIDENCE_POSTURES
                and profile.get("lifecycle_state")
                in VERIFICATION_READINESS_STATE_ACTIONS
                and profile.get("next_action_id")
                == VERIFICATION_READINESS_STATE_ACTIONS[
                    str(profile.get("lifecycle_state", ""))
                ]
                and set(_text_values(profile.get("readiness_gaps")))
                <= set(READINESS_GAP_PRIORITIES)
                and profile.get("source_status")
                == finding_metadata.get("source_status")
                and profile.get("finding_disposition")
                == finding_metadata.get("disposition")
            ):
                return False
            entity_fields = (
                "test_candidate_entity_ids",
                "coverage_entity_ids",
                "implemented_test_entity_ids",
                "assignment_entity_ids",
            )
            reference_fields = (
                "obligation_ids",
                "execution_ids",
                "evidence_artifact_ids",
                "relationship_ids",
            )
            if not all(
                isinstance(profile.get(field), list)
                for field in (*entity_fields, *reference_fields)
            ):
                return False
            expected_kinds = {
                "test_candidate_entity_ids": {"test_candidate"},
                "coverage_entity_ids": {"coverage_observation"},
                "implemented_test_entity_ids": {"implemented_test"},
                "assignment_entity_ids": {
                    "finding_owner",
                    "finding_reviewer",
                    "assurance_owner",
                    "assurance_reviewer",
                },
            }
            if any(
                any(
                    entity_id not in entities_by_id
                    or entities_by_id[entity_id].get("kind")
                    not in expected_kinds[field]
                    for entity_id in _text_values(profile.get(field))
                )
                for field in entity_fields
            ):
                return False
            obligation_ids = _text_values(profile.get("obligation_ids"))
            execution_ids = _text_values(profile.get("execution_ids"))
            evidence_ids = _text_values(profile.get("evidence_artifact_ids"))
            if not (
                set(obligation_ids) <= entity_raw_ids_by_kind["obligation"]
                and set(execution_ids) <= entity_raw_ids_by_kind["execution"]
                and set(evidence_ids) <= entity_raw_ids_by_kind["evidence"]
                and set(_text_values(profile.get("relationship_ids")))
                <= relationship_id_set
            ):
                return False
            latest_execution_id = str(profile.get("latest_execution_id", ""))
            if latest_execution_id and latest_execution_id not in execution_ids:
                return False
            execution_records = [
                entities_by_id[_entity_id("execution", execution_id)].get(
                    "metadata", {}
                )
                for execution_id in execution_ids
                if _entity_id("execution", execution_id) in entities_by_id
            ]
            if latest_execution_id:
                latest_metadata = entities_by_id[
                    _entity_id("execution", latest_execution_id)
                ].get("metadata", {})
                execution_records = [
                    value for value in execution_records if value is not latest_metadata
                ] + [latest_metadata]
            assurance_statuses = {
                str(
                    entities_by_id[_entity_id("obligation", obligation_id)]
                    .get("metadata", {})
                    .get("status", "")
                )
                for obligation_id in obligation_ids
                if _entity_id("obligation", obligation_id) in entities_by_id
            }
            evidence_statuses = {
                str(
                    entities_by_id[_entity_id("obligation", obligation_id)]
                    .get("metadata", {})
                    .get("evidence_status", "")
                )
                for obligation_id in obligation_ids
                if _entity_id("obligation", obligation_id) in entities_by_id
            }
            expected_posture = _verification_evidence_posture(
                assurance_statuses=assurance_statuses,
                evidence_statuses=evidence_statuses,
                implementation_registered=bool(
                    _text_values(profile.get("implemented_test_entity_ids"))
                ),
                candidate_tests=bool(
                    _text_values(profile.get("test_candidate_entity_ids"))
                ),
                coverage_observed=bool(
                    _text_values(profile.get("coverage_entity_ids"))
                ),
                executions=execution_records,
            )
            assigned_kinds = {
                str(entities_by_id[entity_id].get("kind", ""))
                for entity_id in _text_values(profile.get("assignment_entity_ids"))
                if entity_id in entities_by_id
            }
            expected_signals = {
                "finding_accepted": profile.get("finding_disposition") == "accepted",
                "source_current": bool(
                    profile.get("source_status", "active") == "active"
                    and profile.get("lifecycle_state") != "revalidation_required"
                ),
                "assigned_owner": bool(
                    assigned_kinds & {"finding_owner", "assurance_owner"}
                ),
                "named_reviewer": bool(
                    assigned_kinds & {"finding_reviewer", "assurance_reviewer"}
                ),
                "candidate_test_links": bool(
                    _text_values(profile.get("test_candidate_entity_ids"))
                ),
                "coverage_observation": bool(
                    _text_values(profile.get("coverage_entity_ids"))
                ),
                "implementation_registered": bool(
                    _text_values(profile.get("implemented_test_entity_ids"))
                ),
                "execution_recorded": bool(execution_ids),
                "passing_execution_recorded": bool(
                    execution_records
                    and execution_records[-1].get("status") == "passed"
                ),
                "independent_execution_review": bool(
                    execution_records
                    and execution_records[-1].get("independently_reviewed")
                ),
                "evidence_artifact_recorded": bool(evidence_ids),
                "evidence_sufficient": "sufficient" in evidence_statuses,
                "terminal_verification": bool(
                    assurance_statuses & {"verified", "closed"}
                ),
            }
            expected_gaps: set[str] = set()
            if (
                profile.get("finding_disposition") == "accepted"
                and profile.get("source_status", "active") == "active"
                and profile.get("lifecycle_state") != "resolved"
            ):
                if not expected_signals["assigned_owner"]:
                    expected_gaps.add("accepted_finding_without_owner")
                if not expected_signals["named_reviewer"]:
                    expected_gaps.add("accepted_finding_without_reviewer")
                if profile.get("lifecycle_state") == "revalidation_required":
                    expected_gaps.add("accepted_finding_requires_revalidation")
                if not (
                    expected_signals["candidate_test_links"]
                    or expected_signals["implementation_registered"]
                ):
                    expected_gaps.add("accepted_finding_without_test_candidate")
                if not expected_signals["implementation_registered"]:
                    expected_gaps.add(
                        "accepted_finding_without_registered_implementation"
                    )
                if (
                    expected_signals["implementation_registered"]
                    and not expected_signals["execution_recorded"]
                ):
                    expected_gaps.add("implemented_test_without_execution")
                if execution_records and execution_records[-1].get("status") in {
                    "failed",
                    "timeout",
                    "error",
                }:
                    expected_gaps.add("failed_or_incomplete_execution")
                if (
                    expected_signals["passing_execution_recorded"]
                    and not expected_signals["independent_execution_review"]
                ):
                    expected_gaps.add(
                        "passing_execution_without_independent_review"
                    )
                if (
                    expected_signals["evidence_sufficient"]
                    and not expected_signals["terminal_verification"]
                ):
                    expected_gaps.add(
                        "sufficient_evidence_without_terminal_verification"
                    )
                if (
                    expected_signals["coverage_observation"]
                    and not expected_signals["candidate_test_links"]
                    and not expected_signals["implementation_registered"]
                    and not expected_signals["execution_recorded"]
                ):
                    expected_gaps.add(
                        "coverage_without_test_or_execution_evidence"
                    )
            profile_relation = _relation_id(
                _entity_id("finding", profile.get("finding_id", "")),
                str(profile.get("id", "")),
                "has_verification_readiness_profile",
                "cross_reference",
            )
            component_finding_relation = _relation_id(
                _entity_id("component", profile.get("component_id", "")),
                _entity_id("finding", profile.get("finding_id", "")),
                "has_failure_mode",
                "sfmea",
            )
            readiness_target_entity_ids = {
                *(
                    entity_id
                    for field in entity_fields
                    for entity_id in _text_values(profile.get(field))
                ),
                *(_entity_id("obligation", value) for value in obligation_ids),
                *(_entity_id("execution", value) for value in execution_ids),
                *(_entity_id("evidence", value) for value in evidence_ids),
            }
            readiness_evidence_relations = {
                _relation_id(
                    str(profile.get("id", "")),
                    target_entity_id,
                    "considers_readiness_evidence",
                    "verification_readiness",
                )
                for target_entity_id in readiness_target_entity_ids
            }
            finding_obligation_relations = {
                _relation_id(
                    _entity_id("finding", profile.get("finding_id", "")),
                    _entity_id("obligation", obligation_id),
                    "generates_obligation",
                    "assurance_planner",
                )
                for obligation_id in obligation_ids
            }
            profile_relationship_ids = set(
                _text_values(profile.get("relationship_ids"))
            )
            return bool(
                signals == expected_signals
                and profile.get("readiness_gaps") == sorted(expected_gaps)
                and profile.get("evidence_posture") == expected_posture
                and profile.get("latest_execution_status", "")
                == (
                    str(execution_records[-1].get("status", ""))
                    if execution_records
                    else ""
                )
                and profile_relation
                in profile_relationship_ids
                and profile_relation in relationship_id_set
                and component_finding_relation in relationship_id_set
                and readiness_evidence_relations <= profile_relationship_ids
                and readiness_evidence_relations <= relationship_id_set
                and finding_obligation_relations <= relationship_id_set
            )

        checks["verification_readiness_integrity"] = bool(
            isinstance(readiness_profiles, list)
            and len(readiness_profile_ids) == len(readiness_profiles)
            and all(readiness_profile_ids)
            and len(readiness_profile_ids) == len(set(readiness_profile_ids))
            and set(readiness_profile_ids) == readiness_profile_entity_ids
            and {
                str(profile.get("finding_id", ""))
                for profile in readiness_profiles
                if isinstance(profile, dict)
            }
            == finding_entity_ids
            and all(readiness_profile_valid(profile) for profile in readiness_profiles)
        )
        if not checks["verification_readiness_integrity"]:
            fail(
                "cross_reference.verification_readiness_integrity_invalid",
                "Verification-readiness profiles must resolve their findings, lifecycle evidence, typed entities, and deterministic posture without promoting candidate signals.",
            )
        readiness_profile_id_set = set(readiness_profile_ids)

        quality_gate_projection = value.get("quality_gate_projection")
        governance_profiles = value.get("review_governance_profiles")
        governance_profile_ids = (
            [
                str(profile.get("id", ""))
                for profile in governance_profiles
                if isinstance(profile, dict)
            ]
            if isinstance(governance_profiles, list)
            else []
        )
        governance_profile_entity_ids = {
            str(entity.get("id", ""))
            for entity in entities or []
            if isinstance(entity, dict)
            and entity.get("kind") == "review_governance_profile"
        }
        quality_diagnostic_entity_ids = {
            str(entity.get("id", ""))
            for entity in entities or []
            if isinstance(entity, dict)
            and entity.get("kind") == "quality_gate_diagnostic"
        }
        governance_profiles_by_id = {
            str(profile.get("id", "")): profile
            for profile in governance_profiles or []
            if isinstance(profile, dict) and profile.get("id")
        }
        diagnostic_identity_groups: dict[tuple[str, str, str, str, str], list[int]] = (
            defaultdict(list)
        )
        diagnostic_identity_valid = True
        for diagnostic_id in quality_diagnostic_entity_ids:
            entity = entities_by_id.get(diagnostic_id, {})
            metadata_value = entity.get("metadata", {})
            occurrence = metadata_value.get("occurrence")
            if not isinstance(occurrence, int) or isinstance(occurrence, bool):
                diagnostic_identity_valid = False
                continue
            expected_raw_id = _quality_diagnostic_raw_id(
                metadata_value, occurrence=occurrence
            )
            if (
                entity.get("raw_id") != expected_raw_id
                or diagnostic_id
                != _entity_id("quality_gate_diagnostic", expected_raw_id)
                or metadata_value.get("level")
                not in {"error", "warning", "information"}
                or metadata_value.get("scope") not in {"analysis", "finding"}
            ):
                diagnostic_identity_valid = False
            identity_key = (
                str(metadata_value.get("rule_id", "")),
                str(metadata_value.get("level", "")),
                str(metadata_value.get("item_id", "")),
                str(metadata_value.get("field", "")),
                str(metadata_value.get("message", "")),
            )
            diagnostic_identity_groups[identity_key].append(occurrence)
        diagnostic_identity_valid = diagnostic_identity_valid and all(
            sorted(occurrences) == list(range(1, len(occurrences) + 1))
            for occurrences in diagnostic_identity_groups.values()
        )

        def governance_profile_valid(profile: object) -> bool:
            if not isinstance(profile, dict):
                return False
            profile_id = str(profile.get("id", ""))
            finding_id = str(profile.get("finding_id", ""))
            diagnostic_ids = _text_values(profile.get("diagnostic_entity_ids"))
            blocking_ids = _text_values(
                profile.get("blocking_diagnostic_entity_ids")
            )
            relationship_ids_for_profile = set(
                _text_values(profile.get("relationship_ids"))
            )
            readiness_profile = readiness_profiles_by_id.get(
                str(profile.get("readiness_profile_id", ""))
            )
            finding_metadata = finding_entities_by_raw_id.get(finding_id, {}).get(
                "metadata", {}
            )
            if not (
                profile_id in governance_profile_entity_ids
                and finding_id in finding_entity_ids
                and profile.get("component_id") in component_ids
                and isinstance(profile.get("revalidation_required"), bool)
                and isinstance(profile.get("diagnostic_entity_ids"), list)
                and isinstance(profile.get("blocking_diagnostic_entity_ids"), list)
                and isinstance(profile.get("diagnostic_counts"), dict)
                and isinstance(profile.get("relationship_ids"), list)
                and profile.get("state") in REVIEW_GOVERNANCE_STATES
                and readiness_profile is not None
                and readiness_profile.get("finding_id") == finding_id
                and profile.get("source_status")
                == finding_metadata.get("source_status")
                and profile.get("source_change")
                == finding_metadata.get("source_change")
                and profile.get("screening_priority")
                == finding_metadata.get("priority")
                and profile.get("finding_disposition")
                == finding_metadata.get("disposition")
                and profile.get("workflow_status")
                == finding_metadata.get("workflow_status")
                and profile.get("revalidation_required")
                == finding_metadata.get("revalidation_required")
                and set(diagnostic_ids) <= quality_diagnostic_entity_ids
                and set(blocking_ids) <= set(diagnostic_ids)
                and relationship_ids_for_profile <= relationship_id_set
            ):
                return False
            diagnostic_metadata = [
                entities_by_id[diagnostic_id].get("metadata", {})
                for diagnostic_id in diagnostic_ids
                if diagnostic_id in entities_by_id
            ]
            if any(
                metadata.get("scope") != "finding"
                or metadata.get("item_id") != finding_id
                for metadata in diagnostic_metadata
            ):
                return False
            expected_counts = dict(
                sorted(
                    Counter(
                        str(metadata.get("level", "unknown"))
                        for metadata in diagnostic_metadata
                    ).items()
                )
            )
            expected_blocking_ids = sorted(
                diagnostic_id
                for diagnostic_id in diagnostic_ids
                if entities_by_id[diagnostic_id].get("metadata", {}).get("level")
                == "error"
                and entities_by_id[diagnostic_id]
                .get("metadata", {})
                .get("rule_id")
                != "review.unreviewed"
            )
            expected_state, expected_next_action = _review_governance_state(
                source_status=str(profile.get("source_status", "active")),
                revalidation_required=bool(profile.get("revalidation_required")),
                blocking_error_count=len(expected_blocking_ids),
                disposition=str(profile.get("finding_disposition", "")),
                readiness_state=str(readiness_profile.get("lifecycle_state", "")),
                readiness_next_action=str(readiness_profile.get("next_action_id", "")),
            )
            profile_relation = _relation_id(
                _entity_id("finding", finding_id),
                profile_id,
                "has_review_governance_profile",
                "cross_reference",
            )
            diagnostic_relations = {
                _relation_id(
                    profile_id,
                    diagnostic_id,
                    "has_finding_quality_gate_diagnostic",
                    "validation",
                )
                for diagnostic_id in diagnostic_ids
            }
            return bool(
                profile.get("diagnostic_counts") == expected_counts
                and blocking_ids == expected_blocking_ids
                and profile.get("state") == expected_state
                and profile.get("next_action_id") == expected_next_action
                and profile_relation in relationship_ids_for_profile
                and profile_relation in relationship_id_set
                and diagnostic_relations <= relationship_ids_for_profile
                and diagnostic_relations <= relationship_id_set
            )

        global_diagnostic_ids = (
            _text_values(quality_gate_projection.get("global_diagnostic_entity_ids"))
            if isinstance(quality_gate_projection, dict)
            else []
        )
        analysis_scope_entity_id = (
            str(quality_gate_projection.get("analysis_scope_entity_id", ""))
            if isinstance(quality_gate_projection, dict)
            else ""
        )
        global_relationship_ids = (
            _text_values(quality_gate_projection.get("global_relationship_ids"))
            if isinstance(quality_gate_projection, dict)
            else []
        )
        global_metadata = [
            entities_by_id[diagnostic_id].get("metadata", {})
            for diagnostic_id in global_diagnostic_ids
            if diagnostic_id in entities_by_id
        ]
        expected_global_counts = dict(
            sorted(
                Counter(
                    str(metadata.get("level", "unknown"))
                    for metadata in global_metadata
                ).items()
            )
        )
        all_diagnostic_metadata = [
            entities_by_id[diagnostic_id].get("metadata", {})
            for diagnostic_id in quality_diagnostic_entity_ids
            if diagnostic_id in entities_by_id
        ]
        expected_analysis_gate_state = (
            "blocked"
            if any(
                metadata.get("level") == "error"
                for metadata in all_diagnostic_metadata
            )
            else "review_required"
            if any(
                metadata.get("level") == "warning"
                for metadata in all_diagnostic_metadata
            )
            else "clear"
        )
        expected_global_relations = {
            _relation_id(
                analysis_scope_entity_id,
                diagnostic_id,
                "has_analysis_quality_gate_diagnostic",
                "validation",
            )
            for diagnostic_id in global_diagnostic_ids
        }
        finding_diagnostic_ids = {
            diagnostic_id
            for profile in governance_profiles or []
            if isinstance(profile, dict)
            for diagnostic_id in _text_values(profile.get("diagnostic_entity_ids"))
        }
        checks["review_governance_integrity"] = bool(
            isinstance(quality_gate_projection, dict)
            and isinstance(governance_profiles, list)
            and len(governance_profile_ids) == len(governance_profiles)
            and all(governance_profile_ids)
            and len(governance_profile_ids) == len(set(governance_profile_ids))
            and set(governance_profile_ids) == governance_profile_entity_ids
            and diagnostic_identity_valid
            and {
                str(profile.get("finding_id", ""))
                for profile in governance_profiles
                if isinstance(profile, dict)
            }
            == finding_entity_ids
            and all(governance_profile_valid(profile) for profile in governance_profiles)
            and analysis_scope_entity_id in entities_by_id
            and entities_by_id[analysis_scope_entity_id].get("kind")
            == "analysis_scope"
            and set(global_diagnostic_ids) <= quality_diagnostic_entity_ids
            and all(metadata.get("scope") == "analysis" for metadata in global_metadata)
            and set(global_relationship_ids) == expected_global_relations
            and expected_global_relations <= relationship_id_set
            and quality_gate_projection.get("global_diagnostic_counts")
            == expected_global_counts
            and quality_gate_projection.get("analysis_gate_state")
            == expected_analysis_gate_state
            and set(global_diagnostic_ids).isdisjoint(finding_diagnostic_ids)
            and set(global_diagnostic_ids) | finding_diagnostic_ids
            == quality_diagnostic_entity_ids
        )
        if not checks["review_governance_integrity"]:
            fail(
                "cross_reference.review_governance_integrity_invalid",
                "Review-governance profiles must partition global and finding diagnostics, preserve source/revalidation state, and resolve deterministic next actions.",
            )
        governance_profile_id_set = set(governance_profile_ids)

        adapter_provenance = value.get("adapter_provenance")
        adapter_profiles = (
            adapter_provenance.get("adapter_run_profiles")
            if isinstance(adapter_provenance, dict)
            else None
        )
        adapter_profile_ids = (
            [
                str(profile.get("id", ""))
                for profile in adapter_profiles
                if isinstance(profile, dict)
            ]
            if isinstance(adapter_profiles, list)
            else []
        )
        adapter_run_entity_ids = {
            str(entity.get("id", ""))
            for entity in entities or []
            if isinstance(entity, dict) and entity.get("kind") == "adapter_run"
        }
        run_manifest_entity_id = (
            str(adapter_provenance.get("run_manifest_entity_id", ""))
            if isinstance(adapter_provenance, dict)
            else ""
        )
        adapter_ledger_entity_id = (
            str(adapter_provenance.get("adapter_ledger_entity_id", ""))
            if isinstance(adapter_provenance, dict)
            else ""
        )
        analysis_scope_entity_ids = {
            str(entity.get("id", ""))
            for entity in entities or []
            if isinstance(entity, dict) and entity.get("kind") == "analysis_scope"
        }
        raw_entity_index: dict[str, set[str]] = defaultdict(set)
        for entity in entities or []:
            if isinstance(entity, dict) and entity.get("id"):
                raw_entity_index[str(entity.get("raw_id", ""))].add(
                    str(entity["id"])
                )
        expected_adapter_relationship_ids: set[str] = set()
        if len(analysis_scope_entity_ids) == 1:
            analysis_scope_id = next(iter(analysis_scope_entity_ids))
            expected_adapter_relationship_ids.update(
                {
                    _relation_id(
                        analysis_scope_id,
                        run_manifest_entity_id,
                        "has_run_manifest",
                        "run_manifest",
                    ),
                    _relation_id(
                        analysis_scope_id,
                        adapter_ledger_entity_id,
                        "has_adapter_ledger",
                        "adapter_ledger",
                    ),
                    _relation_id(
                        run_manifest_entity_id,
                        adapter_ledger_entity_id,
                        "binds_adapter_ledger",
                        "run_manifest",
                    ),
                }
            )
        expected_adapter_relationship_ids.update(
            _relation_id(
                adapter_ledger_entity_id,
                profile_id,
                "records_adapter_run",
                "adapter_ledger",
            )
            for profile_id in adapter_profile_ids
        )

        def adapter_profile_valid(profile: object) -> bool:
            if not isinstance(profile, dict):
                return False
            profile_id = str(profile.get("id", ""))
            adapter_id = str(profile.get("adapter_id", ""))
            entity = entities_by_id.get(profile_id, {})
            contribution_ids = _text_values(profile.get("contribution_entity_ids"))
            linked_ids = _text_values(
                profile.get("linked_contribution_entity_ids")
            )
            unlinked_ids = _text_values(
                profile.get("unlinked_contribution_entity_ids")
            )
            supplied_relationship_ids = set(
                _text_values(profile.get("relationship_ids"))
            )
            if not (
                profile_id in adapter_run_entity_ids
                and entity.get("raw_id") == adapter_id
                and entity.get("metadata", {}).get("adapter_id") == adapter_id
                and entity.get("metadata", {}).get("status")
                == profile.get("status")
                and isinstance(profile.get("contribution_entity_ids"), list)
                and isinstance(profile.get("linked_contribution_entity_ids"), list)
                and isinstance(profile.get("unlinked_contribution_entity_ids"), list)
                and isinstance(profile.get("relationship_ids"), list)
                and contribution_ids == sorted(set(contribution_ids))
                and linked_ids == sorted(set(linked_ids))
                and unlinked_ids == sorted(set(unlinked_ids))
                and set(linked_ids).isdisjoint(unlinked_ids)
                and set(linked_ids) | set(unlinked_ids) == set(contribution_ids)
                and _safe_int(entity.get("metadata", {}).get("contribution_count", 0))
                == len(contribution_ids)
            ):
                return False
            expected_linked_ids = {
                contribution_id
                for contribution_id in contribution_ids
                if raw_entity_index.get(contribution_id, set()) - {profile_id}
            }
            expected_relationship_ids = {
                _relation_id(
                    profile_id,
                    target_entity_id,
                    "contributed_entity",
                    "adapter_ledger",
                )
                for contribution_id in contribution_ids
                for target_entity_id in raw_entity_index.get(contribution_id, set())
                if target_entity_id != profile_id
            }
            if not all(
                relationships_by_id.get(relation_id, {}).get("metadata", {}).get(
                    "contribution_entity_id"
                )
                in contribution_ids
                for relation_id in expected_relationship_ids
            ):
                return False
            expected_adapter_relationship_ids.update(expected_relationship_ids)
            return bool(
                set(linked_ids) == expected_linked_ids
                and set(unlinked_ids) == set(contribution_ids) - expected_linked_ids
                and supplied_relationship_ids == expected_relationship_ids
                and expected_relationship_ids <= relationship_id_set
            )

        adapter_profiles_valid = bool(
            isinstance(adapter_profiles, list)
            and len(adapter_profile_ids) == len(adapter_profiles)
            and all(adapter_profile_ids)
            and len(adapter_profile_ids) == len(set(adapter_profile_ids))
            and set(adapter_profile_ids) == adapter_run_entity_ids
            and all(adapter_profile_valid(profile) for profile in adapter_profiles)
        )
        supplied_adapter_relationship_ids = (
            set(_text_values(adapter_provenance.get("relationship_ids")))
            if isinstance(adapter_provenance, dict)
            else set()
        )
        checks["adapter_provenance_integrity"] = bool(
            isinstance(adapter_provenance, dict)
            and adapter_profiles_valid
            and run_manifest_entity_id in entities_by_id
            and entities_by_id[run_manifest_entity_id].get("kind") == "run_manifest"
            and adapter_ledger_entity_id in entities_by_id
            and entities_by_id[adapter_ledger_entity_id].get("kind")
            == "adapter_ledger"
            and entities_by_id[run_manifest_entity_id]
            .get("metadata", {})
            .get("adapter_run_ledger_sha256")
            == entities_by_id[adapter_ledger_entity_id]
            .get("metadata", {})
            .get("ledger_sha256")
            and supplied_adapter_relationship_ids
            == expected_adapter_relationship_ids
            and expected_adapter_relationship_ids <= relationship_id_set
        )
        if not checks["adapter_provenance_integrity"]:
            fail(
                "cross_reference.adapter_provenance_integrity_invalid",
                "Adapter provenance must bind the run manifest and ledger, retain every contribution identity, and resolve exact contribution relationships without implying correctness.",
            )
        adapter_profiles_by_id = {
            str(profile.get("id", "")): profile
            for profile in adapter_profiles or []
            if isinstance(profile, dict) and profile.get("id")
        }
        verified_adapter_entities_by_finding: dict[str, set[str]] = defaultdict(set)
        verified_adapter_relationships_by_finding: dict[str, set[str]] = defaultdict(
            set
        )
        for relation in relationships or []:
            if not (
                isinstance(relation, dict)
                and relation.get("kind") == "contributed_entity"
                and relation.get("source") in adapter_run_entity_ids
            ):
                continue
            target_entity_record = entities_by_id.get(
                str(relation.get("target", "")), {}
            )
            if target_entity_record.get("kind") != "finding":
                continue
            finding_id = str(target_entity_record.get("raw_id", ""))
            verified_adapter_entities_by_finding[finding_id].add(
                str(relation.get("source", ""))
            )
            verified_adapter_relationships_by_finding[finding_id].add(
                str(relation.get("id", ""))
            )

        chains = value.get("finding_chains")
        chain_ids = (
            [
                str(chain.get("finding_id", ""))
                for chain in chains
                if isinstance(chain, dict)
            ]
            if isinstance(chains, list)
            else []
        )

        def source_chain_valid(chain: object) -> bool:
            if not isinstance(chain, dict):
                return False
            artifact_ids = _text_values(
                chain.get("source_repository_artifact_entity_ids")
            )
            artifact_id_set = set(artifact_ids)
            artifact_id = str(chain.get("source_repository_artifact_entity_id", ""))
            configuration_source_id = str(
                chain.get("source_configuration_input_entity_id", "")
            )
            supplied_relationship_ids = set(
                _text_values(chain.get("source_provenance_relationship_ids"))
            )
            if not artifact_ids and not configuration_source_id:
                return bool(
                    artifact_id == ""
                    and not chain.get("source_repository_status")
                    and not chain.get("source_analysis_depth")
                    and not chain.get("source_snapshot_sha256")
                    and not _text_values(chain.get("source_adapter_ids"))
                    and not supplied_relationship_ids
                    and not chain.get("dimensions", {}).get("source_provenance")
                    and chain.get("finding_id")
                    in set(
                        _text_values(
                            repository_provenance_data.get(
                                "unaccounted_finding_ids", []
                            )
                        )
                    )
                )
            if not (
                artifact_ids == sorted(artifact_id_set)
                and artifact_id == (artifact_ids[0] if artifact_ids else "")
                and artifact_id_set <= repository_artifact_entity_ids
                and (
                    not configuration_source_id
                    or configuration_source_id == configuration_input_entity_id
                )
            ):
                return False
            expected_relationship_ids = ({
                _relation_id(
                    _entity_id("finding", chain.get("finding_id", "")),
                    source_artifact_id,
                    "originates_from_repository_artifact",
                    "repository_inventory",
                )
                for source_artifact_id in artifact_id_set
            } | {
                _relation_id(
                    _entity_id("component", chain.get("component_id", "")),
                    source_artifact_id,
                    "defined_in_repository_artifact",
                    "repository_inventory",
                )
                for source_artifact_id in artifact_id_set
            } | ({
                _relation_id(
                    _entity_id("component", chain.get("component_id", "")),
                    configuration_source_id,
                    "configured_by_analysis_input",
                    "analysis_input",
                ),
                _relation_id(
                    _entity_id("finding", chain.get("finding_id", "")),
                    configuration_source_id,
                    "originates_from_analysis_input",
                    "analysis_input",
                ),
            } if configuration_source_id else set())) & relationship_id_set
            expected_adapter_ids = sorted(
                {
                    adapter_id
                    for source_artifact_id in artifact_id_set
                    for adapter_id in _text_values(
                        entities_by_id[source_artifact_id]
                        .get("metadata", {})
                        .get("adapter_ids")
                    )
                }
            )
            primary_metadata = (
                entities_by_id[artifact_id].get("metadata", {})
                if artifact_id
                else {}
            )
            configuration_metadata = (
                entities_by_id[configuration_source_id].get("metadata", {})
                if configuration_source_id
                else {}
            )
            return bool(
                (
                    len(artifact_ids) != 1
                    or chain.get("source_repository_path")
                    == primary_metadata.get("path")
                )
                and (
                    not configuration_source_id
                    or chain.get("source_repository_path")
                    == configuration_metadata.get("source_label")
                )
                and chain.get("source_repository_status")
                == (
                    primary_metadata.get("status")
                    if len(artifact_ids) == 1
                    else "multiple"
                    if artifact_ids
                    else "configured"
                )
                and chain.get("source_analysis_depth")
                == (
                    primary_metadata.get("analysis_depth")
                    if len(artifact_ids) == 1
                    else "aggregate_dependency_manifests"
                    if artifact_ids
                    else "project_configuration"
                )
                and chain.get("source_snapshot_sha256")
                == (
                    primary_metadata.get("sha256")
                    if len(artifact_ids) == 1
                    else configuration_metadata.get("sha256", "")
                    if configuration_source_id
                    else ""
                )
                and _text_values(chain.get("source_adapter_ids"))
                == expected_adapter_ids
                and supplied_relationship_ids == expected_relationship_ids
                and chain.get("dimensions", {}).get("source_provenance") is True
            )

        checks["finding_chain_integrity"] = bool(
            isinstance(chains, list)
            and len(chain_ids) == len(chains)
            and all(chain_ids)
            and len(chain_ids) == len(set(chain_ids))
            and set(chain_ids) <= finding_entity_ids
            and all(
                isinstance(chain, dict)
                and isinstance(chain.get("dimensions"), dict)
                and all(
                    isinstance(chain.get(field), list)
                    for field in (
                        "requirement_ids",
                        "hazard_ids",
                        "citation_ids",
                        "obligation_ids",
                        "evidence_artifact_ids",
                        "execution_ids",
                        "sfta_event_ids",
                        "cascade_component_ids",
                        "cascade_paths",
                        "resilience_entity_ids",
                        "timing_relationship_ids",
                        "semantic_entity_ids",
                        "semantic_relationship_ids",
                        "compound_exposure_kinds",
                        "test_candidate_entity_ids",
                        "coverage_entity_ids",
                        "implemented_test_entity_ids",
                        "assignment_entity_ids",
                        "readiness_relationship_ids",
                        "verification_readiness_gaps",
                        "quality_diagnostic_entity_ids",
                        "blocking_quality_diagnostic_entity_ids",
                        "review_governance_relationship_ids",
                        "source_adapter_ids",
                        "source_repository_artifact_entity_ids",
                        "source_provenance_relationship_ids",
                        "adapter_run_entity_ids",
                        "adapter_provenance_relationship_ids",
                        "machine_assistance_entity_ids",
                        "machine_assistance_relationship_ids",
                        "interface_entity_ids",
                        "inbound_fusion_ids",
                        "outbound_fusion_ids",
                    )
                )
                and source_chain_valid(chain)
                and set(
                    _text_values(chain.get("inbound_fusion_ids"))
                    + _text_values(chain.get("outbound_fusion_ids"))
                )
                <= fusion_id_set
                and set(_text_values(chain.get("cascade_component_ids")))
                <= component_ids
                and all(
                    isinstance(path, list) for path in chain.get("cascade_paths", [])
                )
                and all(
                    set(_text_values(path)) <= component_ids
                    for path in chain.get("cascade_paths", [])
                )
                and set(_text_values(chain.get("resilience_entity_ids")))
                <= entity_id_set
                and set(_text_values(chain.get("timing_relationship_ids")))
                <= relationship_id_set
                and (
                    not chain.get("semantic_profile_id")
                    or chain.get("semantic_profile_id") in semantic_profile_id_set
                )
                and isinstance(chain.get("semantic_dimensions"), dict)
                and set(chain["semantic_dimensions"])
                == set(SEMANTIC_EXPOSURE_DIMENSIONS)
                and all(
                    isinstance(chain["semantic_dimensions"][dimension], bool)
                    for dimension in SEMANTIC_EXPOSURE_DIMENSIONS
                )
                and (
                    (
                        chain["semantic_dimensions"]
                        == semantic_profiles_by_id[
                            str(chain.get("semantic_profile_id", ""))
                        ].get("dimensions")
                        and set(_text_values(chain.get("semantic_entity_ids")))
                        == {
                            str(chain.get("semantic_profile_id", "")),
                            *_text_values(
                                semantic_profiles_by_id[
                                    str(chain.get("semantic_profile_id", ""))
                                ].get("entity_ids")
                            ),
                        }
                        and set(
                            _text_values(chain.get("semantic_relationship_ids"))
                        )
                        == set(
                            _text_values(
                                semantic_profiles_by_id[
                                    str(chain.get("semantic_profile_id", ""))
                                ].get("relationship_ids")
                            )
                        )
                        and chain["dimensions"].get("semantic_exposure")
                        == (
                            _safe_int(
                                semantic_profiles_by_id[
                                    str(chain.get("semantic_profile_id", ""))
                                ].get("populated_dimension_count", 0)
                            )
                            > 0
                        )
                    )
                    if chain.get("semantic_profile_id")
                    else (
                        not any(chain["semantic_dimensions"].values())
                        and not _text_values(chain.get("semantic_entity_ids"))
                        and not _text_values(chain.get("semantic_relationship_ids"))
                        and not chain["dimensions"].get("semantic_exposure")
                    )
                )
                and set(_text_values(chain.get("semantic_entity_ids")))
                <= entity_id_set
                and set(_text_values(chain.get("semantic_relationship_ids")))
                <= relationship_id_set
                and set(_text_values(chain.get("compound_exposure_kinds")))
                <= set(COMPOUND_EXPOSURE_PRIORITIES)
                and _text_values(chain.get("compound_exposure_kinds"))
                == _compound_exposure_kinds(
                    chain["semantic_dimensions"], chain["dimensions"]
                )
                and chain.get("verification_readiness_profile_id")
                in readiness_profile_id_set
                and (
                    chain.get("test_candidate_entity_ids")
                    == readiness_profiles_by_id[
                        str(chain.get("verification_readiness_profile_id", ""))
                    ].get("test_candidate_entity_ids")
                    and chain.get("coverage_entity_ids")
                    == readiness_profiles_by_id[
                        str(chain.get("verification_readiness_profile_id", ""))
                    ].get("coverage_entity_ids")
                    and chain.get("implemented_test_entity_ids")
                    == readiness_profiles_by_id[
                        str(chain.get("verification_readiness_profile_id", ""))
                    ].get("implemented_test_entity_ids")
                    and chain.get("assignment_entity_ids")
                    == readiness_profiles_by_id[
                        str(chain.get("verification_readiness_profile_id", ""))
                    ].get("assignment_entity_ids")
                    and chain.get("readiness_relationship_ids")
                    == readiness_profiles_by_id[
                        str(chain.get("verification_readiness_profile_id", ""))
                    ].get("relationship_ids")
                    and chain.get("verification_lifecycle_state")
                    == readiness_profiles_by_id[
                        str(chain.get("verification_readiness_profile_id", ""))
                    ].get("lifecycle_state")
                    and chain.get("verification_evidence_posture")
                    == readiness_profiles_by_id[
                        str(chain.get("verification_readiness_profile_id", ""))
                    ].get("evidence_posture")
                    and chain.get("verification_next_action_id")
                    == readiness_profiles_by_id[
                        str(chain.get("verification_readiness_profile_id", ""))
                    ].get("next_action_id")
                    and chain.get("verification_readiness_gaps")
                    == readiness_profiles_by_id[
                        str(chain.get("verification_readiness_profile_id", ""))
                    ].get("readiness_gaps")
                    and chain["dimensions"].get("verification_readiness")
                    == any(
                        readiness_profiles_by_id[
                            str(chain.get("verification_readiness_profile_id", ""))
                        ]["evidence_signals"][field]
                        for field in (
                            "assigned_owner",
                            "named_reviewer",
                            "candidate_test_links",
                            "coverage_observation",
                            "implementation_registered",
                            "execution_recorded",
                            "evidence_artifact_recorded",
                        )
                    )
                )
                and set(_text_values(chain.get("test_candidate_entity_ids")))
                <= entity_id_set
                and set(_text_values(chain.get("coverage_entity_ids")))
                <= entity_id_set
                and set(_text_values(chain.get("implemented_test_entity_ids")))
                <= entity_id_set
                and set(_text_values(chain.get("assignment_entity_ids")))
                <= entity_id_set
                and set(_text_values(chain.get("readiness_relationship_ids")))
                <= relationship_id_set
                and chain.get("review_governance_profile_id")
                in governance_profile_id_set
                and (
                    chain.get("quality_diagnostic_entity_ids")
                    == governance_profiles_by_id[
                        str(chain.get("review_governance_profile_id", ""))
                    ].get("diagnostic_entity_ids")
                    and chain.get("blocking_quality_diagnostic_entity_ids")
                    == governance_profiles_by_id[
                        str(chain.get("review_governance_profile_id", ""))
                    ].get("blocking_diagnostic_entity_ids")
                    and chain.get("review_governance_relationship_ids")
                    == governance_profiles_by_id[
                        str(chain.get("review_governance_profile_id", ""))
                    ].get("relationship_ids")
                    and chain.get("review_governance_state")
                    == governance_profiles_by_id[
                        str(chain.get("review_governance_profile_id", ""))
                    ].get("state")
                    and chain.get("review_next_action_id")
                    == governance_profiles_by_id[
                        str(chain.get("review_governance_profile_id", ""))
                    ].get("next_action_id")
                    and chain.get("quality_diagnostic_counts")
                    == governance_profiles_by_id[
                        str(chain.get("review_governance_profile_id", ""))
                    ].get("diagnostic_counts")
                    and chain.get("source_change")
                    == governance_profiles_by_id[
                        str(chain.get("review_governance_profile_id", ""))
                    ].get("source_change")
                    and chain.get("revalidation_required")
                    == governance_profiles_by_id[
                        str(chain.get("review_governance_profile_id", ""))
                    ].get("revalidation_required")
                    and chain["dimensions"].get("quality_governance")
                    == bool(
                        governance_profiles_by_id[
                            str(chain.get("review_governance_profile_id", ""))
                        ].get("diagnostic_entity_ids")
                        or governance_profiles_by_id[
                            str(chain.get("review_governance_profile_id", ""))
                        ].get("revalidation_required")
                        or governance_profiles_by_id[
                            str(chain.get("review_governance_profile_id", ""))
                        ].get("source_change")
                        or governance_profiles_by_id[
                            str(chain.get("review_governance_profile_id", ""))
                        ].get("finding_disposition")
                        != "unreviewed"
                    )
                )
                and set(_text_values(chain.get("quality_diagnostic_entity_ids")))
                <= quality_diagnostic_entity_ids
                and set(
                    _text_values(chain.get("blocking_quality_diagnostic_entity_ids"))
                )
                <= quality_diagnostic_entity_ids
                and set(
                    _text_values(chain.get("review_governance_relationship_ids"))
                )
                <= relationship_id_set
                and isinstance(chain.get("adapter_statuses"), dict)
                and (
                    lambda expected_adapter_ids, expected_relation_ids: (
                        set(_text_values(chain.get("adapter_run_entity_ids")))
                        == expected_adapter_ids
                        and set(
                            _text_values(
                                chain.get("adapter_provenance_relationship_ids")
                            )
                        )
                        == expected_relation_ids
                        and chain.get("adapter_statuses")
                        == {
                            str(adapter_profiles_by_id[adapter_id]["adapter_id"]): str(
                                adapter_profiles_by_id[adapter_id]["status"]
                            )
                            for adapter_id in sorted(expected_adapter_ids)
                        }
                        and chain["dimensions"].get("tool_provenance")
                        == bool(expected_adapter_ids)
                    )
                )(
                    verified_adapter_entities_by_finding.get(
                        str(chain.get("finding_id", "")), set()
                    ),
                    verified_adapter_relationships_by_finding.get(
                        str(chain.get("finding_id", "")), set()
                    ),
                )
                and (
                    lambda expected_entity_ids, expected_relation_ids: (
                        set(
                            _text_values(
                                chain.get("machine_assistance_entity_ids")
                            )
                        )
                        == expected_entity_ids
                        and set(
                            _text_values(
                                chain.get("machine_assistance_relationship_ids")
                            )
                        )
                        == expected_relation_ids
                        and chain["dimensions"].get("machine_assistance")
                        == bool(expected_entity_ids)
                    )
                )(
                    verified_machine_entities_by_finding.get(
                        str(chain.get("finding_id", "")), set()
                    ),
                    verified_machine_relationships_by_finding.get(
                        str(chain.get("finding_id", "")), set()
                    ),
                )
                and set(_text_values(chain.get("requirement_ids")))
                <= entity_raw_ids_by_kind["requirement"]
                and set(_text_values(chain.get("hazard_ids")))
                <= entity_raw_ids_by_kind["hazard"]
                and set(_text_values(chain.get("citation_ids")))
                <= entity_raw_ids_by_kind["citation"]
                and set(_text_values(chain.get("obligation_ids")))
                <= entity_raw_ids_by_kind["obligation"]
                and set(_text_values(chain.get("evidence_artifact_ids")))
                <= entity_raw_ids_by_kind["evidence"]
                and set(_text_values(chain.get("execution_ids")))
                <= entity_raw_ids_by_kind["execution"]
                and set(_text_values(chain.get("sfta_event_ids")))
                <= entity_raw_ids_by_kind["sfta_event"]
                and set(_text_values(chain.get("interface_entity_ids")))
                <= entity_id_set
                for chain in chains
            )
        )
        if not checks["finding_chain_integrity"]:
            fail(
                "cross_reference.finding_chain_integrity_invalid",
                "Finding chains must be unique and resolve findings, cascades, resilience records, and fused relationships.",
            )

        leads = value.get("review_leads")
        lead_ids = (
            [str(lead.get("id", "")) for lead in leads if isinstance(lead, dict)]
            if isinstance(leads, list)
            else []
        )
        checks["review_lead_integrity"] = bool(
            isinstance(leads, list)
            and len(lead_ids) == len(leads)
            and all(lead_ids)
            and len(lead_ids) == len(set(lead_ids))
            and all(
                isinstance(lead, dict)
                and isinstance(lead.get("subject_ids"), list)
                and set(_text_values(lead.get("subject_ids"))) <= entity_id_set
                for lead in leads
            )
        )
        if not checks["review_lead_integrity"]:
            fail(
                "cross_reference.review_lead_integrity_invalid",
                "Review leads must have unique IDs and resolve every subject to an embedded entity.",
            )
        summary = value.get("summary")
        classification_counts = dict(
            sorted(
                Counter(
                    str(fusion.get("classification", ""))
                    for fusion in (fusions or [])
                    if isinstance(fusion, dict)
                ).items()
            )
        )
        lead_counts = dict(
            sorted(
                Counter(
                    str(lead.get("kind", ""))
                    for lead in (leads or [])
                    if isinstance(lead, dict)
                ).items()
            )
        )
        semantic_dimension_counts = dict(
            sorted(
                Counter(
                    dimension
                    for profile in (semantic_profiles or [])
                    if isinstance(profile, dict)
                    and isinstance(profile.get("dimensions"), dict)
                    for dimension, populated in profile["dimensions"].items()
                    if populated
                ).items()
            )
        )
        compound_exposure_counts = dict(
            sorted(
                Counter(
                    exposure
                    for chain in (chains or [])
                    if isinstance(chain, dict)
                    for exposure in _text_values(chain.get("compound_exposure_kinds"))
                ).items()
            )
        )
        verification_lifecycle_counts = dict(
            sorted(
                Counter(
                    str(profile.get("lifecycle_state", ""))
                    for profile in (readiness_profiles or [])
                    if isinstance(profile, dict)
                ).items()
            )
        )
        verification_posture_counts = dict(
            sorted(
                Counter(
                    str(profile.get("evidence_posture", ""))
                    for profile in (readiness_profiles or [])
                    if isinstance(profile, dict)
                ).items()
            )
        )
        verification_gap_counts = dict(
            sorted(
                Counter(
                    gap
                    for profile in (readiness_profiles or [])
                    if isinstance(profile, dict)
                    for gap in _text_values(profile.get("readiness_gaps"))
                ).items()
            )
        )
        quality_diagnostic_counts = dict(
            sorted(
                Counter(
                    str(metadata.get("level", "unknown"))
                    for metadata in all_diagnostic_metadata
                ).items()
            )
        )
        governance_state_counts = dict(
            sorted(
                Counter(
                    str(profile.get("state", ""))
                    for profile in (governance_profiles or [])
                    if isinstance(profile, dict)
                ).items()
            )
        )
        source_change_counts = dict(
            sorted(
                Counter(
                    str(profile.get("source_change", "")) or "unspecified"
                    for profile in (governance_profiles or [])
                    if isinstance(profile, dict)
                ).items()
            )
        )
        adapter_status_counts = dict(
            sorted(
                Counter(
                    str(profile.get("status", ""))
                    for profile in (adapter_profiles or [])
                    if isinstance(profile, dict)
                ).items()
            )
        )
        repository_artifact_status_counts = dict(
            sorted(
                Counter(
                    str(entities_by_id[entity_id].get("metadata", {}).get("status", "unknown"))
                    for entity_id in repository_artifact_entity_ids
                ).items()
            )
        )
        machine_suggestion_status_counts = dict(
            sorted(
                Counter(
                    str(profile.get("status", ""))
                    for profile in (suggestion_profiles or [])
                    if isinstance(profile, dict)
                ).items()
            )
        )
        machine_claim_relationship_type_counts = dict(
            sorted(
                Counter(
                    str(relationships_by_id[relation_id].get("kind", ""))
                    for relation_id in machine_claim_relation_ids
                ).items()
            )
        )
        components_with_repository_source = {
            str(entities_by_id[str(relation.get("source"))].get("raw_id", ""))
            for relation in relationships_by_id.values()
            if relation.get("kind") == "defined_in_repository_artifact"
            and relation.get("target") in repository_artifact_entity_ids
            and str(relation.get("source")) in entities_by_id
        }
        configured_component_id_set = set(
            _text_values(
                repository_provenance_data.get("configured_component_ids", [])
            )
        )
        configured_finding_id_set = set(
            _text_values(repository_provenance_data.get("configured_finding_ids", []))
        )
        checks["summary_reconciliation"] = bool(
            isinstance(summary, dict)
            and isinstance(leads, list)
            and summary.get("entities") == len(entities or [])
            and summary.get("relationships") == len(relationships or [])
            and summary.get("component_relationship_fusions") == len(fusions or [])
            and summary.get("semantic_profiles") == len(semantic_profiles or [])
            and summary.get("semantic_profiles_with_records")
            == sum(
                _safe_int(profile.get("populated_dimension_count", 0)) > 0
                for profile in (semantic_profiles or [])
                if isinstance(profile, dict)
            )
            and summary.get("verification_readiness_profiles")
            == len(readiness_profiles or [])
            and summary.get("verification_profiles_with_signals")
            == sum(
                any(
                    profile.get("evidence_signals", {}).get(field) is True
                    for field in (
                        "assigned_owner",
                        "named_reviewer",
                        "candidate_test_links",
                        "coverage_observation",
                        "implementation_registered",
                        "execution_recorded",
                        "evidence_artifact_recorded",
                    )
                )
                for profile in (readiness_profiles or [])
                if isinstance(profile, dict)
            )
            and summary.get("review_governance_profiles")
            == len(governance_profiles or [])
            and summary.get("quality_gate_diagnostics")
            == len(quality_diagnostic_entity_ids)
            and summary.get("global_quality_gate_diagnostics")
            == len(global_diagnostic_ids)
            and summary.get("profiles_with_blocking_quality_diagnostics")
            == sum(
                bool(_text_values(profile.get("blocking_diagnostic_entity_ids")))
                for profile in (governance_profiles or [])
                if isinstance(profile, dict)
            )
            and summary.get("adapter_runs") == len(adapter_profiles or [])
            and summary.get("findings_with_tool_provenance")
            == sum(
                bool(_text_values(chain.get("adapter_run_entity_ids")))
                for chain in (chains or [])
                if isinstance(chain, dict)
            )
            and summary.get("adapter_contribution_relationships")
            == sum(
                len(_text_values(profile.get("relationship_ids")))
                for profile in (adapter_profiles or [])
                if isinstance(profile, dict)
            )
            and summary.get("unlinked_adapter_contributions")
            == sum(
                len(_text_values(profile.get("unlinked_contribution_entity_ids")))
                for profile in (adapter_profiles or [])
                if isinstance(profile, dict)
            )
            and summary.get("repository_artifacts")
            == len(repository_artifact_entity_ids)
            and summary.get("semantically_analyzed_repository_artifacts")
            == sum(
                entities_by_id[entity_id].get("metadata", {}).get("status")
                == "analyzed"
                for entity_id in repository_artifact_entity_ids
            )
            and summary.get("opaque_repository_artifacts")
            == len(opaque_entity_ids)
            and summary.get("excluded_repository_regions")
            == len(repository_region_entity_ids)
            and summary.get("dependency_entities") == len(dependency_entity_id_set)
            and summary.get("contract_entities") == len(contract_entity_id_set)
            and summary.get("components_with_repository_provenance")
            == len(components_with_repository_source)
            and summary.get("findings_with_repository_provenance")
            == sum(
                bool(chain.get("source_repository_artifact_entity_id"))
                for chain in (chains or [])
                if isinstance(chain, dict)
            )
            and summary.get("configured_source_components")
            == len(configured_component_id_set)
            and summary.get("configured_source_findings")
            == len(configured_finding_id_set)
            and summary.get("components_with_source_provenance")
            == len(component_ids)
            - len(
                set(
                    _text_values(
                        repository_provenance_data.get(
                            "unaccounted_component_ids", []
                        )
                    )
                )
            )
            and summary.get("findings_with_source_provenance")
            == sum(
                bool(chain.get("dimensions", {}).get("source_provenance"))
                for chain in (chains or [])
                if isinstance(chain, dict)
            )
            and summary.get("repository_provenance_relationships")
            == len(repository_channel_relationship_ids)
            and summary.get("machine_suggestions")
            == len(suggestion_profiles or [])
            and summary.get("proposed_machine_suggestions")
            == sum(
                profile.get("status") == "proposed"
                for profile in (suggestion_profiles or [])
                if isinstance(profile, dict)
            )
            and summary.get("machine_summaries") == len(summary_profiles or [])
            and summary.get("stale_machine_summaries")
            == len(expected_stale_summary_ids)
            and summary.get("machine_claim_relationships")
            == len(machine_claim_relation_ids)
            and summary.get("machine_assistance_relationships")
            == len(machine_channel_relationship_ids)
            and summary.get(
                "machine_assistance_unresolved_evidence_references"
            )
            == len(expected_unresolved_evidence_references)
            and summary.get(
                "machine_assistance_unresolved_citation_references"
            )
            == len(expected_unresolved_citation_references)
            and summary.get("findings_with_machine_assistance")
            == sum(
                bool(_text_values(chain.get("machine_assistance_entity_ids")))
                for chain in (chains or [])
                if isinstance(chain, dict)
            )
            and summary.get("compound_exposure_chains")
            == sum(
                bool(_text_values(chain.get("compound_exposure_kinds")))
                for chain in (chains or [])
                if isinstance(chain, dict)
            )
            and summary.get("finding_chains") == len(chains or [])
            and summary.get("review_leads") == len(leads)
            and summary.get("active_finding_chains")
            == sum(
                chain.get("source_status", "active") == "active"
                for chain in (chains or [])
                if isinstance(chain, dict)
            )
            and summary.get("historical_finding_chains")
            == sum(
                chain.get("source_status", "active") != "active"
                for chain in (chains or [])
                if isinstance(chain, dict)
            )
            and summary.get("runtime_observed_fusions")
            == sum(
                bool(fusion.get("runtime_observed"))
                for fusion in (fusions or [])
                if isinstance(fusion, dict)
            )
            and summary.get("multi_source_fusions")
            == sum(
                _safe_int(fusion.get("corroboration_count", 0)) > 1
                for fusion in (fusions or [])
                if isinstance(fusion, dict)
            )
            and summary.get("classifications") == classification_counts
            and summary.get("review_leads_by_kind") == lead_counts
            and summary.get("semantic_dimensions") == semantic_dimension_counts
            and summary.get("compound_exposures_by_kind")
            == compound_exposure_counts
            and summary.get("verification_lifecycle_states")
            == verification_lifecycle_counts
            and summary.get("verification_evidence_postures")
            == verification_posture_counts
            and summary.get("verification_readiness_gaps")
            == verification_gap_counts
            and summary.get("quality_diagnostics_by_level")
            == quality_diagnostic_counts
            and summary.get("global_quality_diagnostics_by_level")
            == expected_global_counts
            and summary.get("review_governance_states")
            == governance_state_counts
            and summary.get("source_change_states") == source_change_counts
            and summary.get("adapter_run_statuses") == adapter_status_counts
            and summary.get("repository_artifact_statuses")
            == repository_artifact_status_counts
            and summary.get("machine_suggestion_statuses")
            == machine_suggestion_status_counts
            and summary.get("machine_claim_relationship_types")
            == machine_claim_relationship_type_counts
        )
        if not checks["summary_reconciliation"]:
            fail(
                "cross_reference.summary_mismatch",
                "Summary counts do not reconcile to the embedded registers.",
            )

        if analysis is not None:
            checks["analysis_binding"] = value.get(
                "analysis_state_sha256"
            ) == canonical_json_sha256(analysis)
            if not checks["analysis_binding"]:
                fail(
                    "cross_reference.analysis_binding_mismatch",
                    "The fabric analysis-state digest differs from the supplied analysis.",
                )
            try:
                expected = build_cross_reference_index(analysis)
                checks["exact_regeneration"] = (
                    supplied_digest == expected.get("content_sha256")
                    and value == expected
                )
            except (KeyError, TypeError, ValueError, OverflowError):
                checks["exact_regeneration"] = False
                fail(
                    "cross_reference.regeneration_failed",
                    "Exact regeneration could not be completed from the supplied analysis.",
                )
            if not checks["exact_regeneration"] and not any(
                error["code"] == "cross_reference.regeneration_failed"
                for error in errors
            ):
                fail(
                    "cross_reference.regeneration_mismatch",
                    "The fabric does not exactly regenerate from the supplied analysis.",
                )

    completed = [passed for passed in checks.values() if passed is not None]
    valid = bool(completed) and all(completed)
    binding_checked = analysis is not None and isinstance(value, dict)
    status = (
        "matched"
        if valid and binding_checked
        else "valid_binding_not_checked"
        if valid
        else "mismatched"
        if binding_checked
        else "invalid"
    )
    return {
        "format": CROSS_REFERENCE_VERIFICATION_FORMAT,
        "verifier": {"name": "PySFMEA", "version": __version__},
        "path": str(document.path),
        "bytes": document.size,
        "artifact_sha256": hashlib.sha256(document.raw).hexdigest(),
        "valid": valid,
        "status": status,
        "binding_requested": analysis is not None,
        "binding_checked": binding_checked,
        "checks": checks,
        "failed_checks": [name for name, passed in checks.items() if passed is False],
        "unchecked_checks": [name for name, passed in checks.items() if passed is None],
        "errors": errors,
        "content_sha256": value.get("content_sha256", "")
        if isinstance(value, dict)
        else "",
        "entity_count": (
            _safe_int(value.get("summary", {}).get("entities", 0))
            if isinstance(value, dict) and isinstance(value.get("summary"), dict)
            else 0
        ),
        "relationship_count": (
            _safe_int(value.get("summary", {}).get("relationships", 0))
            if isinstance(value, dict) and isinstance(value.get("summary"), dict)
            else 0
        ),
        "fusion_count": (
            _safe_int(value.get("summary", {}).get("component_relationship_fusions", 0))
            if isinstance(value, dict) and isinstance(value.get("summary"), dict)
            else 0
        ),
        "semantic_profile_count": (
            _safe_int(value.get("summary", {}).get("semantic_profiles", 0))
            if isinstance(value, dict) and isinstance(value.get("summary"), dict)
            else 0
        ),
        "verification_readiness_profile_count": (
            _safe_int(
                value.get("summary", {}).get("verification_readiness_profiles", 0)
            )
            if isinstance(value, dict) and isinstance(value.get("summary"), dict)
            else 0
        ),
        "review_governance_profile_count": (
            _safe_int(value.get("summary", {}).get("review_governance_profiles", 0))
            if isinstance(value, dict) and isinstance(value.get("summary"), dict)
            else 0
        ),
        "quality_gate_diagnostic_count": (
            _safe_int(value.get("summary", {}).get("quality_gate_diagnostics", 0))
            if isinstance(value, dict) and isinstance(value.get("summary"), dict)
            else 0
        ),
        "adapter_run_count": (
            _safe_int(value.get("summary", {}).get("adapter_runs", 0))
            if isinstance(value, dict) and isinstance(value.get("summary"), dict)
            else 0
        ),
        "repository_artifact_count": (
            _safe_int(value.get("summary", {}).get("repository_artifacts", 0))
            if isinstance(value, dict) and isinstance(value.get("summary"), dict)
            else 0
        ),
        "machine_suggestion_count": (
            _safe_int(value.get("summary", {}).get("machine_suggestions", 0))
            if isinstance(value, dict) and isinstance(value.get("summary"), dict)
            else 0
        ),
        "machine_summary_count": (
            _safe_int(value.get("summary", {}).get("machine_summaries", 0))
            if isinstance(value, dict) and isinstance(value.get("summary"), dict)
            else 0
        ),
        "machine_claim_relationship_count": (
            _safe_int(
                value.get("summary", {}).get("machine_claim_relationships", 0)
            )
            if isinstance(value, dict) and isinstance(value.get("summary"), dict)
            else 0
        ),
        "compound_exposure_chain_count": (
            _safe_int(value.get("summary", {}).get("compound_exposure_chains", 0))
            if isinstance(value, dict) and isinstance(value.get("summary"), dict)
            else 0
        ),
        "finding_chain_count": (
            _safe_int(value.get("summary", {}).get("finding_chains", 0))
            if isinstance(value, dict) and isinstance(value.get("summary"), dict)
            else 0
        ),
        "review_lead_count": (
            _safe_int(value.get("summary", {}).get("review_leads", 0))
            if isinstance(value, dict) and isinstance(value.get("summary"), dict)
            else 0
        ),
        "notice": (
            "Verification detects corruption, inconsistent references, and optional "
            "analysis drift; it does not establish completeness, compliance, verification "
            "success, or risk acceptance."
        ),
    }
