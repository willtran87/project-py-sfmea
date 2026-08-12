"""Deterministic cross-scanner and assurance relationship fabric."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .architecture import architecture_graph
from .assurance import ensure_assurance_register
from .file_publication import atomic_publish_text
from .guidance import guidance_traceability
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document
from .model import stable_id
from .sfta import build_sfta
from .version import __version__

CROSS_REFERENCE_FORMAT = "pysfmea-cross-reference-index-1"
CROSS_REFERENCE_VERIFICATION_FORMAT = "pysfmea-cross-reference-verification-1"
CROSS_REFERENCE_VERIFICATION_CHECKS = (
    "format",
    "content_integrity",
    "entity_identity",
    "relationship_integrity",
    "fusion_integrity",
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


def build_cross_reference_index(
    analysis: dict[str, Any],
    *,
    assurance_register: dict[str, Any] | None = None,
    guidance_trace: dict[str, Any] | None = None,
    sfta_model: dict[str, Any] | None = None,
    architecture: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Fuse independently derived relationships without overstating their authority."""

    assurance = assurance_register or ensure_assurance_register(analysis)
    analysis_sha256 = canonical_json_sha256(analysis)
    guidance = guidance_trace or guidance_traceability(analysis)
    sfta = sfta_model or build_sfta(analysis)
    graph = architecture or architecture_graph(analysis)

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
        dimensions["cascade_analysis"] = bool(upstream_paths)
        dimensions["timing_and_resilience"] = bool(
            resilience_entity_ids or timing_relation_ids
        )
        finding_chains.append(
            {
                "finding_id": finding_id,
                "component_id": component_id,
                "source_status": item.get("source_status", "active"),
                "requirement_ids": requirements,
                "hazard_ids": hazards,
                "citation_ids": citation_ids,
                "obligation_ids": sorted(
                    str(value.get("id", "")) for value in finding_obligations
                ),
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
        chain["linkage_completeness_percent"] = round(
            100 * sum(chain["dimensions"].values()) / len(chain["dimensions"]),
            1,
        )

    review_leads: list[dict[str, Any]] = []
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

    entities_list = sorted(entities.values(), key=lambda value: value["id"])
    relationships_list = sorted(relationships.values(), key=lambda value: value["id"])
    finding_chains.sort(key=lambda value: value["finding_id"])
    classification_counts = Counter(value["classification"] for value in fusions)
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
            "omitted_by_bound": dict(sorted(omitted.items())),
        },
        "entities": entities_list,
        "relationships": relationships_list,
        "component_relationship_fusions": fusions,
        "finding_chains": finding_chains,
        "review_leads": review_leads,
        "limitations": [
            "Static relationships can omit dynamic dispatch, generated code, and environment wiring.",
            "Runtime relationships describe imported observations only and do not prove path completeness or absence.",
            "Guidance links express relevance to a candidate; they do not assert noncompliance.",
            "Configured hazards, requirements, interfaces, and SFTA logic retain project-supplied authority.",
            "Cascade paths, retry amplification, literal timing budgets, and circuit-breaker models are bounded static candidates, not runtime causality, latency, or control-effectiveness proof.",
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

        chains = value.get("finding_chains")
        finding_entity_ids = {
            str(entity.get("raw_id", ""))
            for entity in entities or []
            if isinstance(entity, dict) and entity.get("kind") == "finding"
        }
        chain_ids = (
            [
                str(chain.get("finding_id", ""))
                for chain in chains
                if isinstance(chain, dict)
            ]
            if isinstance(chains, list)
            else []
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
                        "interface_entity_ids",
                        "inbound_fusion_ids",
                        "outbound_fusion_ids",
                    )
                )
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
        checks["summary_reconciliation"] = bool(
            isinstance(summary, dict)
            and isinstance(leads, list)
            and summary.get("entities") == len(entities or [])
            and summary.get("relationships") == len(relationships or [])
            and summary.get("component_relationship_fusions") == len(fusions or [])
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
