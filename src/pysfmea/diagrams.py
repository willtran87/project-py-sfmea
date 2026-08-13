"""Canonical diagram models, validation, imports, and SFMEA diagram builders."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .architecture import architecture_graph
from .cross_reference import build_cross_reference_index
from .file_publication import atomic_publish_text
from .guidance import guidance_traceability
from .integrity import canonical_json_sha256
from .json_ingestion import BoundedJsonDocument, load_bounded_json_document
from .model import stable_id, utc_now
from .sfta import build_sfta
from .version import __version__
from .visuals import sequence_model

DIAGRAM_SCHEMA = "pysfmea-diagram-1"
DIAGRAM_BUNDLE_SCHEMA = "pysfmea-diagram-bundle-1"
DIAGRAM_BUNDLE_VERIFICATION_FORMAT = "pysfmea-diagram-bundle-verification-1"
DIAGRAM_TYPES = (
    "directed_graph",
    "flow",
    "sequence",
    "traceability",
    "cause_effect",
    "state",
)
GENERATED_DIAGRAM_KINDS = (
    "all",
    "architecture",
    "interface_flow",
    "data_flow",
    "traceability",
    "guidance_traceability",
    "assurance_traceability",
    "cross_reference",
    "sfta",
    "failure_propagation",
    "control_coverage",
    "circuit_breaker",
    "sequence",
)
MAX_DIAGRAMS = 50
MAX_DIAGRAM_NODES = 2_000
MAX_DIAGRAM_EDGES = 5_000
MAX_DIAGRAM_FILE_BYTES = 5_000_000
MAX_DIAGRAM_IMPORT_FILES = 50
MAX_DIAGRAM_IMPORT_TOTAL_BYTES = 25_000_000
MAX_DIAGRAM_JSON_DEPTH = 100
MAX_DIAGRAM_JSON_NODES = 250_000
MAX_TEXT_LENGTH = 8_000
DEFAULT_PROPAGATION_RECORD_LIMIT = 40
DEFAULT_PROPAGATION_PATH_LIMIT = 3
DEFAULT_PROPAGATION_DEPTH = 6
MAX_PROPAGATION_RECORD_LIMIT = 250
MAX_PROPAGATION_PATH_LIMIT = 25
MAX_PROPAGATION_DEPTH = 12
INTEGRITY_REQUIRED_GENERATOR_VERSION = (0, 31, 0)
_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")


def validate_propagation_limits(record_limit: int, path_limit: int, depth: int) -> None:
    """Reject invalid or conservatively oversized propagation projections."""

    if not 1 <= record_limit <= MAX_PROPAGATION_RECORD_LIMIT:
        raise ValueError(
            "propagation record limit must be from 1 through "
            f"{MAX_PROPAGATION_RECORD_LIMIT}"
        )
    if not 0 <= path_limit <= MAX_PROPAGATION_PATH_LIMIT:
        raise ValueError(
            "propagation path limit must be from 0 through "
            f"{MAX_PROPAGATION_PATH_LIMIT}"
        )
    if not 0 <= depth <= MAX_PROPAGATION_DEPTH:
        raise ValueError(
            f"propagation depth must be from 0 through {MAX_PROPAGATION_DEPTH}"
        )
    estimated_nodes = record_limit * (8 + path_limit * depth)
    if estimated_nodes > MAX_DIAGRAM_NODES:
        raise ValueError(
            "combined propagation limits exceed the conservative diagram node budget "
            f"({estimated_nodes} > {MAX_DIAGRAM_NODES}); reduce the record, path, or depth limit"
        )


def normalize_propagation_finding_ids(
    values: Iterable[str] | None,
) -> list[str]:
    """Normalize repeatable projection pins without changing request order."""

    return list(
        dict.fromkeys(
            str(value).strip() for value in (values or []) if str(value).strip()
        )
    )


def _string(value: Any, field: str, *, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValueError(f"diagram {field} must be a string")
    cleaned = value.strip()
    if required and not cleaned:
        raise ValueError(f"diagram {field} is required")
    if len(cleaned) > MAX_TEXT_LENGTH:
        raise ValueError(f"diagram {field} exceeds {MAX_TEXT_LENGTH} characters")
    return cleaned


def _identifier(value: Any, field: str) -> str:
    identifier = _string(value, field, required=True)
    if not _ID_PATTERN.fullmatch(identifier):
        raise ValueError(
            f"diagram {field} must start with an alphanumeric character and contain "
            "only letters, numbers, dot, underscore, colon, or hyphen"
        )
    return identifier


def _string_list(value: Any, field: str, *, maximum: int = 100) -> list[str]:
    if value in (None, ""):
        return []
    if not isinstance(value, list):
        raise ValueError(f"diagram {field} must be an array of strings")
    if len(value) > maximum:
        raise ValueError(f"diagram {field} exceeds {maximum} entries")
    return [_string(entry, field, required=True) for entry in value]


def _metadata(value: Any, field: str) -> dict[str, Any]:
    if value in (None, ""):
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"diagram {field} must be an object")
    normalized: dict[str, Any] = {}
    for key, entry in value.items():
        name = _string(key, f"{field} key", required=True)
        if isinstance(entry, (str, int, float, bool)) or entry is None:
            normalized[name] = entry
        elif (
            isinstance(entry, list)
            and len(entry) <= 100
            and all(
                isinstance(part, (str, int, float, bool)) or part is None
                for part in entry
            )
        ):
            normalized[name] = entry
        else:
            raise ValueError(
                f"diagram {field}.{name} must be a scalar or bounded scalar array"
            )
    return normalized


def normalize_diagram_model(model: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize one canonical diagram model."""

    if not isinstance(model, dict):
        raise ValueError("each diagram must be an object")
    diagram_type = _string(model.get("type"), "type", required=True)
    if diagram_type not in DIAGRAM_TYPES:
        raise ValueError(f"diagram type must be one of: {', '.join(DIAGRAM_TYPES)}")
    raw_nodes = model.get("nodes", [])
    raw_edges = model.get("edges", [])
    if not isinstance(raw_nodes, list):
        raise ValueError("diagram nodes must be an array")
    if not isinstance(raw_edges, list):
        raise ValueError("diagram edges must be an array")
    if len(raw_nodes) > MAX_DIAGRAM_NODES:
        raise ValueError(f"diagram exceeds {MAX_DIAGRAM_NODES} nodes")
    if len(raw_edges) > MAX_DIAGRAM_EDGES:
        raise ValueError(f"diagram exceeds {MAX_DIAGRAM_EDGES} edges")

    nodes: list[dict[str, Any]] = []
    node_ids: set[str] = set()
    for index, raw in enumerate(raw_nodes):
        if not isinstance(raw, dict):
            raise ValueError(f"diagram node {index + 1} must be an object")
        node_id = _identifier(raw.get("id"), f"node {index + 1} id")
        if node_id in node_ids:
            raise ValueError(f"duplicate diagram node id: {node_id}")
        node_ids.add(node_id)
        layer = raw.get("layer")
        order = raw.get("order")
        if layer is not None and (
            isinstance(layer, bool)
            or not isinstance(layer, int)
            or not 0 <= layer <= 100
        ):
            raise ValueError(
                f"diagram node {node_id} layer must be an integer from 0 through 100"
            )
        if order is not None and (
            isinstance(order, bool)
            or not isinstance(order, int)
            or not 0 <= order <= 100_000
        ):
            raise ValueError(
                f"diagram node {node_id} order must be a non-negative integer"
            )
        nodes.append(
            {
                "id": node_id,
                "label": _string(
                    raw.get("label"), f"node {node_id} label", required=True
                ),
                "kind": _string(
                    raw.get("kind", "element"), f"node {node_id} kind", required=True
                ),
                "group": _string(raw.get("group", ""), f"node {node_id} group"),
                "description": _string(
                    raw.get("description", ""), f"node {node_id} description"
                ),
                "source": _string(raw.get("source", ""), f"node {node_id} source"),
                "tags": _string_list(raw.get("tags", []), f"node {node_id} tags"),
                "metrics": _metadata(raw.get("metrics", {}), f"node {node_id} metrics"),
                "layer": layer,
                "order": order,
            }
        )

    edges: list[dict[str, Any]] = []
    edge_ids: set[str] = set()
    for index, raw in enumerate(raw_edges):
        if not isinstance(raw, dict):
            raise ValueError(f"diagram edge {index + 1} must be an object")
        edge_id = _identifier(
            raw.get("id", f"edge-{index + 1}"), f"edge {index + 1} id"
        )
        if edge_id in edge_ids:
            raise ValueError(f"duplicate diagram edge id: {edge_id}")
        edge_ids.add(edge_id)
        source = _identifier(raw.get("source"), f"edge {edge_id} source")
        target = _identifier(raw.get("target"), f"edge {edge_id} target")
        if source not in node_ids or target not in node_ids:
            raise ValueError(
                f"diagram edge {edge_id} references an unknown node: {source} -> {target}"
            )
        order = raw.get("order")
        if order is not None and (
            isinstance(order, bool)
            or not isinstance(order, int)
            or not 0 <= order <= 100_000
        ):
            raise ValueError(
                f"diagram edge {edge_id} order must be a non-negative integer"
            )
        edges.append(
            {
                "id": edge_id,
                "source": source,
                "target": target,
                "label": _string(raw.get("label", ""), f"edge {edge_id} label"),
                "kind": _string(
                    raw.get("kind", "relationship"),
                    f"edge {edge_id} kind",
                    required=True,
                ),
                "evidence": _string(
                    raw.get("evidence", ""), f"edge {edge_id} evidence"
                ),
                "description": _string(
                    raw.get("description", ""), f"edge {edge_id} description"
                ),
                "order": order,
                "cycle": bool(raw.get("cycle", False)),
            }
        )

    return {
        "schema_version": DIAGRAM_SCHEMA,
        "id": _identifier(model.get("id"), "id"),
        "title": _string(model.get("title"), "title", required=True),
        "type": diagram_type,
        "description": _string(model.get("description", ""), "description"),
        "notice": _string(model.get("notice", ""), "notice"),
        "nodes": nodes,
        "edges": edges,
        "metadata": _metadata(model.get("metadata", {}), "metadata"),
    }


def _node(
    node_id: str,
    label: str,
    kind: str,
    *,
    group: str = "",
    description: str = "",
    source: str = "",
    tags: Iterable[str] = (),
    metrics: dict[str, Any] | None = None,
    layer: int | None = None,
    order: int | None = None,
) -> dict[str, Any]:
    return {
        "id": node_id,
        "label": label or node_id,
        "kind": kind,
        "group": group,
        "description": description,
        "source": source,
        "tags": list(tags),
        "metrics": metrics or {},
        "layer": layer,
        "order": order,
    }


def _edge(
    edge_id: str,
    source: str,
    target: str,
    label: str,
    kind: str,
    *,
    evidence: str = "",
    description: str = "",
    order: int | None = None,
    cycle: bool = False,
) -> dict[str, Any]:
    return {
        "id": edge_id,
        "source": source,
        "target": target,
        "label": label,
        "kind": kind,
        "evidence": evidence,
        "description": description,
        "order": order,
        "cycle": cycle,
    }


def _component_group(component: dict[str, Any]) -> str:
    subsystems = component.get("subsystems", [])
    if subsystems:
        return str(subsystems[0])
    path = str(component.get("source", {}).get("path", ""))
    parts = [part for part in path.replace("\\", "/").split("/") if part]
    return (
        "/".join(parts[:2]) if len(parts) > 1 else (parts[0] if parts else "Unassigned")
    )


def architecture_diagram(
    analysis: dict[str, Any], *, component_limit: int = 120
) -> dict[str, Any]:
    graph = architecture_graph(analysis)
    components = [
        component
        for component in analysis.get("components", [])
        if component.get("kind") not in {"environment", "common_cause", "contract"}
    ]
    components.sort(
        key=lambda component: (
            -bool(component.get("entrypoint_types")),
            -int(component.get("screening", {}).get("score", 0) or 0),
            -int(component.get("fan_in", 0) or 0),
            str(component.get("source", {}).get("path", "")),
            str(component.get("qualname", "")),
        )
    )

    by_id = {str(component.get("id", "")): component for component in components}
    seed_limit = min(component_limit, 40)
    selected = {
        str(component.get("id", "")): component for component in components[:seed_limit]
    }
    internal_edges = [
        relation
        for relation in graph.get("edges", [])
        if relation.get("kind") in {"internal_call", "observed_runtime"}
    ]
    while len(selected) < component_limit:
        changed = False
        for relation in internal_edges:
            source_id = str(relation.get("source", ""))
            target_id = str(relation.get("target", ""))
            if (
                source_id in selected
                and target_id in by_id
                and target_id not in selected
            ):
                selected[target_id] = by_id[target_id]
                changed = True
            elif (
                target_id in selected
                and source_id in by_id
                and source_id not in selected
            ):
                selected[source_id] = by_id[source_id]
                changed = True
            if len(selected) >= component_limit:
                break
        if not changed:
            break
    for component in components:
        if len(selected) >= component_limit:
            break
        selected.setdefault(str(component.get("id", "")), component)
    nodes = [
        _node(
            component_id,
            str(component.get("qualname", component_id)),
            "component",
            group=_component_group(component),
            description=str(component.get("docstring_summary", "")),
            source=f"{component.get('source', {}).get('path', '')}:{component.get('source', {}).get('line', '')}",
            tags=[
                *component.get("frameworks", []),
                *component.get("entrypoint_types", []),
            ],
            metrics={
                "fan_in": component.get("fan_in", 0),
                "complexity": component.get("complexity", 0),
                "screening_score": component.get("screening", {}).get("score", 0),
            },
        )
        for component_id, component in selected.items()
    ]
    edges = []
    for index, relation in enumerate(graph.get("edges", [])):
        if relation.get("source") in selected and relation.get("target") in selected:
            edges.append(
                _edge(
                    f"architecture-edge-{index + 1}",
                    str(relation["source"]),
                    str(relation["target"]),
                    str(relation.get("label", "calls")),
                    str(relation.get("kind", "relationship")),
                    evidence=str(relation.get("evidence", "")),
                )
            )
    return normalize_diagram_model(
        {
            "id": "architecture-components",
            "title": "Component architecture",
            "type": "directed_graph",
            "description": "Highest-priority and highest-connectivity components with resolved internal relationships.",
            "notice": f"Bounded to {len(nodes)} components; static relationships can omit dynamic dispatch and runtime wiring.",
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "category": "architecture",
                "component_limit": component_limit,
                "total_components": len(components),
            },
        }
    )


def cross_reference_diagram(
    analysis: dict[str, Any],
    *,
    finding_limit: int = 40,
    node_limit: int = 500,
    index: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Project the highest-leverage guidance-to-evidence relationship chains."""

    index = index or build_cross_reference_index(analysis)
    entity_by_id = {value["id"]: value for value in index["entities"]}
    priority = {
        value["id"]: value.get("metadata", {}).get("priority", "")
        for value in index["entities"]
        if value.get("kind") == "finding"
    }
    priority_order = {"high": 0, "medium": 1, "low": 2}
    fusion_by_id = {
        value["id"]: value for value in index["component_relationship_fusions"]
    }
    chains = sorted(
        index["finding_chains"],
        key=lambda value: (
            value.get("source_status", "active") != "active",
            priority_order.get(priority.get(f"finding:{value['finding_id']}", ""), 3),
            value.get("linkage_completeness_percent", 0),
            value["finding_id"],
        ),
    )[:finding_limit]
    selected: set[str] = set()
    for chain in chains:
        selected.update(
            entity_id
            for entity_id in (
                f"finding:{chain['finding_id']}",
                f"component:{chain['component_id']}",
                *(f"requirement:{value}" for value in chain["requirement_ids"]),
                *(f"hazard:{value}" for value in chain["hazard_ids"]),
                *(f"citation:{value}" for value in chain["citation_ids"]),
                *(f"obligation:{value}" for value in chain["obligation_ids"]),
                *(f"evidence:{value}" for value in chain["evidence_artifact_ids"]),
                *(f"execution:{value}" for value in chain["execution_ids"]),
                *(f"sfta_event:{value}" for value in chain["sfta_event_ids"]),
                *chain.get("interface_entity_ids", []),
                *(
                    f"component:{value}"
                    for value in chain.get("cascade_component_ids", [])
                ),
                *chain.get("resilience_entity_ids", []),
                *chain.get("semantic_entity_ids", []),
                chain.get("verification_readiness_profile_id", ""),
                *chain.get("test_candidate_entity_ids", []),
                *chain.get("coverage_entity_ids", []),
                *chain.get("implemented_test_entity_ids", []),
                *chain.get("assignment_entity_ids", []),
                chain.get("review_governance_profile_id", ""),
                *chain.get("quality_diagnostic_entity_ids", []),
                *chain.get("adapter_run_entity_ids", []),
            )
            if entity_id in entity_by_id
        )
        for fusion_id in (
            *chain.get("inbound_fusion_ids", []),
            *chain.get("outbound_fusion_ids", []),
        ):
            fusion = fusion_by_id.get(fusion_id)
            if fusion:
                selected.update(
                    {
                        f"component:{fusion['source_component_id']}",
                        f"component:{fusion['target_component_id']}",
                    }
                )
        if len(selected) >= node_limit:
            break
    selected = set(sorted(selected)[:node_limit])
    layer_by_kind = {
        "citation": 0,
        "requirement": 0,
        "hazard": 0,
        "sfta_event": 0,
        "component": 1,
        "resilience_operation": 1,
        "resilience_effect_summary": 1,
        "transaction_summary": 1,
        "resource_summary": 1,
        "retry_path": 1,
        "circuit_breaker_model": 1,
        "semantic_profile": 1,
        "data_flow_edge": 1,
        "alias_object_binding": 1,
        "concurrency_operation": 1,
        "concurrency_relation": 1,
        "exception_raise": 1,
        "exception_handler": 1,
        "exception_propagation_edge": 1,
        "state_candidate": 1,
        "state_guard": 1,
        "state_transition": 1,
        "authorization_context": 1,
        "authorization_scope_edge": 1,
        "contract_operation": 1,
        "contract_compatibility": 1,
        "deployment_node": 1,
        "shared_fate_region": 1,
        "architecture_node": 1,
        "finding": 2,
        "review_governance_profile": 2,
        "quality_gate_diagnostic": 2,
        "adapter_run": 2,
        "verification_readiness_profile": 3,
        "test_candidate": 3,
        "coverage_observation": 3,
        "implemented_test": 3,
        "finding_owner": 3,
        "finding_reviewer": 3,
        "assurance_owner": 3,
        "assurance_reviewer": 3,
        "obligation": 3,
        "execution": 4,
        "evidence": 4,
    }
    nodes = [
        _node(
            entity_id,
            str(entity_by_id[entity_id].get("label", entity_id)),
            str(entity_by_id[entity_id].get("kind", "entity")),
            group=str(entity_by_id[entity_id].get("kind", "entity")),
            description=str(entity_by_id[entity_id].get("authority", "")),
            tags=[str(entity_by_id[entity_id].get("raw_id", ""))],
            layer=layer_by_kind.get(str(entity_by_id[entity_id].get("kind", ""))),
        )
        for entity_id in sorted(selected)
    ]
    edges = [
        _edge(
            value["id"],
            value["source"],
            value["target"],
            value["kind"].replace("_", " "),
            value["kind"],
            evidence=value["channel"],
            description=value["authority"],
        )
        for value in index["relationships"]
        if value["source"] in selected and value["target"] in selected
    ]
    summary = index["summary"]
    return normalize_diagram_model(
        {
            "id": "cross-reference-evidence-fabric",
            "title": "Cross-reference evidence fabric",
            "type": "traceability",
            "description": (
                "Bounded guidance, requirement, hazard, SFTA, component, cascade, resilience, "
                "semantic exposure, finding, verification, execution, and evidence relationships."
                " Quality diagnostics and review-governance state remain workflow evidence."
            ),
            "notice": (
                f"Showing {len(chains)} of {summary['finding_chains']} finding chains and "
                f"{len(nodes)} entities. Relationship presence is not compliance, "
                "verification success, or risk acceptance."
            ),
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "category": "cross_reference",
                "analysis_state_sha256": index["analysis_state_sha256"],
                "content_sha256": index["content_sha256"],
                "finding_limit": finding_limit,
                "total_finding_chains": summary["finding_chains"],
                "semantic_profiles": summary["semantic_profiles"],
                "verification_readiness_profiles": summary[
                    "verification_readiness_profiles"
                ],
                "verification_profiles_with_signals": summary[
                    "verification_profiles_with_signals"
                ],
                "review_governance_profiles": summary[
                    "review_governance_profiles"
                ],
                "quality_gate_diagnostics": summary["quality_gate_diagnostics"],
                "adapter_runs": summary["adapter_runs"],
                "findings_with_tool_provenance": summary[
                    "findings_with_tool_provenance"
                ],
                "compound_exposure_chains": summary["compound_exposure_chains"],
                "review_leads": summary["review_leads"],
            },
        }
    )


def deployment_topology_diagram(
    analysis: dict[str, Any], *, node_limit: int = 250, component_limit: int = 750
) -> dict[str, Any]:
    """Project declared deployment entities and candidate component placements."""

    topology = analysis.get("deployment_topology", {})
    source_nodes = [
        value for value in topology.get("nodes", []) if isinstance(value, dict)
    ][:node_limit]
    selected_node_ids = {str(value.get("id", "")) for value in source_nodes}
    nodes = [
        _node(
            str(value.get("id", "")),
            str(value.get("name", value.get("id", ""))),
            str(value.get("kind", "deployment_entity")),
            group=str(value.get("artifact_path", "Repository declaration")),
            source=str(value.get("artifact_path", "")),
            description=str(value.get("authority", "")),
            tags=[str(value.get("kind", "deployment_entity"))],
        )
        for value in source_nodes
    ]
    edges = [
        _edge(
            str(value.get("id", "")),
            str(value.get("source_node_id", "")),
            str(value.get("target_node_id", "")),
            str(value.get("kind", "relationship")).replace("_", " "),
            str(value.get("kind", "deployment_relationship")),
            evidence=str(value.get("artifact_path", "")),
        )
        for value in topology.get("edges", [])
        if isinstance(value, dict)
        and value.get("source_node_id") in selected_node_ids
        and value.get("target_node_id") in selected_node_ids
    ]
    component_by_id = {
        str(value.get("id", "")): value
        for value in analysis.get("components", [])
        if isinstance(value, dict)
    }
    embedded_components = 0
    for placement in topology.get("placements", []):
        if not isinstance(placement, dict):
            continue
        component_id = str(placement.get("component_id", ""))
        targets = [
            str(value)
            for value in placement.get("node_ids", [])
            if value in selected_node_ids
        ]
        component = component_by_id.get(component_id)
        if not targets or component is None or embedded_components >= component_limit:
            continue
        nodes.append(
            _node(
                component_id,
                str(component.get("qualname", component_id)),
                "component",
                group="Candidate placements",
                source=str(component.get("source", {}).get("path", "")),
                description=str(placement.get("basis", "")),
                tags=["heuristic placement"],
            )
        )
        embedded_components += 1
        edges.extend(
            _edge(
                stable_id("DIAGRAM-PLACEMENT", component_id, target),
                component_id,
                target,
                "candidate placement",
                "candidate_placement",
                evidence=str(placement.get("basis", "")),
            )
            for target in targets
        )
    summary = topology.get("summary", {})
    return normalize_diagram_model(
        {
            "id": "declared-deployment-topology",
            "title": "Declared deployment topology",
            "type": "directed_graph",
            "description": "Repository-declared deployment entities, relationships, and review-required component placement candidates.",
            "notice": "This view is repository evidence, not observed runtime routing or reachability. Placements are heuristic until reviewed.",
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "category": "architecture",
                "subtype": "deployment_topology",
                "source_format": topology.get("format", ""),
                "nodes_discovered": summary.get("nodes_discovered", 0),
                "nodes_embedded": len(source_nodes),
                "placed_components_embedded": embedded_components,
                "projection_truncated": len(source_nodes)
                < int(summary.get("nodes_embedded", 0) or 0)
                or embedded_components < int(summary.get("placed_components", 0) or 0),
            },
        }
    )


def shared_fate_diagram(
    analysis: dict[str, Any], *, region_limit: int = 100, component_limit: int = 1_500
) -> dict[str, Any]:
    """Project shared-resource candidates as regions linked to affected components."""

    model = analysis.get("shared_fate_analysis", {})
    regions = [value for value in model.get("regions", []) if isinstance(value, dict)][
        :region_limit
    ]
    affected_ids: list[str] = []
    for region in regions:
        for component_id in region.get("affected_component_ids", []):
            if component_id not in affected_ids and len(affected_ids) < component_limit:
                affected_ids.append(str(component_id))
    component_by_id = {
        str(value.get("id", "")): value
        for value in analysis.get("components", [])
        if isinstance(value, dict)
    }
    nodes = [
        _node(
            str(region.get("id", "")),
            str(region.get("key", region.get("id", ""))),
            "shared_fate_region",
            group=str(region.get("kind", "shared_fate")),
            description=str(region.get("authority", "")),
            tags=[str(region.get("kind", "shared_fate"))],
            metrics={
                "affected_components": len(region.get("affected_component_ids", []))
            },
        )
        for region in regions
    ]
    nodes.extend(
        _node(
            component_id,
            str(component_by_id.get(component_id, {}).get("qualname", component_id)),
            "component",
            group="Affected components",
            source=str(
                component_by_id.get(component_id, {}).get("source", {}).get("path", "")
            ),
        )
        for component_id in affected_ids
    )
    affected_set = set(affected_ids)
    edges = [
        _edge(
            stable_id("DIAGRAM-SHARED-FATE", str(region.get("id", "")), component_id),
            str(region.get("id", "")),
            str(component_id),
            "may affect",
            "shared_fate_membership",
            evidence=str(region.get("authority", "")),
        )
        for region in regions
        for component_id in region.get("affected_component_ids", [])
        if component_id in affected_set
    ]
    summary = model.get("summary", {})
    return normalize_diagram_model(
        {
            "id": "shared-fate-regions",
            "title": "Shared-fate regions",
            "type": "cause_effect",
            "description": "Automatically discovered shared deployment, subsystem, and external-dependency candidates.",
            "notice": "Membership is a conservative common-cause review lead, not proof of correlated failure or independence.",
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "category": "architecture",
                "subtype": "shared_fate",
                "source_format": model.get("format", ""),
                "regions_discovered": summary.get("regions_discovered", 0),
                "regions_embedded": len(regions),
                "projection_truncated": len(regions)
                < int(summary.get("regions", 0) or 0),
            },
        }
    )


def architecture_hierarchy_diagram(
    analysis: dict[str, Any], *, node_limit: int = 1_000
) -> dict[str, Any]:
    """Render the deterministic repository/subsystem/source-package hierarchy."""

    model = analysis.get("architecture_hierarchy", {})
    source_nodes = [
        value for value in model.get("nodes", []) if isinstance(value, dict)
    ]
    selected: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    for value in source_nodes:
        parent_id = str(value.get("parent_id", ""))
        if len(selected) >= node_limit:
            break
        if parent_id and parent_id not in selected_ids:
            continue
        selected.append(value)
        selected_ids.add(str(value.get("id", "")))
    nodes = [
        _node(
            str(value.get("id", "")),
            str(value.get("name", value.get("id", ""))),
            str(value.get("kind", "architecture_node")),
            group=str(value.get("kind", "architecture")),
            description=str(value.get("path", "")),
            tags=[
                f"{len(value.get('component_ids', []))} components",
                f"{len(value.get('effective_trace', {}).get('requirements', []))} requirements",
                f"{len(value.get('effective_trace', {}).get('hazards', []))} hazards",
            ],
            metrics={
                "components": len(value.get("component_ids", [])),
                "requirements": len(
                    value.get("effective_trace", {}).get("requirements", [])
                ),
                "hazards": len(value.get("effective_trace", {}).get("hazards", [])),
                "interfaces": len(
                    value.get("effective_trace", {}).get("interfaces", [])
                ),
            },
        )
        for value in selected
    ]
    edges = [
        _edge(
            stable_id(
                "DIAGRAM-HIERARCHY",
                str(value.get("parent_id", "")),
                str(value.get("id", "")),
            ),
            str(value.get("parent_id", "")),
            str(value.get("id", "")),
            "contains",
            "architecture_inheritance",
            evidence="deterministic reviewed mapping or repository path",
        )
        for value in selected
        if value.get("parent_id") in selected_ids
    ]
    summary = model.get("summary", {})
    return normalize_diagram_model(
        {
            "id": "architecture-hierarchy",
            "title": "Architecture hierarchy and inherited trace",
            "type": "directed_graph",
            "description": "Nested repository, subsystem, and source-package structure with upward trace aggregation.",
            "notice": "Only supplied mappings and repository paths are represented; this is not architecture approval.",
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "category": "architecture",
                "subtype": "hierarchy",
                "source_format": model.get("format", ""),
                "nodes_discovered": summary.get("nodes", 0),
                "nodes_embedded": len(selected),
                "projection_truncated": len(selected)
                < int(summary.get("nodes", 0) or 0),
            },
        }
    )


def interface_flow_diagram(analysis: dict[str, Any]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    total_candidates = sum(
        len(value.get("external_call_candidates", []))
        for value in analysis.get("components", [])
        if isinstance(value, dict)
        and isinstance(value.get("external_call_candidates", []), list)
    )
    for index, interface in enumerate(
        analysis.get("context", {}).get("system_interfaces", [])
    ):
        source_label = str(interface.get("source", "Source"))
        target_label = str(interface.get("target", "Target"))
        source_id = stable_id("boundary", source_label).lower()
        target_id = stable_id("boundary", target_label).lower()
        nodes.setdefault(source_id, _node(source_id, source_label, "boundary", layer=0))
        nodes.setdefault(target_id, _node(target_id, target_label, "boundary", layer=1))
        edges.append(
            _edge(
                f"interface-{index + 1}",
                source_id,
                target_id,
                str(interface.get("id", "interface")),
                "system_interface",
                evidence="configured_interface",
                description=str(interface.get("description", "")),
                order=index,
            )
        )
    candidate_count = 0
    candidate_limit = 500
    for component in analysis.get("components", []):
        component_id = str(component.get("id", ""))
        candidates = component.get("external_call_candidates", [])
        if not component_id or not isinstance(candidates, list):
            continue
        for candidate in candidates:
            if candidate_count >= candidate_limit or not isinstance(candidate, dict):
                break
            reference = str(candidate.get("reference", ""))
            if not reference:
                continue
            candidate_count += 1
            external_id = stable_id("external-call", reference).lower()
            nodes.setdefault(
                component_id,
                _node(
                    component_id,
                    str(component.get("qualname", component_id)),
                    "component",
                    source=(
                        f"{component.get('source', {}).get('path', '')}:"
                        f"{component.get('source', {}).get('line', '')}"
                    ),
                    layer=0,
                ),
            )
            nodes.setdefault(
                external_id,
                _node(
                    external_id,
                    reference,
                    "external_interface_candidate",
                    tags=[
                        str(candidate.get("confidence", "medium")),
                        str(candidate.get("basis", "unresolved")),
                        str(candidate.get("resolution", "lexical_name")),
                    ],
                    layer=1,
                ),
            )
            edges.append(
                _edge(
                    f"interface-candidate-{candidate_count}",
                    component_id,
                    external_id,
                    reference,
                    "external_interface_candidate",
                    evidence="static_candidate",
                    description=(
                        f"{candidate.get('confidence', 'medium')} confidence; "
                        f"{candidate.get('basis', 'unresolved')}; "
                        f"resolution {candidate.get('resolution', 'lexical_name')}"
                    ),
                    order=len(edges),
                )
            )
    return normalize_diagram_model(
        {
            "id": "system-interface-flow",
            "title": "System interface flow",
            "type": "flow",
            "description": "Configured boundaries plus bounded static external-call candidates.",
            "notice": (
                "Configured interfaces are engineer-declared; static candidates identify calls "
                "requiring interface review and do not prove a deployed boundary."
            ),
            "nodes": list(nodes.values()),
            "edges": edges,
            "metadata": {
                "category": "interface_flow",
                "external_candidate_limit": candidate_limit,
                "external_candidates_emitted": candidate_count,
                "external_candidates_total": total_candidates,
                "external_candidates_truncated": total_candidates > candidate_count,
            },
        }
    )


def data_flow_diagram(analysis: dict[str, Any]) -> dict[str, Any]:
    """Render the bounded interprocedural value-flow projection."""

    model = analysis.get("interprocedural_data_flow", {})
    raw_edges = model.get("edges", []) if isinstance(model, dict) else []
    raw_edges = raw_edges if isinstance(raw_edges, list) else []
    components = {
        str(value.get("id", "")): value
        for value in analysis.get("components", [])
        if isinstance(value, dict) and value.get("id")
    }
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    omitted_by_node_budget = 0
    omitted_by_edge_budget = 0
    for value in raw_edges:
        if not isinstance(value, dict):
            continue
        source = str(value.get("caller_component_id", ""))
        target = str(value.get("callee_component_id", ""))
        if source not in components or target not in components:
            continue
        if len(edges) >= MAX_DIAGRAM_EDGES:
            omitted_by_edge_budget += 1
            continue
        missing_nodes = sum(identifier not in nodes for identifier in (source, target))
        if len(nodes) + missing_nodes > MAX_DIAGRAM_NODES:
            omitted_by_node_budget += 1
            continue
        for identifier, layer in ((source, 0), (target, 1)):
            component = components[identifier]
            nodes.setdefault(
                identifier,
                _node(
                    identifier,
                    str(component.get("qualname", identifier)),
                    "component",
                    source=(
                        f"{component.get('source', {}).get('path', '')}:"
                        f"{component.get('source', {}).get('line', '')}"
                    ),
                    tags=[str(component.get("kind", "component"))],
                    layer=layer,
                ),
            )
        arguments = [
            str(argument.get("target_parameter", "?"))
            for argument in value.get("arguments", [])
            if isinstance(argument, dict)
        ]
        dimensions = value.get("flow_dimensions", {})
        label_parts = ["parameters " + ", ".join(arguments)] if arguments else []
        if isinstance(dimensions, dict) and dimensions.get("return"):
            sink = str(
                value.get("result_flow", {}).get("context", {}).get("kind", "sink")
            )
            label_parts.append("return to " + sink.replace("_", " "))
        edges.append(
            _edge(
                str(value.get("id", f"data-flow-{len(edges) + 1}")),
                source,
                target,
                "; ".join(label_parts) or "call value flow",
                "interprocedural_value_flow",
                evidence=str(value.get("resolution", "static")),
                description=(
                    "Path-insensitive static argument and result flow; dimensions: "
                    + ", ".join(key for key, enabled in dimensions.items() if enabled)
                ),
                order=len(edges),
            )
        )
    total_edges = int(
        model.get("summary", {}).get("resolved_call_edges", len(raw_edges)) or 0
    )
    projected_omissions = max(0, total_edges - len(edges))
    return normalize_diagram_model(
        {
            "id": "interprocedural-data-flow",
            "title": "Interprocedural value flow",
            "type": "flow",
            "description": "Static caller-expression to callee-parameter and callee-return to caller-context relationships.",
            "notice": (
                "This bounded, path-insensitive projection does not prove runtime reachability, "
                "taint, validity, confidentiality, or hazard causality."
            ),
            "nodes": list(nodes.values()),
            "edges": edges,
            "metadata": {
                "category": "data_flow",
                "source_format": str(model.get("format", "unavailable")),
                "total_flow_edges": total_edges,
                "embedded_flow_edges": len(edges),
                "flow_edges_omitted": projected_omissions,
                "source_edges_omitted": int(
                    model.get("summary", {}).get("edges_omitted", 0) or 0
                ),
                "omitted_by_node_budget": omitted_by_node_budget,
                "omitted_by_edge_budget": omitted_by_edge_budget,
                "truncated": projected_omissions > 0,
            },
        }
    )


def traceability_diagram(analysis: dict[str, Any]) -> dict[str, Any]:
    context = analysis.get("context", {})
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    requirement_ids: set[str] = set()
    hazard_ids: set[str] = set()
    for index, requirement in enumerate(context.get("requirements", [])):
        reference_id = str(requirement.get("id", ""))
        node_id = f"requirement:{reference_id}"
        requirement_ids.add(reference_id)
        nodes.append(
            _node(
                node_id,
                reference_id,
                "requirement",
                description=str(requirement.get("text", "")),
                source=str(requirement.get("source", "")),
                layer=0,
                order=index,
            )
        )
    for index, hazard in enumerate(context.get("hazards", [])):
        reference_id = str(hazard.get("id", ""))
        node_id = f"hazard:{reference_id}"
        hazard_ids.add(reference_id)
        nodes.append(
            _node(
                node_id,
                reference_id,
                "hazard",
                description=str(hazard.get("description", "")),
                metrics={"severity": hazard.get("severity", "")},
                layer=1,
                order=index,
            )
        )
    edge_index = 0
    for requirement in context.get("requirements", []):
        requirement_id = str(requirement.get("id", ""))
        if requirement_id not in requirement_ids:
            continue
        for hazard_id in requirement.get("hazards", []):
            if hazard_id not in hazard_ids:
                continue
            edge_index += 1
            edges.append(
                _edge(
                    f"trace-{edge_index}",
                    f"requirement:{requirement_id}",
                    f"hazard:{hazard_id}",
                    "mitigates",
                    "mitigates",
                    evidence="configured_trace",
                )
            )
    return normalize_diagram_model(
        {
            "id": "requirement-hazard-traceability",
            "title": "Requirement-to-hazard traceability",
            "type": "traceability",
            "description": "Configured mitigation relationships between requirement and hazard catalogs.",
            "notice": "A configured link establishes trace intent, not mitigation effectiveness.",
            "nodes": nodes,
            "edges": edges,
            "metadata": {"category": "traceability"},
        }
    )


def _ordered_items(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    priority = {"high": 0, "medium": 1, "low": 2}
    return sorted(
        [
            item
            for item in analysis.get("items", [])
            if item.get("source_status", "active") == "active"
        ],
        key=lambda item: (
            priority.get(item.get("scanner", {}).get("screening_priority", ""), 3),
            item.get("review", {}).get("disposition", "unreviewed") == "unreviewed",
            str(item.get("source", {}).get("path", "")),
            int(item.get("source", {}).get("line", 0) or 0),
            str(item.get("id", "")),
        ),
    )


def _component_diverse_items(
    ordered_items: list[dict[str, Any]],
    record_limit: int,
    *,
    represented_component_ids: Iterable[str] = (),
) -> list[dict[str, Any]]:
    """Select one priority-ordered finding per component before filling capacity."""

    if record_limit <= 0:
        return []
    selected: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    represented_components = {str(value) for value in represented_component_ids}
    for item in ordered_items:
        component_id = str(item.get("component_id", "")) or str(item.get("id", ""))
        if component_id in represented_components:
            continue
        selected.append(item)
        selected_ids.add(str(item.get("id", "")))
        represented_components.add(component_id)
        if len(selected) >= record_limit:
            return selected
    for item in ordered_items:
        item_id = str(item.get("id", ""))
        if item_id in selected_ids:
            continue
        selected.append(item)
        if len(selected) >= record_limit:
            break
    return selected


def _valid_upstream_paths(component: dict[str, Any]) -> list[list[str]]:
    """Return normalized caller paths without changing their discovery order."""

    return [
        [str(reference) for reference in path if str(reference)]
        for path in component.get("upstream_paths", [])
        if isinstance(path, list) and len(path) > 1
    ]


def failure_propagation_diagram(
    analysis: dict[str, Any],
    *,
    record_limit: int = DEFAULT_PROPAGATION_RECORD_LIMIT,
    cascade_paths_per_component: int = DEFAULT_PROPAGATION_PATH_LIMIT,
    cascade_depth: int = DEFAULT_PROPAGATION_DEPTH,
    include_finding_ids: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Build reviewed effect chains plus bounded static/observed caller exposure paths."""

    validate_propagation_limits(
        record_limit, cascade_paths_per_component, cascade_depth
    )
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    components = {
        str(value.get("id", "")): value
        for value in analysis.get("components", [])
        if value.get("id")
    }
    components_by_reference = {
        f"{value.get('source', {}).get('path', '')}:{value.get('qualname', '')}": value
        for value in components.values()
    }
    runtime_relations = {
        (
            str(value.get("source_component_id", "")),
            str(value.get("target_component_id", "")),
        )
        for value in analysis.get("runtime_evidence", {}).get("edges", [])
        if value.get("source_component_id") and value.get("target_component_id")
    }
    cascade_path_count = 0
    cascade_edge_count = 0
    observed_cascade_edge_count = 0
    records_with_cascade_paths = 0
    components_with_cascade_paths: set[str] = set()
    emitted_cascade_components: set[str] = set()
    shared_edges: set[str] = set()
    ordered_items = _ordered_items(analysis)
    requested_finding_ids = normalize_propagation_finding_ids(include_finding_ids)
    if len(requested_finding_ids) > record_limit:
        raise ValueError(
            "propagation include-finding count exceeds the propagation record limit"
        )
    items_by_id = {str(value.get("id", "")): value for value in ordered_items}
    unknown_finding_ids = [
        value for value in requested_finding_ids if value not in items_by_id
    ]
    if unknown_finding_ids:
        raise ValueError(
            "propagation include finding IDs must identify active findings: "
            + ", ".join(unknown_finding_ids)
        )
    pinned_items = [items_by_id[value] for value in requested_finding_ids]
    pinned_component_ids = {
        str(value.get("component_id", "")) or str(value.get("id", ""))
        for value in pinned_items
    }
    pinned_ids = set(requested_finding_ids)
    remaining_items = [
        value for value in ordered_items if str(value.get("id", "")) not in pinned_ids
    ]
    selected_items = [
        *pinned_items,
        *_component_diverse_items(
            remaining_items,
            record_limit - len(pinned_items),
            represented_component_ids=pinned_component_ids,
        ),
    ]
    active_component_ids = {
        str(value.get("component_id", "")) or str(value.get("id", ""))
        for value in ordered_items
    }
    selected_component_ids = {
        str(value.get("component_id", "")) or str(value.get("id", ""))
        for value in selected_items
    }
    total_active_components = len(active_component_ids)
    embedded_components = len(selected_component_ids)
    component_pass_additions = len(selected_component_ids - pinned_component_ids)
    path_inventory = {
        component_id: _valid_upstream_paths(components.get(component_id, {}))
        for component_id in active_component_ids
    }
    available_cascade_paths = sum(len(paths) for paths in path_inventory.values())
    selected_available_cascade_paths = sum(
        len(path_inventory.get(component_id, []))
        for component_id in selected_component_ids
    )
    paths_omitted_by_component_projection = sum(
        len(paths)
        for component_id, paths in path_inventory.items()
        if component_id not in selected_component_ids
    )
    paths_omitted_by_path_limit = sum(
        max(0, len(path_inventory.get(component_id, [])) - cascade_paths_per_component)
        for component_id in selected_component_ids
    )
    selected_paths = [
        path
        for component_id in selected_component_ids
        for path in path_inventory.get(component_id, [])[:cascade_paths_per_component]
    ]
    depth_truncated_paths = sum(
        len(path) - 1 > cascade_depth for path in selected_paths
    )
    segments_omitted_by_depth_limit = sum(
        max(0, len(path) - 1 - cascade_depth) for path in selected_paths
    )
    source_path_inventory_truncated_components = sum(
        1
        for component_id in active_component_ids
        if not components.get(component_id, {})
        .get("upstream_path_analysis", {})
        .get("complete_within_static_call_model", True)
    )
    finding_counts_by_component: dict[str, int] = {}
    for value in selected_items:
        component_key = str(value.get("component_id", ""))
        finding_counts_by_component[component_key] = (
            finding_counts_by_component.get(component_key, 0) + 1
        )
    for item in selected_items:
        item_id = str(item.get("id", ""))
        review = item.get("review", {})
        scanner = item.get("scanner", {})
        raw_component_id = str(item.get("component_id", ""))
        component = components.get(raw_component_id, {})
        component_id = f"component:{raw_component_id}"
        failure_id = f"failure:{item_id}"
        all_upstream_paths = path_inventory.get(raw_component_id, [])
        upstream_paths = all_upstream_paths[:cascade_paths_per_component]
        if upstream_paths:
            records_with_cascade_paths += 1
        nodes.setdefault(
            component_id,
            _node(
                component_id,
                str(item.get("component", {}).get("qualname", "component")),
                "component",
                group=(item.get("component", {}).get("subsystems") or [""])[0],
                source=f"{item.get('source', {}).get('path', '')}:{item.get('source', {}).get('line', '')}",
                layer=0,
            ),
        )
        nodes[failure_id] = _node(
            failure_id,
            str(review.get("failure_mode") or scanner.get("failure_mode", item_id)),
            "failure_mode",
            description=str(review.get("trigger") or scanner.get("trigger", "")),
            source=item_id,
            tags=[
                str(scanner.get("failure_class", "")),
                str(scanner.get("screening_priority", "")),
                *(["static_cascade_paths"] if upstream_paths else []),
            ],
            metrics={"static_upstream_paths": len(all_upstream_paths)},
            layer=1,
        )
        edges.append(
            _edge(
                f"{item_id}-may-fail",
                component_id,
                failure_id,
                "may fail as",
                "may_fail_as",
                evidence=str(scanner.get("rule_id", "")),
            )
        )

        cascade_start = failure_id
        cascade_layer = 1
        breaker = next(
            (
                value
                for value in scanner.get("detected_controls", [])
                if isinstance(value, dict) and value.get("kind") == "circuit_breaker"
            ),
            {},
        )
        if breaker and (
            breaker.get("clock_sources") or breaker.get("cooldown_expressions")
        ):
            breaker_scope = str(
                breaker.get("scope_qualname")
                or item.get("component", {}).get("qualname", "")
            )
            breaker_scope_key = stable_id(
                "breaker-scope",
                str(item.get("source", {}).get("path", "")),
                breaker_scope,
            ).lower()
            timing_id = f"timing:{breaker_scope_key}"
            nodes.setdefault(
                timing_id,
                _node(
                    timing_id,
                    "BREAKER TIMING WINDOW",
                    "timing_boundary",
                    description="Shared clock and cooldown evidence that bounds containment or recovery behavior.",
                    source=f"{item.get('source', {}).get('path', '')}:{breaker_scope}",
                    tags=("static_candidate", "timing_review_required", "scope_shared"),
                    metrics={
                        "clock_sources": breaker.get("clock_sources", []),
                        "cooldown_expressions": breaker.get("cooldown_expressions", []),
                        "control_scope": breaker_scope,
                    },
                    layer=2,
                ),
            )
            timing_metrics = nodes[timing_id]["metrics"]
            for field in ("clock_sources", "cooldown_expressions"):
                timing_metrics[field] = sorted(
                    {
                        *timing_metrics.get(field, []),
                        *breaker.get(field, []),
                    }
                )
            edges.append(
                _edge(
                    f"{item_id}-timing-window",
                    failure_id,
                    timing_id,
                    "occurs across timing boundary",
                    "timing_exposure",
                    evidence="static breaker clock/cooldown evidence",
                )
            )
            cascade_start = timing_id
            cascade_layer = 2
        if breaker:
            breaker_scope = str(
                breaker.get("scope_qualname")
                or item.get("component", {}).get("qualname", "")
            )
            breaker_scope_key = stable_id(
                "breaker-scope",
                str(item.get("source", {}).get("path", "")),
                breaker_scope,
            ).lower()
            containment_id = f"containment:{breaker_scope_key}"
            nodes.setdefault(
                containment_id,
                _node(
                    containment_id,
                    breaker_scope or "CIRCUIT BREAKER",
                    "containment_boundary",
                    description="Shared candidate containment boundary. Static detection does not establish effectiveness.",
                    source=f"{item.get('source', {}).get('path', '')}:{breaker_scope}",
                    tags=("static_candidate", "control_not_credited", "scope_shared"),
                    metrics={
                        "roles": breaker.get("roles", []),
                        "evidence_strength": breaker.get(
                            "evidence_strength", "static_candidate"
                        ),
                        "control_scope": breaker_scope,
                    },
                    layer=cascade_layer + 1,
                ),
            )
            containment_metrics = nodes[containment_id]["metrics"]
            containment_metrics["roles"] = sorted(
                {
                    *containment_metrics.get("roles", []),
                    *breaker.get("roles", []),
                }
            )
            if breaker.get("evidence_strength") == "strong":
                containment_metrics["evidence_strength"] = "strong"
            if cascade_start.startswith("timing:"):
                boundary_edge_id = f"{breaker_scope_key}-timing-containment"
            else:
                boundary_edge_id = f"{item_id}-containment-boundary"
            if boundary_edge_id not in shared_edges:
                edges.append(
                    _edge(
                        boundary_edge_id,
                        cascade_start,
                        containment_id,
                        "challenges containment",
                        "containment_challenge",
                        evidence="detected control candidate; effectiveness unconfirmed",
                    )
                )
                shared_edges.add(boundary_edge_id)
            cascade_start = containment_id
            cascade_layer += 1

        cascade_origin_id = ""
        paths_to_emit: list[list[str]] = []
        if upstream_paths:
            components_with_cascade_paths.add(raw_component_id)
            cascade_origin_id = f"cascade-origin:{raw_component_id}"
            nodes.setdefault(
                cascade_origin_id,
                _node(
                    cascade_origin_id,
                    f"{component.get('qualname', 'component')} · CALLER EXPOSURE",
                    "cascade_origin",
                    group=_component_group(component) if component else "Unassigned",
                    description="Shared origin for bounded upstream caller paths contributed by this component's selected failure modes.",
                    source=(
                        f"{component.get('source', {}).get('path', '')}:"
                        f"{component.get('source', {}).get('line', '')}"
                    ),
                    tags=("static_ast", "component_shared"),
                    metrics={
                        "selected_findings": finding_counts_by_component.get(
                            raw_component_id, 0
                        ),
                        "available_static_paths": len(all_upstream_paths),
                        "embedded_static_paths": len(upstream_paths),
                        "paths_omitted_by_diagram_limit": max(
                            0, len(all_upstream_paths) - len(upstream_paths)
                        ),
                        "source_path_inventory_complete": component.get(
                            "upstream_path_analysis", {}
                        ).get("complete_within_static_call_model", True),
                        "source_depth_limited_paths": component.get(
                            "upstream_path_analysis", {}
                        ).get("depth_limited_paths", 0),
                    },
                    layer=cascade_layer + 1,
                ),
            )
            if cascade_start.startswith(("containment:", "timing:")):
                origin_edge_id = stable_id(
                    "cascade-origin-edge", cascade_start, cascade_origin_id
                ).lower()
            else:
                origin_edge_id = f"{item_id}-cascade-origin"
            if origin_edge_id not in shared_edges:
                edges.append(
                    _edge(
                        origin_edge_id,
                        cascade_start,
                        cascade_origin_id,
                        "may escape to callers",
                        "potential_cascade_origin",
                        evidence="bounded static upstream paths",
                        description="Shared path infrastructure; each incoming finding remains independently reviewable.",
                    )
                )
                shared_edges.add(origin_edge_id)
            if raw_component_id not in emitted_cascade_components:
                emitted_cascade_components.add(raw_component_id)
                paths_to_emit = upstream_paths

        for path_index, path in enumerate(paths_to_emit, start=1):
            cascade_path_count += 1
            outward_chain = list(reversed(path))
            callee_reference = outward_chain[0]
            previous = cascade_origin_id
            seen_references = {callee_reference}
            for depth, caller_reference in enumerate(
                outward_chain[1 : cascade_depth + 1], start=1
            ):
                caller = components_by_reference.get(caller_reference, {})
                callee = components_by_reference.get(callee_reference, {})
                cycle = caller_reference in seen_references
                caller_node_id = stable_id(
                    "cascade",
                    raw_component_id,
                    str(path_index),
                    str(depth),
                    caller_reference,
                ).lower()
                observed = bool(
                    caller
                    and callee
                    and (
                        str(caller.get("id", "")),
                        str(callee.get("id", "")),
                    )
                    in runtime_relations
                )
                nodes[caller_node_id] = _node(
                    caller_node_id,
                    str(caller.get("qualname") or caller_reference),
                    "cascade_component",
                    group=_component_group(caller)
                    if caller
                    else "Unresolved static caller",
                    description=(
                        "Caller relation is present in imported runtime evidence."
                        if observed
                        else "Potential caller exposure derived from conservative static call evidence."
                    ),
                    source=(
                        f"{caller.get('source', {}).get('path', '')}:"
                        f"{caller.get('source', {}).get('line', '')}"
                        if caller
                        else caller_reference
                    ),
                    tags=(
                        ("static_ast", "observed_runtime")
                        if observed
                        else ("static_ast", "causality_unconfirmed")
                    ),
                    metrics={
                        "path_index": path_index,
                        "cascade_depth": depth,
                        "runtime_relation_observed": observed,
                        "cycle": cycle,
                    },
                    layer=cascade_layer + 1 + depth,
                    order=path_index * 10 + depth,
                )
                edges.append(
                    _edge(
                        stable_id(
                            "cascade-edge",
                            raw_component_id,
                            str(path_index),
                            str(depth),
                        ).lower(),
                        previous,
                        caller_node_id,
                        "observed caller exposure" if observed else "may expose caller",
                        "observed_upstream_exposure"
                        if observed
                        else "potential_upstream_exposure",
                        evidence="static_ast + observed_runtime"
                        if observed
                        else "static_ast",
                        description="This relationship is exposure evidence, not proof of effect propagation.",
                        order=path_index * 10 + depth,
                        cycle=cycle,
                    )
                )
                cascade_edge_count += 1
                observed_cascade_edge_count += int(observed)
                previous = caller_node_id
                callee_reference = caller_reference
                seen_references.add(caller_reference)

        previous = failure_id
        for layer, (field, kind, label) in enumerate(
            (
                ("local_effect", "local_effect", "causes locally"),
                ("next_higher_effect", "next_higher_effect", "propagates as"),
                ("end_effect", "end_effect", "may contribute to"),
            ),
            start=2,
        ):
            effect = str(review.get(field, "")).strip()
            if not effect:
                continue
            effect_id = stable_id(kind, item_id, effect).lower()
            nodes[effect_id] = _node(
                effect_id, effect, kind, source=item_id, layer=layer
            )
            edges.append(
                _edge(
                    f"{item_id}-{kind}",
                    previous,
                    effect_id,
                    label,
                    "propagates_to",
                    evidence="review_field" if review.get(field) else "scanner_seed",
                )
            )
            previous = effect_id
    records_truncated = len(selected_items) < len(ordered_items)
    cascade_paths_truncated = (
        cascade_path_count < available_cascade_paths
        or source_path_inventory_truncated_components > 0
    )
    projection_reason_codes = [
        code
        for condition, code in (
            (records_truncated, "finding_record_limit"),
            (embedded_components < total_active_components, "component_projection"),
            (paths_omitted_by_path_limit > 0, "path_limit"),
            (segments_omitted_by_depth_limit > 0, "depth_limit"),
            (
                source_path_inventory_truncated_components > 0,
                "source_path_inventory_limit",
            ),
        )
        if condition
    ]
    if source_path_inventory_truncated_components:
        projection_status = "source_inventory_bounded"
    elif projection_reason_codes:
        projection_status = "bounded_projection"
    else:
        projection_status = "complete_within_discovered_static_inventory"
    return normalize_diagram_model(
        {
            "id": "failure-propagation",
            "title": "Failure propagation",
            "type": "cause_effect",
            "description": "Component-to-failure-to-effect chains with bounded upstream caller exposure, timing, and containment evidence.",
            "notice": f"{'Explicitly included findings are embedded first; remaining capacity uses component-first selection. ' if requested_finding_ids else ''}Component-first selection embeds one priority-ordered finding per component before filling the {record_limit}-record limit; caller paths are bounded to {cascade_paths_per_component} per component and depth {cascade_depth}. Coverage counts scanner-emitted static paths and explicitly reports source, component, path, and depth truncation. Shared paths reduce duplicate graph infrastructure; static caller paths show potential exposure, not runtime causality or confirmed effect propagation.",
            "nodes": list(nodes.values()),
            "edges": edges,
            "metadata": {
                "category": "failure_propagation",
                "record_limit": record_limit,
                "conservative_node_estimate": record_limit
                * (8 + cascade_paths_per_component * cascade_depth),
                "projection_node_budget": MAX_DIAGRAM_NODES,
                "node_budget_utilization_percent": round(
                    100
                    * record_limit
                    * (8 + cascade_paths_per_component * cascade_depth)
                    / MAX_DIAGRAM_NODES,
                    1,
                ),
                "records_embedded": len(selected_items),
                "records_truncated": records_truncated,
                "projection_status": projection_status,
                "projection_reason_codes": projection_reason_codes,
                "selection_policy": (
                    "pinned_then_component_first_then_priority_fill"
                    if requested_finding_ids
                    else "component_first_then_priority_fill"
                ),
                "requested_included_finding_ids": requested_finding_ids,
                "pinned_findings_embedded": len(pinned_items),
                "pinned_components_embedded": len(pinned_component_ids),
                "components_embedded": embedded_components,
                "total_active_components": total_active_components,
                "components_truncated": embedded_components < total_active_components,
                "additional_findings_after_component_pass": max(
                    0,
                    len(selected_items) - len(pinned_items) - component_pass_additions,
                ),
                "component_coverage_percent": round(
                    100 * embedded_components / total_active_components, 1
                )
                if total_active_components
                else None,
                "cascade_paths_per_component": cascade_paths_per_component,
                "cascade_depth": cascade_depth,
                "available_discovered_cascade_paths": available_cascade_paths,
                "selected_component_discovered_cascade_paths": selected_available_cascade_paths,
                "embedded_cascade_paths": cascade_path_count,
                "cascade_paths_truncated": cascade_paths_truncated,
                "known_cascade_path_coverage_percent": round(
                    100 * cascade_path_count / available_cascade_paths, 1
                )
                if available_cascade_paths
                else None,
                "paths_omitted_by_component_projection": paths_omitted_by_component_projection,
                "paths_omitted_by_path_limit": paths_omitted_by_path_limit,
                "depth_truncated_paths": depth_truncated_paths,
                "segments_omitted_by_depth_limit": segments_omitted_by_depth_limit,
                "source_path_inventory_truncated_components": source_path_inventory_truncated_components,
                "cascade_projection_complete": not any(
                    (
                        paths_omitted_by_component_projection,
                        paths_omitted_by_path_limit,
                        depth_truncated_paths,
                        source_path_inventory_truncated_components,
                    )
                ),
                "embedded_cascade_edges": cascade_edge_count,
                "observed_cascade_edges": observed_cascade_edge_count,
                "records_with_cascade_paths": records_with_cascade_paths,
                "components_with_cascade_paths": len(components_with_cascade_paths),
                "deduplicated_record_path_reuses": max(
                    0,
                    records_with_cascade_paths - len(components_with_cascade_paths),
                ),
                "total_active_records": len(ordered_items),
            },
        }
    )


def circuit_breaker_diagrams(
    analysis: dict[str, Any], *, breaker_limit: int = 12
) -> list[dict[str, Any]]:
    """Render one reviewable state model per detected breaker scope.

    Class-based controls are usually distributed across admission, failure,
    success, and recovery methods.  Their local evidence is deliberately retained
    on each component, while this view merges only members that declare the same
    source path and control scope.
    """

    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for component in analysis.get("components", []):
        for control in component.get("detected_controls", []):
            if isinstance(control, dict) and control.get("kind") == "circuit_breaker":
                path = str(component.get("source", {}).get("path", ""))
                scope = str(
                    control.get("scope_qualname")
                    or control.get("member_qualname")
                    or component.get("qualname", "")
                )
                entry = grouped.setdefault(
                    (path, scope),
                    {"components": [], "controls": []},
                )
                entry["components"].append(component)
                entry["controls"].append(control)
    candidates = sorted(
        grouped.items(),
        key=lambda value: (
            value[0][0],
            min(
                int(component.get("source", {}).get("line", 0) or 0)
                for component in value[1]["components"]
            ),
            value[0][1],
        ),
    )
    diagrams: list[dict[str, Any]] = []
    list_fields = (
        "roles",
        "states",
        "observed_states",
        "expected_states",
        "state_symbols",
        "failure_counter_symbols",
        "threshold_expressions",
        "cooldown_expressions",
        "clock_sources",
        "synchronization",
        "scope_keys",
        "fallback_indicators",
        "detection_basis",
    )
    for index, ((path, scope), group) in enumerate(candidates[:breaker_limit], start=1):
        components = sorted(
            group["components"],
            key=lambda component: (
                int(component.get("source", {}).get("line", 0) or 0),
                str(component.get("qualname", "")),
            ),
        )
        component = components[0]
        control = {
            field: sorted(
                {
                    str(value)
                    for member_control in group["controls"]
                    for value in member_control.get(field, [])
                    if str(value)
                }
            )
            for field in list_fields
        }
        member_qualnames = sorted(
            {
                str(value.get("qualname", ""))
                for value in components
                if value.get("qualname")
            }
        )
        prefix = stable_id(
            "CB",
            path,
            scope,
        ).casefold()
        source = (
            f"{component.get('source', {}).get('path', '')}:"
            f"{component.get('source', {}).get('line', '')}"
        )
        observed_states = set(
            control.get("observed_states") or control.get("states", [])
        )
        expected_states = set(control.get("expected_states", [])) | {
            "closed",
            "open",
        }
        roles = set(control.get("roles", []))
        review_gaps: list[str] = []
        if "admission_guard" not in roles:
            review_gaps.append("Open-state admission guard is not statically evident.")
        if "failure_recording" not in roles:
            review_gaps.append("Failure accounting is not statically evident.")
        if not control.get("threshold_expressions"):
            review_gaps.append("Trip threshold expression is not statically evident.")
        recovery_expected = "half_open" in expected_states or "recovery_timer" in roles
        if recovery_expected and not control.get("cooldown_expressions"):
            review_gaps.append(
                "Cooldown boundary expression is not statically evident."
            )
        if recovery_expected and not control.get("clock_sources"):
            review_gaps.append("Elapsed-time clock source is not statically evident.")
        if recovery_expected and "half_open" not in observed_states:
            review_gaps.append(
                "HALF-OPEN state or bounded recovery probe is not explicit."
            )
        if recovery_expected and "success_reset" not in roles:
            review_gaps.append(
                "Successful recovery-to-CLOSED transition is not statically evident."
            )
        clock_sources = set(control.get("clock_sources", []))
        if any(value.endswith("time") for value in clock_sources) and not any(
            value.endswith(("monotonic", "perf_counter")) for value in clock_sources
        ):
            review_gaps.append(
                "Wall-clock timing is present without an observed monotonic duration source."
            )
        if recovery_expected and not control.get("synchronization"):
            review_gaps.append(
                "Concurrent recovery-probe serialization is not statically evident."
            )
        if not control.get("scope_keys"):
            review_gaps.append(
                "Dependency or tenant isolation key is not statically evident."
            )
        if "degraded_fallback" not in roles:
            review_gaps.append(
                "Caller-visible degraded or fallback contract is not statically evident."
            )

        def state_node(
            state: str, label: str, description: str, layer: int, order: int
        ) -> dict[str, Any]:
            observed = state in observed_states
            return _node(
                f"{prefix}-{state.replace('_', '-')}",
                label,
                "breaker_state" if observed else "unconfirmed_state",
                description=(
                    description
                    if observed
                    else f"Conceptual breaker state requiring confirmation. {description}"
                ),
                source=source,
                tags=("observed",) if observed else ("conceptual", "review_required"),
                metrics={
                    "evidence_status": "observed in AST"
                    if observed
                    else "not directly observed",
                    "scope_members": len(member_qualnames),
                },
                layer=layer,
                order=order,
            )

        nodes = [
            state_node(
                "closed",
                "CLOSED",
                "Dependency calls are admitted and consecutive failures are counted.",
                0,
                0,
            ),
            state_node(
                "open",
                "OPEN",
                "Dependency calls are contained until the recovery policy permits a probe.",
                1,
                1,
            ),
        ]
        edges: list[dict[str, Any]] = []
        threshold_evidence = " | ".join(control.get("threshold_expressions", []))
        cooldown_evidence = " | ".join(control.get("cooldown_expressions", []))
        if roles & {"failure_recording", "admission_guard", "breaker_state_management"}:
            edges.append(
                _edge(
                    f"{prefix}-trip",
                    f"{prefix}-closed",
                    f"{prefix}-open",
                    "failure threshold reached"
                    if threshold_evidence
                    else "trip policy invoked",
                    "state_transition",
                    evidence=threshold_evidence
                    or "Trip threshold requires definition and review.",
                    order=0,
                )
            )
        if recovery_expected:
            half_open_observed = "half_open" in observed_states
            nodes.append(
                state_node(
                    "half_open",
                    "HALF-OPEN" if half_open_observed else "RECOVERY PROBE",
                    "A bounded recovery probe determines whether normal admission can resume.",
                    2,
                    2,
                )
            )
            edges.append(
                _edge(
                    f"{prefix}-cooldown",
                    f"{prefix}-open",
                    f"{prefix}-half-open",
                    "cooldown elapsed"
                    if cooldown_evidence
                    else "recovery policy permits probe",
                    "timed_transition",
                    evidence=cooldown_evidence
                    or "Cooldown boundary requires definition and review.",
                    order=1,
                )
            )
            if "success_reset" in roles:
                edges.append(
                    _edge(
                        f"{prefix}-probe-success",
                        f"{prefix}-half-open",
                        f"{prefix}-closed",
                        "probe succeeds",
                        "state_transition",
                        evidence="success-reset candidate",
                        order=2,
                    )
                )
            if "failure_recording" in roles:
                edges.append(
                    _edge(
                        f"{prefix}-probe-failure",
                        f"{prefix}-half-open",
                        f"{prefix}-open",
                        "probe fails",
                        "state_transition",
                        evidence="failure-recording candidate",
                        order=3,
                    )
                )
        elif "success_reset" in roles:
            edges.append(
                _edge(
                    f"{prefix}-reset",
                    f"{prefix}-open",
                    f"{prefix}-closed",
                    "reset or success",
                    "state_transition",
                    evidence="success-reset candidate; recovery policy requires review",
                    order=2,
                )
            )
        if "degraded_fallback" in roles:
            nodes.append(
                _node(
                    f"{prefix}-fallback",
                    "DEGRADED / FALLBACK",
                    "degraded_output",
                    description="Caller-visible response while the protected dependency is isolated.",
                    source=source,
                    layer=2,
                    order=3,
                )
            )
            edges.append(
                _edge(
                    f"{prefix}-fallback-route",
                    f"{prefix}-open",
                    f"{prefix}-fallback",
                    "return degraded response",
                    "fallback",
                    evidence=" | ".join(control.get("fallback_indicators", [])),
                    order=4,
                )
            )
        if review_gaps:
            nodes.append(
                _node(
                    f"{prefix}-review-gaps",
                    f"REVIEW GAPS · {len(review_gaps)}",
                    "review_gap",
                    description="\n".join(review_gaps),
                    source=source,
                    tags=("static_evidence_gap", "review_required"),
                    metrics={"gap_count": len(review_gaps)},
                    layer=3,
                    order=10,
                )
            )
            edges.append(
                _edge(
                    f"{prefix}-gap-link",
                    f"{prefix}-open",
                    f"{prefix}-review-gaps",
                    "requires definition / evidence",
                    "evidence_gap",
                    evidence=" | ".join(review_gaps),
                    order=10,
                )
            )
        diagrams.append(
            normalize_diagram_model(
                {
                    "id": f"circuit-breaker-{index}-{prefix}",
                    "title": f"Circuit breaker: {scope or component.get('qualname', 'component')}",
                    "type": "state",
                    "description": (
                        "Candidate breaker state machine composed from Python AST "
                        f"evidence across {len(member_qualnames)} callable(s)."
                    ),
                    "notice": "Observed states are distinguished from conceptual states. Review gaps record missing static evidence, not proven defects; effectiveness still requires controlled fault-injection evidence.",
                    "nodes": nodes,
                    "edges": edges,
                    "metadata": {
                        "category": "circuit_breaker",
                        "component_id": str(component.get("id", "")),
                        "component_ids": sorted(
                            {
                                str(value.get("id", ""))
                                for value in components
                                if value.get("id")
                            }
                        ),
                        "scope_qualname": scope,
                        "member_qualnames": member_qualnames,
                        "roles": sorted(roles),
                        "observed_states": sorted(observed_states),
                        "expected_states": sorted(expected_states),
                        "review_gaps": review_gaps,
                        "detection_basis": control.get("detection_basis", []),
                        "clock_sources": control.get("clock_sources", []),
                        "scope_keys": control.get("scope_keys", []),
                        "threshold_expressions": control.get(
                            "threshold_expressions", []
                        ),
                        "cooldown_expressions": control.get("cooldown_expressions", []),
                    },
                }
            )
        )
    return diagrams


def guidance_traceability_diagram(
    analysis: dict[str, Any], *, record_limit: int = 30
) -> dict[str, Any]:
    """Build a bounded document-to-citation-to-rule-to-finding graph."""

    trace = guidance_traceability(analysis)
    finding_links = [
        value for value in trace["finding_links"] if value.get("citations")
    ][:record_limit]
    citation_ids = {
        link["citation_id"]
        for finding in finding_links
        for link in finding["citations"]
    }
    source_ids = {
        citation["source_id"]
        for citation in trace["citations"]
        if citation["id"] in citation_ids
    }
    citations = {value["id"]: value for value in trace["citations"]}
    sources = {value["id"]: value for value in trace["sources"]}
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    for index, source_id in enumerate(sorted(source_ids)):
        source = sources[source_id]
        nodes[f"guidance-source:{source_id}"] = _node(
            f"guidance-source:{source_id}",
            source["title"],
            "guidance_source",
            description=f"Version {source.get('version', '')}; status {source.get('status', '')}",
            source=source.get("url", ""),
            tags=[source.get("publisher", ""), source.get("status", "")],
            layer=0,
            order=index,
        )
    for index, citation_id in enumerate(sorted(citation_ids)):
        citation = citations[citation_id]
        locator = citation.get("locator", {})
        citation_node = f"guidance-citation:{citation_id}"
        nodes[citation_node] = _node(
            citation_node,
            f"{locator.get('section', '')} {locator.get('heading', '')}".strip(),
            "guidance_citation",
            description=citation.get("summary", ""),
            source=citation_id,
            tags=[citation.get("applicability", "")],
            layer=1,
            order=index,
        )
        edges.append(
            _edge(
                f"guidance-contains-{index}",
                f"guidance-source:{citation['source_id']}",
                citation_node,
                "contains",
                "contains_citation",
                evidence=citation_id,
            )
        )
    rule_ids = sorted({finding["rule_id"] for finding in finding_links})
    for index, rule_id in enumerate(rule_ids):
        nodes[f"guidance-rule:{rule_id}"] = _node(
            f"guidance-rule:{rule_id}",
            rule_id,
            "scanner_rule",
            layer=2,
            order=index,
        )
    seen_mapping_edges: set[str] = set()
    for finding_index, finding in enumerate(finding_links):
        finding_id = str(finding["finding_id"])
        finding_node = f"guidance-finding:{finding_id}"
        nodes[finding_node] = _node(
            finding_node,
            f"{finding['component']} / {finding['rule_id']}",
            "failure_mode",
            description="Candidate finding; engineering confirmation required.",
            source=f"{finding.get('source', {}).get('path', '')}:{finding.get('source', {}).get('line', '')}",
            tags=[finding.get("failure_class", "")],
            layer=3,
            order=finding_index,
        )
        rule_node = f"guidance-rule:{finding['rule_id']}"
        edges.append(
            _edge(
                f"guidance-finding-link-{finding_index}",
                rule_node,
                finding_node,
                "generated candidate",
                "generated_finding",
                evidence=finding_id,
            )
        )
        for link in finding["citations"]:
            mapping_id = str(link["mapping_id"])
            if mapping_id in seen_mapping_edges:
                continue
            seen_mapping_edges.add(mapping_id)
            edges.append(
                _edge(
                    f"guidance-{mapping_id.lower()}",
                    f"guidance-citation:{link['citation_id']}",
                    rule_node,
                    link["relationship"].replace("_", " "),
                    link["relationship"],
                    evidence=mapping_id,
                    description=(
                        f"{link['strength']} mapping; {link['applicability']} applicability"
                    ),
                )
            )
    return normalize_diagram_model(
        {
            "id": "guidance-traceability",
            "title": "Guidance-to-finding traceability",
            "type": "traceability",
            "description": "Versioned documents and exact locators mapped through curated scanner rules to candidate findings.",
            "notice": (
                f"Bounded to {record_limit} cited active findings. Relationships express "
                "methodology or review relevance, not noncompliance."
            ),
            "nodes": list(nodes.values()),
            "edges": edges,
            "metadata": {
                "category": "guidance_traceability",
                "record_limit": record_limit,
                "catalog_version": trace["catalog_version"],
                "catalog_sha256": trace["catalog_sha256"],
            },
        }
    )


def assurance_traceability_diagram(
    analysis: dict[str, Any], *, record_limit: int = 30
) -> dict[str, Any]:
    """Build a bounded finding-to-obligation-to-test-to-evidence graph."""

    obligations = [
        value
        for value in analysis.get("assurance", {}).get("obligations", [])
        if value.get("source_status", "active") == "active"
    ][:record_limit]
    items = {value.get("id", ""): value for value in analysis.get("items", [])}
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    for index, obligation in enumerate(obligations):
        finding_id = str(obligation.get("finding_id", ""))
        item = items.get(finding_id, {})
        finding_node = f"assurance-finding:{finding_id}"
        obligation_node = f"assurance-obligation:{obligation.get('id', '')}"
        test_node = f"assurance-test:{obligation.get('id', '')}"
        evidence_node = f"assurance-evidence:{obligation.get('id', '')}"
        nodes.extend(
            [
                _node(
                    finding_node,
                    str(
                        item.get("review", {}).get("failure_mode")
                        or item.get("scanner", {}).get("failure_mode", finding_id)
                    ),
                    "failure_mode",
                    source=(
                        f"{item.get('source', {}).get('path', '')}:"
                        f"{item.get('source', {}).get('line', '')}"
                    ),
                    tags=[str(obligation.get("failure_class", ""))],
                    layer=0,
                    order=index,
                ),
                _node(
                    obligation_node,
                    str(obligation.get("id", "")),
                    "verification_obligation",
                    description=str(obligation.get("objective", "")),
                    tags=[
                        str(obligation.get("verification_method", "")),
                        str(obligation.get("assurance_status", "")),
                    ],
                    layer=1,
                    order=index,
                ),
                _node(
                    test_node,
                    str(
                        obligation.get("automation", {}).get(
                            "proposed_test_path", "test not planned"
                        )
                    ),
                    "test_case",
                    description=str(
                        obligation.get("stimulus", {}).get("description", "")
                    ),
                    tags=[
                        str(
                            obligation.get("automation", {}).get(
                                "implementation_status", ""
                            )
                        )
                    ],
                    layer=2,
                    order=index,
                ),
                _node(
                    evidence_node,
                    f"Evidence: {obligation.get('evidence_status', 'missing')}",
                    "verification_evidence",
                    description="Execution and review artifacts; missing evidence cannot support closure.",
                    tags=[str(obligation.get("evidence_status", ""))],
                    layer=3,
                    order=index,
                ),
            ]
        )
        edges.extend(
            [
                _edge(
                    f"assurance-requires-{index}",
                    finding_node,
                    obligation_node,
                    "requires verification",
                    "requires_verification",
                    evidence=str(obligation.get("id", "")),
                ),
                _edge(
                    f"assurance-plans-{index}",
                    obligation_node,
                    test_node,
                    "planned test",
                    "planned_implementation",
                    evidence=str(
                        obligation.get("automation", {}).get(
                            "implementation_status", ""
                        )
                    ),
                ),
                _edge(
                    f"assurance-evidence-{index}",
                    test_node,
                    evidence_node,
                    "produces evidence",
                    "produces_evidence",
                    evidence=str(obligation.get("evidence_status", "")),
                ),
            ]
        )
    return normalize_diagram_model(
        {
            "id": "assurance-traceability",
            "title": "Failure-mode assurance traceability",
            "type": "traceability",
            "description": "Candidate findings mapped to verification obligations, planned tests, and evidence state.",
            "notice": (
                f"Bounded to {record_limit} active obligations. Planned or implemented tests "
                "are not evidence until approved execution and independent review."
            ),
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "category": "assurance_traceability",
                "record_limit": record_limit,
                "total_active_obligations": len(
                    [
                        value
                        for value in analysis.get("assurance", {}).get(
                            "obligations", []
                        )
                        if value.get("source_status", "active") == "active"
                    ]
                ),
            },
        }
    )


def control_coverage_diagram(
    analysis: dict[str, Any], *, record_limit: int = 30
) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    included = 0
    for item in _ordered_items(analysis):
        review = item.get("review", {})
        fields = (
            ("prevention_controls", "prevention_control", "prevented by"),
            ("detection_controls", "detection_control", "detected by"),
            ("recommended_actions", "recommended_action", "addressed by"),
            ("verification_evidence", "verification_evidence", "verified by"),
        )
        if not any(review.get(field) for field, _kind, _label in fields):
            continue
        included += 1
        if included > record_limit:
            break
        item_id = str(item.get("id", ""))
        scanner = item.get("scanner", {})
        failure_id = f"failure:{item_id}"
        nodes[failure_id] = _node(
            failure_id,
            str(review.get("failure_mode") or scanner.get("failure_mode", item_id)),
            "failure_mode",
            source=item_id,
            tags=[str(review.get("disposition", "unreviewed"))],
            layer=0,
        )
        edge_index = 0
        for field, kind, label in fields:
            for value in review.get(field, []):
                edge_index += 1
                control_id = stable_id(kind, str(value)).lower()
                nodes.setdefault(
                    control_id,
                    _node(control_id, str(value), kind, layer=1),
                )
                edges.append(
                    _edge(
                        f"{item_id}-control-{edge_index}",
                        failure_id,
                        control_id,
                        label,
                        kind,
                        evidence="review_field",
                    )
                )
    return normalize_diagram_model(
        {
            "id": "control-coverage",
            "title": "Control and action coverage",
            "type": "traceability",
            "description": "Failure modes connected to recorded controls, actions, and verification evidence.",
            "notice": "Recorded text is not proof that a control is effective or independent.",
            "nodes": list(nodes.values()),
            "edges": edges,
            "metadata": {
                "category": "control_coverage",
                "record_limit": record_limit,
                "included_records": min(included, record_limit),
            },
        }
    )


def sfta_diagrams(
    analysis: dict[str, Any], *, tree_limit: int = 12
) -> list[dict[str, Any]]:
    """Render explicit or undeveloped Software Fault Trees with SFMEA correlations."""

    model = build_sfta(analysis)
    items = {value.get("id"): value for value in analysis.get("items", [])}
    diagrams: list[dict[str, Any]] = []
    trees = model.get("trees", [])
    for tree_index, tree in enumerate(trees[:tree_limit], start=1):
        node_ids = {
            str(value["id"]): stable_id(
                "SFTA-NODE", str(tree["id"]), str(value["id"])
            ).lower()
            for value in tree.get("nodes", [])
        }
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        for order, value in enumerate(tree.get("nodes", [])):
            node_id = node_ids[str(value["id"])]
            subtype = str(value.get("gate_type") or value.get("event_type", "event"))
            nodes.append(
                _node(
                    node_id,
                    str(value.get("label", value["id"])),
                    f"sfta_{value.get('kind', 'event')}",
                    description=str(value.get("description", "")),
                    source=f"{tree.get('id')}:{value.get('id')}",
                    tags=[subtype, *value.get("assumptions", [])[:3]],
                    metrics={
                        "linked_findings": len(value.get("linked_finding_ids", []))
                    },
                    order=order,
                )
            )
            for finding_id in value.get("linked_finding_ids", [])[:20]:
                item = items.get(finding_id, {})
                finding_node = stable_id(
                    "SFTA-FINDING", str(tree["id"]), finding_id
                ).lower()
                nodes.append(
                    _node(
                        finding_node,
                        str(
                            item.get("review", {}).get("failure_mode")
                            or item.get("scanner", {}).get("failure_mode", finding_id)
                        ),
                        "failure_mode",
                        source=finding_id,
                        tags=[str(item.get("scanner", {}).get("failure_class", ""))],
                    )
                )
                edges.append(
                    _edge(
                        stable_id("SFTA-CORR", finding_id, str(value["id"])).lower(),
                        finding_node,
                        node_id,
                        "correlates to",
                        "candidate_correlation",
                        evidence=finding_id,
                    )
                )
        for value in tree.get("edges", []):
            edges.append(
                _edge(
                    stable_id("SFTA-EDGE", str(tree["id"]), str(value["id"])).lower(),
                    node_ids[str(value["source"])],
                    node_ids[str(value["target"])],
                    str(value.get("label", "input")),
                    "fault_tree_input",
                    evidence="explicit_configuration"
                    if tree.get("source") == "explicit_configuration"
                    else "generated_gap",
                )
            )
        diagrams.append(
            normalize_diagram_model(
                {
                    "id": f"sfta-{tree_index}-{stable_id('TREE', str(tree['id'])).lower()}",
                    "title": f"SFTA: {tree.get('hazard_id')} — {tree.get('top_event')}",
                    "type": "cause_effect",
                    "description": str(tree.get("description", "")),
                    "notice": model["notice"],
                    "nodes": nodes,
                    "edges": edges,
                    "metadata": {
                        "category": "sfta",
                        "tree_id": tree.get("id", ""),
                        "hazard_id": tree.get("hazard_id", ""),
                        "source": tree.get("source", ""),
                        "logic_status": tree.get("logic_status", ""),
                    },
                }
            )
        )
    return diagrams


def _selected_sequence_models(
    analysis: dict[str, Any], *, limit: int = 6
) -> list[dict[str, Any]]:
    components = [
        component
        for component in analysis.get("components", [])
        if component.get("kind") not in {"environment", "common_cause", "contract"}
    ]
    components.sort(
        key=lambda component: (
            -bool(component.get("entrypoint_types")),
            -int(component.get("screening", {}).get("score", 0) or 0),
            -int(component.get("fan_in", 0) or 0),
            str(component.get("source", {}).get("path", "")),
            str(component.get("qualname", "")),
        )
    )
    selected: list[dict[str, Any]] = []
    paths: set[str] = set()
    for component in components:
        path = str(component.get("source", {}).get("path", ""))
        if path in paths and len(selected) < max(2, limit // 2):
            continue
        try:
            model = sequence_model(
                analysis,
                str(component.get("id", "")),
                max_depth=5,
                max_interactions=40,
            )
        except ValueError:
            continue
        if not model.get("interactions"):
            continue
        model["title"] = component.get("qualname", "")
        model["path"] = path
        selected.append(model)
        paths.add(path)
        if len(selected) >= limit:
            break
    return selected


def sequence_diagrams(
    analysis: dict[str, Any], *, limit: int = 6
) -> list[dict[str, Any]]:
    diagrams: list[dict[str, Any]] = []
    for diagram_index, sequence in enumerate(
        _selected_sequence_models(analysis, limit=limit)
    ):
        nodes = [
            _node(
                str(participant.get("id", "")),
                str(participant.get("label", participant.get("id", ""))),
                "participant",
                source=str(participant.get("path", "")),
                tags=participant.get("frameworks", []),
                order=index,
            )
            for index, participant in enumerate(sequence.get("participants", []))
        ]
        edges = [
            _edge(
                f"sequence-{diagram_index + 1}-message-{index + 1}",
                str(interaction.get("source", "")),
                str(interaction.get("target", "")),
                str(interaction.get("label", "call")),
                "message",
                evidence=str(interaction.get("evidence", "")),
                order=index,
                cycle=bool(interaction.get("cycle", False)),
                description=json.dumps(
                    {
                        "confidence": interaction.get("confidence", ""),
                        "resolution": interaction.get("resolution", ""),
                        "source_line": int(interaction.get("source_line", 0) or 0),
                        "awaited": bool(interaction.get("awaited", False)),
                        "control_context": interaction.get("control_context", []),
                        "observation_status": interaction.get("observation_status", ""),
                        "static_alignment": interaction.get("static_alignment", ""),
                        "timing_status": interaction.get("timing_status", ""),
                        "duration_ns": interaction.get("duration_ns"),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
            for index, interaction in enumerate(sequence.get("interactions", []))
        ]
        diagrams.append(
            normalize_diagram_model(
                {
                    "id": f"sequence-{diagram_index + 1}-{stable_id('seq', str(sequence.get('entrypoint', ''))).lower()}",
                    "title": f"Sequence: {sequence.get('title', 'entrypoint')}",
                    "type": "sequence",
                    "description": f"{sequence.get('path', '')}:{sequence.get('title', '')}",
                    "notice": sequence.get("notice", ""),
                    "nodes": nodes,
                    "edges": edges,
                    "metadata": {
                        "category": "sequence",
                        "entrypoint": sequence.get("entrypoint", ""),
                        "truncated": bool(sequence.get("truncated")),
                        "truncation_reasons": sequence.get("truncation_reasons", []),
                        "reconciliation_static_internal_relations": sequence.get(
                            "reconciliation", {}
                        ).get("static_internal_relations", 0),
                        "reconciliation_observed_internal_relations": sequence.get(
                            "reconciliation", {}
                        ).get("observed_internal_relations", 0),
                        "reconciliation_corroborated_relations": sequence.get(
                            "reconciliation", {}
                        ).get("corroborated_relations", 0),
                        "reconciliation_static_not_observed_relations": sequence.get(
                            "reconciliation", {}
                        ).get("static_not_observed_relations", 0),
                        "reconciliation_runtime_only_relations": sequence.get(
                            "reconciliation", {}
                        ).get("runtime_only_relations", 0),
                        "reconciliation_static_observation_coverage_percent": sequence.get(
                            "reconciliation", {}
                        ).get("static_observation_coverage_percent"),
                        "reconciliation_runtime_timing_statuses": [
                            f"{key}={value}"
                            for key, value in sequence.get("reconciliation", {})
                            .get("runtime_timing_statuses", {})
                            .items()
                        ],
                    },
                }
            )
        )
    return diagrams


def build_diagram_models(
    analysis: dict[str, Any],
    *,
    kind: str = "all",
    propagation_record_limit: int = DEFAULT_PROPAGATION_RECORD_LIMIT,
    propagation_path_limit: int = DEFAULT_PROPAGATION_PATH_LIMIT,
    propagation_depth: int = DEFAULT_PROPAGATION_DEPTH,
    propagation_include_finding_ids: Iterable[str] | None = None,
    cross_reference_index: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build one category or the complete default set of canonical diagrams."""

    if kind not in GENERATED_DIAGRAM_KINDS:
        raise ValueError(
            f"diagram kind must be one of: {', '.join(GENERATED_DIAGRAM_KINDS)}"
        )
    included_finding_ids = normalize_propagation_finding_ids(
        propagation_include_finding_ids
    )
    propagation_settings_are_custom = bool(included_finding_ids) or (
        propagation_record_limit != DEFAULT_PROPAGATION_RECORD_LIMIT
        or propagation_path_limit != DEFAULT_PROPAGATION_PATH_LIMIT
        or propagation_depth != DEFAULT_PROPAGATION_DEPTH
    )
    if kind not in {"all", "failure_propagation"} and propagation_settings_are_custom:
        raise ValueError(
            "propagation projection options require diagram kind "
            "'failure_propagation' or 'all'"
        )
    builders = {
        "architecture": lambda: [
            architecture_diagram(analysis),
            deployment_topology_diagram(analysis),
            shared_fate_diagram(analysis),
            architecture_hierarchy_diagram(analysis),
        ],
        "interface_flow": lambda: [interface_flow_diagram(analysis)],
        "data_flow": lambda: [data_flow_diagram(analysis)],
        "traceability": lambda: [traceability_diagram(analysis)],
        "guidance_traceability": lambda: [guidance_traceability_diagram(analysis)],
        "assurance_traceability": lambda: [assurance_traceability_diagram(analysis)],
        "cross_reference": lambda: [
            cross_reference_diagram(analysis, index=cross_reference_index)
        ],
        "sfta": lambda: sfta_diagrams(analysis),
        "failure_propagation": lambda: [
            failure_propagation_diagram(
                analysis,
                record_limit=propagation_record_limit,
                cascade_paths_per_component=propagation_path_limit,
                cascade_depth=propagation_depth,
                include_finding_ids=included_finding_ids,
            )
        ],
        "control_coverage": lambda: [control_coverage_diagram(analysis)],
        "circuit_breaker": lambda: circuit_breaker_diagrams(analysis),
        "sequence": lambda: sequence_diagrams(analysis),
    }
    selected = list(builders) if kind == "all" else [kind]
    diagrams = [diagram for name in selected for diagram in builders[name]()]
    if len(diagrams) > MAX_DIAGRAMS:
        raise ValueError(f"generated diagram set exceeds {MAX_DIAGRAMS} diagrams")
    return diagrams


def load_diagram_files(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    """Load canonical custom diagram objects or bundles from bounded JSON files."""

    diagrams: list[dict[str, Any]] = []
    ids: set[str] = set()
    consumed_bytes = 0
    for index, source in enumerate(paths, start=1):
        if index > MAX_DIAGRAM_IMPORT_FILES:
            raise ValueError(
                "diagram imports exceed the "
                f"{MAX_DIAGRAM_IMPORT_FILES}-file import limit"
            )
        document = _read_bounded_diagram_document(
            source,
            label="diagram file",
        )
        path = document.path
        payload = document.value
        consumed_bytes += document.size
        if consumed_bytes > MAX_DIAGRAM_IMPORT_TOTAL_BYTES:
            raise ValueError(
                "diagram imports exceed the "
                f"{MAX_DIAGRAM_IMPORT_TOTAL_BYTES}-byte aggregate import limit"
            )
        if (
            isinstance(payload, dict)
            and payload.get("schema_version") == DIAGRAM_BUNDLE_SCHEMA
            and ("integrity" in payload or _bundle_requires_integrity(payload))
        ):
            try:
                verify_diagram_bundle_integrity(payload)
            except ValueError as exc:
                raise ValueError(
                    f"diagram bundle integrity failed: {path}: {exc}"
                ) from exc
        if isinstance(payload, dict) and "diagrams" in payload:
            raw_diagrams = payload.get("diagrams")
        elif isinstance(payload, list):
            raw_diagrams = payload
        else:
            raw_diagrams = [payload]
        if not isinstance(raw_diagrams, list):
            raise ValueError(f"diagram bundle diagrams must be an array: {path}")
        for raw in raw_diagrams:
            diagram = normalize_diagram_model(raw)
            if diagram["id"] in ids:
                raise ValueError(f"duplicate imported diagram id: {diagram['id']}")
            ids.add(diagram["id"])
            diagram["metadata"]["imported_from"] = path.name
            diagram["metadata"]["imported_file"] = {
                "bytes": document.size,
                "sha256": hashlib.sha256(document.raw).hexdigest(),
            }
            diagrams.append(diagram)
            if len(diagrams) > MAX_DIAGRAMS:
                raise ValueError(f"diagram imports exceed {MAX_DIAGRAMS} diagrams")
    return diagrams


def _read_bounded_diagram_json(
    source: str | Path, *, label: str
) -> tuple[Path, Any, int]:
    """Read one strict diagram JSON document through the shared safe boundary."""

    document = _read_bounded_diagram_document(source, label=label)
    return document.path, document.value, document.size


def _read_bounded_diagram_document(
    source: str | Path, *, label: str
) -> BoundedJsonDocument:
    """Capture strict diagram JSON from one exact identity-stable file snapshot."""

    candidate = Path(source).expanduser().absolute()
    try:
        return load_bounded_json_document(
            candidate,
            label=label,
            max_bytes=MAX_DIAGRAM_FILE_BYTES,
            max_depth=MAX_DIAGRAM_JSON_DEPTH,
            max_nodes=MAX_DIAGRAM_JSON_NODES,
        )
    except ValueError as exc:
        message = str(exc)
        if message == f"{label} exceeds the {MAX_DIAGRAM_FILE_BYTES}-byte limit":
            message = f"{label} exceeds {MAX_DIAGRAM_FILE_BYTES} bytes"
        elif message in {
            f"{label} must be an available regular file",
            f"{label} must be a regular non-symbolic-link file",
        }:
            message = f"{label} must be a regular non-symbolic link file"
        elif message in {
            f"{label} is not valid UTF-8 JSON",
            f"{label} is not valid JSON",
            f"{label} exceeds the JSON parser nesting limit",
        }:
            message = f"{label} is not valid bounded UTF-8 JSON"
        raise ValueError(f"{message}: {candidate}") from exc


def diagram_bundle(
    analysis: dict[str, Any],
    *,
    kind: str = "all",
    propagation_record_limit: int = DEFAULT_PROPAGATION_RECORD_LIMIT,
    propagation_path_limit: int = DEFAULT_PROPAGATION_PATH_LIMIT,
    propagation_depth: int = DEFAULT_PROPAGATION_DEPTH,
    propagation_include_finding_ids: Iterable[str] | None = None,
) -> dict[str, Any]:
    included_finding_ids = normalize_propagation_finding_ids(
        propagation_include_finding_ids
    )
    bundle = {
        "schema_version": DIAGRAM_BUNDLE_SCHEMA,
        "generator": {"name": "PySFMEA", "version": __version__},
        "generated_at": utc_now(),
        "project": {
            "name": analysis.get("project", {}).get("name", ""),
            "baseline_id": analysis.get("project", {})
            .get("baseline", {})
            .get("id", ""),
        },
        "generation": {
            "kind": kind,
            "failure_propagation": {
                "record_limit": propagation_record_limit,
                "paths_per_component": propagation_path_limit,
                "depth": propagation_depth,
                "include_finding_ids": included_finding_ids,
            },
        },
        "binding": {
            "format": DIAGRAM_BUNDLE_SCHEMA,
            "baseline_id": str(
                analysis.get("project", {}).get("baseline", {}).get("id", "")
            ),
            "analysis_schema_version": str(analysis.get("schema_version", "")),
            "analysis_state_sha256": canonical_json_sha256(analysis),
        },
        "diagrams": build_diagram_models(
            analysis,
            kind=kind,
            propagation_record_limit=propagation_record_limit,
            propagation_path_limit=propagation_path_limit,
            propagation_depth=propagation_depth,
            propagation_include_finding_ids=included_finding_ids,
        ),
    }
    bundle["integrity"] = {
        "algorithm": "sha256",
        "canonicalization": "json-sort-keys-compact-utf8",
        "content_sha256": _diagram_bundle_content_sha256(bundle),
    }
    return bundle


def _diagram_bundle_content_sha256(bundle: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in bundle.items() if key != "integrity"}
    return canonical_json_sha256(unsigned)


def _bundle_requires_integrity(bundle: dict[str, Any]) -> bool:
    generator = bundle.get("generator")
    if not isinstance(generator, dict) or generator.get("name") != "PySFMEA":
        return False
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", str(generator.get("version", "")))
    if not match:
        return False
    return tuple(int(value) for value in match.groups()) >= (
        INTEGRITY_REQUIRED_GENERATOR_VERSION
    )


def verify_diagram_bundle_integrity(
    bundle: dict[str, Any], *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Verify bundle content and optionally its governed-analysis binding."""

    if bundle.get("schema_version") != DIAGRAM_BUNDLE_SCHEMA:
        raise ValueError("diagram bundle schema version is not supported")
    integrity = bundle.get("integrity")
    if not isinstance(integrity, dict):
        raise ValueError("diagram bundle integrity record is missing")
    if integrity.get("algorithm") != "sha256":
        raise ValueError("diagram bundle integrity algorithm must be sha256")
    if integrity.get("canonicalization") != "json-sort-keys-compact-utf8":
        raise ValueError("diagram bundle canonicalization is not supported")
    expected = str(integrity.get("content_sha256", "")).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("diagram bundle content digest is malformed")
    actual = _diagram_bundle_content_sha256(bundle)
    if actual != expected:
        raise ValueError("diagram bundle content digest does not match its contents")
    binding = bundle.get("binding")
    if not isinstance(binding, dict):
        raise ValueError("diagram bundle analysis binding is missing")
    if binding.get("format") != DIAGRAM_BUNDLE_SCHEMA:
        raise ValueError("diagram bundle binding format does not match its schema")
    bound_state = str(binding.get("analysis_state_sha256", "")).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", bound_state):
        raise ValueError("diagram bundle analysis-state digest is malformed")
    binding_matches: bool | None = None
    if analysis is not None:
        if str(binding.get("analysis_schema_version", "")) != str(
            analysis.get("schema_version", "")
        ):
            raise ValueError("diagram bundle analysis schema binding does not match")
        if str(binding.get("baseline_id", "")) != str(
            analysis.get("project", {}).get("baseline", {}).get("id", "")
        ):
            raise ValueError("diagram bundle baseline binding does not match")
        binding_matches = bound_state == canonical_json_sha256(analysis)
        if not binding_matches:
            raise ValueError("diagram bundle analysis-state binding does not match")
    return {
        "algorithm": "sha256",
        "content_sha256": actual,
        "analysis_state_sha256": bound_state,
        "analysis_binding_matches": binding_matches,
    }


def verify_diagram_bundle_file(
    source: str | Path, *, analysis: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Verify a bounded bundle file, its diagram schemas, and optional analysis binding."""

    path, payload, size = _read_bounded_diagram_json(source, label="diagram bundle")
    if not isinstance(payload, dict):
        raise ValueError("diagram bundle root must be an object")
    verification = verify_diagram_bundle_integrity(payload, analysis=analysis)
    raw_diagrams = payload.get("diagrams")
    if not isinstance(raw_diagrams, list):
        raise ValueError("diagram bundle diagrams must be an array")
    if len(raw_diagrams) > MAX_DIAGRAMS:
        raise ValueError(f"diagram bundle exceeds {MAX_DIAGRAMS} diagrams")
    diagram_ids = [normalize_diagram_model(value)["id"] for value in raw_diagrams]
    if len(diagram_ids) != len(set(diagram_ids)):
        raise ValueError("diagram bundle contains duplicate diagram IDs")
    return {
        "format": DIAGRAM_BUNDLE_VERIFICATION_FORMAT,
        "verifier": {"name": "PySFMEA", "version": __version__},
        "path": str(path),
        "bytes": size,
        "valid": True,
        "status": "matched" if analysis is not None else "valid_binding_not_checked",
        "binding_requested": analysis is not None,
        "binding_checked": analysis is not None,
        "schema_version": payload.get("schema_version", ""),
        "generator": payload.get("generator", {}),
        "generated_at": payload.get("generated_at", ""),
        "project": payload.get("project", {}),
        "binding": payload.get("binding", {}),
        "generation": payload.get("generation", {}),
        "diagram_count": len(diagram_ids),
        "diagram_ids": diagram_ids,
        "checks": {
            "content_integrity": True,
            "diagram_schema": True,
            "analysis_binding": verification["analysis_binding_matches"],
        },
        "failed_checks": [],
        "unchecked_checks": [] if analysis is not None else ["analysis_binding"],
        "errors": [],
        "content_sha256": verification["content_sha256"],
        "notice": (
            "Integrity and binding checks detect unreconciled changes and staleness; "
            "they do not authenticate an author, approve the analysis, or accept risk."
        ),
    }


def export_diagram_bundle(
    analysis: dict[str, Any],
    destination: str | Path,
    *,
    kind: str = "all",
    propagation_record_limit: int = DEFAULT_PROPAGATION_RECORD_LIMIT,
    propagation_path_limit: int = DEFAULT_PROPAGATION_PATH_LIMIT,
    propagation_depth: int = DEFAULT_PROPAGATION_DEPTH,
    propagation_include_finding_ids: Iterable[str] | None = None,
) -> Path:
    document = (
        json.dumps(
            diagram_bundle(
                analysis,
                kind=kind,
                propagation_record_limit=propagation_record_limit,
                propagation_path_limit=propagation_path_limit,
                propagation_depth=propagation_depth,
                propagation_include_finding_ids=propagation_include_finding_ids,
            ),
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )
    return atomic_publish_text(
        destination,
        document,
        label="diagram bundle",
    )
