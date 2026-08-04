"""Canonical diagram models, validation, imports, and SFMEA diagram builders."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from .architecture import architecture_graph
from .guidance import guidance_traceability
from .model import stable_id, utc_now
from .sfta import build_sfta
from .version import __version__
from .visuals import sequence_model

DIAGRAM_SCHEMA = "pysfmea-diagram-1"
DIAGRAM_BUNDLE_SCHEMA = "pysfmea-diagram-bundle-1"
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
    "traceability",
    "guidance_traceability",
    "assurance_traceability",
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
MAX_TEXT_LENGTH = 8_000
_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")


def _string(value: Any, field: str, *, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValueError(f"diagram {field} must be a string")
    value = value.strip()
    if required and not value:
        raise ValueError(f"diagram {field} is required")
    if len(value) > MAX_TEXT_LENGTH:
        raise ValueError(f"diagram {field} exceeds {MAX_TEXT_LENGTH} characters")
    return value


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
        elif isinstance(entry, list) and len(entry) <= 100 and all(
            isinstance(part, (str, int, float, bool)) or part is None
            for part in entry
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
        raise ValueError(
            f"diagram type must be one of: {', '.join(DIAGRAM_TYPES)}"
        )
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
            isinstance(layer, bool) or not isinstance(layer, int) or not 0 <= layer <= 100
        ):
            raise ValueError(f"diagram node {node_id} layer must be an integer from 0 through 100")
        if order is not None and (
            isinstance(order, bool) or not isinstance(order, int) or not 0 <= order <= 100_000
        ):
            raise ValueError(f"diagram node {node_id} order must be a non-negative integer")
        nodes.append(
            {
                "id": node_id,
                "label": _string(raw.get("label"), f"node {node_id} label", required=True),
                "kind": _string(raw.get("kind", "element"), f"node {node_id} kind", required=True),
                "group": _string(raw.get("group", ""), f"node {node_id} group"),
                "description": _string(raw.get("description", ""), f"node {node_id} description"),
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
        edge_id = _identifier(raw.get("id", f"edge-{index + 1}"), f"edge {index + 1} id")
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
            isinstance(order, bool) or not isinstance(order, int) or not 0 <= order <= 100_000
        ):
            raise ValueError(f"diagram edge {edge_id} order must be a non-negative integer")
        edges.append(
            {
                "id": edge_id,
                "source": source,
                "target": target,
                "label": _string(raw.get("label", ""), f"edge {edge_id} label"),
                "kind": _string(raw.get("kind", "relationship"), f"edge {edge_id} kind", required=True),
                "evidence": _string(raw.get("evidence", ""), f"edge {edge_id} evidence"),
                "description": _string(raw.get("description", ""), f"edge {edge_id} description"),
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
    return "/".join(parts[:2]) if len(parts) > 1 else (parts[0] if parts else "Unassigned")


def architecture_diagram(analysis: dict[str, Any], *, component_limit: int = 120) -> dict[str, Any]:
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
            if source_id in selected and target_id in by_id and target_id not in selected:
                selected[target_id] = by_id[target_id]
                changed = True
            elif target_id in selected and source_id in by_id and source_id not in selected:
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
            tags=[*component.get("frameworks", []), *component.get("entrypoint_types", [])],
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


def interface_flow_diagram(analysis: dict[str, Any]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    for index, interface in enumerate(analysis.get("context", {}).get("system_interfaces", [])):
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
    return normalize_diagram_model(
        {
            "id": "system-interface-flow",
            "title": "System interface flow",
            "type": "flow",
            "description": "Configured sources, targets, and system-boundary relationships.",
            "notice": "Direction and meaning come from configured system-interface statements.",
            "nodes": list(nodes.values()),
            "edges": edges,
            "metadata": {"category": "interface_flow"},
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


def failure_propagation_diagram(
    analysis: dict[str, Any], *, record_limit: int = 40
) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    for item in _ordered_items(analysis)[:record_limit]:
        item_id = str(item.get("id", ""))
        review = item.get("review", {})
        scanner = item.get("scanner", {})
        component_id = f"component:{item.get('component_id', '')}"
        failure_id = f"failure:{item_id}"
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
            tags=[str(scanner.get("failure_class", "")), str(scanner.get("screening_priority", ""))],
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
            nodes[effect_id] = _node(effect_id, effect, kind, source=item_id, layer=layer)
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
    return normalize_diagram_model(
        {
            "id": "failure-propagation",
            "title": "Failure propagation",
            "type": "cause_effect",
            "description": "Component-to-failure-to-effect chains for the highest-priority active records.",
            "notice": f"Bounded to {record_limit} records. Candidate and seeded effects require engineering confirmation.",
            "nodes": list(nodes.values()),
            "edges": edges,
            "metadata": {
                "category": "failure_propagation",
                "record_limit": record_limit,
                "total_active_records": len(_ordered_items(analysis)),
            },
        }
    )


def circuit_breaker_diagrams(
    analysis: dict[str, Any], *, breaker_limit: int = 12
) -> list[dict[str, Any]]:
    """Render statically detected breaker candidates as reviewable state models."""

    candidates: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for component in analysis.get("components", []):
        for control in component.get("detected_controls", []):
            if isinstance(control, dict) and control.get("kind") == "circuit_breaker":
                candidates.append((component, control))
    candidates.sort(
        key=lambda value: (
            str(value[0].get("source", {}).get("path", "")),
            int(value[0].get("source", {}).get("line", 0) or 0),
            str(value[0].get("qualname", "")),
        )
    )
    diagrams: list[dict[str, Any]] = []
    for index, (component, control) in enumerate(candidates[:breaker_limit], start=1):
        prefix = stable_id(
            "CB",
            str(component.get("id", "")),
            str(component.get("qualname", "")),
        ).casefold()
        source = (
            f"{component.get('source', {}).get('path', '')}:"
            f"{component.get('source', {}).get('line', '')}"
        )
        states = set(control.get("states", []))
        roles = set(control.get("roles", []))
        nodes = [
            _node(
                f"{prefix}-closed",
                "CLOSED",
                "breaker_state",
                description="Dependency calls are admitted and consecutive failures are counted.",
                source=source,
                layer=0,
                order=0,
            ),
            _node(
                f"{prefix}-open",
                "OPEN",
                "breaker_state",
                description="Dependency calls are contained until the recovery policy permits a probe.",
                source=source,
                layer=1,
                order=1,
            ),
        ]
        edges: list[dict[str, Any]] = []
        threshold = " | ".join(control.get("threshold_expressions", [])) or "static candidate threshold"
        cooldown = " | ".join(control.get("cooldown_expressions", [])) or "configured cooldown"
        if roles & {"failure_recording", "admission_guard", "breaker_state_management"}:
            edges.append(
                _edge(
                    f"{prefix}-trip",
                    f"{prefix}-closed",
                    f"{prefix}-open",
                    "failure threshold reached",
                    "state_transition",
                    evidence=threshold,
                    order=0,
                )
            )
        if "half_open" in states:
            nodes.append(
                _node(
                    f"{prefix}-half-open",
                    "HALF-OPEN",
                    "breaker_state",
                    description="A bounded recovery probe determines whether normal admission can resume.",
                    source=source,
                    layer=2,
                    order=2,
                )
            )
            edges.extend(
                [
                    _edge(
                        f"{prefix}-cooldown",
                        f"{prefix}-open",
                        f"{prefix}-half-open",
                        "cooldown elapsed",
                        "timed_transition",
                        evidence=cooldown,
                        order=1,
                    ),
                    _edge(
                        f"{prefix}-probe-success",
                        f"{prefix}-half-open",
                        f"{prefix}-closed",
                        "probe succeeds",
                        "state_transition",
                        evidence="success-reset candidate",
                        order=2,
                    ),
                    _edge(
                        f"{prefix}-probe-failure",
                        f"{prefix}-half-open",
                        f"{prefix}-open",
                        "probe fails",
                        "state_transition",
                        evidence="failure-recording candidate",
                        order=3,
                    ),
                ]
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
        diagrams.append(
            normalize_diagram_model(
                {
                    "id": f"circuit-breaker-{index}-{prefix}",
                    "title": f"Circuit breaker: {component.get('qualname', 'component')}",
                    "type": "state",
                    "description": "Candidate breaker state machine extracted from Python AST evidence.",
                    "notice": "Static candidate only. Transitions, timing, isolation, and fallback effectiveness require controlled fault-injection evidence.",
                    "nodes": nodes,
                    "edges": edges,
                    "metadata": {
                        "category": "circuit_breaker",
                        "component_id": str(component.get("id", "")),
                        "roles": sorted(roles),
                        "clock_sources": control.get("clock_sources", []),
                        "scope_keys": control.get("scope_keys", []),
                        "threshold_expressions": control.get("threshold_expressions", []),
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


def sfta_diagrams(analysis: dict[str, Any], *, tree_limit: int = 12) -> list[dict[str, Any]]:
    """Render explicit or undeveloped Software Fault Trees with SFMEA correlations."""

    model = build_sfta(analysis)
    items = {value.get("id"): value for value in analysis.get("items", [])}
    diagrams: list[dict[str, Any]] = []
    trees = model.get("trees", [])
    for tree_index, tree in enumerate(trees[:tree_limit], start=1):
        node_ids = {
            str(value["id"]): stable_id("SFTA-NODE", str(tree["id"]), str(value["id"])).lower()
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
                    metrics={"linked_findings": len(value.get("linked_finding_ids", []))},
                    order=order,
                )
            )
            for finding_id in value.get("linked_finding_ids", [])[:20]:
                item = items.get(finding_id, {})
                finding_node = stable_id("SFTA-FINDING", str(tree["id"]), finding_id).lower()
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


def sequence_diagrams(analysis: dict[str, Any], *, limit: int = 6) -> list[dict[str, Any]]:
    diagrams: list[dict[str, Any]] = []
    for diagram_index, sequence in enumerate(_selected_sequence_models(analysis, limit=limit)):
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
                    },
                }
            )
        )
    return diagrams


def build_diagram_models(
    analysis: dict[str, Any], *, kind: str = "all"
) -> list[dict[str, Any]]:
    """Build one category or the complete default set of canonical diagrams."""

    if kind not in GENERATED_DIAGRAM_KINDS:
        raise ValueError(
            f"diagram kind must be one of: {', '.join(GENERATED_DIAGRAM_KINDS)}"
        )
    builders = {
        "architecture": lambda: [architecture_diagram(analysis)],
        "interface_flow": lambda: [interface_flow_diagram(analysis)],
        "traceability": lambda: [traceability_diagram(analysis)],
        "guidance_traceability": lambda: [guidance_traceability_diagram(analysis)],
        "assurance_traceability": lambda: [assurance_traceability_diagram(analysis)],
        "sfta": lambda: sfta_diagrams(analysis),
        "failure_propagation": lambda: [failure_propagation_diagram(analysis)],
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
    for source in paths:
        path = Path(source).expanduser().resolve()
        if not path.is_file():
            raise ValueError(f"diagram file does not exist: {path}")
        if path.stat().st_size > MAX_DIAGRAM_FILE_BYTES:
            raise ValueError(f"diagram file exceeds {MAX_DIAGRAM_FILE_BYTES} bytes: {path}")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"diagram file is not valid UTF-8 JSON: {path}: {exc}") from exc
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
            diagrams.append(diagram)
            if len(diagrams) > MAX_DIAGRAMS:
                raise ValueError(f"diagram imports exceed {MAX_DIAGRAMS} diagrams")
    return diagrams


def diagram_bundle(
    analysis: dict[str, Any], *, kind: str = "all"
) -> dict[str, Any]:
    return {
        "schema_version": DIAGRAM_BUNDLE_SCHEMA,
        "generator": {"name": "PySFMEA", "version": __version__},
        "generated_at": utc_now(),
        "project": {
            "name": analysis.get("project", {}).get("name", ""),
            "baseline_id": analysis.get("project", {}).get("baseline", {}).get("id", ""),
        },
        "diagrams": build_diagram_models(analysis, kind=kind),
    }


def export_diagram_bundle(
    analysis: dict[str, Any],
    destination: str | Path,
    *,
    kind: str = "all",
) -> Path:
    path = Path(destination).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(diagram_bundle(analysis, kind=kind), indent=2, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
    )
    return path
