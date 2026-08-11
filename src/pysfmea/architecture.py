"""Functional propagation graph derived from scanner evidence and project context."""

from __future__ import annotations

import hashlib
import html
import json
import re
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text


def architecture_graph(analysis: dict[str, Any]) -> dict[str, Any]:
    components = analysis.get("components", [])
    by_reference = {
        f"{component.get('source', {}).get('path', '')}:{component.get('qualname', '')}": component
        for component in components
    }
    nodes = [
        {
            "id": component.get("id", ""),
            "kind": "component",
            "label": component.get("qualname", ""),
            "path": component.get("source", {}).get("path", ""),
            "subsystems": component.get("subsystems", []),
            "requirements": component.get("requirement_ids", []),
            "affected_component_ids": component.get("affected_component_ids", []),
        }
        for component in components
    ]
    edges: list[dict[str, Any]] = []
    for target in components:
        for caller_reference in target.get("called_by", []):
            caller = by_reference.get(caller_reference)
            if caller:
                edges.append(
                    {
                        "source": caller.get("id", ""),
                        "target": target.get("id", ""),
                        "kind": "internal_call",
                        "label": "calls",
                        "evidence": "static_ast",
                    }
                )
    for common_cause in components:
        if common_cause.get("kind") != "common_cause":
            continue
        for affected_id in common_cause.get("affected_component_ids", []):
            edges.append(
                {
                    "source": common_cause.get("id", ""),
                    "target": affected_id,
                    "kind": "common_cause",
                    "label": "may affect",
                    "evidence": "configured_common_cause",
                }
            )
    interfaces = analysis.get("context", {}).get("system_interfaces", [])
    for interface in interfaces:
        source = "EXT-" + _safe_id(interface.get("source", "source"))
        target = "EXT-" + _safe_id(interface.get("target", "target"))
        for node_id, label in (
            (source, interface.get("source", "")),
            (target, interface.get("target", "")),
        ):
            if not any(node["id"] == node_id for node in nodes):
                nodes.append(
                    {
                        "id": node_id,
                        "kind": "system_boundary",
                        "label": label,
                        "path": "",
                        "subsystems": [],
                        "requirements": [],
                    }
                )
        edges.append(
            {
                "source": source,
                "target": target,
                "kind": "system_interface",
                "label": interface.get("id", "interface"),
                "description": interface.get("description", ""),
                "evidence": "configured_interface",
            }
        )
        interface_id = interface.get("id", "")
        for component in components:
            if interface_id and interface_id in component.get("interface_ids", []):
                edges.append(
                    {
                        "source": component.get("id", ""),
                        "target": target,
                        "kind": "component_interface",
                        "label": interface_id,
                        "evidence": "configured_mapping",
                    }
                )
    component_ids = {component.get("id", "") for component in components}
    for runtime_edge in analysis.get("runtime_evidence", {}).get("edges", []):
        source = runtime_edge.get("source_component_id", "")
        target = runtime_edge.get("target_component_id", "")
        if source in component_ids and target in component_ids:
            edges.append(
                {
                    "source": source,
                    "target": target,
                    "kind": "observed_runtime",
                    "label": runtime_edge.get("operation", "observed call"),
                    "evidence": "observed_runtime",
                    "trace_id": runtime_edge.get("trace_id", ""),
                }
            )
    return {
        "nodes": nodes,
        "edges": edges,
        "system_interfaces": interfaces,
        "deployment_topology": analysis.get("deployment_topology", {}),
        "shared_fate_analysis": analysis.get("shared_fate_analysis", {}),
        "architecture_hierarchy": analysis.get("architecture_hierarchy", {}),
    }


def export_architecture(
    analysis: dict[str, Any], destination: str | Path, *, format: str = "markdown"
) -> Path:
    graph = architecture_graph(analysis)
    if format == "json":
        return atomic_publish_text(
            destination,
            json.dumps(graph, indent=2, ensure_ascii=False) + "\n",
            label="architecture JSON export",
        )
    if format != "markdown":
        raise ValueError("architecture format must be markdown or json")
    context = analysis.get("context", {})
    analysis_context = dict(context.get("analysis", {}))
    for field in ("phase", "revision"):
        if analysis_context.get(field):
            analysis_context[field] = _markdown_text(analysis_context[field])
    lines = [
        f"# Functional propagation view — {analysis.get('project', {}).get('name', '')}",
        "",
        f"- Lifecycle phase: {analysis_context.get('phase', 'not configured')}",
        f"- Analysis revision: {analysis_context.get('revision', 'not configured') or 'not configured'}",
        "",
        "> This graph is derived from conservative static call evidence and configured system interfaces. Dynamic dispatch and runtime wiring can be missing.",
        "",
        "```mermaid",
        "flowchart LR",
    ]
    lines[0] = "# Functional propagation view - " + _markdown_text(
        analysis.get("project", {}).get("name", "")
    )
    node_names: dict[str, str] = {}
    for index, node in enumerate(graph["nodes"]):
        node_name = f"N{index}"
        node_names[node["id"]] = node_name
        suffix = f"\\n{node['path']}" if node.get("path") else ""
        lines.append(f'  {node_name}["{_label(node["label"] + suffix)}"]')
    for edge in graph["edges"]:
        source = node_names.get(edge["source"])
        target = node_names.get(edge["target"])
        if source and target:
            lines.append(f'  {source} -->|"{_label(edge.get("label", ""))}"| {target}')
    lines.extend(["```", "", "## Ground rules", ""])
    ground_rules = analysis_context.get("ground_rules", [])
    lines.extend(f"- {_markdown_text(rule)}" for rule in ground_rules)
    if not ground_rules:
        lines.append("- Not configured")
    lines.extend(["", "## System interfaces", ""])
    for interface in graph["system_interfaces"]:
        interface = {
            key: _markdown_text(value) if isinstance(value, str) else value
            for key, value in interface.items()
        }
        lines.append(
            f"- **{interface.get('id', '')}**: {interface.get('source', '')} → "
            f"{interface.get('target', '')} — {interface.get('description', '')}"
        )
    if not graph["system_interfaces"]:
        lines.append("- None configured")
    deployment = graph.get("deployment_topology", {})
    deployment_summary = deployment.get("summary", {})
    deployment_nodes = deployment.get("nodes", [])[:100]
    deployment_node_names = {
        str(value.get("id", "")): f"D{index}"
        for index, value in enumerate(deployment_nodes)
    }
    lines.extend(
        [
            "",
            "## Declared deployment topology",
            "",
            f"- Nodes: {deployment_summary.get('nodes_embedded', 0)} embedded / {deployment_summary.get('nodes_discovered', 0)} discovered",
            f"- Relationships: {deployment_summary.get('edges_embedded', 0)} embedded / {deployment_summary.get('edges_discovered', 0)} discovered",
            f"- Candidate placements: {deployment_summary.get('placed_components', 0)} placed; {deployment_summary.get('unplaced_components', 0)} unplaced",
            "",
            "> Repository declarations and heuristic placements are not observed runtime topology.",
        ]
    )
    if deployment_nodes:
        lines.extend(["", "```mermaid", "flowchart LR"])
        for node in deployment_nodes:
            node_name = deployment_node_names[str(node.get("id", ""))]
            label = f"{node.get('name', '')}\\n{node.get('kind', '')}"
            lines.append(f'  {node_name}["{_label(label)}"]')
        for edge in deployment.get("edges", []):
            source = deployment_node_names.get(str(edge.get("source_node_id", "")))
            target = deployment_node_names.get(str(edge.get("target_node_id", "")))
            if source and target:
                lines.append(
                    f'  {source} -->|"{_label(str(edge.get("kind", "")))}"| {target}'
                )
        lines.extend(["```", ""])
    else:
        lines.extend(["", "- No supported deployment declarations were discovered."])
    shared_fate = graph.get("shared_fate_analysis", {})
    lines.extend(["", "## Shared-fate candidates", ""])
    for region in shared_fate.get("regions", [])[:100]:
        lines.append(
            f"- **{_markdown_text(region.get('kind', 'candidate'))}: "
            f"{_markdown_text(region.get('key', ''))}** - "
            f"{len(region.get('affected_component_ids', []))} affected components"
        )
    if not shared_fate.get("regions"):
        lines.append("- No multi-component shared-fate candidate was discovered.")
    lines.extend(
        [
            "",
            "> Shared membership is a common-cause review lead, not proof of correlated failure or independence.",
        ]
    )
    hierarchy = graph.get("architecture_hierarchy", {})
    hierarchy_nodes = hierarchy.get("nodes", [])[:100]
    hierarchy_names = {
        str(value.get("id", "")): f"H{index}"
        for index, value in enumerate(hierarchy_nodes)
    }
    lines.extend(["", "## Architecture hierarchy and inherited trace", ""])
    if hierarchy_nodes:
        lines.extend(["```mermaid", "flowchart TD"])
        for node in hierarchy_nodes:
            node_name = hierarchy_names[str(node.get("id", ""))]
            trace = node.get("effective_trace", {})
            label = (
                f"{node.get('name', '')}\\n{len(node.get('component_ids', []))} components"
                f" / {len(trace.get('requirements', []))} requirements"
                f" / {len(trace.get('hazards', []))} hazards"
            )
            lines.append(f'  {node_name}["{_label(label)}"]')
        for node in hierarchy_nodes:
            parent = hierarchy_names.get(str(node.get("parent_id", "")))
            child = hierarchy_names.get(str(node.get("id", "")))
            if parent and child:
                lines.append(f"  {parent} --> {child}")
        lines.extend(["```", ""])
    else:
        lines.append("- No architecture hierarchy was generated.")
    lines.append(
        "> Trace rolls upward only from governed mappings; the projection does not approve the architecture."
    )
    return atomic_publish_text(
        destination,
        "\n".join(lines) + "\n",
        label="architecture Markdown export",
    )


def _safe_id(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", value).strip("-") or "boundary"
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
    return f"{slug}-{digest}"


def _label(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("\r\n", "\\n")
        .replace("\r", "\\n")
        .replace("\n", "\\n")
        .replace('"', "'")
        .replace("`", "'")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _markdown_text(value: Any) -> str:
    return (
        html.escape(str(value or ""), quote=False).replace("\r", " ").replace("\n", " ")
    )
