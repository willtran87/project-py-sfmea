"""Functional propagation graph derived from scanner evidence and project context."""

from __future__ import annotations

import hashlib
import html
import json
import re
from pathlib import Path
from typing import Any


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
        for node_id, label in ((source, interface.get("source", "")), (target, interface.get("target", ""))):
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
    return {"nodes": nodes, "edges": edges, "system_interfaces": interfaces}


def export_architecture(
    analysis: dict[str, Any], destination: str | Path, *, format: str = "markdown"
) -> Path:
    path = Path(destination).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    graph = architecture_graph(analysis)
    if format == "json":
        path.write_text(json.dumps(graph, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return path
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
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


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
    return html.escape(str(value or ""), quote=False).replace("\r", " ").replace("\n", " ")
