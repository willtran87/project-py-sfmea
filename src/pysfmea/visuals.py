"""Sequence, traceability, and analysis-coverage visualizations."""

from __future__ import annotations

import hashlib
import html
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .architecture import architecture_graph
from .file_publication import atomic_publish_text
from .repository_inventory import repository_inventory_summary_projection


def _md(value: Any) -> str:
    return (
        html.escape(str(value or ""), quote=False).replace("\r", " ").replace("\n", " ")
    )


def _mermaid(value: Any) -> str:
    return (
        str(value or "")
        .replace("\\", "\\\\")
        .replace("\r", " ")
        .replace("\n", " ")
        .replace('"', "'")
        .replace("`", "'")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _alias(index: int) -> str:
    return f"P{index}"


def _component_reference(component: dict[str, Any]) -> str:
    return (
        f"{component.get('source', {}).get('path', '')}:{component.get('qualname', '')}"
    )


def _select_component(analysis: dict[str, Any], selector: str) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for component in analysis.get("components", []):
        values = {
            component.get("id", ""),
            component.get("name", ""),
            component.get("qualname", ""),
            _component_reference(component),
        }
        if selector in values:
            matches.append(component)
    if not matches:
        raise ValueError(f"sequence entrypoint does not match a component: {selector}")
    if len(matches) > 1:
        references = ", ".join(_component_reference(value) for value in matches[:5])
        raise ValueError(
            f"sequence entrypoint is ambiguous; use path:qualname ({references})"
        )
    return matches[0]


def sequence_model(
    analysis: dict[str, Any],
    entrypoint: str,
    *,
    max_depth: int = 6,
    max_interactions: int = 100,
    include_runtime: bool = True,
) -> dict[str, Any]:
    """Build a bounded sequence model from static and observed call evidence."""

    if max_depth < 1 or max_interactions < 1:
        raise ValueError("sequence limits must be positive")
    root = _select_component(analysis, entrypoint)
    components = {
        component.get("id", ""): component
        for component in analysis.get("components", [])
    }
    graph = architecture_graph(analysis)
    adjacency: dict[str, list[str]] = defaultdict(list)
    for edge in graph["edges"]:
        if edge.get("kind") == "internal_call":
            adjacency[edge["source"]].append(edge["target"])

    def ordered_targets(component_id: str) -> list[tuple[str, dict[str, Any]]]:
        component = components.get(component_id, {})
        targets = adjacency.get(component_id, [])
        raw_sites = component.get("call_sites", [])
        sites = (
            [value for value in raw_sites if isinstance(value, dict)]
            if isinstance(raw_sites, list)
            else []
        )
        if not sites:
            sites = [
                {
                    "reference": str(call),
                    "order": index,
                    "line": 0,
                    "control_context": [],
                    "awaited": False,
                }
                for index, call in enumerate(
                    component.get("ordered_calls", component.get("calls", []))
                )
            ]
        records: list[tuple[str, dict[str, Any]]] = []
        represented: set[str] = set()
        for site in sites:
            reference = str(site.get("reference", ""))
            leaf = reference.rsplit(".", 1)[-1]
            matches = [
                target
                for target in targets
                if leaf == components.get(target, {}).get("name", "")
                or reference.endswith(
                    "." + str(components.get(target, {}).get("qualname", ""))
                )
            ]
            for target in matches:
                records.append((target, {**site, "_match_count": len(matches)}))
                represented.add(target)
        for target in targets:
            if target not in represented:
                records.append(
                    (
                        target,
                        {
                            "reference": components.get(target, {}).get("name", ""),
                            "order": 10_000,
                            "line": 0,
                            "control_context": [],
                            "awaited": False,
                        },
                    )
                )
        return records

    interactions: list[dict[str, Any]] = []
    truncation_reasons: set[str] = set()

    def walk(component_id: str, depth: int, stack: tuple[str, ...]) -> None:
        if depth >= max_depth:
            if adjacency.get(component_id):
                truncation_reasons.add("max_depth")
            return
        if len(interactions) >= max_interactions:
            truncation_reasons.add("max_interactions")
            return
        for target_id, call_site in ordered_targets(component_id):
            if len(interactions) >= max_interactions:
                truncation_reasons.add("max_interactions")
                return
            target = components.get(target_id, {})
            cycle = target_id in stack
            interactions.append(
                {
                    "source": component_id,
                    "target": target_id,
                    "label": target.get("name") or target.get("qualname", "call"),
                    "evidence": "static_ast",
                    "cycle": cycle,
                    "depth": depth,
                    "sequence_index": call_site.get("order", 0),
                    "source_line": call_site.get("line", 0),
                    "control_context": call_site.get("control_context", []),
                    "awaited": bool(call_site.get("awaited")),
                    "confidence": (
                        "high" if call_site.get("_match_count", 1) == 1 else "low"
                    ),
                    "resolution": (
                        "static_internal_call"
                        if call_site.get("_match_count", 1) == 1
                        else "ambiguous_static_internal_call"
                    ),
                }
            )
            if not cycle:
                walk(target_id, depth + 1, (*stack, target_id))

    walk(root["id"], 0, (root["id"],))
    visited_component_ids = {root["id"]} | {
        value[key] for value in interactions for key in ("source", "target")
    }
    seen_external: set[tuple[str, str, int]] = set()
    external_limit_reached = False
    for component_id in list(visited_component_ids):
        component = components.get(component_id, {})
        call_sites = component.get("call_sites", [])
        for candidate in component.get("external_call_candidates", []):
            call = str(candidate.get("reference", ""))
            matching_sites = [
                value
                for value in call_sites
                if isinstance(value, dict) and value.get("reference") == call
            ] or [{"order": 0, "line": 0, "control_context": [], "awaited": False}]
            for site in matching_sites:
                if len(interactions) >= max_interactions:
                    truncation_reasons.add("max_interactions")
                    external_limit_reached = True
                    break
                external_id = (
                    "EXTCALL-"
                    + hashlib.sha256(str(call).encode("utf-8")).hexdigest()[:12].upper()
                )
                edge_key = (
                    component_id,
                    external_id,
                    int(site.get("order", 0)),
                )
                if edge_key in seen_external:
                    continue
                seen_external.add(edge_key)
                interactions.append(
                    {
                        "source": component_id,
                        "target": external_id,
                        "target_label": str(call),
                        "label": str(call),
                        "evidence": "static_external_candidate",
                        "cycle": False,
                        "depth": 0,
                        "sequence_index": site.get("order", 0),
                        "source_line": site.get("line", 0),
                        "control_context": site.get("control_context", []),
                        "awaited": bool(site.get("awaited")),
                        "confidence": candidate.get("confidence", "medium"),
                        "resolution": candidate.get("basis", "unresolved"),
                    }
                )
            if len(interactions) >= max_interactions:
                break
        if external_limit_reached:
            break
    for component_id in list(visited_component_ids):
        component = components.get(component_id, {})
        call_sites = component.get("call_sites", [])
        for site in call_sites if isinstance(call_sites, list) else []:
            if not isinstance(site, dict) or not site.get("dynamic_target"):
                continue
            if len(interactions) >= max_interactions:
                truncation_reasons.add("max_interactions")
                break
            reference = str(site.get("reference", "<dynamic call>"))
            identity = "|".join(
                (
                    component_id,
                    reference,
                    str(site.get("line", 0)),
                    str(site.get("order", 0)),
                )
            )
            dynamic_id = (
                "DYNAMICCALL-"
                + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12].upper()
            )
            interactions.append(
                {
                    "source": component_id,
                    "target": dynamic_id,
                    "target_label": reference,
                    "label": reference,
                    "evidence": "static_dynamic_call",
                    "cycle": False,
                    "depth": 0,
                    "sequence_index": site.get("order", 0),
                    "source_line": site.get("line", 0),
                    "control_context": site.get("control_context", []),
                    "awaited": bool(site.get("awaited")),
                    "confidence": "low",
                    "resolution": site.get("resolution", "unresolved_dynamic_call"),
                }
            )
        if len(interactions) >= max_interactions:
            break
    if include_runtime:
        included_ids = {root["id"]} | {
            value[key] for value in interactions for key in ("source", "target")
        }
        for edge in analysis.get("runtime_evidence", {}).get("edges", []):
            if len(interactions) >= max_interactions:
                truncation_reasons.add("max_interactions")
                break
            source_id = edge.get("source_component_id", "")
            target_id = edge.get("target_component_id", "")
            if source_id in included_ids or target_id in included_ids:
                interactions.append(
                    {
                        "source": source_id or "RUNTIME-EXTERNAL-SOURCE",
                        "target": target_id or "RUNTIME-EXTERNAL-TARGET",
                        "source_label": edge.get(
                            "source_name", "External/runtime source"
                        ),
                        "target_label": edge.get(
                            "target_name", "External/runtime target"
                        ),
                        "label": edge.get("operation", "observed call"),
                        "evidence": "observed_runtime",
                        "cycle": False,
                        "depth": 0,
                        "trace_id": edge.get("trace_id", ""),
                        "start_time": edge.get("start_time", ""),
                        "end_time": edge.get("end_time", ""),
                        "timing_status": edge.get("timing_status", "unavailable"),
                        "duration_ns": edge.get("duration_ns"),
                        "observation_index": edge.get("observation_index"),
                        "confidence": "observed",
                        "resolution": "runtime_parent_child",
                    }
                )
    static_internal = {
        (str(value.get("source", "")), str(value.get("target", "")))
        for value in interactions
        if value.get("evidence") == "static_ast"
    }
    observed_internal = {
        (str(value.get("source", "")), str(value.get("target", "")))
        for value in interactions
        if value.get("evidence") == "observed_runtime"
        and value.get("source") in components
        and value.get("target") in components
    }
    for interaction in interactions:
        pair = (str(interaction.get("source", "")), str(interaction.get("target", "")))
        if interaction.get("evidence") == "static_ast":
            interaction["observation_status"] = (
                "runtime_corroborated" if pair in observed_internal else "not_observed"
            )
        elif interaction.get("evidence") == "observed_runtime":
            interaction["static_alignment"] = (
                "statically_predicted" if pair in static_internal else "runtime_only"
            )
    corroborated = static_internal & observed_internal
    timing_statuses: dict[str, int] = {}
    for interaction in interactions:
        if interaction.get("evidence") != "observed_runtime":
            continue
        status = str(interaction.get("timing_status", "unavailable"))
        timing_statuses[status] = timing_statuses.get(status, 0) + 1
    reconciliation = {
        "static_internal_relations": len(static_internal),
        "observed_internal_relations": len(observed_internal),
        "corroborated_relations": len(corroborated),
        "static_not_observed_relations": len(static_internal - observed_internal),
        "runtime_only_relations": len(observed_internal - static_internal),
        "static_observation_coverage_percent": (
            round(len(corroborated) * 100 / len(static_internal), 1)
            if static_internal
            else None
        ),
        "runtime_timing_statuses": dict(sorted(timing_statuses.items())),
        "static_dynamic_calls": sum(
            value.get("evidence") == "static_dynamic_call"
            for value in interactions
        ),
        "notice": (
            "Not observed does not mean unreachable, and runtime-only does not prove the static "
            "model is wrong; instrumentation scope and execution selection require review."
        ),
    }
    participant_ids: list[str] = []
    for value in [
        root["id"],
        *(entry[key] for entry in interactions for key in ("source", "target")),
    ]:
        if value not in participant_ids:
            participant_ids.append(value)
    participants = []
    for component_id in participant_ids:
        component = components.get(component_id, {})
        fallback = next(
            (
                entry.get("source_label")
                if entry.get("source") == component_id
                else entry.get("target_label")
                for entry in interactions
                if entry.get("source") == component_id
                or entry.get("target") == component_id
            ),
            component_id,
        )
        participants.append(
            {
                "id": component_id,
                "label": component.get("qualname") or fallback or component_id,
                "path": component.get("source", {}).get("path", ""),
                "frameworks": component.get("frameworks", []),
            }
        )
    return {
        "entrypoint": root["id"],
        "participants": participants,
        "interactions": interactions,
        "limits": {"max_depth": max_depth, "max_interactions": max_interactions},
        "truncated": bool(truncation_reasons),
        "truncation_reasons": sorted(truncation_reasons),
        "reconciliation": reconciliation,
        "notice": (
            "Static call-site order and control context are conservative possibilities, not a "
            "path-sensitive execution proof; observed runtime edges prove only captured executions."
        ),
    }


def export_sequence(
    analysis: dict[str, Any],
    destination: str | Path,
    entrypoint: str,
    *,
    format: str = "markdown",
    max_depth: int = 6,
    max_interactions: int = 100,
    include_runtime: bool = True,
) -> Path:
    model = sequence_model(
        analysis,
        entrypoint,
        max_depth=max_depth,
        max_interactions=max_interactions,
        include_runtime=include_runtime,
    )
    if format == "json":
        return atomic_publish_text(
            destination,
            json.dumps(model, indent=2, ensure_ascii=False) + "\n",
            label="sequence JSON export",
        )
    if format != "markdown":
        raise ValueError("sequence format must be markdown or json")
    aliases = {
        participant["id"]: _alias(index)
        for index, participant in enumerate(model["participants"])
    }
    lines = [
        "# Sequence view - " + _md(analysis.get("project", {}).get("name", "")),
        "",
        "> " + model["notice"],
        "",
        "```mermaid",
        "sequenceDiagram",
        "  autonumber",
    ]
    if model["truncated"]:
        lines[2] += (
            " View truncated by: " + ", ".join(model["truncation_reasons"]) + "."
        )
    for participant in model["participants"]:
        lines.append(
            f'  participant {aliases[participant["id"]]} as "{_mermaid(participant["label"])}"'
        )
    for interaction in model["interactions"]:
        arrow = "-->>" if interaction["evidence"] == "observed_runtime" else "->>"
        suffix = (
            " [observed]"
            if interaction["evidence"] == "observed_runtime"
            else " [static dynamic]"
            if interaction["evidence"] == "static_dynamic_call"
            else " [static candidate]"
            if interaction["evidence"] == "static_external_candidate"
            else " [static]"
        )
        if interaction.get("awaited"):
            suffix += " [await]"
        context = interaction.get("control_context", [])
        if context:
            suffix += " [" + " > ".join(str(value) for value in context) + "]"
        if interaction.get("cycle"):
            suffix += " [cycle]"
        if interaction.get("observation_status") == "runtime_corroborated":
            suffix += " [runtime corroborated]"
        if interaction.get("static_alignment") == "runtime_only":
            suffix += " [runtime only]"
        lines.append(
            f"  {aliases[interaction['source']]}{arrow}{aliases[interaction['target']]}: "
            f"{_mermaid(interaction['label'] + suffix)}"
        )
    lines.extend(
        [
            "```",
            "",
            "## Evidence legend",
            "",
            "- `[static]`: conservative AST-resolved internal call relation.",
            "- `[static candidate]`: unresolved or known external call requiring interface review.",
            "- `[static dynamic]`: a known invocation whose runtime callable target remains unresolved.",
            "- `[observed]`: imported runtime parent-child span relation.",
            "- `[runtime corroborated]`: the same component relation appears in static and imported runtime evidence.",
            "- `[runtime only]`: observed relation absent from the bounded static model; review instrumentation and dynamic dispatch.",
            "- Control-context and `await` annotations are static syntax evidence, not path or scheduling proof.",
            "",
            "## Static/observed reconciliation",
            "",
            f"- Static internal relations: {model['reconciliation']['static_internal_relations']}",
            f"- Observed internal relations: {model['reconciliation']['observed_internal_relations']}",
            f"- Corroborated relations: {model['reconciliation']['corroborated_relations']}",
            f"- Static relations not observed: {model['reconciliation']['static_not_observed_relations']}",
            f"- Runtime-only relations: {model['reconciliation']['runtime_only_relations']}",
            "- Static observation coverage: "
            + (
                f"{model['reconciliation']['static_observation_coverage_percent']}%"
                if model["reconciliation"]["static_observation_coverage_percent"]
                is not None
                else "not applicable (no static internal relations)"
            ),
            "- " + model["reconciliation"]["notice"],
        ]
    )
    return atomic_publish_text(
        destination,
        "\n".join(lines) + "\n",
        label="sequence Markdown export",
    )


def traceability_model(analysis: dict[str, Any]) -> dict[str, Any]:
    """Build requirement/component/failure-mode/hazard trace relationships."""

    nodes: list[dict[str, str]] = []
    edges: list[dict[str, str]] = []
    requirement_nodes: dict[str, str] = {}
    hazard_nodes: dict[str, str] = {}
    component_nodes: dict[str, str] = {}
    for requirement in analysis.get("context", {}).get("requirements", []):
        reference_id = requirement.get("id", "")
        if not reference_id:
            continue
        node_id = f"requirement:{reference_id}"
        requirement_nodes[reference_id] = node_id
        nodes.append(
            {
                "id": node_id,
                "reference_id": reference_id,
                "kind": "requirement",
                "label": requirement.get("text", ""),
            }
        )
    for hazard in analysis.get("context", {}).get("hazards", []):
        reference_id = hazard.get("id", "")
        if not reference_id:
            continue
        node_id = f"hazard:{reference_id}"
        hazard_nodes[reference_id] = node_id
        nodes.append(
            {
                "id": node_id,
                "reference_id": reference_id,
                "kind": "hazard",
                "label": hazard.get("description", ""),
            }
        )
    for requirement in analysis.get("context", {}).get("requirements", []):
        source = requirement_nodes.get(requirement.get("id", ""))
        for hazard_id in requirement.get("hazards", []):
            target = hazard_nodes.get(hazard_id)
            if source and target:
                edges.append({"source": source, "target": target, "kind": "mitigates"})
    for component in analysis.get("components", []):
        reference_id = component.get("id", "")
        if not reference_id:
            continue
        node_id = f"component:{reference_id}"
        component_nodes[reference_id] = node_id
        nodes.append(
            {
                "id": node_id,
                "reference_id": reference_id,
                "kind": "component",
                "label": component.get("qualname", ""),
            }
        )
        for requirement_id in component.get("requirement_ids", []):
            source = requirement_nodes.get(requirement_id)
            if source:
                edges.append(
                    {"source": source, "target": node_id, "kind": "allocated_to"}
                )
    for item in analysis.get("items", []):
        if item.get("source_status", "active") != "active":
            continue
        review = item.get("review", {})
        label = review.get("failure_mode") or item.get("scanner", {}).get(
            "failure_mode", ""
        )
        reference_id = item.get("id", "")
        if not reference_id:
            continue
        item_node = f"failure_mode:{reference_id}"
        nodes.append(
            {
                "id": item_node,
                "reference_id": reference_id,
                "kind": "failure_mode",
                "label": label,
            }
        )
        component_node = component_nodes.get(item.get("component_id", ""))
        if component_node:
            edges.append(
                {"source": component_node, "target": item_node, "kind": "may_fail_as"}
            )
        requirement_ids = {
            value.strip()
            for line in str(review.get("requirement", "")).splitlines()
            for value in line.split(",")
            if value.strip()
        }
        for requirement_id in sorted(requirement_ids):
            requirement_node = requirement_nodes.get(requirement_id)
            if requirement_node:
                edges.append(
                    {
                        "source": requirement_node,
                        "target": item_node,
                        "kind": "traces_to",
                    }
                )
        for hazard_id in review.get("linked_hazards", []):
            hazard_node = hazard_nodes.get(hazard_id)
            if hazard_node:
                edges.append(
                    {
                        "source": item_node,
                        "target": hazard_node,
                        "kind": "may_contribute_to",
                    }
                )
    return {"nodes": nodes, "edges": edges}


def export_traceability(
    analysis: dict[str, Any], destination: str | Path, *, format: str = "markdown"
) -> Path:
    model = traceability_model(analysis)
    if format == "json":
        return atomic_publish_text(
            destination,
            json.dumps(model, indent=2, ensure_ascii=False) + "\n",
            label="traceability JSON export",
        )
    if format != "markdown":
        raise ValueError("traceability format must be markdown or json")
    aliases = {
        node["id"]: f"N{index}"
        for index, node in enumerate(model["nodes"])
        if node["id"]
    }
    lines = [
        "# SFMEA traceability - " + _md(analysis.get("project", {}).get("name", "")),
        "",
        "```mermaid",
        "flowchart LR",
    ]
    shapes = {
        "requirement": ("[", "]"),
        "hazard": ("{{", "}}"),
        "failure_mode": ("([", "])"),
    }
    for node in model["nodes"]:
        if node["id"] not in aliases:
            continue
        left, right = shapes.get(node["kind"], ('["', '"]'))
        label = _mermaid(f"{node.get('reference_id', node['id'])}\\n{node['label']}")
        if left == '["':
            lines.append(f"  {aliases[node['id']]}{left}{label}{right}")
        else:
            lines.append(f'  {aliases[node["id"]]}{left}"{label}"{right}')
    for edge in model["edges"]:
        if edge["source"] in aliases and edge["target"] in aliases:
            lines.append(
                f'  {aliases[edge["source"]]} -->|"{_mermaid(edge["kind"])}"| {aliases[edge["target"]]}'
            )
    lines.append("```")
    return atomic_publish_text(
        destination,
        "\n".join(lines) + "\n",
        label="traceability Markdown export",
    )


def coverage_metrics(analysis: dict[str, Any]) -> dict[str, Any]:
    """Measure analysis coverage without claiming semantic adequacy."""

    active_items = [
        item
        for item in analysis.get("items", [])
        if item.get("source_status", "active") == "active"
    ]
    components = [
        component
        for component in analysis.get("components", [])
        if component.get("kind") not in {"environment", "common_cause"}
    ]
    reviewed = [
        item
        for item in active_items
        if item.get("review", {}).get("disposition") != "unreviewed"
    ]
    accepted = [
        item
        for item in active_items
        if item.get("review", {}).get("disposition") == "accepted"
    ]
    requirements = {
        value.get("id")
        for value in analysis.get("context", {}).get("requirements", [])
        if value.get("id")
    }
    hazards = {
        value.get("id")
        for value in analysis.get("context", {}).get("hazards", [])
        if value.get("id")
    }
    interfaces = {
        value.get("id")
        for value in analysis.get("context", {}).get("system_interfaces", [])
        if value.get("id")
    }
    linked_requirements = {
        value.strip()
        for item in active_items
        for line in str(item.get("review", {}).get("requirement", "")).splitlines()
        for value in line.split(",")
        if value.strip()
    }
    linked_hazards = {
        value
        for item in active_items
        for value in item.get("review", {}).get("linked_hazards", [])
    }
    mapped_interfaces = {
        value
        for component in components
        for value in component.get("interface_ids", [])
    }
    repository_projection = repository_inventory_summary_projection(
        analysis.get("repository_inventory", {})
    )
    repository_summary = repository_projection["summary"]
    repository_status = repository_summary.get("by_status", {})

    def ratio(numerator: int, denominator: int) -> float | None:
        return round(100 * numerator / denominator, 1) if denominator else None

    return {
        "components": {
            "total": len(components),
            "with_requirements": sum(
                bool(value.get("requirement_ids")) for value in components
            ),
            "with_interfaces": sum(
                bool(value.get("interface_ids")) for value in components
            ),
        },
        "failure_modes": {
            "active": len(active_items),
            "reviewed": len(reviewed),
            "accepted": len(accepted),
            "review_percent": ratio(len(reviewed), len(active_items)),
        },
        "requirements": {
            "configured": len(requirements),
            "linked": len(requirements & linked_requirements),
            "coverage_percent": ratio(
                len(requirements & linked_requirements), len(requirements)
            ),
        },
        "hazards": {
            "configured": len(hazards),
            "linked": len(hazards & linked_hazards),
            "coverage_percent": ratio(len(hazards & linked_hazards), len(hazards)),
        },
        "interfaces": {
            "configured": len(interfaces),
            "mapped": len(interfaces & mapped_interfaces),
            "coverage_percent": ratio(
                len(interfaces & mapped_interfaces), len(interfaces)
            ),
        },
        "repository_artifacts": {
            "reconciliation_status": repository_projection["status"],
            "display_source": repository_projection["display_source"],
            "files": repository_summary.get("files"),
            "regions": repository_summary.get("regions"),
            "analyzed": repository_status.get("analyzed"),
            "indexed": repository_status.get("indexed"),
            "excluded": repository_status.get("excluded_region"),
            "opaque_or_unresolved": repository_summary.get("opaque_or_unresolved"),
            "semantic_coverage_percent": repository_summary.get(
                "semantic_coverage_percent"
            ),
            "by_snapshot_source": repository_summary.get("by_snapshot_source", {}),
            "notice": repository_projection["notice"],
        },
        "limitations": [
            "Coverage measures linkage and disposition completeness, not correctness or hazard-analysis sufficiency.",
            "Repository artifact coverage measures static accounting depth, not behavioral or test adequacy.",
        ],
    }


def export_coverage(
    analysis: dict[str, Any],
    destination: str | Path,
    *,
    format: str = "markdown",
    include_repository_accounting: bool = True,
) -> Path:
    metrics = coverage_metrics(analysis)
    if format == "json":
        return atomic_publish_text(
            destination,
            json.dumps(metrics, indent=2, ensure_ascii=False) + "\n",
            label="coverage JSON export",
        )
    if format != "markdown":
        raise ValueError("coverage format must be markdown or json")
    lines = [
        "# SFMEA analysis coverage",
        "",
        "> " + metrics["limitations"][0],
        "",
        "| Area | Covered | Total | Percent |",
        "|---|---:|---:|---:|",
    ]
    for area, metric_key, covered_key, total_key, percent_key in (
        (
            "Failure-mode review",
            "failure_modes",
            "reviewed",
            "active",
            "review_percent",
        ),
        ("Requirements", "requirements", "linked", "configured", "coverage_percent"),
        ("Hazards", "hazards", "linked", "configured", "coverage_percent"),
        ("Interfaces", "interfaces", "mapped", "configured", "coverage_percent"),
    ):
        values = metrics[metric_key]
        percent = values[percent_key]
        lines.append(
            f"| {area} | {values[covered_key]} | {values[total_key]} | {percent if percent is not None else 'n/a'} |"
        )
    if include_repository_accounting:
        repository = metrics["repository_artifacts"]
        semantic_coverage = repository["semantic_coverage_percent"]
        lines.extend(
            [
                "",
                "## Repository artifact accounting",
                "",
                f"- Reconciliation: {repository['reconciliation_status']}",
                f"- Files: {repository['files'] if repository['files'] is not None else 'unavailable'}",
                f"- Regions: {repository['regions'] if repository['regions'] is not None else 'unavailable'}",
                f"- Semantically analyzed: {repository['analyzed'] if repository['analyzed'] is not None else 'unavailable'}",
                f"- Indexed: {repository['indexed'] if repository['indexed'] is not None else 'unavailable'}",
                f"- Opaque or unresolved: {repository['opaque_or_unresolved'] if repository['opaque_or_unresolved'] is not None else 'unavailable'}",
                "- Semantic accounting coverage: "
                + (f"{semantic_coverage}%" if semantic_coverage is not None else "n/a"),
                "",
                "> " + repository["notice"],
            ]
        )
    return atomic_publish_text(
        destination,
        "\n".join(lines) + "\n",
        label="coverage Markdown export",
    )
