"""Deterministic Software Fault Tree model and SFMEA/SFTA reconciliation."""

from __future__ import annotations

import csv
import fnmatch
import json
from pathlib import Path
from typing import Any

from .model import stable_id, utc_now


SFTA_SCHEMA_VERSION = "1.0"
SFTA_NOTICE = (
    "Software Fault Trees are top-down engineering models. PySFMEA preserves explicit "
    "user-supplied gate logic and correlates it with bottom-up candidates, but does not "
    "infer causal sufficiency, independence, minimal cut sets, or hazard completeness. "
    "Automatically created placeholder trees identify missing decomposition only."
)


def _active_findings(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        value
        for value in analysis.get("items", [])
        if value.get("source_status", "active") == "active"
        and value.get("review", {}).get("disposition") != "rejected"
    ]


def _component_key(item: dict[str, Any]) -> str:
    return f"{item.get('source', {}).get('path', '')}:{item.get('component', {}).get('qualname', '')}"


def _failure_text(item: dict[str, Any]) -> str:
    review = item.get("review", {})
    return str(review.get("failure_mode") or item.get("scanner", {}).get("failure_mode", ""))


def _matches_event(item: dict[str, Any], event: dict[str, Any]) -> bool:
    finding_ids = set(event.get("finding_ids", []))
    component_patterns = list(event.get("component_patterns", []))
    failure_patterns = list(event.get("failure_mode_patterns", []))
    selectors_present = bool(finding_ids or component_patterns or failure_patterns)
    if not selectors_present:
        return False
    if item.get("id") in finding_ids:
        return True
    component_match = not component_patterns or any(
        fnmatch.fnmatchcase(_component_key(item), pattern) for pattern in component_patterns
    )
    text = _failure_text(item).casefold()
    failure_match = not failure_patterns or any(
        fnmatch.fnmatchcase(text, pattern.casefold()) for pattern in failure_patterns
    )
    return component_match and failure_match


def _placeholder_tree(hazard: dict[str, Any]) -> dict[str, Any]:
    hazard_id = str(hazard.get("id", ""))
    top_id = stable_id("SFTA-TOP", hazard_id)
    gap_id = stable_id("SFTA-UNDEV", hazard_id)
    return {
        "id": stable_id("SFTA", hazard_id, "placeholder"),
        "hazard_id": hazard_id,
        "hazard_description": str(hazard.get("description", "")),
        "top_event_id": top_id,
        "top_event": str(hazard.get("description") or hazard_id),
        "description": "Placeholder generated because no explicit top-down fault tree was supplied.",
        "source": "generated_placeholder",
        "logic_status": "undeveloped",
        "assumptions": [],
        "nodes": [
            {
                "id": top_id,
                "kind": "event",
                "event_type": "top",
                "label": str(hazard.get("description") or hazard_id),
                "description": str(hazard.get("end_effect", "")),
                "inputs": [gap_id],
                "linked_finding_ids": [],
                "evidence": [],
                "assumptions": [],
            },
            {
                "id": gap_id,
                "kind": "event",
                "event_type": "undeveloped",
                "label": "Top-down software contributors not decomposed",
                "description": "Define validated software events and logical gates for this hazard.",
                "inputs": [],
                "linked_finding_ids": [],
                "evidence": [],
                "assumptions": [],
            },
        ],
        "edges": [
            {
                "id": stable_id("SFTA-EDGE", gap_id, top_id),
                "source": gap_id,
                "target": top_id,
                "kind": "input_to",
                "label": "undeveloped",
            }
        ],
    }


def _explicit_tree(
    definition: dict[str, Any],
    hazard: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    hazard_id = str(definition.get("hazard", ""))
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    for gate in definition.get("gates", []):
        gate_id = str(gate["id"])
        gate_type = str(gate["type"])
        label = f"{gate_type} gate"
        if gate_type == "VOTE":
            label = f"{gate.get('k')}-of-{len(gate.get('inputs', []))} VOTE gate"
        nodes.append(
            {
                "id": gate_id,
                "kind": "gate",
                "gate_type": gate_type,
                "label": label,
                "description": str(gate.get("description", "")),
                "inputs": list(gate.get("inputs", [])),
                "k": gate.get("k"),
                "linked_finding_ids": [],
                "evidence": [],
                "assumptions": [],
            }
        )
    for event in definition.get("events", []):
        matched = sorted(
            value["id"] for value in findings if _matches_event(value, event)
        )
        nodes.append(
            {
                "id": str(event["id"]),
                "kind": "event",
                "event_type": str(event["type"]),
                "label": str(event["description"]),
                "description": str(event["description"]),
                "inputs": list(event.get("inputs", [])),
                "linked_finding_ids": matched,
                "finding_selectors": {
                    "finding_ids": list(event.get("finding_ids", [])),
                    "component_patterns": list(event.get("component_patterns", [])),
                    "failure_mode_patterns": list(event.get("failure_mode_patterns", [])),
                },
                "evidence": list(event.get("evidence", [])),
                "assumptions": list(event.get("assumptions", [])),
            }
        )
    for parent in nodes:
        for child_id in parent.get("inputs", []):
            edges.append(
                {
                    "id": stable_id("SFTA-EDGE", str(child_id), str(parent["id"])),
                    "source": str(child_id),
                    "target": str(parent["id"]),
                    "kind": "input_to",
                    "label": str(parent.get("gate_type") or parent.get("event_type", "")),
                }
            )
    return {
        "id": str(definition["id"]),
        "hazard_id": hazard_id,
        "hazard_description": str(hazard.get("description", "")),
        "top_event_id": str(definition["top_event_id"]),
        "top_event": str(definition["top_event"]),
        "description": str(definition.get("description", "")),
        "source": "explicit_configuration",
        "logic_status": "preliminary_requires_review",
        "assumptions": list(definition.get("assumptions", [])),
        "nodes": nodes,
        "edges": edges,
    }


def build_sfta(analysis: dict[str, Any]) -> dict[str, Any]:
    """Build explicit/placeholder fault trees and bidirectional coverage gaps."""

    context = analysis.get("context", {})
    hazards = [value for value in context.get("hazards", []) if value.get("id")]
    hazard_by_id = {str(value["id"]): value for value in hazards}
    findings = _active_findings(analysis)
    definitions = list(context.get("fault_trees", []))
    trees = [
        _explicit_tree(definition, hazard_by_id[str(definition["hazard"])], findings)
        for definition in definitions
    ]
    hazards_with_tree = {value["hazard_id"] for value in trees}
    trees.extend(
        _placeholder_tree(hazard)
        for hazard in hazards
        if str(hazard["id"]) not in hazards_with_tree
    )
    finding_links: dict[str, list[dict[str, str]]] = {}
    top_down_uncovered: list[dict[str, str]] = []
    hazard_link_mismatches: list[dict[str, str]] = []
    for tree in trees:
        for node in tree["nodes"]:
            linked = list(node.get("linked_finding_ids", []))
            if (
                tree["source"] == "explicit_configuration"
                and node.get("event_type") in {"basic", "undeveloped"}
                and node.get("finding_selectors", {})
                and not linked
            ):
                top_down_uncovered.append(
                    {
                        "tree_id": tree["id"],
                        "hazard_id": tree["hazard_id"],
                        "event_id": node["id"],
                        "description": node["description"],
                    }
                )
            for finding_id in linked:
                finding_links.setdefault(finding_id, []).append(
                    {
                        "tree_id": tree["id"],
                        "event_id": node["id"],
                        "hazard_id": tree["hazard_id"],
                    }
                )
                item = next(value for value in findings if value["id"] == finding_id)
                if tree["hazard_id"] not in item.get("review", {}).get("linked_hazards", []):
                    hazard_link_mismatches.append(
                        {
                            "tree_id": tree["id"],
                            "hazard_id": tree["hazard_id"],
                            "event_id": node["id"],
                            "finding_id": finding_id,
                        }
                    )
    bottom_up_unmapped: list[dict[str, str]] = []
    for item in findings:
        for hazard_id in item.get("review", {}).get("linked_hazards", []):
            if hazard_id in hazard_by_id and not any(
                value["hazard_id"] == hazard_id for value in finding_links.get(item["id"], [])
            ):
                bottom_up_unmapped.append(
                    {
                        "finding_id": item["id"],
                        "hazard_id": hazard_id,
                        "component": _component_key(item),
                        "failure_mode": _failure_text(item),
                    }
                )
    explicit_trees = sum(value["source"] == "explicit_configuration" for value in trees)
    linked_findings = len(finding_links)
    active_hazard_findings = {
        value["id"]
        for value in findings
        if any(hazard in hazard_by_id for hazard in value.get("review", {}).get("linked_hazards", []))
    }
    return {
        "schema_version": SFTA_SCHEMA_VERSION,
        "generated_at": utc_now(),
        "baseline_id": analysis.get("project", {}).get("baseline", {}).get("id", ""),
        "notice": SFTA_NOTICE,
        "trees": trees,
        "reconciliation": {
            "summary": {
                "hazards": len(hazards),
                "trees": len(trees),
                "explicit_trees": explicit_trees,
                "placeholder_trees": len(trees) - explicit_trees,
                "top_down_events": sum(
                    node.get("kind") == "event" for tree in trees for node in tree["nodes"]
                ),
                "hazard_linked_findings": len(active_hazard_findings),
                "findings_correlated_to_events": linked_findings,
                "top_down_uncovered_events": len(top_down_uncovered),
                "bottom_up_unmapped_findings": len(bottom_up_unmapped),
                "hazard_link_mismatches": len(hazard_link_mismatches),
            },
            "finding_to_events": [
                {"finding_id": finding_id, "links": links}
                for finding_id, links in sorted(finding_links.items())
            ],
            "top_down_uncovered_events": top_down_uncovered,
            "bottom_up_unmapped_findings": bottom_up_unmapped,
            "hazard_link_mismatches": hazard_link_mismatches,
        },
    }


def export_sfta(
    analysis: dict[str, Any], destination: str | Path, *, format: str = "json"
) -> Path:
    """Export the current SFTA/reconciliation model as JSON or a flat CSV gap register."""

    target = Path(destination).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    model = build_sfta(analysis)
    if format == "json":
        target.write_text(json.dumps(model, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return target
    if format != "csv":
        raise ValueError("SFTA export format must be json or csv")
    rows: list[dict[str, str]] = []
    reconciliation = model["reconciliation"]
    for value in reconciliation["top_down_uncovered_events"]:
        rows.append({"gap_type": "top_down_uncovered_event", **value})
    for value in reconciliation["bottom_up_unmapped_findings"]:
        rows.append({"gap_type": "bottom_up_unmapped_finding", **value})
    for value in reconciliation["hazard_link_mismatches"]:
        rows.append({"gap_type": "hazard_link_mismatch", **value})
    fields = [
        "gap_type",
        "tree_id",
        "hazard_id",
        "event_id",
        "finding_id",
        "component",
        "failure_mode",
        "description",
    ]
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return target
