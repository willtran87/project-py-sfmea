"""Deterministic Software Fault Tree model and SFMEA/SFTA reconciliation."""

from __future__ import annotations

import csv
import fnmatch
import io
import json
from collections.abc import Iterable
from itertools import combinations, product
from pathlib import Path
from typing import Any

from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .model import preserve_unchanged_generated_at, stable_id, utc_now

SFTA_SCHEMA_VERSION = "1.0"
SFTA_NOTICE = (
    "Software Fault Trees are top-down engineering models. PySFMEA preserves explicit "
    "user-supplied gate logic and correlates it with bottom-up candidates. Qualitative "
    "minimal cut sets are computed only for an exact tree definition approved through the "
    "governed authoring workflow; they do not establish causal sufficiency, independence, "
    "probability, risk acceptance, or hazard completeness. Automatically created placeholder "
    "trees identify missing decomposition only."
)
MAX_CUT_SETS_PER_TREE = 1_000
MAX_CUT_SET_WIDTH = 100
MAX_CUT_SET_OPERATIONS = 250_000
SFTA_GAP_FIELDS = (
    "gap_type",
    "tree_id",
    "hazard_id",
    "event_id",
    "finding_id",
    "component",
    "failure_mode",
    "description",
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
    return str(
        review.get("failure_mode") or item.get("scanner", {}).get("failure_mode", "")
    )


def _matches_event(
    item: dict[str, Any],
    event: dict[str, Any],
    *,
    legacy_id_wildcard: bool = False,
) -> bool:
    finding_ids = set(event.get("finding_ids", []))
    component_patterns = list(event.get("component_patterns", []))
    failure_patterns = list(event.get("failure_mode_patterns", []))
    if item.get("id") in finding_ids:
        return True
    if not component_patterns and not failure_patterns:
        return bool(legacy_id_wildcard and finding_ids)
    component_match = not component_patterns or any(
        fnmatch.fnmatchcase(_component_key(item), pattern)
        for pattern in component_patterns
    )
    text = _failure_text(item).casefold()
    failure_match = not failure_patterns or any(
        fnmatch.fnmatchcase(text, pattern.casefold()) for pattern in failure_patterns
    )
    return component_match and failure_match


def _matched_finding_ids(
    findings: list[dict[str, Any]],
    findings_by_id: dict[str, dict[str, Any]],
    event: dict[str, Any],
    *,
    legacy_id_wildcard: bool = False,
) -> list[str]:
    """Resolve explicit IDs directly and scan only when glob selectors are present."""

    matched = {
        finding_id
        for value in event.get("finding_ids", [])
        if (finding_id := str(value)) in findings_by_id
    }
    if (
        event.get("component_patterns")
        or event.get("failure_mode_patterns")
        or (legacy_id_wildcard and event.get("finding_ids"))
    ):
        matched.update(
            str(value["id"])
            for value in findings
            if value.get("id")
            and _matches_event(value, event, legacy_id_wildcard=legacy_id_wildcard)
        )
    return sorted(matched)


class _CutSetLimitError(ValueError):
    pass


class _CutSetLogicError(ValueError):
    pass


def _minimal_terms(
    candidates: set[frozenset[str]], *, operations: list[int]
) -> set[frozenset[str]]:
    """Remove duplicate/superset terms while enforcing deterministic work bounds."""

    ordered = sorted(candidates, key=lambda value: (len(value), tuple(sorted(value))))
    minimal: list[frozenset[str]] = []
    for candidate in ordered:
        operations[0] += 1
        if operations[0] > MAX_CUT_SET_OPERATIONS:
            raise _CutSetLimitError("qualitative cut-set operation limit exceeded")
        if len(candidate) > MAX_CUT_SET_WIDTH:
            raise _CutSetLimitError("qualitative cut-set width limit exceeded")
        if any(existing <= candidate for existing in minimal):
            continue
        minimal.append(candidate)
        if len(minimal) > MAX_CUT_SETS_PER_TREE:
            raise _CutSetLimitError("qualitative cut-set count limit exceeded")
    return set(minimal)


def _qualitative_cut_sets(
    tree: dict[str, Any], approval: dict[str, Any] | None
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "method": "exact_boolean_expansion_with_superset_absorption",
        "qualitative_only": True,
        "independence_assumed": False,
        "probability_calculated": False,
        "limits": {
            "cut_sets": MAX_CUT_SETS_PER_TREE,
            "cut_set_width": MAX_CUT_SET_WIDTH,
            "operations": MAX_CUT_SET_OPERATIONS,
        },
        "cut_sets": [],
        "cut_set_count": 0,
        "operations": 0,
        "authority": (
            "mechanical_expansion_of_exact_reviewed_logic_not_causal_sufficiency_"
            "independence_probability_or_risk_acceptance"
        ),
    }
    if approval is None:
        return {
            **base,
            "status": "not_computed_unapproved_tree",
            "review": None,
            "notice": (
                "Approve the exact tree through SFTA authoring before qualitative cut-set "
                "calculation."
            ),
        }
    nodes = {
        str(value.get("id", "")): value
        for value in tree.get("nodes", [])
        if isinstance(value, dict) and value.get("id")
    }
    top_id = str(tree.get("top_event_id", ""))
    operations = [0]
    memo: dict[str, set[frozenset[str]]] = {}
    visiting: set[str] = set()

    def expand(node_id: str) -> set[frozenset[str]]:
        if node_id in memo:
            return memo[node_id]
        if node_id in visiting:
            raise _CutSetLogicError(f"cycle encountered at {node_id}")
        node = nodes.get(node_id)
        if node is None:
            raise _CutSetLogicError(f"unknown node {node_id}")
        visiting.add(node_id)
        inputs = [str(value) for value in node.get("inputs", [])]
        kind = str(node.get("kind", ""))
        if kind == "event":
            event_type = str(node.get("event_type", ""))
            if not inputs:
                if event_type in {"top", "intermediate"}:
                    raise _CutSetLogicError(
                        f"{event_type} event {node_id} has no defining input"
                    )
                result = {frozenset({node_id})}
            elif len(inputs) == 1:
                result = expand(inputs[0])
            else:
                raise _CutSetLogicError(
                    f"event {node_id} has multiple inputs without an explicit gate"
                )
        elif kind == "gate":
            gate_type = str(node.get("gate_type", ""))
            expanded_inputs = [expand(value) for value in inputs]
            if gate_type == "OR":
                result = _minimal_terms(
                    set().union(*expanded_inputs), operations=operations
                )
            else:
                if gate_type == "VOTE":
                    k = node.get("k")
                    if (
                        isinstance(k, bool)
                        or not isinstance(k, int)
                        or not 1 <= k <= len(inputs)
                    ):
                        raise _CutSetLogicError(f"VOTE gate {node_id} has invalid k")
                    groups: Iterable[tuple[set[frozenset[str]], ...]] = combinations(
                        expanded_inputs, k
                    )
                elif gate_type in {"AND", "INHIBIT"}:
                    groups = (tuple(expanded_inputs),)
                else:
                    raise _CutSetLogicError(
                        f"gate {node_id} has unsupported type {gate_type}"
                    )
                combined: set[frozenset[str]] = set()
                for group in groups:
                    for terms in product(*group):
                        operations[0] += 1
                        if operations[0] > MAX_CUT_SET_OPERATIONS:
                            raise _CutSetLimitError(
                                "qualitative cut-set operation limit exceeded"
                            )
                        merged = frozenset().union(*terms)
                        if len(merged) > MAX_CUT_SET_WIDTH:
                            raise _CutSetLimitError(
                                "qualitative cut-set width limit exceeded"
                            )
                        combined.add(merged)
                        if len(combined) > MAX_CUT_SETS_PER_TREE * 2:
                            combined = _minimal_terms(combined, operations=operations)
                result = _minimal_terms(combined, operations=operations)
        else:
            raise _CutSetLogicError(f"node {node_id} has unsupported kind {kind}")
        visiting.remove(node_id)
        memo[node_id] = result
        return result

    try:
        terms = _minimal_terms(expand(top_id), operations=operations)
    except _CutSetLimitError as exc:
        return {
            **base,
            "status": "not_computed_limit_exceeded",
            "review": approval,
            "operations": operations[0],
            "notice": str(exc),
        }
    except _CutSetLogicError as exc:
        return {
            **base,
            "status": "not_computed_unsupported_logic",
            "review": approval,
            "operations": operations[0],
            "notice": str(exc),
        }
    records = []
    for term in sorted(terms, key=lambda value: (len(value), tuple(sorted(value)))):
        event_ids = sorted(term)
        event_nodes = [nodes[value] for value in event_ids]
        records.append(
            {
                "id": stable_id("SFTA-CUT", str(tree.get("id", "")), *event_ids),
                "event_ids": event_ids,
                "cardinality": len(event_ids),
                "linked_finding_ids": sorted(
                    {
                        str(finding_id)
                        for node in event_nodes
                        for finding_id in node.get("linked_finding_ids", [])
                    }
                ),
                "contains_undeveloped": any(
                    node.get("event_type") == "undeveloped" for node in event_nodes
                ),
                "contains_external": any(
                    node.get("event_type") == "external" for node in event_nodes
                ),
                "contains_conditioning": any(
                    node.get("event_type") == "conditioning" for node in event_nodes
                ),
            }
        )
    return {
        **base,
        "status": "computed",
        "review": approval,
        "cut_sets": records,
        "cut_set_count": len(records),
        "operations": operations[0],
        "notice": (
            "Cut sets are qualitative consequences of the exact approved Boolean model. "
            "Events marked undeveloped, external, or conditioning remain explicit."
        ),
    }


def _approved_tree_reviews(
    analysis: dict[str, Any], definitions: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    definition_digests = {
        str(value.get("hazard", "")): canonical_json_sha256(value)
        for value in definitions
        if isinstance(value, dict) and value.get("hazard")
    }
    approvals: dict[str, dict[str, Any]] = {}
    authoring = analysis.get("sfta_authoring", {})
    history = authoring.get("history", []) if isinstance(authoring, dict) else []
    for record in history if isinstance(history, list) else []:
        if not isinstance(record, dict):
            continue
        for review in record.get("reviews", []):
            if not isinstance(review, dict) or review.get("status") != "approved":
                continue
            hazard_id = str(review.get("hazard_id", ""))
            definition_sha256 = str(review.get("definition_sha256", ""))
            if definition_digests.get(hazard_id) != definition_sha256:
                continue
            approvals[hazard_id] = {
                "status": "approved",
                "reviewer": str(review.get("reviewer", "")),
                "rationale": str(review.get("rationale", "")),
                "definition_sha256": definition_sha256,
                "sealed_input_sha256": str(record.get("sealed_input_sha256", "")),
                "applied_at": str(record.get("applied_at", "")),
                "authority": "named_structural_logic_review_not_risk_acceptance",
            }
    return approvals


def _placeholder_tree(hazard: dict[str, Any]) -> dict[str, Any]:
    hazard_id = str(hazard.get("id", ""))
    top_id = stable_id("SFTA-TOP", hazard_id)
    gap_id = stable_id("SFTA-UNDEV", hazard_id)
    tree: dict[str, Any] = {
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
    tree["cut_set_analysis"] = _qualitative_cut_sets(tree, None)
    return tree


def _explicit_tree(
    definition: dict[str, Any],
    hazard: dict[str, Any],
    findings: list[dict[str, Any]],
    findings_by_id: dict[str, dict[str, Any]],
    *,
    legacy_id_wildcard: bool = False,
    approval: dict[str, Any] | None = None,
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
        matched = _matched_finding_ids(
            findings,
            findings_by_id,
            event,
            legacy_id_wildcard=legacy_id_wildcard,
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
                    "failure_mode_patterns": list(
                        event.get("failure_mode_patterns", [])
                    ),
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
                    "label": str(
                        parent.get("gate_type") or parent.get("event_type", "")
                    ),
                }
            )
    tree: dict[str, Any] = {
        "id": str(definition["id"]),
        "hazard_id": hazard_id,
        "hazard_description": str(hazard.get("description", "")),
        "top_event_id": str(definition["top_event_id"]),
        "top_event": str(definition["top_event"]),
        "description": str(definition.get("description", "")),
        "source": "explicit_configuration",
        "logic_status": (
            "approved_for_qualitative_cut_sets"
            if approval is not None
            else "preliminary_requires_review"
        ),
        "review": approval,
        "assumptions": list(definition.get("assumptions", [])),
        "nodes": nodes,
        "edges": edges,
    }
    tree["cut_set_analysis"] = _qualitative_cut_sets(tree, approval)
    return tree


def build_sfta(
    analysis: dict[str, Any], *, legacy_id_wildcard: bool = False
) -> dict[str, Any]:
    """Build explicit/placeholder fault trees and bidirectional coverage gaps."""

    context = analysis.get("context", {})
    hazards = [value for value in context.get("hazards", []) if value.get("id")]
    hazard_by_id = {str(value["id"]): value for value in hazards}
    findings = _active_findings(analysis)
    findings_by_id = {str(value["id"]): value for value in findings if value.get("id")}
    definitions = list(context.get("fault_trees", []))
    approvals = _approved_tree_reviews(analysis, definitions)
    trees = [
        _explicit_tree(
            definition,
            hazard_by_id[str(definition["hazard"])],
            findings,
            findings_by_id,
            legacy_id_wildcard=legacy_id_wildcard,
            approval=approvals.get(str(definition["hazard"])),
        )
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
                item = findings_by_id[finding_id]
                if tree["hazard_id"] not in item.get("review", {}).get(
                    "linked_hazards", []
                ):
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
                value["hazard_id"] == hazard_id
                for value in finding_links.get(item["id"], [])
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
        if any(
            hazard in hazard_by_id
            for hazard in value.get("review", {}).get("linked_hazards", [])
        )
    }
    model = {
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
                "approved_trees": sum(
                    value.get("logic_status") == "approved_for_qualitative_cut_sets"
                    for value in trees
                ),
                "cut_set_trees": sum(
                    value.get("cut_set_analysis", {}).get("status") == "computed"
                    for value in trees
                ),
                "qualitative_cut_sets": sum(
                    int(value.get("cut_set_analysis", {}).get("cut_set_count", 0))
                    for value in trees
                ),
                "top_down_events": sum(
                    node.get("kind") == "event"
                    for tree in trees
                    for node in tree["nodes"]
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
    preserve_unchanged_generated_at(analysis.get("sfta"), model)
    return model


def export_sfta(
    analysis: dict[str, Any], destination: str | Path, *, format: str = "json"
) -> Path:
    """Export the current SFTA/reconciliation model as JSON or a flat CSV gap register."""

    model = build_sfta(analysis)
    if format == "json":
        return atomic_publish_text(
            destination,
            json.dumps(model, indent=2, ensure_ascii=False) + "\n",
            label="SFTA JSON export",
        )
    if format != "csv":
        raise ValueError("SFTA export format must be json or csv")
    rows = sfta_gap_rows(model)
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=SFTA_GAP_FIELDS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return atomic_publish_text(
        destination,
        handle.getvalue(),
        label="SFTA CSV export",
    )


def sfta_gap_rows(model: dict[str, Any]) -> list[dict[str, str]]:
    """Return the deterministic flat reconciliation-gap projection."""

    rows: list[dict[str, str]] = []
    reconciliation = model["reconciliation"]
    for value in reconciliation["top_down_uncovered_events"]:
        rows.append({"gap_type": "top_down_uncovered_event", **value})
    for value in reconciliation["bottom_up_unmapped_findings"]:
        rows.append({"gap_type": "bottom_up_unmapped_finding", **value})
    for value in reconciliation["hazard_link_mismatches"]:
        rows.append({"gap_type": "hazard_link_mismatch", **value})
    return rows
