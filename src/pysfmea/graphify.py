"""Bounded Graphify import and code-only extraction integration.

Graphify is an optional external static graph provider.  This module deliberately
keeps its result separate from PySFMEA's native AST evidence: a Graphify-only edge
is a review lead, not a confirmed call or a newly generated failure mode.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .json_ingestion import load_bounded_json_document
from .model import stable_id

GRAPHIFY_RECONCILIATION_FORMAT = "pysfmea-graphify-reconciliation-1"
MAX_GRAPHIFY_JSON_BYTES = 100_000_000
MAX_GRAPHIFY_JSON_DEPTH = 100
MAX_GRAPHIFY_JSON_NODES = 2_000_000
MAX_GRAPHIFY_RECONCILED_EDGES = 100_000
MAX_GRAPHIFY_TEXT_LENGTH = 4_096


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _line(value: Any) -> int | None:
    match = re.fullmatch(r"L(\d+)", str(value or "").strip())
    return int(match.group(1)) if match else None


def _text(value: Any, *, limit: int = MAX_GRAPHIFY_TEXT_LENGTH) -> str:
    """Keep untrusted external graph strings bounded in normalized output."""

    return str(value or "")[:limit]


def _qualname_from_label(value: Any) -> str:
    label = _text(value).strip()
    if label.startswith("."):
        label = label[1:]
    return label.removesuffix("()")


def _native_call_pairs(analysis: dict[str, Any]) -> set[tuple[str, str]]:
    """Return native caller/callee pairs using stable component IDs."""

    by_reference = {
        f"{value.get('source', {}).get('path', '')}:{value.get('qualname', '')}": str(
            value.get("id", "")
        )
        for value in analysis.get("components", [])
        if isinstance(value, dict)
    }
    pairs: set[tuple[str, str]] = set()
    for target in analysis.get("components", []):
        if not isinstance(target, dict):
            continue
        target_id = str(target.get("id", ""))
        for caller_reference in target.get("called_by", []):
            caller_id = by_reference.get(str(caller_reference))
            if caller_id and target_id:
                pairs.add((caller_id, target_id))
    return pairs


def _component_mapping(analysis: dict[str, Any]) -> dict[tuple[str, int | None, str], str]:
    mapping: dict[tuple[str, int | None, str], str] = {}
    for component in analysis.get("components", []):
        if not isinstance(component, dict):
            continue
        source = component.get("source", {})
        if not isinstance(source, dict):
            continue
        path = str(source.get("path", "")).replace("\\", "/")
        line = source.get("line")
        component_id = str(component.get("id", ""))
        qualname = str(component.get("qualname", ""))
        if path and component_id:
            mapping[(path, int(line) if isinstance(line, int) else None, qualname)] = component_id
    return mapping


def _map_node(
    node: dict[str, Any],
    component_mapping: dict[tuple[str, int | None, str], str],
) -> str:
    path = _text(node.get("source_file")).replace("\\", "/")
    line = _line(node.get("source_location"))
    label = _qualname_from_label(node.get("label"))
    exact = component_mapping.get((path, line, label))
    if exact:
        return exact
    line_matches = {
        component_id
        for (candidate_path, candidate_line, _qualname), component_id in component_mapping.items()
        if candidate_path == path and candidate_line == line
    }
    if len(line_matches) == 1:
        return next(iter(line_matches))
    label_matches = {
        component_id
        for (candidate_path, _candidate_line, qualname), component_id in component_mapping.items()
        if candidate_path == path and qualname.rsplit(".", 1)[-1] == label
    }
    return next(iter(label_matches)) if len(label_matches) == 1 else ""


def load_graphify_reconciliation(
    analysis: dict[str, Any], source: str | Path
) -> dict[str, Any]:
    """Normalize a Graphify ``graph.json`` and reconcile it with native call facts."""

    document = load_bounded_json_document(
        source,
        label="Graphify graph JSON",
        max_bytes=MAX_GRAPHIFY_JSON_BYTES,
        max_depth=MAX_GRAPHIFY_JSON_DEPTH,
        max_nodes=MAX_GRAPHIFY_JSON_NODES,
    )
    graph = document.value
    if not isinstance(graph, dict):
        raise ValueError("Graphify graph JSON root must be an object")
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        raise ValueError("Graphify graph JSON must contain nodes and edges arrays")
    if not all(isinstance(value, dict) for value in nodes + edges):
        raise ValueError("Graphify graph JSON nodes and edges must contain objects")

    component_mapping = _component_mapping(analysis)
    node_component_ids = {
        _text(node.get("id", "")): _map_node(node, component_mapping)
        for node in nodes
        if _text(node.get("id", ""))
    }
    native_pairs = _native_call_pairs(analysis)
    normalized_edges: list[dict[str, Any]] = []
    total_mapped_edges = 0
    call_edges = 0
    corroborated_calls = 0
    graphify_only_calls = 0
    for edge in edges:
        source_node_id = _text(edge.get("source", ""))
        target_node_id = _text(edge.get("target", ""))
        source_component_id = node_component_ids.get(source_node_id, "")
        target_component_id = node_component_ids.get(target_node_id, "")
        if not source_component_id or not target_component_id:
            continue
        total_mapped_edges += 1
        relation = _text(edge.get("relation", "unknown"), limit=128)
        confidence_score = edge.get("confidence_score")
        if not isinstance(confidence_score, (int, float)) or isinstance(
            confidence_score, bool
        ) or not math.isfinite(confidence_score):
            confidence_score = None
        is_call = relation == "calls"
        if is_call:
            call_edges += 1
            reconciliation = (
                "corroborated" if (source_component_id, target_component_id) in native_pairs else "graphify_only_review_lead"
            )
            corroborated_calls += reconciliation == "corroborated"
            graphify_only_calls += reconciliation == "graphify_only_review_lead"
        else:
            reconciliation = "outside_native_call_comparison"
        if len(normalized_edges) < MAX_GRAPHIFY_RECONCILED_EDGES:
            normalized_edges.append(
                {
                    "id": stable_id(
                        "GRAPHIFY",
                        source_node_id,
                        target_node_id,
                        relation,
                        str(edge.get("source_location", "")),
                    ),
                    "source_component_id": source_component_id,
                    "target_component_id": target_component_id,
                    "relation": relation,
                    "context": _text(edge.get("context"), limit=256),
                    "confidence": _text(edge.get("confidence", "unknown"), limit=64),
                    "confidence_score": confidence_score,
                    "source_file": _text(edge.get("source_file")).replace("\\", "/"),
                    "source_location": _text(edge.get("source_location"), limit=64),
                    "reconciliation": reconciliation,
                }
            )
    raw_sha256 = hashlib.sha256(document.raw).hexdigest()
    source_reference = str(document.path)
    return {
        "format": GRAPHIFY_RECONCILIATION_FORMAT,
        "source": {
            "path": source_reference,
            "sha256": raw_sha256,
            "bytes": document.size,
            "ingestion": "strict_bounded_identity_stable_json",
        },
        "authority": (
            "External Graphify code-graph reconciliation is supplementary static evidence; "
            "Graphify-only edges are review leads and do not establish runtime behavior, "
            "failure propagation, or assurance credit."
        ),
        "summary": {
            "nodes_discovered": len(nodes),
            "edges_discovered": len(edges),
            "mapped_nodes": sum(bool(value) for value in node_component_ids.values()),
            "mapped_edges": total_mapped_edges,
            "edges_embedded": len(normalized_edges),
            "edges_omitted": max(0, total_mapped_edges - len(normalized_edges)),
            "call_edges_between_mapped_components": call_edges,
            "corroborated_call_edges": corroborated_calls,
            "graphify_only_call_review_leads": graphify_only_calls,
            "native_call_edges": len(native_pairs),
            "truncated": total_mapped_edges > len(normalized_edges),
        },
        "edges": normalized_edges,
        "reconciliation_sha256": _digest(
            {
                "source_sha256": raw_sha256,
                "summary": {
                    "nodes_discovered": len(nodes),
                    "edges_discovered": len(edges),
                    "mapped_edges": total_mapped_edges,
                    "corroborated_call_edges": corroborated_calls,
                    "graphify_only_call_review_leads": graphify_only_calls,
                },
                "edges": normalized_edges,
            }
        ),
    }


def run_graphify_code_only(
    repository: str | Path,
    output_directory: str | Path,
    *,
    timeout_seconds: int = 600,
) -> Path:
    """Run Graphify's local AST-only extraction and return its graph artifact path."""

    if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 3_600:
        raise ValueError("Graphify timeout_seconds must be an integer from 1 through 3600")
    executable = shutil.which("graphify")
    if not executable:
        raise ValueError(
            "Graphify executable was not found. Install the graphifyy package, then rerun with --graphify."
        )
    repository_path = Path(repository).expanduser().resolve()
    destination = Path(output_directory).expanduser().absolute()
    if not repository_path.is_dir():
        raise ValueError(f"Graphify repository path is not a directory: {repository_path}")
    if destination.is_symlink():
        raise ValueError("Graphify output directory must not be a symbolic link")
    destination.mkdir(parents=True, exist_ok=True)
    command = [
        executable,
        "extract",
        str(repository_path),
        "--code-only",
        "--force",
        "--no-cluster",
        "--output",
        str(destination),
    ]
    try:
        result = subprocess.run(
            command,
            cwd=repository_path,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError(f"Graphify code-only extraction timed out after {timeout_seconds} seconds") from exc
    if result.returncode:
        raise ValueError(f"Graphify code-only extraction failed with exit code {result.returncode}")
    graph_path = destination / "graphify-out" / "graph.json"
    if not graph_path.is_file() or graph_path.is_symlink():
        raise ValueError("Graphify extraction did not produce a regular graphify-out/graph.json")
    return graph_path
