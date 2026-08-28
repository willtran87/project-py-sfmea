"""Deterministic Goal Structuring Notation semantic projection.

The projection makes PySFMEA assurance cases navigable with familiar GSN node
semantics while retaining exact source binding.  It is deliberately described as
a semantic projection rather than a claim of conformance to a particular GSN
exchange serialization.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

from .assurance_case import load_assurance_case, verify_assurance_case
from .file_publication import atomic_publish_text
from .integrity import canonical_json_sha256
from .json_ingestion import load_bounded_json_document

GSN_PROJECTION_FORMAT = "pysfmea-gsn-semantic-projection-1"
GSN_VERIFICATION_FORMAT = "pysfmea-gsn-semantic-projection-verification-1"


def _digest(value: dict[str, Any]) -> str:
    unsigned = copy.deepcopy(value)
    unsigned.pop("content_sha256", None)
    return canonical_json_sha256(unsigned)


def _node_id(prefix: str, identifier: str) -> str:
    return f"{prefix}-{identifier}"


def gsn_projection(case_source: str | Path | dict[str, Any]) -> dict[str, Any]:
    """Project a verified assurance case onto closed GSN semantic node types."""

    if isinstance(case_source, dict):
        case = copy.deepcopy(case_source)
        source_ref = "embedded://assurance-case"
    else:
        path = Path(case_source).expanduser().resolve()
        case = load_assurance_case(path)
        source_ref = path.name
    verdict = verify_assurance_case(case)
    if not verdict["valid"]:
        raise ValueError("assurance case is not valid: " + "; ".join(verdict["errors"]))

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    id_map: dict[str, str] = {}
    claims = case.get("claims", [])
    arguments = case.get("arguments", [])
    evidence = case.get("evidence", [])
    defeaters = case.get("defeaters", [])

    for claim in claims:
        source_id = str(claim["id"])
        node_id = _node_id("G", source_id)
        id_map[source_id] = node_id
        nodes.append(
            {
                "id": node_id,
                "kind": "goal",
                "source_id": source_id,
                "statement": str(claim["statement"]),
                "status": str(claim["status"]),
                "metadata": {"title": str(claim["title"]), "scope": str(claim["scope"])},
            }
        )
        for index, assumption in enumerate(claim.get("assumptions", []), start=1):
            assumption_id = _node_id("A", f"{source_id}-{index}")
            nodes.append(
                {
                    "id": assumption_id,
                    "kind": "assumption",
                    "source_id": f"{source_id}:assumption:{index}",
                    "statement": str(assumption),
                    "status": "declared",
                    "metadata": {},
                }
            )
            edges.append({"source": node_id, "target": assumption_id, "kind": "in_context_of"})

    for argument in arguments:
        source_id = str(argument["id"])
        node_id = _node_id("S", source_id)
        id_map[source_id] = node_id
        nodes.append(
            {
                "id": node_id,
                "kind": "strategy",
                "source_id": source_id,
                "statement": str(argument["reasoning"]),
                "status": str(argument["status"]),
                "metadata": {"strategy": str(argument["strategy"])},
            }
        )

    for item in evidence:
        source_id = str(item["id"])
        node_id = _node_id("Sn", source_id)
        id_map[source_id] = node_id
        nodes.append(
            {
                "id": node_id,
                "kind": "solution",
                "source_id": source_id,
                "statement": str(item["description"]),
                "status": "cited",
                "metadata": {
                    "artifact_type": str(item["kind"]),
                    "artifact_ref": str(item["artifact"]),
                    "artifact_sha256": str(item["sha256"]),
                    "artifact_bytes": int(item["bytes"]),
                    "content_sha256": str(item["content_sha256"]),
                    "authority": str(item["authority"]),
                    "limitations": str(item["limitations"]),
                },
            }
        )

    for item in defeaters:
        source_id = str(item["id"])
        node_id = _node_id("D", source_id)
        id_map[source_id] = node_id
        nodes.append(
            {
                "id": node_id,
                "kind": "defeater",
                "source_id": source_id,
                "statement": str(item["statement"]),
                "status": "open",
                "metadata": {"resolution": str(item["resolution"])},
            }
        )
        target = id_map.get(str(item["claim_id"]))
        if target:
            edges.append({"source": node_id, "target": target, "kind": "challenges"})

    for relationship in case.get("relationships", []):
        source = id_map.get(str(relationship["source"]))
        target = id_map.get(str(relationship["target"]))
        if source and target:
            # GSN relationships point from the claim/strategy being supported to
            # the strategy/solution/subgoal that supplies support.
            edges.append({"source": target, "target": source, "kind": "supported_by"})

    node_ids = {node["id"] for node in nodes}
    top_source = str(case.get("summary", {}).get("top_claim_id", ""))
    result = {
        "format": GSN_PROJECTION_FORMAT,
        "generated_at": str(case["generated_at"]),
        "binding": {
            "assurance_case_ref": source_ref,
            "assurance_case_sha256": str(case["content_sha256"]),
        },
        "profile": {
            "notation": "Goal Structuring Notation",
            "semantic_basis": "GSN Community Standard Version 3 concepts",
            "extensions": ["defeater node", "challenges relationship"],
            "serialization": "PySFMEA closed JSON projection; not claimed as GSN interchange conformance",
        },
        "top_node_id": id_map.get(top_source, ""),
        "nodes": sorted(nodes, key=lambda item: str(item["id"])),
        "edges": sorted(edges, key=lambda item: (str(item["target"]), str(item["source"]), str(item["kind"]))),
        "summary": {
            "nodes": len(nodes),
            "edges": len(edges),
            "goals": sum(node["kind"] == "goal" for node in nodes),
            "strategies": sum(node["kind"] == "strategy" for node in nodes),
            "solutions": sum(node["kind"] == "solution" for node in nodes),
            "assumptions": sum(node["kind"] == "assumption" for node in nodes),
            "open_defeaters": sum(node["kind"] == "defeater" for node in nodes),
            "dangling_edges": sum(edge["source"] not in node_ids or edge["target"] not in node_ids for edge in edges),
        },
        "notice": "This deterministic semantic projection supports review and visualization. It does not establish safety, certification, ISO/IEC/IEEE 15026 conformity, or conformance to a GSN exchange serialization.",
        "content_sha256": "",
    }
    result["content_sha256"] = _digest(result)
    verdict = verify_gsn_projection(result)
    if not verdict["valid"]:
        raise RuntimeError("generated GSN projection failed verification: " + "; ".join(verdict["errors"]))
    return result


def verify_gsn_projection(value: dict[str, Any]) -> dict[str, Any]:
    required = {"format", "generated_at", "binding", "profile", "top_node_id", "nodes", "edges", "summary", "notice", "content_sha256"}
    structure = set(value) == required and value.get("format") == GSN_PROJECTION_FORMAT
    claimed = str(value.get("content_sha256", ""))
    integrity = bool(re.fullmatch(r"[0-9a-f]{64}", claimed) and claimed == _digest(value))
    nodes = value.get("nodes", [])
    edges = value.get("edges", [])
    node_fields = {"id", "kind", "source_id", "statement", "status", "metadata"}
    node_kinds = {"goal", "strategy", "solution", "assumption", "defeater"}
    node_shapes = bool(
        isinstance(nodes, list)
        and nodes
        and all(
            isinstance(node, dict)
            and set(node) == node_fields
            and node.get("kind") in node_kinds
            and all(
                isinstance(node.get(name), str) and bool(str(node.get(name)).strip())
                for name in ("id", "source_id", "statement", "status")
            )
            and isinstance(node.get("metadata"), dict)
            for node in nodes
        )
    )
    node_ids = [str(node["id"]) for node in nodes] if node_shapes else []
    node_by_id = {str(node["id"]): node for node in nodes} if node_shapes else {}
    graph = bool(
        node_ids
        and len(node_ids) == len(set(node_ids))
        and str(value.get("top_node_id", "")) in set(node_ids)
        and node_by_id[str(value.get("top_node_id", ""))]["kind"] == "goal"
        and isinstance(edges, list)
        and all(
            isinstance(edge, dict)
            and set(edge) == {"source", "target", "kind"}
            and edge["kind"] in {"supported_by", "in_context_of", "challenges"}
            and edge["source"] in set(node_ids)
            and edge["target"] in set(node_ids)
            for edge in edges
        )
    )
    summary = value.get("summary", {})
    expected_summary = {
        "nodes": len(node_ids),
        "edges": len(edges) if isinstance(edges, list) else 0,
        "goals": sum(node.get("kind") == "goal" for node in nodes) if node_shapes else 0,
        "strategies": sum(node.get("kind") == "strategy" for node in nodes) if node_shapes else 0,
        "solutions": sum(node.get("kind") == "solution" for node in nodes) if node_shapes else 0,
        "assumptions": sum(node.get("kind") == "assumption" for node in nodes) if node_shapes else 0,
        "open_defeaters": sum(node.get("kind") == "defeater" for node in nodes) if node_shapes else 0,
        "dangling_edges": 0,
    }
    semantic = bool(isinstance(summary, dict) and summary == expected_summary)
    errors = []
    if not structure:
        errors.append("GSN projection fields do not match format 1")
    if not integrity:
        errors.append("GSN projection content digest does not match")
    if not graph:
        errors.append("GSN projection graph has missing, duplicate, or dangling nodes")
    if not semantic:
        errors.append("GSN projection summary does not reconcile")
    valid = bool(structure and integrity and node_shapes and graph and semantic)
    return {
        "format": GSN_VERIFICATION_FORMAT,
        "valid": valid,
        "complete": valid,
        "checks": {"closed_structure": structure, "content_integrity": integrity, "graph_integrity": graph, "semantic_reconciliation": semantic, "source_regeneration": None},
        "errors": errors,
        "content_sha256": claimed,
        "notice": "Verification proves projection integrity, not assurance-case evidence truth or safety.",
    }


def verify_gsn_projection_file(source: str | Path, *, assurance_case_source: str | Path | None = None) -> dict[str, Any]:
    try:
        document = load_bounded_json_document(source, label="GSN projection", max_bytes=100_000_000, max_depth=100, max_nodes=3_000_000)
        if not isinstance(document.value, dict):
            raise ValueError("GSN projection must contain an object")
        result = verify_gsn_projection(document.value)
        result["path"] = str(document.path)
        if assurance_case_source is not None and result["valid"]:
            exact = gsn_projection(assurance_case_source) == document.value
            result["checks"]["source_regeneration"] = exact
            result["valid"] = bool(result["valid"] and exact)
            result["complete"] = bool(result["complete"] and exact)
            if not exact:
                result["errors"].append("GSN projection does not exactly regenerate")
        return result
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"path": str(Path(source).expanduser().absolute()), "format": GSN_VERIFICATION_FORMAT, "valid": False, "complete": False, "checks": {"closed_structure": False, "content_integrity": False, "graph_integrity": False, "semantic_reconciliation": False, "source_regeneration": None}, "errors": [str(exc)], "content_sha256": "", "notice": "The GSN projection could not be safely verified."}


def export_gsn_projection(value: dict[str, Any], destination: str | Path) -> Path:
    return atomic_publish_text(destination, json.dumps(value, indent=2, ensure_ascii=False) + "\n", label="GSN projection")
