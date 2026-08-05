"""Canonical hashing primitives shared by governed PySFMEA artifacts."""

from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_GOVERNED_JSON_DEPTH = 100
MAX_GOVERNED_JSON_NODES = 2_000_000


def canonical_json_sha256(value: Any) -> str:
    """Hash JSON-compatible data using the project's canonical UTF-8 encoding."""

    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def bounded_json_structure_metrics(
    value: Any,
    *,
    max_depth: int = MAX_GOVERNED_JSON_DEPTH,
    max_nodes: int = MAX_GOVERNED_JSON_NODES,
) -> dict[str, int | bool]:
    """Measure JSON-compatible structure iteratively and stop at the node bound."""

    node_count = 0
    observed_depth = 0
    depth_within_limit = True
    node_within_limit = True
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        node_count += 1
        observed_depth = max(observed_depth, depth)
        if depth > max_depth:
            depth_within_limit = False
        if node_count > max_nodes:
            node_within_limit = False
            break
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
    return {
        "node_count": node_count,
        "max_depth": observed_depth,
        "depth_within_limit": depth_within_limit,
        "node_within_limit": node_within_limit,
    }
