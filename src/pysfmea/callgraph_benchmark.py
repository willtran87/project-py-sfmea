"""Exact-source comparison of PyCG simple-JSON adjacency graphs.

Reference: https://github.com/vitsalis/PyCG#simple-json-format
An observed runtime graph is not a complete negative-label oracle.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .governed_artifact import bounded_text, seal, verify_seal
from .json_ingestion import load_bounded_json_document


def _graph(path: str | Path) -> tuple[set[tuple[str, str]], dict[str, Any]]:
    document = load_bounded_json_document(
        Path(path),
        label="callgraph benchmark",
        max_bytes=50000000,
        max_depth=10,
        max_nodes=2000000,
    )
    value = document.value
    if not isinstance(value, dict) or not value or len(value) > 100000:
        raise ValueError("callgraph requires a nonempty bounded adjacency object")
    edges: set[tuple[str, str]] = set()
    for caller, callees in value.items():
        bounded_text(caller, "callgraph caller")
        if (
            not isinstance(callees, list)
            or any(not isinstance(c, str) or not c.strip() for c in callees)
            or len(callees) != len(set(callees))
        ):
            raise ValueError("callgraph callees must be a unique list of names")
        for callee in callees:
            bounded_text(callee, "callgraph callee")
        edges.update((caller, callee) for callee in callees)
        if len(edges) > 1000000:
            raise ValueError("callgraph edge limit exceeded")
    return edges, {
        "name": Path(path).name,
        "bytes": document.size,
        "sha256": hashlib.sha256(document.raw).hexdigest(),
    }


def compare_callgraphs(
    expected: str | Path, actual: str | Path, *, subject_revision: str, authority: str
) -> dict[str, Any]:
    oracle, expected_binding = _graph(expected)
    predicted, actual_binding = _graph(actual)
    tp, fp, fn = (
        len(oracle & predicted),
        len(predicted - oracle),
        len(oracle - predicted),
    )
    return seal(
        {
            "format": "pysfmea-callgraph-benchmark-1",
            "subject_revision": bounded_text(
                subject_revision, "callgraph subject revision"
            ),
            "authority": bounded_text(authority, "callgraph comparison authority"),
            "sources": {"expected": expected_binding, "actual": actual_binding},
            "metrics": {
                "true_positive": tp,
                "false_positive": fp,
                "false_negative": fn,
                "precision": tp / (tp + fp) if tp + fp else None,
                "recall": tp / (tp + fn) if tp + fn else None,
            },
            "edges": [
                {
                    "caller": a,
                    "callee": b,
                    "expected": (a, b) in oracle,
                    "predicted": (a, b) in predicted,
                }
                for a, b in sorted(oracle | predicted)
            ],
            "claim_boundary": "Review input only. Precision and false-positive interpretation require an independently reviewed, complete expected graph for this exact subject. Dynamic traces alone cannot supply negative labels. No true-negative denominator, external benchmark execution, independence, or qualification is inferred.",
        }
    )


def verify_callgraph_comparison(
    value: dict[str, Any], expected: str | Path, actual: str | Path
) -> bool:
    try:
        verify_seal(
            value,
            label="callgraph comparison",
            format_value="pysfmea-callgraph-benchmark-1",
        )
        return (
            compare_callgraphs(
                expected,
                actual,
                subject_revision=value["subject_revision"],
                authority=value["authority"],
            )
            == value
        )
    except (OSError, KeyError, TypeError, ValueError):
        return False
