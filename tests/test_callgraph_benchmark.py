from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from pysfmea.callgraph_benchmark import compare_callgraphs, verify_callgraph_comparison
from pysfmea.cli import main
from pysfmea.governed_artifact import seal
from pysfmea.schemas import schema_document


def test_callgraph_metrics_and_exact_replay(tmp_path: Path) -> None:
    expected, actual, output = (
        tmp_path / n for n in ("expected.json", "actual.json", "report.json")
    )
    expected.write_text(json.dumps({"a": ["b", "c"]}), encoding="utf-8")
    actual.write_text(json.dumps({"a": ["b", "d"]}), encoding="utf-8")
    value = compare_callgraphs(
        expected, actual, subject_revision="reviewed-revision", authority="reviewer"
    )
    assert value["metrics"] == {
        "true_positive": 1,
        "false_positive": 1,
        "false_negative": 1,
        "precision": 0.5,
        "recall": 0.5,
    }
    Draft202012Validator(schema_document("callgraph-benchmark")).validate(value)
    assert verify_callgraph_comparison(value, expected, actual)
    value["metrics"]["precision"] = 1
    assert not verify_callgraph_comparison(seal(value), expected, actual)
    assert (
        main(
            [
                "callgraph-benchmark",
                str(expected),
                str(actual),
                "--revision",
                "reviewed-revision",
                "--authority",
                "reviewer",
                "-o",
                str(output),
            ]
        )
        == 0
    )
    assert (
        main(["callgraph-benchmark-verify", str(output), str(expected), str(actual)])
        == 0
    )
    actual.write_text('{"a": ["b"]}', encoding="utf-8")
    assert (
        main(["callgraph-benchmark-verify", str(output), str(expected), str(actual)])
        == 1
    )


@pytest.mark.parametrize(
    "graph",
    [{}, [], {"a": ["b", "b"]}, {"a": [False]}, {"a": [""]}, {"": []}, {"a": "b"}],
)
def test_invalid_graph_rejected(tmp_path: Path, graph: object) -> None:
    source = tmp_path / "graph.json"
    source.write_text(json.dumps(graph), encoding="utf-8")
    with pytest.raises(ValueError):
        compare_callgraphs(source, source, subject_revision="r", authority="a")


def test_no_edges_has_no_precision_or_recall_denominator(tmp_path: Path) -> None:
    source = tmp_path / "graph.json"
    source.write_text('{"a": []}', encoding="utf-8")
    value = compare_callgraphs(source, source, subject_revision="r", authority="a")
    assert value["metrics"]["precision"] is None
    assert value["metrics"]["recall"] is None
    Draft202012Validator(schema_document("callgraph-benchmark")).validate(value)


def test_duplicate_json_keys_fail_closed(tmp_path: Path) -> None:
    source = tmp_path / "graph.json"
    source.write_text('{"a": [], "a": ["b"]}', encoding="utf-8")
    with pytest.raises(ValueError):
        compare_callgraphs(source, source, subject_revision="r", authority="a")
