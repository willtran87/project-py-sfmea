from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pysfmea.runtime import (
    MAX_RUNTIME_ATTRIBUTE_DEPTH,
    _attribute_value,
    _attributes,
    _component_from_span,
    _component_lookup,
    _iter_spans,
    _span_timing,
    import_runtime_trace,
)
from pysfmea.scanner import scan_repository
from pysfmea.validation import validate_analysis


class RuntimeNormalizationTests(unittest.TestCase):
    def test_otlp_attribute_variants_and_bounds(self) -> None:
        self.assertEqual(_attribute_value("plain"), "plain")
        for field, value in (
            ("stringValue", "text"),
            ("intValue", "7"),
            ("doubleValue", 1.5),
            ("boolValue", True),
        ):
            with self.subTest(field=field):
                self.assertEqual(_attribute_value({field: value}), value)
        self.assertEqual(
            _attribute_value(
                {"arrayValue": {"values": [{"stringValue": "a"}, {"intValue": 2}]}}
            ),
            ["a", 2],
        )
        self.assertEqual(_attribute_value({"arrayValue": []}), [])
        self.assertEqual(_attribute_value({"arrayValue": {"values": "bad"}}), [])
        self.assertEqual(
            _attribute_value({"nested": {"boolValue": False}}), {"nested": False}
        )
        nested: object = "leaf"
        for _index in range(MAX_RUNTIME_ATTRIBUTE_DEPTH + 2):
            nested = [nested]
        with self.assertRaisesRegex(ValueError, "attribute nesting"):
            _attribute_value(nested)

    def test_attribute_collections_and_span_envelopes(self) -> None:
        self.assertEqual(_attributes({"service.name": "api"}), {"service.name": "api"})
        self.assertEqual(_attributes(None), {})
        self.assertEqual(
            _attributes(
                [
                    {"key": "service.name", "value": {"stringValue": "api"}},
                    {"missing": "key"},
                    "invalid",
                ]
            ),
            {"service.name": "api"},
        )
        self.assertEqual(list(_iter_spans("invalid")), [])
        self.assertEqual(
            list(_iter_spans([{"name": "one"}, "skip"])), [{"name": "one"}]
        )
        self.assertEqual(
            list(_iter_spans({"spans": [{"name": "simple"}, 1]})),
            [{"name": "simple"}],
        )
        otlp = {
            "resourceSpans": [
                "skip",
                {"scopeSpans": "invalid"},
                {
                    "resource": {
                        "attributes": [
                            {
                                "key": "service.name",
                                "value": {"stringValue": "worker"},
                            }
                        ]
                    },
                    "instrumentationLibrarySpans": [
                        "skip",
                        {"spans": "invalid"},
                        {"spans": [{"name": "work"}, None]},
                    ],
                },
            ]
        }
        spans = list(_iter_spans(otlp))
        self.assertEqual(spans[0]["name"], "work")
        self.assertEqual(spans[0]["_resource_attributes"]["service.name"], "worker")

    def test_component_mapping_is_collision_aware(self) -> None:
        analysis = {
            "components": [
                {
                    "id": "CMP-1",
                    "name": "run",
                    "qualname": "Alpha.run",
                    "source": {"path": "alpha.py"},
                },
                {
                    "id": "CMP-2",
                    "name": "run",
                    "qualname": "Beta.run",
                    "source": {"path": "beta.py"},
                },
            ]
        }
        lookup = _component_lookup(analysis)
        self.assertNotIn("run", lookup)
        self.assertEqual(lookup["Alpha.run"], "CMP-1")
        self.assertEqual(
            _component_from_span(
                analysis, lookup, {"sfmea.component": "Alpha.run"}, "span"
            ),
            ("CMP-1", "sfmea.component", "Alpha.run"),
        )
        self.assertEqual(
            _component_from_span(analysis, lookup, {}, "Beta.run"),
            ("CMP-2", "span.name", "Beta.run"),
        )
        self.assertEqual(
            _component_from_span(
                analysis,
                lookup,
                {"code.file.path": "/workspace/alpha.py", "code.function.name": "run"},
                "operation",
            ),
            ("CMP-1", "code.file.path+function", "/workspace/alpha.py:run"),
        )
        self.assertEqual(
            _component_from_span(analysis, lookup, {}, "unknown"),
            ("", "unmapped", "unknown"),
        )

    def test_timing_status_is_explicit(self) -> None:
        self.assertEqual(_span_timing("", ""), ("unavailable", None))
        self.assertEqual(_span_timing("bad", "2"), ("invalid", None))
        self.assertEqual(_span_timing("3", "2"), ("invalid", None))
        self.assertEqual(_span_timing("2", "7"), ("observed", 5))

    def test_otlp_import_retains_timing_and_resource_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "service.py").write_text(
                "def run():\n    return 1\n", encoding="utf-8"
            )
            analysis = scan_repository(root)
            trace = root / "otlp.json"
            trace.write_text(
                json.dumps(
                    {
                        "resourceSpans": [
                            {
                                "resource": {
                                    "attributes": [
                                        {
                                            "key": "service.name",
                                            "value": {"stringValue": "fixture"},
                                        }
                                    ]
                                },
                                "scopeSpans": [
                                    {
                                        "spans": [
                                            {
                                                "traceId": "T",
                                                "spanId": "S",
                                                "name": "run",
                                                "startTimeUnixNano": "10",
                                                "endTimeUnixNano": "25",
                                            },
                                            {
                                                "traceId": "T",
                                                "spanId": "C",
                                                "parentSpanId": "S",
                                                "name": "run",
                                                "startTimeUnixNano": "12",
                                                "endTimeUnixNano": "20",
                                            },
                                        ]
                                    }
                                ],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            record = import_runtime_trace(analysis, trace)
            self.assertEqual(record["timing_statuses"], {"observed": 2})
            span = analysis["runtime_evidence"]["spans"][0]
            self.assertEqual(span["duration_ns"], 15)
            self.assertEqual(span["attributes"]["service.name"], "fixture")
            edge = analysis["runtime_evidence"]["edges"][0]
            self.assertEqual(edge["timing_status"], "observed")
            self.assertEqual(edge["duration_ns"], 8)
            self.assertEqual(edge["static_alignment"], "runtime_only")
            self.assertEqual(record["edge_alignment"]["runtime_only"], 1)

    def test_runtime_edge_correlates_unresolved_dynamic_call_site(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "dispatch.py").write_text(
                "def target():\n"
                "    return 1\n\n"
                "def dispatch(fn):\n"
                "    return fn()\n",
                encoding="utf-8",
            )
            analysis = scan_repository(root)
            components = {item["name"]: item for item in analysis["components"]}
            call_line = components["dispatch"]["call_sites"][0]["line"]
            trace = root / "dynamic.json"
            trace.write_text(
                json.dumps(
                    {
                        "spans": [
                            {
                                "trace_id": "T",
                                "span_id": "P",
                                "name": "dispatch",
                            },
                            {
                                "trace_id": "T",
                                "span_id": "C",
                                "parent_span_id": "P",
                                "name": "target",
                                "attributes": {
                                    "sfmea.caller.callsite.line": call_line
                                },
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            record = import_runtime_trace(analysis, trace)
            edge = analysis["runtime_evidence"]["edges"][0]
            self.assertEqual(edge["static_alignment"], "runtime_only")
            self.assertEqual(record["dynamic_call_site_candidate_count"], 1)
            candidate = edge["dynamic_call_site_candidates"][0]
            self.assertEqual(candidate["reference"], "fn")
            self.assertEqual(candidate["correlation"], "observed_callsite_line")
            self.assertEqual(candidate["claim"], "review_candidate_not_static_target")

    def test_instrumentation_manifest_reconciles_expected_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "service.py").write_text(
                "def run():\n    return 1\n", encoding="utf-8"
            )
            analysis = scan_repository(root)
            complete = root / "complete.json"
            complete.write_text(
                json.dumps(
                    {
                        "sfmea_instrumentation": {
                            "schema_version": "pysfmea-runtime-instrumentation-1",
                            "scenario_id": "nominal-run",
                            "producer": "integration-suite",
                            "clock_domain": "process-monotonic",
                            "sampling_policy": "always_on",
                            "expected_components": ["run"],
                            "expected_relationships": [
                                {"source": "run", "target": "run"}
                            ],
                            "dropped_spans": 0,
                            "declared_complete": True,
                        },
                        "spans": [
                            {"trace_id": "T1", "span_id": "S1", "name": "run"},
                            {
                                "trace_id": "T1",
                                "span_id": "S2",
                                "parent_span_id": "S1",
                                "name": "run",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            record = import_runtime_trace(analysis, complete)
            instrumentation = record["instrumentation"]
            self.assertEqual(
                instrumentation["status"], "complete_declared_and_observed"
            )
            self.assertEqual(instrumentation["coverage_percent"], 100.0)
            self.assertEqual(instrumentation["missing_expected_components"], [])
            self.assertEqual(instrumentation["relationship_coverage_percent"], 100.0)
            self.assertEqual(instrumentation["missing_expected_relationships"], [])

            incomplete = root / "incomplete.json"
            incomplete.write_text(
                json.dumps(
                    {
                        "sfmea_instrumentation": {
                            "schema_version": "pysfmea-runtime-instrumentation-1",
                            "scenario_id": "partial-run",
                            "producer": "integration-suite",
                            "clock_domain": "unsynchronized-host-clocks",
                            "sampling_policy": "head_sampled",
                            "expected_components": ["run", "missing.component"],
                            "expected_relationships": [
                                {"source": "run", "target": "missing.component"},
                                {"source": "run", "target": "run"},
                            ],
                            "dropped_spans": 2,
                            "declared_complete": True,
                        },
                        "spans": [{"trace_id": "T2", "span_id": "S1", "name": "run"}],
                    }
                ),
                encoding="utf-8",
            )
            incomplete_record = import_runtime_trace(analysis, incomplete)
            self.assertEqual(
                incomplete_record["instrumentation"]["status"], "incomplete"
            )
            self.assertEqual(
                incomplete_record["instrumentation"]["unknown_expected_components"],
                ["missing.component"],
            )
            self.assertEqual(
                incomplete_record["instrumentation"]["unknown_expected_relationships"],
                [{"source": "run", "target": "missing.component"}],
            )
            self.assertEqual(
                incomplete_record["instrumentation"]["missing_expected_relationships"],
                [{"source": "run", "target": "run"}],
            )
            codes = {
                value["rule_id"] for value in validate_analysis(analysis)["findings"]
            }
            self.assertIn("runtime.incomplete_instrumentation_scope", codes)

    def test_instrumentation_manifest_is_closed_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "service.py").write_text(
                "def run():\n    return 1\n", encoding="utf-8"
            )
            analysis = scan_repository(root)
            trace = root / "invalid.json"
            base = {
                "schema_version": "pysfmea-runtime-instrumentation-1",
                "scenario_id": "run",
                "producer": "suite",
                "clock_domain": "process",
                "sampling_policy": "always_on",
                "expected_components": ["run"],
                "dropped_spans": 0,
                "declared_complete": True,
            }
            for update, message in (
                ({"unknown": True}, "unsupported fields"),
                ({"sampling_policy": "sometimes"}, "sampling_policy"),
                ({"expected_components": ["run", "run"]}, "must be unique"),
                (
                    {
                        "expected_relationships": [
                            {"source": "run", "target": "run"},
                            {"source": "run", "target": "run"},
                        ]
                    },
                    "expected_relationships must be unique",
                ),
                (
                    {"expected_relationships": [{"source": "run"}]},
                    "exactly source and target",
                ),
                ({"dropped_spans": -1}, "non-negative integer"),
            ):
                with self.subTest(message=message):
                    trace.write_text(
                        json.dumps(
                            {
                                "sfmea_instrumentation": {**base, **update},
                                "spans": [
                                    {"trace_id": "T", "span_id": "S", "name": "run"}
                                ],
                            }
                        ),
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(ValueError, message):
                        import_runtime_trace(analysis, trace)


if __name__ == "__main__":
    unittest.main()
