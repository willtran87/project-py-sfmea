from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.cli import main
from pysfmea.diagrams import (
    DIAGRAM_BUNDLE_SCHEMA,
    DIAGRAM_SCHEMA,
    build_diagram_models,
    export_diagram_bundle,
    failure_propagation_diagram,
    load_diagram_files,
    normalize_diagram_model,
    verify_diagram_bundle_integrity,
)
from pysfmea.html_report import export_html_report
from pysfmea.report import analysis_state_sha256
from pysfmea.scanner import scan_repository
from pysfmea.store import save_analysis


def custom_state_diagram() -> dict[str, object]:
    return {
        "schema_version": DIAGRAM_SCHEMA,
        "id": "workflow-state-machine",
        "title": "Workflow state machine",
        "type": "state",
        "description": "Configured execution lifecycle.",
        "notice": "Transitions are project-supplied and require review.",
        "nodes": [
            {
                "id": "draft",
                "label": "Draft <untrusted>",
                "kind": "state",
                "layer": 0,
            },
            {
                "id": "running",
                "label": "Running",
                "kind": "state",
                "layer": 1,
                "metrics": {"terminal": False},
            },
            {
                "id": "complete",
                "label": "Complete",
                "kind": "state",
                "layer": 2,
            },
        ],
        "edges": [
            {
                "id": "start",
                "source": "draft",
                "target": "running",
                "label": "start",
                "kind": "transition",
                "evidence": "project configuration",
                "order": 0,
            },
            {
                "id": "finish",
                "source": "running",
                "target": "complete",
                "label": "finish",
                "kind": "transition",
                "order": 1,
            },
        ],
        "metadata": {"owner": "Systems engineering"},
    }


class DiagramTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "service.py").write_text(
            "def validate(value):\n    return bool(value)\n\n"
            "def execute(value):\n    validate(value)\n    return value\n",
            encoding="utf-8",
        )
        self.analysis = scan_repository(
            self.root,
            config={
                "requirements": [
                    {
                        "id": "REQ-1",
                        "text": "Execute a valid request.",
                        "hazards": ["HZ-1"],
                    }
                ],
                "hazards": [
                    {
                        "id": "HZ-1",
                        "description": "Incorrect execution",
                        "end_effect": "An operation is incorrect.",
                    }
                ],
                "system_interfaces": [
                    {
                        "id": "IF-1",
                        "source": "Client",
                        "target": "Service",
                        "description": "Execution request",
                    }
                ],
                "component_mappings": [
                    {
                        "pattern": "service.py:execute",
                        "subsystem": "Execution",
                        "requirements": ["REQ-1"],
                        "hazards": ["HZ-1"],
                        "interfaces": ["IF-1"],
                    }
                ],
            },
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_canonical_model_supports_general_state_diagrams(self) -> None:
        model = normalize_diagram_model(custom_state_diagram())
        self.assertEqual(model["schema_version"], DIAGRAM_SCHEMA)
        self.assertEqual(model["type"], "state")
        self.assertEqual(len(model["nodes"]), 3)
        self.assertEqual(model["edges"][0]["evidence"], "project configuration")

        dangling = custom_state_diagram()
        dangling["edges"][0]["target"] = "missing"
        with self.assertRaisesRegex(ValueError, "unknown node"):
            normalize_diagram_model(dangling)

        duplicate = custom_state_diagram()
        duplicate["nodes"].append(dict(duplicate["nodes"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate diagram node"):
            normalize_diagram_model(duplicate)

    def test_analysis_generates_all_core_diagram_categories(self) -> None:
        diagrams = build_diagram_models(self.analysis)
        categories = {diagram["metadata"].get("category") for diagram in diagrams}
        self.assertTrue(
            {
                "architecture",
                "interface_flow",
                "traceability",
                "guidance_traceability",
                "assurance_traceability",
                "failure_propagation",
                "control_coverage",
                "sequence",
            }.issubset(categories)
        )
        self.assertTrue(all(diagram["schema_version"] == DIAGRAM_SCHEMA for diagram in diagrams))
        self.assertTrue(
            all(
                edge["source"] in {node["id"] for node in diagram["nodes"]}
                and edge["target"] in {node["id"] for node in diagram["nodes"]}
                for diagram in diagrams
                for edge in diagram["edges"]
            )
        )

    def test_bundle_cli_and_category_export(self) -> None:
        output = export_diagram_bundle(
            self.analysis,
            self.root / "traceability.json",
            kind="traceability",
        )
        bundle = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(bundle["schema_version"], DIAGRAM_BUNDLE_SCHEMA)
        self.assertEqual(
            bundle["binding"]["analysis_state_sha256"],
            analysis_state_sha256(self.analysis),
        )
        self.assertEqual(bundle["binding"]["format"], DIAGRAM_BUNDLE_SCHEMA)
        verification = verify_diagram_bundle_integrity(
            bundle, analysis=self.analysis
        )
        self.assertEqual(
            verification["content_sha256"],
            bundle["integrity"]["content_sha256"],
        )
        self.assertTrue(verification["analysis_binding_matches"])
        self.assertEqual(len(bundle["diagrams"]), 1)
        self.assertEqual(bundle["diagrams"][0]["type"], "traceability")

        tampered = json.loads(json.dumps(bundle))
        tampered["diagrams"][0]["title"] = "Changed after publication"
        tampered_path = self.root / "tampered-bundle.json"
        tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "integrity failed"):
            load_diagram_files([tampered_path])
        changed_analysis = json.loads(json.dumps(self.analysis))
        changed_analysis["project"]["name"] = "Different governed state"
        with self.assertRaisesRegex(ValueError, "state binding does not match"):
            verify_diagram_bundle_integrity(bundle, analysis=changed_analysis)

        analysis_path = self.root / "analysis.json"
        save_analysis(analysis_path, self.analysis)
        included_id = self.analysis["items"][-1]["id"]
        cli_output = io.StringIO()
        with contextlib.redirect_stdout(cli_output):
            result = main(
                [
                    "diagram",
                    str(analysis_path),
                    "--type",
                    "failure_propagation",
                    "--propagation-record-limit",
                    "1",
                    "--propagation-include-finding",
                    included_id,
                    "--propagation-path-limit",
                    "0",
                    "--propagation-depth",
                    "0",
                ]
            )
        self.assertEqual(result, 0)
        self.assertIn("Verified diagram artifact", cli_output.getvalue())
        self.assertIn("analysis-state=", cli_output.getvalue())
        generated = self.root / "analysis-failure_propagation-diagrams.json"
        self.assertTrue(generated.is_file())
        generated_bundle = json.loads(generated.read_text(encoding="utf-8"))
        self.assertEqual(
            generated_bundle["generation"]["failure_propagation"],
            {
                "record_limit": 1,
                "paths_per_component": 0,
                "depth": 0,
                "include_finding_ids": [included_id],
            },
        )
        self.assertEqual(
            generated_bundle["diagrams"][0]["metadata"]["record_limit"], 1
        )
        self.assertIn(
            f"failure:{included_id}",
            {node["id"] for node in generated_bundle["diagrams"][0]["nodes"]},
        )
        error_output = io.StringIO()
        with contextlib.redirect_stderr(error_output):
            result = main(
                [
                    "diagram",
                    str(analysis_path),
                    "--type",
                    "architecture",
                    "--propagation-include-finding",
                    included_id,
                ]
            )
        self.assertEqual(result, 2)
        self.assertIn("require diagram kind", error_output.getvalue())

    def test_diagram_bundle_publication_is_atomic(self) -> None:
        destination = self.root / "atomic-bundle.json"
        destination.write_text("previous artifact", encoding="utf-8")

        with patch("pysfmea.diagrams.os.replace", side_effect=OSError("blocked")):
            with self.assertRaisesRegex(OSError, "blocked"):
                export_diagram_bundle(self.analysis, destination)

        self.assertEqual(destination.read_text(encoding="utf-8"), "previous artifact")
        self.assertFalse(list(self.root.glob(".atomic-bundle.json.*.tmp")))

    def test_failure_propagation_can_pin_specific_active_findings(self) -> None:
        included_id = self.analysis["items"][-1]["id"]
        diagram = build_diagram_models(
            self.analysis,
            kind="failure_propagation",
            propagation_record_limit=1,
            propagation_path_limit=0,
            propagation_depth=0,
            propagation_include_finding_ids=[included_id, included_id],
        )[0]

        self.assertIn(
            f"failure:{included_id}", {node["id"] for node in diagram["nodes"]}
        )
        self.assertEqual(
            diagram["metadata"]["requested_included_finding_ids"], [included_id]
        )
        self.assertEqual(diagram["metadata"]["pinned_findings_embedded"], 1)
        self.assertEqual(
            diagram["metadata"]["selection_policy"],
            "pinned_then_component_first_then_priority_fill",
        )
        with self.assertRaisesRegex(ValueError, "active findings"):
            build_diagram_models(
                self.analysis,
                kind="failure_propagation",
                propagation_include_finding_ids=["FM-UNKNOWN"],
            )
        with self.assertRaisesRegex(ValueError, "count exceeds"):
            build_diagram_models(
                self.analysis,
                kind="failure_propagation",
                propagation_record_limit=1,
                propagation_include_finding_ids=[
                    self.analysis["items"][0]["id"],
                    self.analysis["items"][-1]["id"],
                ],
            )

    def test_failure_propagation_limits_are_configurable_and_budgeted(self) -> None:
        configured = build_diagram_models(
            self.analysis,
            kind="failure_propagation",
            propagation_record_limit=2,
            propagation_path_limit=1,
            propagation_depth=1,
        )[0]

        self.assertEqual(configured["metadata"]["record_limit"], 2)
        self.assertEqual(configured["metadata"]["cascade_paths_per_component"], 1)
        self.assertEqual(configured["metadata"]["cascade_depth"], 1)
        self.assertEqual(configured["metadata"]["conservative_node_estimate"], 18)
        self.assertEqual(configured["metadata"]["projection_node_budget"], 2_000)
        self.assertEqual(configured["metadata"]["node_budget_utilization_percent"], 0.9)
        self.assertEqual(configured["metadata"]["projection_status"], "bounded_projection")
        self.assertIn(
            "finding_record_limit",
            configured["metadata"]["projection_reason_codes"],
        )
        with self.assertRaisesRegex(ValueError, "require diagram kind"):
            build_diagram_models(
                self.analysis,
                kind="architecture",
                propagation_record_limit=2,
            )
        with self.assertRaisesRegex(ValueError, "record limit"):
            build_diagram_models(
                self.analysis,
                kind="failure_propagation",
                propagation_record_limit=0,
            )
        with self.assertRaisesRegex(ValueError, "combined propagation limits"):
            build_diagram_models(
                self.analysis,
                kind="failure_propagation",
                propagation_record_limit=250,
                propagation_path_limit=25,
                propagation_depth=12,
            )

    def test_failure_propagation_includes_bounded_evidence_labeled_cascades(self) -> None:
        components = {
            value["qualname"]: value for value in self.analysis["components"]
        }
        self.analysis["runtime_evidence"] = {
            "edges": [
                {
                    "source_component_id": components["execute"]["id"],
                    "target_component_id": components["validate"]["id"],
                    "operation": "execute calls validate",
                }
            ]
        }

        diagram = build_diagram_models(
            self.analysis, kind="failure_propagation"
        )[0]
        cascade_nodes = [
            value for value in diagram["nodes"] if value["kind"] == "cascade_component"
        ]
        observed_edges = [
            value
            for value in diagram["edges"]
            if value["kind"] == "observed_upstream_exposure"
        ]

        self.assertTrue(cascade_nodes)
        self.assertEqual(len(cascade_nodes), 1)
        self.assertEqual(
            len(
                [
                    value
                    for value in diagram["nodes"]
                    if value["kind"] == "cascade_origin"
                ]
            ),
            1,
        )
        self.assertTrue(observed_edges)
        self.assertTrue(
            all("observed_runtime" in value["tags"] for value in cascade_nodes)
        )
        self.assertTrue(
            all("not proof" in value["description"] for value in observed_edges)
        )
        self.assertGreater(diagram["metadata"]["embedded_cascade_paths"], 0)
        self.assertGreater(diagram["metadata"]["observed_cascade_edges"], 0)
        self.assertEqual(diagram["metadata"]["cascade_paths_per_component"], 3)
        self.assertEqual(diagram["metadata"]["cascade_depth"], 6)
        self.assertGreater(diagram["metadata"]["deduplicated_record_path_reuses"], 0)
        self.assertIn("potential exposure", diagram["notice"])
        validate_finding_ids = {
            value["id"]
            for value in self.analysis["items"]
            if value["component"]["qualname"] == "validate"
        }
        obligation = next(
            value
            for value in self.analysis["assurance"]["obligations"]
            if value["finding_id"] in validate_finding_ids
        )
        self.assertIn("service.py:execute", obligation["cascade_context"]["direct_callers"])
        self.assertEqual(
            obligation["cascade_context"]["static_upstream_paths"][0],
            ["service.py:execute", "service.py:validate"],
        )
        self.assertTrue(
            any("caller path" in value for value in obligation["acceptance_criteria"])
        )

    def test_failure_cascade_cycles_remain_explicit_and_bounded(self) -> None:
        (self.root / "cycle.py").write_text(
            "def first(value):\n"
            "    return second(value)\n\n"
            "def second(value):\n"
            "    return first(value)\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)

        diagram = build_diagram_models(
            analysis, kind="failure_propagation"
        )[0]

        self.assertTrue(
            any(
                value["cycle"]
                for value in diagram["edges"]
                if value["kind"] == "potential_upstream_exposure"
            )
        )
        self.assertLessEqual(diagram["metadata"]["cascade_depth"], 6)
        self.assertLessEqual(
            diagram["metadata"]["embedded_cascade_edges"],
            diagram["metadata"]["embedded_cascade_paths"]
            * diagram["metadata"]["cascade_depth"],
        )

    def test_failure_projection_prioritizes_component_diversity(self) -> None:
        (self.root / "many_components.py").write_text(
            "\n\n".join(
                f"def component_{index:02d}(value):\n    return value"
                for index in range(45)
            )
            + "\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)

        diagram = build_diagram_models(
            analysis, kind="failure_propagation"
        )[0]
        component_nodes = [
            value for value in diagram["nodes"] if value["kind"] == "component"
        ]

        self.assertEqual(len(component_nodes), 40)
        self.assertEqual(diagram["metadata"]["records_embedded"], 40)
        self.assertEqual(diagram["metadata"]["components_embedded"], 40)
        self.assertGreater(diagram["metadata"]["total_active_components"], 40)
        self.assertTrue(diagram["metadata"]["records_truncated"])
        self.assertTrue(diagram["metadata"]["components_truncated"])
        self.assertEqual(
            diagram["metadata"]["projection_status"], "bounded_projection"
        )
        self.assertIn(
            "component_projection",
            diagram["metadata"]["projection_reason_codes"],
        )
        self.assertEqual(
            diagram["metadata"]["selection_policy"],
            "component_first_then_priority_fill",
        )
        self.assertEqual(
            diagram["metadata"]["additional_findings_after_component_pass"], 0
        )
        self.assertIn("Component-first selection", diagram["notice"])

    def test_failure_projection_discloses_each_cascade_bound(self) -> None:
        component = next(
            value for value in self.analysis["components"] if value["qualname"] == "validate"
        )
        target = f"{component['source']['path']}:{component['qualname']}"
        component["upstream_paths"] = [
            [f"external.py:caller_{index}", target] for index in range(5)
        ]
        component["upstream_path_analysis"] = {
            "emitted_paths": 5,
            "complete_within_static_call_model": False,
            "path_limit_truncated": True,
            "depth_limited_paths": 1,
        }

        diagram = failure_propagation_diagram(
            self.analysis, cascade_paths_per_component=2, cascade_depth=0
        )
        metadata = diagram["metadata"]
        origin = next(
            value
            for value in diagram["nodes"]
            if value["id"] == f"cascade-origin:{component['id']}"
        )

        self.assertEqual(metadata["available_discovered_cascade_paths"], 5)
        self.assertEqual(metadata["embedded_cascade_paths"], 2)
        self.assertEqual(metadata["paths_omitted_by_path_limit"], 3)
        self.assertEqual(metadata["depth_truncated_paths"], 2)
        self.assertEqual(metadata["segments_omitted_by_depth_limit"], 2)
        self.assertEqual(metadata["source_path_inventory_truncated_components"], 1)
        self.assertEqual(metadata["projection_status"], "source_inventory_bounded")
        self.assertIn(
            "source_path_inventory_limit", metadata["projection_reason_codes"]
        )
        self.assertTrue(metadata["cascade_paths_truncated"])
        self.assertFalse(metadata["cascade_projection_complete"])
        self.assertEqual(origin["metrics"]["paths_omitted_by_diagram_limit"], 3)
        self.assertFalse(origin["metrics"]["source_path_inventory_complete"])

    def test_failure_projection_complete_status_is_scoped_to_discovered_inventory(
        self,
    ) -> None:
        analysis = json.loads(json.dumps(self.analysis))
        item = analysis["items"][0]
        analysis["items"] = [item]
        component = next(
            value
            for value in analysis["components"]
            if value["id"] == item["component_id"]
        )
        component["upstream_paths"] = []
        component["upstream_path_analysis"] = {
            "emitted_paths": 0,
            "complete_within_static_call_model": True,
            "path_limit_truncated": False,
            "depth_limited_paths": 0,
        }

        diagram = failure_propagation_diagram(analysis, record_limit=1)

        self.assertEqual(
            diagram["metadata"]["projection_status"],
            "complete_within_discovered_static_inventory",
        )
        self.assertEqual(diagram["metadata"]["projection_reason_codes"], [])

    def test_detected_circuit_breaker_generates_state_diagram(self) -> None:
        (self.root / "breaker.py").write_text(
            "import asyncio\nimport time\n"
            "_circuit_lock = asyncio.Lock()\n"
            "_failures = {}\n_circuit_open = {}\n"
            "async def check_circuit(service_id):\n"
            "    async with _circuit_lock:\n"
            "        if service_id in _circuit_open:\n"
            "            if time.monotonic() - _circuit_open[service_id] < 30:\n"
            "                return True\n"
            "            del _circuit_open[service_id]\n"
            "        if _failures.get(service_id, 0) >= 3:\n"
            "            _circuit_open[service_id] = time.monotonic()\n"
            "            return True\n"
            "        return False\n",
            encoding="utf-8",
        )
        analysis = scan_repository(self.root)
        diagrams = build_diagram_models(analysis, kind="circuit_breaker")
        self.assertEqual(len(diagrams), 1)
        diagram = diagrams[0]
        self.assertEqual(diagram["type"], "state")
        self.assertEqual(diagram["metadata"]["category"], "circuit_breaker")
        by_label = {value["label"]: value for value in diagram["nodes"]}
        self.assertTrue(
            {"CLOSED", "OPEN", "RECOVERY PROBE"} <= set(by_label)
        )
        self.assertTrue(any(label.startswith("REVIEW GAPS") for label in by_label))
        self.assertEqual(by_label["OPEN"]["kind"], "breaker_state")
        self.assertEqual(by_label["CLOSED"]["kind"], "unconfirmed_state")
        self.assertEqual(by_label["RECOVERY PROBE"]["kind"], "unconfirmed_state")
        self.assertEqual(diagram["metadata"]["observed_states"], ["open"])
        self.assertTrue(
            any(
                "recovery-to-CLOSED" in value
                for value in diagram["metadata"]["review_gaps"]
            )
        )
        self.assertTrue(
            {"failure threshold reached", "cooldown elapsed", "probe fails"}
            <= {value["label"] for value in diagram["edges"]}
        )
        self.assertNotIn("probe succeeds", {value["label"] for value in diagram["edges"]})

        propagation = build_diagram_models(
            analysis, kind="failure_propagation"
        )[0]
        propagation_kinds = {value["kind"] for value in propagation["nodes"]}
        self.assertIn("timing_boundary", propagation_kinds)
        self.assertIn("containment_boundary", propagation_kinds)
        self.assertEqual(
            len(
                [
                    value
                    for value in propagation["nodes"]
                    if value["kind"] == "timing_boundary"
                ]
            ),
            1,
        )
        self.assertEqual(
            len(
                [
                    value
                    for value in propagation["nodes"]
                    if value["kind"] == "containment_boundary"
                ]
            ),
            1,
        )
        self.assertTrue(
            any(
                value["kind"] == "containment_challenge"
                and "effectiveness unconfirmed" in value["evidence"]
                for value in propagation["edges"]
            )
        )

    def test_class_breaker_members_share_one_aggregated_state_diagram(self) -> None:
        (self.root / "class_breaker.py").write_text(
            "import time\n\n"
            "class ServiceCircuitBreaker:\n"
            "    def allow_request(self):\n"
            "        if self.state == 'OPEN':\n"
            "            if time.monotonic() - self.opened_at >= self.cooldown:\n"
            "                self.state = 'HALF_OPEN'\n"
            "                return True\n"
            "            return False\n"
            "        return True\n\n"
            "    def record_failure(self):\n"
            "        self.failure_count += 1\n"
            "        if self.failure_count >= self.threshold:\n"
            "            self.state = 'OPEN'\n"
            "            self.opened_at = time.monotonic()\n\n"
            "    def record_success(self):\n"
            "        self.failure_count = 0\n"
            "        self.state = 'CLOSED'\n",
            encoding="utf-8",
        )

        analysis = scan_repository(self.root)
        diagrams = build_diagram_models(analysis, kind="circuit_breaker")

        self.assertEqual(len(diagrams), 1)
        diagram = diagrams[0]
        self.assertEqual(
            diagram["metadata"]["scope_qualname"], "ServiceCircuitBreaker"
        )
        self.assertEqual(
            set(diagram["metadata"]["member_qualnames"]),
            {
                "ServiceCircuitBreaker.allow_request",
                "ServiceCircuitBreaker.record_failure",
                "ServiceCircuitBreaker.record_success",
            },
        )
        self.assertEqual(len(diagram["metadata"]["component_ids"]), 3)
        self.assertIn("across 3 callable(s)", diagram["description"])
        self.assertTrue(
            {"failure threshold reached", "cooldown elapsed", "probe succeeds", "probe fails"}
            <= {value["label"] for value in diagram["edges"]}
        )

        propagation = build_diagram_models(
            analysis, kind="failure_propagation"
        )[0]
        containment_nodes = [
            value
            for value in propagation["nodes"]
            if value["kind"] == "containment_boundary"
        ]
        timing_nodes = [
            value
            for value in propagation["nodes"]
            if value["kind"] == "timing_boundary"
        ]
        self.assertEqual(len(containment_nodes), 1)
        self.assertEqual(len(timing_nodes), 1)
        self.assertTrue(
            {
                "admission_guard",
                "failure_recording",
                "success_reset",
                "recovery_timer",
            }
            <= set(containment_nodes[0]["metrics"]["roles"])
        )
        self.assertIn("time.monotonic", timing_nodes[0]["metrics"]["clock_sources"])

    def test_custom_diagram_import_is_bounded_and_embedded_safely(self) -> None:
        custom_path = self.root / "custom.json"
        custom_path.write_text(json.dumps(custom_state_diagram()), encoding="utf-8")
        imported = load_diagram_files([custom_path])
        self.assertEqual(imported[0]["metadata"]["imported_from"], "custom.json")

        report = export_html_report(
            self.analysis,
            self.root / "report.html",
            diagrams=[custom_path],
        ).read_text(encoding="utf-8")
        self.assertIn('data-view="diagrams"', report)
        self.assertIn("General diagram explorer", report)
        self.assertIn("workflow-state-machine", report)
        self.assertNotIn("Draft <untrusted>", report)
        self.assertIn(r"Draft \u003cuntrusted\u003e", report)

        bundle_path = self.root / "duplicates.json"
        bundle_path.write_text(
            json.dumps({"diagrams": [custom_state_diagram(), custom_state_diagram()]}),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "duplicate imported diagram"):
            load_diagram_files([bundle_path])


if __name__ == "__main__":
    unittest.main()
