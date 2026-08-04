from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.cli import main
from pysfmea.diagrams import (
    DIAGRAM_BUNDLE_SCHEMA,
    DIAGRAM_SCHEMA,
    build_diagram_models,
    export_diagram_bundle,
    load_diagram_files,
    normalize_diagram_model,
)
from pysfmea.html_report import export_html_report
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
        self.assertEqual(len(bundle["diagrams"]), 1)
        self.assertEqual(bundle["diagrams"][0]["type"], "traceability")

        analysis_path = self.root / "analysis.json"
        save_analysis(analysis_path, self.analysis)
        with contextlib.redirect_stdout(io.StringIO()):
            result = main(
                [
                    "diagram",
                    str(analysis_path),
                    "--type",
                    "failure_propagation",
                ]
            )
        self.assertEqual(result, 0)
        self.assertTrue((self.root / "analysis-failure_propagation-diagrams.json").is_file())

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
