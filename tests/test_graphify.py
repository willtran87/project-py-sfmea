from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.architecture import architecture_graph
from pysfmea.cli import _parser, _scan
from pysfmea.graphify import (
    GRAPHIFY_RECONCILIATION_FORMAT,
    load_graphify_reconciliation,
)
from pysfmea.scanner import scan_repository
from pysfmea.store import load_analysis
from pysfmea.validation import validate_analysis


class GraphifyIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        (self.root / "app.py").write_text(
            "def caller():\n"
            "    return callee()\n"
            "\n"
            "def callee():\n"
            "    return 1\n",
            encoding="utf-8",
        )
        self.graph = self.root / "graph.json"
        self.graph.write_text(
            json.dumps(
                {
                    "nodes": [
                        {
                            "id": "caller",
                            "label": "caller()",
                            "source_file": "app.py",
                            "source_location": "L1",
                        },
                        {
                            "id": "callee",
                            "label": "callee()",
                            "source_file": "app.py",
                            "source_location": "L4",
                        },
                    ],
                    "edges": [
                        {
                            "source": "caller",
                            "target": "callee",
                            "relation": "calls",
                            "context": "call",
                            "confidence": "EXTRACTED",
                            "confidence_score": 1.0,
                            "source_file": "app.py",
                            "source_location": "L2",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_import_reconciles_mapped_static_call_with_native_evidence(self) -> None:
        analysis = scan_repository(self.root)
        reconciliation = load_graphify_reconciliation(analysis, self.graph)

        self.assertEqual(reconciliation["format"], GRAPHIFY_RECONCILIATION_FORMAT)
        self.assertEqual(reconciliation["summary"]["mapped_nodes"], 2)
        self.assertEqual(reconciliation["summary"]["corroborated_call_edges"], 1)
        self.assertEqual(
            reconciliation["edges"][0]["reconciliation"], "corroborated"
        )
        analysis["graphify_reconciliation"] = reconciliation
        graph = architecture_graph(analysis)
        self.assertTrue(
            any(edge["kind"] == "graphify_static_call" for edge in graph["edges"])
        )

    def test_scan_imports_graphify_and_binds_artifact_to_manifest(self) -> None:
        analysis = scan_repository(self.root, graphify_json=self.graph)

        self.assertEqual(
            analysis["summary"]["graphify_correlated_call_edges"], 1
        )
        self.assertEqual(
            analysis["summary"]["graphify_call_review_leads"], 0
        )
        self.assertIn(
            "graphify_graph_json_sha256",
            analysis["run_manifest"]["resolved_inputs"],
        )
        run = next(
            value
            for value in analysis["adapter_runs"]["runs"]
            if value["adapter_id"] == "graphify.code_graph"
        )
        self.assertEqual(run["status"], "completed")
        self.assertFalse(
            any(
                value["rule_id"] == "analysis.invalid_graphify_reconciliation"
                for value in validate_analysis(analysis)["findings"]
            )
        )

    def test_graphify_only_call_is_explicit_review_lead(self) -> None:
        graph = json.loads(self.graph.read_text(encoding="utf-8"))
        graph["edges"] = [
            {
                "source": "callee",
                "target": "caller",
                "relation": "calls",
                "confidence": "EXTRACTED",
            }
        ]
        self.graph.write_text(json.dumps(graph), encoding="utf-8")

        reconciliation = load_graphify_reconciliation(scan_repository(self.root), self.graph)

        self.assertEqual(
            reconciliation["summary"]["graphify_only_call_review_leads"], 1
        )
        self.assertEqual(
            reconciliation["edges"][0]["reconciliation"],
            "graphify_only_review_lead",
        )

    def test_rejects_graph_without_nodes_and_edges_arrays(self) -> None:
        self.graph.write_text('{"nodes": {}}', encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "nodes and edges arrays"):
            load_graphify_reconciliation(scan_repository(self.root), self.graph)

    def test_validation_rejects_tampered_reconciliation(self) -> None:
        analysis = scan_repository(self.root, graphify_json=self.graph)
        analysis["graphify_reconciliation"]["edges"][0]["reconciliation"] = (
            "graphify_only_review_lead"
        )

        report = validate_analysis(analysis)

        self.assertTrue(
            any(
                value["rule_id"] == "analysis.invalid_graphify_reconciliation"
                for value in report["findings"]
            )
        )

    def test_cli_marks_explicit_code_only_graphify_run_in_provenance(self) -> None:
        analysis_path = self.root / "sfmea-analysis.json"
        parser = _parser()
        args = parser.parse_args(
            [
                "scan",
                str(self.root),
                "--allow-ungoverned",
                "--fresh",
                "--no-cache",
                "--graphify",
                "--graphify-output",
                str(self.root / "graphify-artifacts"),
                "-o",
                str(analysis_path),
            ]
        )

        with patch("pysfmea.cli.run_graphify_code_only", return_value=self.graph):
            self.assertEqual(_scan(args), 0)

        analysis = load_analysis(analysis_path)
        self.assertEqual(
            analysis["project"]["settings"]["graphify"]["mode"],
            "executed_code_only_static_graph",
        )


if __name__ == "__main__":
    unittest.main()
