from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.config import normalize_config
from pysfmea.diagrams import build_diagram_models
from pysfmea.scanner import scan_repository
from pysfmea.sfta import build_sfta, export_sfta
from pysfmea.validation import validate_analysis


class SoftwareFaultTreeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "service.py").write_text(
            "def execute(value):\n"
            "    if value is None:\n"
            "        raise ValueError('value')\n"
            "    return value\n",
            encoding="utf-8",
        )
        self.config = {
            "hazards": [
                {
                    "id": "HZ-LOSS",
                    "description": "Required service is lost",
                    "end_effect": "A mission operation cannot complete.",
                }
            ],
            "component_mappings": [
                {
                    "pattern": "service.py:execute",
                    "hazards": ["HZ-LOSS"],
                }
            ],
            "fault_trees": [
                {
                    "id": "SFTA-HZ-LOSS",
                    "hazard": "HZ-LOSS",
                    "top_event_id": "TOP-LOSS",
                    "top_event": "Required service is lost",
                    "description": "Software contribution screening tree",
                    "assumptions": ["Infrastructure faults are analyzed elsewhere."],
                    "gates": [
                        {
                            "id": "G-LOSS",
                            "type": "OR",
                            "description": "Either software event can cause loss",
                            "inputs": ["EV-EXECUTE", "EV-UNDEVELOPED"],
                        }
                    ],
                    "events": [
                        {
                            "id": "TOP-LOSS",
                            "type": "top",
                            "description": "Required service is lost",
                            "inputs": ["G-LOSS"],
                        },
                        {
                            "id": "EV-EXECUTE",
                            "type": "basic",
                            "description": "Execution function fails",
                            "component_patterns": ["service.py:execute"],
                        },
                        {
                            "id": "EV-UNDEVELOPED",
                            "type": "undeveloped",
                            "description": "Dynamic deployment contribution",
                            "component_patterns": ["deployment.py:*"],
                        },
                    ],
                }
            ],
        }
        self.analysis = scan_repository(self.root, config=self.config)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_explicit_tree_correlates_bottom_up_and_reports_both_directions(self) -> None:
        model = build_sfta(self.analysis)
        summary = model["reconciliation"]["summary"]
        self.assertEqual(summary["explicit_trees"], 1)
        self.assertEqual(summary["placeholder_trees"], 0)
        self.assertGreater(summary["findings_correlated_to_events"], 0)
        self.assertEqual(summary["top_down_uncovered_events"], 1)
        self.assertEqual(summary["bottom_up_unmapped_findings"], 0)
        tree = model["trees"][0]
        self.assertEqual(tree["source"], "explicit_configuration")
        self.assertEqual({edge["kind"] for edge in tree["edges"]}, {"input_to"})
        event = next(value for value in tree["nodes"] if value["id"] == "EV-EXECUTE")
        self.assertTrue(event["linked_finding_ids"])
        rules = {value["rule_id"] for value in validate_analysis(self.analysis)["findings"]}
        self.assertIn("sfta.uncovered_top_down_event", rules)
        self.assertNotIn("sfta.missing_top_down_decomposition", rules)

    def test_sfta_exports_and_renderer_neutral_diagram(self) -> None:
        json_path = export_sfta(self.analysis, self.root / "sfta.json", format="json")
        csv_path = export_sfta(self.analysis, self.root / "sfta.csv", format="csv")
        self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["schema_version"], "1.0")
        with csv_path.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(rows[0]["gap_type"], "top_down_uncovered_event")
        diagrams = build_diagram_models(self.analysis, kind="sfta")
        self.assertEqual(len(diagrams), 1)
        self.assertEqual(diagrams[0]["metadata"]["category"], "sfta")
        self.assertIn("sfta_gate", {value["kind"] for value in diagrams[0]["nodes"]})
        self.assertIn("candidate_correlation", {value["kind"] for value in diagrams[0]["edges"]})

    def test_fault_tree_cycles_and_unknown_inputs_are_rejected(self) -> None:
        bad = json.loads(json.dumps(self.config))
        bad["fault_trees"][0]["events"][0]["inputs"] = ["TOP-LOSS"]
        with self.assertRaisesRegex(ValueError, "cycle"):
            normalize_config(bad)
        bad = json.loads(json.dumps(self.config))
        bad["fault_trees"][0]["events"][0]["inputs"] = ["MISSING"]
        with self.assertRaisesRegex(ValueError, "unknown inputs"):
            normalize_config(bad)


if __name__ == "__main__":
    unittest.main()
