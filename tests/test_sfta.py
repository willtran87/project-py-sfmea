from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.config import normalize_config
from pysfmea.diagrams import build_diagram_models
from pysfmea.integrity import canonical_json_sha256
from pysfmea.report import (
    _verify_analysis_diagnostics,
    _verify_sfta_projection,
    export_csv,
    export_markdown,
)
from pysfmea.scanner import scan_repository
from pysfmea.sfta import (
    SFTA_GAP_FIELDS,
    _matched_finding_ids,
    build_sfta,
    export_sfta,
    sfta_gap_rows,
)
from pysfmea.validation import validate_analysis


class SoftwareFaultTreeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
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

    def test_explicit_tree_correlates_bottom_up_and_reports_both_directions(
        self,
    ) -> None:
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
        rules = {
            value["rule_id"] for value in validate_analysis(self.analysis)["findings"]
        }
        self.assertIn("sfta.uncovered_top_down_event", rules)
        self.assertNotIn("sfta.missing_top_down_decomposition", rules)

    def test_qualitative_cut_sets_require_exact_authored_approval(self) -> None:
        definition = self.analysis["context"]["fault_trees"][0]
        self.analysis["sfta_authoring"] = {
            "history": [
                {
                    "sealed_input_sha256": "a" * 64,
                    "applied_at": "2026-08-09T12:00:00Z",
                    "reviews": [
                        {
                            "hazard_id": "HZ-LOSS",
                            "definition_sha256": canonical_json_sha256(definition),
                            "status": "approved",
                            "reviewer": "Safety reviewer",
                            "rationale": "Exact Boolean structure reviewed.",
                        }
                    ],
                }
            ]
        }

        model = build_sfta(self.analysis)

        tree = model["trees"][0]
        cut_sets = tree["cut_set_analysis"]
        self.assertEqual(tree["logic_status"], "approved_for_qualitative_cut_sets")
        self.assertEqual(cut_sets["status"], "computed")
        self.assertEqual(cut_sets["cut_set_count"], 2)
        self.assertEqual(
            {tuple(value["event_ids"]) for value in cut_sets["cut_sets"]},
            {("EV-EXECUTE",), ("EV-UNDEVELOPED",)},
        )
        self.assertFalse(cut_sets["independence_assumed"])
        self.assertFalse(cut_sets["probability_calculated"])
        self.assertEqual(model["reconciliation"]["summary"]["qualitative_cut_sets"], 2)

        definition["description"] = "Changed after approval"
        stale = build_sfta(self.analysis)["trees"][0]
        self.assertEqual(stale["logic_status"], "preliminary_requires_review")
        self.assertEqual(
            stale["cut_set_analysis"]["status"], "not_computed_unapproved_tree"
        )

    def test_cut_set_calculation_fails_closed_on_limits_and_ambiguous_event_logic(
        self,
    ) -> None:
        definition = self.analysis["context"]["fault_trees"][0]
        self.analysis["sfta_authoring"] = {
            "history": [
                {
                    "sealed_input_sha256": "b" * 64,
                    "applied_at": "2026-08-09T12:00:00Z",
                    "reviews": [
                        {
                            "hazard_id": "HZ-LOSS",
                            "definition_sha256": canonical_json_sha256(definition),
                            "status": "approved",
                            "reviewer": "Safety reviewer",
                            "rationale": "Exact Boolean structure reviewed.",
                        }
                    ],
                }
            ]
        }
        with patch("pysfmea.sfta.MAX_CUT_SETS_PER_TREE", 1):
            bounded = build_sfta(self.analysis)["trees"][0]["cut_set_analysis"]
        self.assertEqual(bounded["status"], "not_computed_limit_exceeded")
        self.assertEqual(bounded["cut_sets"], [])

        top = next(value for value in definition["events"] if value["id"] == "TOP-LOSS")
        top["inputs"] = ["EV-EXECUTE", "EV-UNDEVELOPED"]
        self.analysis["sfta_authoring"]["history"][0]["reviews"][0][
            "definition_sha256"
        ] = canonical_json_sha256(definition)
        unsupported = build_sfta(self.analysis)["trees"][0]["cut_set_analysis"]
        self.assertEqual(unsupported["status"], "not_computed_unsupported_logic")
        self.assertEqual(unsupported["cut_sets"], [])

    def test_sfta_exports_and_renderer_neutral_diagram(self) -> None:
        json_path = export_sfta(self.analysis, self.root / "sfta.json", format="json")
        csv_path = export_sfta(self.analysis, self.root / "sfta.csv", format="csv")
        self.assertEqual(
            json.loads(json_path.read_text(encoding="utf-8"))["schema_version"], "1.0"
        )
        with csv_path.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(rows[0]["gap_type"], "top_down_uncovered_event")
        diagrams = build_diagram_models(self.analysis, kind="sfta")
        self.assertEqual(len(diagrams), 1)
        self.assertEqual(diagrams[0]["metadata"]["category"], "sfta")
        self.assertIn("sfta_gate", {value["kind"] for value in diagrams[0]["nodes"]})
        self.assertIn(
            "candidate_correlation", {value["kind"] for value in diagrams[0]["edges"]}
        )

    def test_finding_id_selector_is_exact_and_bypasses_pattern_scan(self) -> None:
        target_id = self.analysis["items"][0]["id"]
        events = self.analysis["context"]["fault_trees"][0]["events"]
        event = next(value for value in events if value["id"] == "EV-EXECUTE")
        event.pop("component_patterns")
        event["finding_ids"] = [target_id, "UNKNOWN-FINDING"]

        findings = self.analysis["items"]
        findings_by_id = {str(value["id"]): value for value in findings}
        with patch(
            "pysfmea.sfta._matches_event",
            side_effect=AssertionError("ID-only selectors must not scan every finding"),
        ):
            self.assertEqual(
                _matched_finding_ids(findings, findings_by_id, event), [target_id]
            )
        model = build_sfta(self.analysis)

        correlated = next(
            value for value in model["trees"][0]["nodes"] if value["id"] == "EV-EXECUTE"
        )
        self.assertEqual(correlated["linked_finding_ids"], [target_id])
        legacy = build_sfta(self.analysis, legacy_id_wildcard=True)
        legacy_event = next(
            value
            for value in legacy["trees"][0]["nodes"]
            if value["id"] == "EV-EXECUTE"
        )
        self.assertEqual(
            len(legacy_event["linked_finding_ids"]), len(self.analysis["items"])
        )

    def test_sfta_verifier_replays_declared_producer_selector_semantics(self) -> None:
        target_id = self.analysis["items"][0]["id"]
        events = self.analysis["context"]["fault_trees"][0]["events"]
        event = next(value for value in events if value["id"] == "EV-EXECUTE")
        event.pop("component_patterns")
        event["finding_ids"] = [target_id]
        legacy = build_sfta(self.analysis, legacy_id_wildcard=True)
        self.analysis["sfta"] = legacy
        (self.root / "sfta.json").write_text(
            json.dumps(legacy, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        with (self.root / "sfta-gaps.csv").open(
            "w", encoding="utf-8", newline=""
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=SFTA_GAP_FIELDS)
            writer.writeheader()
            writer.writerows(sfta_gap_rows(legacy))

        listed = {"sfta.json", "sfta-gaps.csv"}
        historical = _verify_sfta_projection(self.root, listed, self.analysis, "0.57.1")
        current = _verify_sfta_projection(self.root, listed, self.analysis, "0.57.2")
        self.assertTrue(historical["valid"])
        self.assertFalse(current["valid"])
        self.assertFalse(current["checks"]["model_projection"])

        diagnostic_documents = {
            "summary.json": self.analysis.get("summary", {}),
            "validation.json": validate_analysis(
                self.analysis, legacy_sfta_id_wildcard=True
            ),
            "system-context.json": self.analysis.get("system_context", {}),
            "repository-inventory.json": self.analysis.get("repository_inventory", {}),
            "adapter-runs.json": self.analysis.get("adapter_runs", {}),
        }
        for filename, document in diagnostic_documents.items():
            (self.root / filename).write_text(
                json.dumps(document, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        diagnostic_files = set(diagnostic_documents)
        historical_diagnostics = _verify_analysis_diagnostics(
            self.root, diagnostic_files, self.analysis, "0.57.1"
        )
        current_diagnostics = _verify_analysis_diagnostics(
            self.root, diagnostic_files, self.analysis, "0.57.2"
        )
        self.assertTrue(historical_diagnostics["valid"])
        self.assertFalse(current_diagnostics["valid"])
        self.assertFalse(current_diagnostics["checks"]["validation"])

        legacy_csv = export_csv(
            self.analysis,
            self.root / "worksheet-legacy.csv",
            legacy_sfta_id_wildcard=True,
        ).read_text(encoding="utf-8-sig")
        current_csv = export_csv(
            self.analysis, self.root / "worksheet-current.csv"
        ).read_text(encoding="utf-8-sig")
        legacy_markdown = export_markdown(
            self.analysis,
            self.root / "worksheet-legacy.md",
            legacy_sfta_id_wildcard=True,
        ).read_text(encoding="utf-8")
        current_markdown = export_markdown(
            self.analysis, self.root / "worksheet-current.md"
        ).read_text(encoding="utf-8")
        self.assertNotEqual(legacy_csv, current_csv)
        self.assertNotEqual(legacy_markdown, current_markdown)

    def test_finding_ids_are_unioned_with_conjunctive_pattern_selectors(self) -> None:
        direct = self.analysis["items"][0]
        patterned = self.analysis["items"][1]
        direct["source"]["path"] = "direct.py"
        direct["component"]["qualname"] = "direct"
        patterned["source"]["path"] = "service.py"
        patterned["review"]["failure_mode"] = "Targeted execution failure"
        events = self.analysis["context"]["fault_trees"][0]["events"]
        event = next(value for value in events if value["id"] == "EV-EXECUTE")
        event["finding_ids"] = [direct["id"]]
        event["component_patterns"] = ["service.py:execute"]
        event["failure_mode_patterns"] = ["Targeted*"]

        model = build_sfta(self.analysis)
        correlated = next(
            value for value in model["trees"][0]["nodes"] if value["id"] == "EV-EXECUTE"
        )
        self.assertIn(direct["id"], correlated["linked_finding_ids"])
        self.assertIn(patterned["id"], correlated["linked_finding_ids"])
        self.assertNotEqual(
            len(correlated["linked_finding_ids"]), len(self.analysis["items"])
        )

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
