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
from pysfmea.diagnostics import analysis_diagnostics
from pysfmea.scanner import scan_repository
from pysfmea.store import save_analysis


class AnalysisDiagnosticsTests(unittest.TestCase):
    def test_diagnostics_reconcile_adapters_and_prioritize_missing_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def run(value):\n    return value\n", encoding="utf-8"
            )
            (root / "client.ts").write_text(
                "export const run = () => fetch('/api/run');\n", encoding="utf-8"
            )
            service = root / "service"
            service.mkdir()
            (service / "requirements.txt").write_text(
                "fastapi>=0.100\n", encoding="utf-8"
            )
            telemetry: dict[str, object] = {}
            analysis = scan_repository(root, telemetry=telemetry)

            result = analysis_diagnostics(analysis)

            self.assertEqual(result["format"], "pysfmea-analysis-diagnostics-1")
            self.assertTrue(result["accounting"]["valid"])
            self.assertTrue(
                all(
                    not value["unexpected_entities"]
                    for value in result["accounting"]["checks"]
                )
            )
            self.assertEqual(result["coverage"]["web_boundary"]["percent"], 100.0)
            self.assertEqual(result["performance"]["telemetry"], telemetry)
            self.assertIn("qualification", result)
            self.assertIn("overall_grade", result["qualification"])
            action_ids = {value["id"] for value in result["recommended_actions"]}
            self.assertIn("govern_system_context", action_ids)
            self.assertIn("import_coverage", action_ids)
            self.assertIn("import_runtime_trace", action_ids)
            self.assertIn("index_test_sources", action_ids)
            self.assertIn("aggregates", result["validation"])
            self.assertIn("queue_projection", result["workload"])
            calibration = result["workload"]["review_calibration"]
            self.assertEqual(calibration["reviewed"], 0)
            self.assertGreater(calibration["unreviewed"], 0)
            self.assertTrue(calibration["rules"])
            self.assertEqual(
                calibration["rules"][0]["calibration_status"], "unreviewed"
            )
            self.assertIsNone(calibration["rules"][0]["acceptance_percent"])
            self.assertIsNone(calibration["rules"][0]["rejection_percent"])
            self.assertIn("architecture_mapping_candidates", result["evidence"])

            language_run = next(
                value
                for value in analysis["adapter_runs"]["runs"]
                if value["adapter_id"] == "web.language_boundary_indexer"
            )
            language_run["contribution_entity_ids"] = []
            tampered = analysis_diagnostics(analysis)
            self.assertFalse(tampered["accounting"]["valid"])
            self.assertEqual(tampered["status"], "invalid_accounting")

    def test_diagnostics_identify_evidence_scope_conflicts_and_warning_budgets(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def run(value):\n    return value\n", encoding="utf-8"
            )
            analysis = scan_repository(
                root,
                config={
                    "scan": {
                        "exclude": ["backend/tests/**", "frontend/**"],
                        "diagnostic_warning_budget": 1,
                        "diagnostic_per_rule_budget": 1,
                    }
                },
            )

            result = analysis_diagnostics(analysis)

            conflict_kinds = {
                value["kind"] for value in result["evidence_scope"]["conflicts"]
            }
            self.assertEqual(
                conflict_kinds,
                {
                    "test_evidence_hidden_by_semantic_exclusion",
                    "web_boundary_hidden_by_semantic_exclusion",
                },
            )
            self.assertTrue(result["validation"]["budgets"]["warning_limit_exceeded"])
            action_ids = {value["id"] for value in result["recommended_actions"]}
            self.assertIn("resolve_evidence_scope_conflicts", action_ids)
            self.assertIn("reduce_diagnostic_repetition", action_ids)

    def test_cli_emits_complete_json_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "def run(value):\n    return value\n", encoding="utf-8"
            )
            analysis_path = root / "analysis.json.gz"
            save_analysis(analysis_path, scan_repository(root), compact=True)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = main(["diagnostics", str(analysis_path), "--json"])
            self.assertEqual(exit_code, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["format"], "pysfmea-analysis-diagnostics-1")
            self.assertIn("recommended_actions", payload)

    def test_cross_stack_score_measures_client_reconciliation_not_unused_routes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "routes.py").write_text(
                "from fastapi import APIRouter\n"
                "router = APIRouter()\n\n"
                "@router.get('/api/used')\n"
                "def used(): return {}\n\n"
                "@router.get('/api/backend-only')\n"
                "def backend_only(): return {}\n",
                encoding="utf-8",
            )
            (root / "client.ts").write_text(
                "export const load = () => fetch('/api/used');\n",
                encoding="utf-8",
            )

            result = analysis_diagnostics(scan_repository(root))
            domain = next(
                value
                for value in result["qualification"]["domains"]
                if value["id"] == "cross_stack_interfaces"
            )

            self.assertEqual(domain["score"], 100.0)
            self.assertEqual(
                domain["basis"], "Static client-endpoint reconciliation coverage"
            )

    def test_runtime_score_measures_observed_scope_not_import_presence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "service.py").write_text(
                "def caller():\n    return callee()\n\ndef callee():\n    return 1\n",
                encoding="utf-8",
            )
            analysis = scan_repository(root)
            caller = next(
                value for value in analysis["components"] if value["name"] == "caller"
            )
            callee = next(
                value for value in analysis["components"] if value["name"] == "callee"
            )
            analysis["runtime_evidence"] = {
                "imports": [{"id": "TRACE-PARTIAL"}],
                "spans": [{"component_id": caller["id"]}],
                "edges": [],
            }
            partial = analysis_diagnostics(analysis)
            corroboration = partial["evidence"]["runtime_corroboration"]
            self.assertEqual(corroboration["static_edges"], 1)
            self.assertEqual(corroboration["corroborated_static_edges"], 0)
            self.assertLess(corroboration["score"], 70)
            self.assertIn(
                "expand_runtime_instrumentation",
                {value["id"] for value in partial["recommended_actions"]},
            )

            analysis["runtime_evidence"]["spans"].append(
                {"component_id": callee["id"]}
            )
            analysis["runtime_evidence"]["edges"].append(
                {
                    "source_component_id": caller["id"],
                    "target_component_id": callee["id"],
                }
            )
            complete = analysis_diagnostics(analysis)
            corroboration = complete["evidence"]["runtime_corroboration"]
            self.assertEqual(corroboration["score"], 100.0)
            self.assertEqual(corroboration["corroborated_static_edges"], 1)
            self.assertNotIn(
                "expand_runtime_instrumentation",
                {value["id"] for value in complete["recommended_actions"]},
            )


if __name__ == "__main__":
    unittest.main()
