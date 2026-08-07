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
    def test_diagnostics_reconcile_adapters_and_prioritize_missing_evidence(self) -> None:
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
            self.assertEqual(result["performance"], telemetry)
            action_ids = {value["id"] for value in result["recommended_actions"]}
            self.assertIn("govern_system_context", action_ids)
            self.assertIn("import_coverage", action_ids)
            self.assertIn("import_runtime_trace", action_ids)
            self.assertIn("index_test_sources", action_ids)

            language_run = next(
                value
                for value in analysis["adapter_runs"]["runs"]
                if value["adapter_id"] == "web.language_boundary_indexer"
            )
            language_run["contribution_entity_ids"] = []
            tampered = analysis_diagnostics(analysis)
            self.assertFalse(tampered["accounting"]["valid"])
            self.assertEqual(tampered["status"], "invalid_accounting")

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


if __name__ == "__main__":
    unittest.main()
