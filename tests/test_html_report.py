from __future__ import annotations

import contextlib
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.cli import main
from pysfmea.html_report import build_html_report_data, export_html_report
from pysfmea.scanner import scan_repository
from pysfmea.store import save_analysis


class HtmlReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "service.py").write_text(
            "def validate(value):\n    return bool(value)\n\n"
            "def publish(value):\n    return value\n\n"
            "def checkout(value):\n    validate(value)\n    return publish(value)\n",
            encoding="utf-8",
        )
        self.analysis = scan_repository(
            self.root,
            config={
                "project": {
                    "name": "Checkout <Service>",
                    "purpose": "Review '</script><script>alert(1)</script>' safely.",
                    "boundary": "Local test boundary.",
                    "operating_context": "Unit test.",
                },
                "requirements": [
                    {
                        "id": "REQ-1",
                        "text": "Publish valid transactions.",
                        "source": "SRS",
                        "hazards": ["HZ-1"],
                    }
                ],
                "hazards": [
                    {
                        "id": "HZ-1",
                        "description": "Incorrect transaction",
                        "end_effect": "A transaction is processed incorrectly.",
                    }
                ],
                "system_interfaces": [
                    {
                        "id": "IF-API",
                        "source": "Client",
                        "target": "Service",
                        "description": "Transaction requests",
                    }
                ],
                "component_mappings": [
                    {
                        "pattern": "service.py:checkout",
                        "requirements": ["REQ-1"],
                        "hazards": ["HZ-1"],
                        "interfaces": ["IF-API"],
                        "subsystem": "Transactions",
                    }
                ],
            },
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_report_is_self_contained_navigable_and_safely_embedded(self) -> None:
        notes = self.root / "notes.md"
        notes.write_text(
            "# Review leads\n\n- Confirm <authorization>.\n- </script><script>bad()</script>\n",
            encoding="utf-8",
        )
        output = export_html_report(
            self.analysis,
            self.root / "report.html",
            notes=notes,
        )
        document = output.read_text(encoding="utf-8")
        self.assertTrue(document.startswith("<!doctype html>"))
        self.assertIn("Content-Security-Policy", document)
        self.assertIn('data-view="failure-modes"', document)
        self.assertIn('data-view="architecture"', document)
        self.assertIn('data-view="traceability"', document)
        self.assertIn('data-view="sequences"', document)
        self.assertIn('data-view="diagrams"', document)
        self.assertIn("Export filtered CSV", document)
        self.assertNotIn("<script>bad()</script>", document)
        self.assertNotIn("<script>alert(1)</script>", document)
        self.assertIn(r"\u003c/script\u003e", document)
        self.assertNotRegex(document, r"<script[^>]+src=")
        self.assertNotRegex(document, r"<link[^>]+rel=[\"']stylesheet")

        match = re.search(
            r'<script id="report-data" type="application/json">(.*?)</script>',
            document,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        payload = json.loads(match.group(1))
        self.assertEqual(payload["project"]["name"], "Checkout <Service>")
        self.assertIn("Confirm <authorization>", payload["report"]["notes"])
        self.assertGreater(len(payload["records"]), 0)
        self.assertEqual(payload["interfaces"][0]["id"], "IF-API")
        self.assertTrue(payload["sequences"])
        self.assertTrue(payload["diagrams"])

    def test_report_data_is_bounded_and_reports_truncation(self) -> None:
        payload = build_html_report_data(self.analysis, max_records=1)
        self.assertEqual(payload["report"]["embedded_records"], 1)
        self.assertEqual(payload["report"]["total_records"], len(self.analysis["items"]))
        self.assertEqual(
            payload["report"]["records_truncated"], len(self.analysis["items"]) > 1
        )
        with self.assertRaisesRegex(ValueError, "max_records"):
            build_html_report_data(self.analysis, max_records=0)

    def test_cli_creates_default_html_report(self) -> None:
        analysis_path = self.root / "analysis.json"
        save_analysis(analysis_path, self.analysis)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = main(["report", str(analysis_path), "--title", "Review report"])
        self.assertEqual(result, 0)
        report_path = self.root / "analysis-report.html"
        self.assertTrue(report_path.is_file())
        self.assertIn("Created self-contained SFMEA report", output.getvalue())
        self.assertIn("<title>Review report</title>", report_path.read_text(encoding="utf-8"))

    def test_embedded_javascript_parses_when_node_is_available(self) -> None:
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js is unavailable")
        output = export_html_report(self.analysis, self.root / "report.html")
        document = output.read_text(encoding="utf-8")
        scripts = re.findall(r"<script(?: [^>]*)?>(.*?)</script>", document, re.DOTALL)
        script = scripts[-1]
        javascript = self.root / "report.js"
        javascript.write_text(script, encoding="utf-8")
        result = subprocess.run(
            [node, "--check", str(javascript)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
