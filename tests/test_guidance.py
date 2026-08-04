from __future__ import annotations

import contextlib
import csv
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.cli import main
from pysfmea.guidance import guidance_traceability, validate_guidance_catalog
from pysfmea.html_report import build_html_report_data, export_html_report
from pysfmea.report import export_guidance_traceability
from pysfmea.scanner import scan_repository
from pysfmea.store import load_analysis, save_analysis
from pysfmea.validation import validate_analysis


class GuidanceTraceabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "service.py").write_text(
            "def transform(value):\n    return value / 100\n",
            encoding="utf-8",
        )
        self.analysis = scan_repository(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_catalog_and_findings_have_typed_versioned_relationships(self) -> None:
        validate_guidance_catalog()
        trace = guidance_traceability(self.analysis)
        self.assertEqual(trace["schema_version"], "1.0")
        self.assertTrue(trace["catalog_sha256"])
        self.assertEqual(trace["coverage"]["finding_coverage_percent"], 100.0)
        faa = next(source for source in trace["sources"] if source["id"] == "FAA-RLV-SCS-2006")
        self.assertEqual(faa["status"], "legacy")
        links = [
            link
            for finding in trace["finding_links"]
            for link in finding["citations"]
        ]
        self.assertTrue(links)
        self.assertTrue(all(link["status"] == "curated" for link in links))
        self.assertNotIn("potential_nonconformance", {link["relationship"] for link in links})

    def test_json_csv_cli_and_persistence_outputs(self) -> None:
        json_path = export_guidance_traceability(
            self.analysis, self.root / "guidance.json", format="json"
        )
        csv_path = export_guidance_traceability(
            self.analysis, self.root / "guidance.csv", format="csv"
        )
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertTrue(payload["finding_links"])
        with csv_path.open(encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertTrue(rows)
        self.assertTrue(rows[0]["citation_id"])
        self.assertTrue(rows[0]["section"])

        analysis_path = self.root / "analysis.json"
        save_analysis(analysis_path, self.analysis)
        persisted = json.loads(analysis_path.read_text(encoding="utf-8"))
        self.assertIn("guidance", persisted)
        self.assertTrue(persisted["items"][0]["scanner"]["citations"])
        with contextlib.redirect_stdout(io.StringIO()):
            result = main(["citations", str(analysis_path), "--format", "json"])
        self.assertEqual(result, 0)
        self.assertTrue((self.root / "analysis.guidance.json").is_file())
        self.assertIn("guidance", load_analysis(analysis_path))

    def test_validation_rejects_an_invented_citation(self) -> None:
        item = self.analysis["items"][0]
        item["scanner"]["citations"][0]["citation_id"] = "NASA-INVENTED-99.99"
        findings = validate_analysis(self.analysis)["findings"]
        self.assertIn("guidance.unknown_citation", {value["rule_id"] for value in findings})

    def test_html_report_has_navigable_guidance_data(self) -> None:
        payload = build_html_report_data(self.analysis)
        self.assertEqual(payload["guidance"]["coverage"]["finding_coverage_percent"], 100.0)
        self.assertTrue(payload["records"][0]["citations"])
        report = export_html_report(self.analysis, self.root / "report.html")
        document = report.read_text(encoding="utf-8")
        self.assertIn('data-view="guidance"', document)
        self.assertIn("Guidance-to-finding traceability", document)
        self.assertIn("Show findings", document)


if __name__ == "__main__":
    unittest.main()
