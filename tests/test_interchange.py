from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.interchange import cyclonedx_document, differential_analysis, sarif_document
from pysfmea.scanner import scan_repository


class InterchangeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "service.py").write_text(
            "def process(value):\n    return value\n", encoding="utf-8"
        )
        (self.root / "pyproject.toml").write_text(
            '[project]\nname = "demo"\nversion = "1.0"\ndependencies = ["requests>=2"]\n',
            encoding="utf-8",
        )
        self.analysis = scan_repository(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_sarif_preserves_candidate_semantics_and_stable_locations(self) -> None:
        document = sarif_document(self.analysis)
        self.assertEqual(document["version"], "2.1.0")
        run = document["runs"][0]
        self.assertTrue(run["tool"]["driver"]["rules"])
        result = run["results"][0]
        self.assertEqual(result["level"], "note")
        self.assertTrue(result["properties"]["pysfmeaCandidate"])
        self.assertIn("not a confirmed defect", result["properties"]["notice"])
        self.assertEqual(result["partialFingerprints"]["pysfmeaFindingId"], self.analysis["items"][0]["id"])
        self.assertFalse(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("C:"))

    def test_cyclonedx_labels_inventory_as_declared_not_resolved(self) -> None:
        document = cyclonedx_document(self.analysis)
        self.assertEqual(document["bomFormat"], "CycloneDX")
        self.assertEqual(document["specVersion"], "1.6")
        names = {value["name"] for value in document["components"]}
        self.assertIn("requests", names)
        request = next(value for value in document["components"] if value["name"] == "requests")
        properties = {value["name"]: value["value"] for value in request["properties"]}
        self.assertEqual(properties["pysfmea:resolution-status"], "declared-not-resolved")
        json.dumps(document)

    def test_diff_reports_changed_risk_assumptions_and_invalidated_evidence(self) -> None:
        previous = copy.deepcopy(self.analysis)
        current = copy.deepcopy(self.analysis)
        finding_id = current["items"][0]["id"]
        previous["items"][0]["review"]["severity"] = 8
        current["items"][0]["review"]["severity"] = 6
        previous["context"]["project"]["assumptions"] = ["Old assumption"]
        current["context"]["project"]["assumptions"] = ["New assumption"]
        previous_obligation = previous["assurance"]["obligations"][0]
        current_obligation = current["assurance"]["obligations"][0]
        previous_obligation["evidence_status"] = "sufficient"
        current_obligation["evidence_status"] = "stale"
        result = differential_analysis(previous, current)
        self.assertEqual(result["summary"]["changed_findings"], 1)
        self.assertTrue(result["summary"]["assumptions_changed"])
        self.assertEqual(result["summary"]["invalidated_verifications"], 1)
        self.assertEqual(result["changed_findings"][0]["finding_id"], finding_id)
        self.assertIn("severity", result["changed_findings"][0]["fields"])


if __name__ == "__main__":
    unittest.main()
