from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.discovery import evaluate_candidates
from pysfmea.guidance import citations_for_rule
from pysfmea.manifest import create_run_manifest
from pysfmea.scanner import scan_repository


class ToolValidationBenchmarkTests(unittest.TestCase):
    corpus = Path(__file__).resolve().parents[1] / "benchmarks" / "python_sfmea_corpus"

    def test_golden_corpus_has_exact_recall_and_precision(self) -> None:
        analysis = scan_repository(self.corpus / "repository")
        expected = json.loads((self.corpus / "expected.json").read_text(encoding="utf-8"))
        result = evaluate_candidates(analysis, expected)
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["unexpected"], [])
        self.assertEqual(result["recall"], 1.0)
        self.assertEqual(result["precision"], 1.0)

    def test_repeated_scan_has_stable_source_and_resolved_input_digests(self) -> None:
        first = scan_repository(self.corpus / "repository")
        second = scan_repository(self.corpus / "repository")
        self.assertEqual(
            first["project"]["baseline"]["source_digest"],
            second["project"]["baseline"]["source_digest"],
        )
        self.assertEqual(
            create_run_manifest(first)["resolved_inputs_sha256"],
            create_run_manifest(second)["resolved_inputs_sha256"],
        )

    def test_regulatory_profile_citations_are_isolated(self) -> None:
        commercial = citations_for_rule(
            "functional.omission", ["faa_commercial_space"]
        )
        airworthiness = citations_for_rule(
            "functional.omission", ["faa_airworthiness"]
        )
        self.assertTrue(commercial)
        self.assertTrue(airworthiness)
        self.assertFalse(
            {link["source_id"] for link in commercial}
            & {link["source_id"] for link in airworthiness}
        )


if __name__ == "__main__":
    unittest.main()
