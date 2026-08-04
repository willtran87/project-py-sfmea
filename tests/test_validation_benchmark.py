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
        self.assertEqual(result["metrics"]["duplicate_rate"], 0.0)
        self.assertEqual(result["metrics"]["source_localization_accuracy"], 1.0)
        self.assertEqual(result["metrics"]["citation_link_accuracy"], 1.0)
        self.assertEqual(result["metrics"]["traceability_integrity"], 1.0)
        self.assertEqual(result["metrics"]["adapter_provenance_coverage"], 1.0)
        self.assertEqual(result["metrics"]["repository_source_accounting"], 1.0)
        self.assertEqual(result["metrics"]["unsupported_verification_claims"], [])

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

    def test_tool_self_sfmea_has_complete_machine_readable_records(self) -> None:
        path = self.corpus.parent / "tool_sfmea.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], "pysfmea-tool-sfmea-1")
        self.assertGreaterEqual(len(payload["failure_modes"]), 10)
        required = {
            "id",
            "function",
            "failure_mode",
            "trigger",
            "effects",
            "controls",
            "verification",
            "residual_risk",
        }
        self.assertTrue(
            all(required <= set(record) for record in payload["failure_modes"])
        )
        self.assertEqual(
            len({record["id"] for record in payload["failure_modes"]}),
            len(payload["failure_modes"]),
        )


if __name__ == "__main__":
    unittest.main()
