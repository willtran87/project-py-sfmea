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
from pysfmea.visuals import sequence_model


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
        self.assertTrue(result["call_resolution"]["enabled"])
        self.assertEqual(result["call_resolution"]["expected"], 8)
        self.assertEqual(result["corpus"]["call_case_count"], 8)
        self.assertEqual(result["call_resolution"]["missing"], [])
        self.assertEqual(result["call_resolution"]["unexpected"], [])
        self.assertEqual(result["call_resolution"]["recall"], 1.0)
        self.assertEqual(result["call_resolution"]["precision"], 1.0)
        self.assertEqual(
            result["call_resolution"]["by_resolution"]["parameter_annotation"][
                "matched"
            ],
            2,
        )
        self.assertTrue(result["control_detection"]["enabled"])
        self.assertEqual(result["corpus"]["control_case_count"], 4)
        self.assertEqual(result["corpus"]["control_scope_count"], 1)
        self.assertEqual(result["control_detection"]["expected"], 4)
        self.assertEqual(result["control_detection"]["actual"], 4)
        self.assertEqual(result["control_detection"]["matched"], 4)
        self.assertEqual(result["control_detection"]["missing"], [])
        self.assertEqual(result["control_detection"]["unexpected"], [])
        self.assertEqual(result["control_detection"]["recall"], 1.0)
        self.assertEqual(result["control_detection"]["precision"], 1.0)
        self.assertEqual(
            result["control_detection"]["population"],
            {
                "scope_basis": "explicit_control_scope",
                "scope_patterns": ["controls.py:*"],
                "evaluated_components": 7,
                "positive_components": 4,
                "negative_components": 3,
            },
        )
        self.assertEqual(
            result["control_detection"]["by_kind"]["circuit_breaker"]["matched"],
            4,
        )
        semantics = result["semantic_output"]
        self.assertTrue(semantics["enabled"])
        self.assertEqual(result["corpus"]["semantic_case_count"], 10)
        self.assertEqual(result["corpus"]["semantic_claim_count"], 78)
        self.assertEqual(semantics["matched"], 10)
        self.assertEqual(semantics["claim_matched"], 78)
        self.assertEqual(semantics["recall"], 1.0)
        self.assertEqual(semantics["precision"], 1.0)
        self.assertEqual(semantics["claim_recall"], 1.0)
        self.assertEqual(semantics["claim_precision"], 1.0)
        self.assertEqual(semantics["missing"], [])
        self.assertEqual(semantics["mismatches"], [])
        self.assertEqual(semantics["by_field"]["failure_mode"]["matched"], 10)

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

    def test_corpus_exercises_typed_interfaces_and_internal_sequences(self) -> None:
        analysis = scan_repository(self.corpus / "repository")
        pipeline = {
            value["qualname"]: value
            for value in analysis["components"]
            if value.get("source", {}).get("path") == "pipeline.py"
        }
        self.assertEqual(len(pipeline), 3)
        self.assertEqual(
            pipeline["fetch_job"]["symbol_types"]["client"], "httpx.AsyncClient"
        )
        typed_candidates = pipeline["fetch_job"]["external_call_candidates"]
        self.assertTrue(
            any(
                value["basis"] == "typed_receiver_known_external_api"
                for value in typed_candidates
            )
        )
        self.assertEqual(
            pipeline["fetch_job"]["called_by"], ["pipeline.py:run_pipeline"]
        )
        self.assertEqual(
            pipeline["decode_response"]["called_by"], ["pipeline.py:fetch_job"]
        )
        sequence = sequence_model(analysis, "pipeline.py:run_pipeline")
        self.assertEqual(sequence["reconciliation"]["static_internal_relations"], 2)
        self.assertEqual(
            [
                value["label"]
                for value in sequence["interactions"]
                if value["evidence"] == "static_ast"
            ],
            ["fetch_job", "decode_response"],
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
