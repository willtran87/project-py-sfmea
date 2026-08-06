from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from pysfmea.integrity import canonical_json_sha256
from scripts.evaluation_to_cohort import cohort_from_result, main


class ValidationCohortToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.result = {
            "format": "pysfmea-evaluation-result-1",
            "verifier": {"name": "PySFMEA", "version": "0.59.0"},
            "corpus": {
                "content_sha256": "a" * 64,
                "case_count": 20,
                "call_case_count": 4,
            },
            "expected": 20,
            "actual": 20,
            "matched": 20,
            "recall": 1.0,
            "precision": 1.0,
            "missing": [],
            "unexpected": [],
            "metrics": {
                "duplicate_count": 0,
                "unsupported_verification_claims": [],
            },
            "call_resolution": {
                "enabled": True,
                "expected": 4,
                "actual": 4,
                "matched": 4,
                "recall": 1.0,
                "precision": 1.0,
                "missing": [],
                "unexpected": [],
            },
        }

    def test_clean_result_becomes_program_compatible_cohort(self) -> None:
        record = cohort_from_result(
            self.result,
            cohort_id="VAL-THIRD-PARTY-1",
            repository="third-party/service",
            framework="FastAPI",
            producer="Benchmark Team",
            reviewer="Safety Review Team",
            artifact_path="evaluation.json",
            artifact_sha256="b" * 64,
        )
        self.assertEqual(record["corpus_sha256"], "a" * 64)
        self.assertTrue(record["independent_reviewed"])
        self.assertEqual(record["case_count"], 20)
        self.assertEqual(record["call_case_count"], 4)
        self.assertEqual(record["call_resolution_recall"], 1.0)
        self.assertEqual(record["matched_count"], 20)
        self.assertEqual(record["actual_matched_count"], 20)
        self.assertEqual(record["actual_count"], 20)
        self.assertEqual(record["call_matched_count"], 4)
        self.assertEqual(record["call_actual_matched_count"], 4)
        self.assertEqual(
            record["evaluation_result_sha256"], canonical_json_sha256(self.result)
        )
        self.assertEqual(record["evaluation_verifier_version"], "0.59.0")
        self.assertEqual(
            record["evaluation_result_artifact"],
            {"path": "evaluation.json", "sha256": "b" * 64},
        )

    def test_nonindependent_or_disqualified_result_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "distinct producer"):
            cohort_from_result(
                self.result,
                cohort_id="VAL-1",
                repository="repo",
                framework="plain",
                producer="same",
                reviewer="Same",
            )
        self.result["metrics"]["duplicate_count"] = 1
        with self.assertRaisesRegex(ValueError, "disqualifying"):
            cohort_from_result(
                self.result,
                cohort_id="VAL-1",
                repository="repo",
                framework="plain",
                producer="one",
                reviewer="two",
            )

    def test_imperfect_but_reconciled_result_remains_valid_evidence(self) -> None:
        self.result.update(
            {
                "actual": 21,
                "matched": 19,
                "recall": 0.95,
                "precision": 0.9524,
                "missing": [{"expected": "missing"}],
                "unexpected": [{"actual": "one"}],
                "call_resolution": {
                    "enabled": False,
                    "missing": [],
                    "unexpected": [],
                },
            }
        )
        self.result["corpus"].pop("call_case_count")
        record = cohort_from_result(
            self.result,
            cohort_id="VAL-IMPERFECT-1",
            repository="repo",
            framework="plain",
            producer="one",
            reviewer="two",
        )
        self.assertEqual(record["matched_count"], 19)
        self.assertEqual(record["actual_matched_count"], 20)
        self.assertEqual(record["actual_count"], 21)
        self.assertEqual(record["precision"], 0.9524)

    def test_failure_mode_only_result_omits_call_metrics(self) -> None:
        self.result["call_resolution"] = {
            "enabled": False,
            "missing": [],
            "unexpected": [],
        }
        self.result["corpus"].pop("call_case_count")
        record = cohort_from_result(
            self.result,
            cohort_id="VAL-FAILURE-MODES-1",
            repository="repo",
            framework="plain",
            producer="one",
            reviewer="two",
        )
        self.assertNotIn("call_case_count", record)
        self.assertNotIn("call_resolution_recall", record)

    def test_enabled_call_evaluation_requires_complete_metrics(self) -> None:
        self.result["corpus"].pop("call_case_count")
        with self.assertRaisesRegex(ValueError, "positive call_case_count"):
            cohort_from_result(
                self.result,
                cohort_id="VAL-CALLS-1",
                repository="repo",
                framework="plain",
                producer="one",
                reviewer="two",
            )

    def test_claimed_metrics_must_reconcile_with_raw_counts(self) -> None:
        self.result["recall"] = 0.95
        with self.assertRaisesRegex(ValueError, "does not reconcile"):
            cohort_from_result(
                self.result,
                cohort_id="VAL-COUNTS-1",
                repository="repo",
                framework="plain",
                producer="one",
                reviewer="two",
            )

    def test_verifier_provenance_is_required(self) -> None:
        self.result.pop("verifier")
        with self.assertRaisesRegex(ValueError, "verifier version"):
            cohort_from_result(
                self.result,
                cohort_id="VAL-PROVENANCE-1",
                repository="repo",
                framework="plain",
                producer="one",
                reviewer="two",
            )

    def test_cli_binds_exact_evaluation_artifact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "evaluation.json"
            output = root / "cohort.json"
            source.write_text(
                json.dumps(self.result, indent=2) + "\n", encoding="utf-8"
            )
            exit_code = main(
                [
                    str(source),
                    "--id",
                    "VAL-CLI-1",
                    "--repository",
                    "repo",
                    "--framework",
                    "plain",
                    "--producer",
                    "one",
                    "--reviewer",
                    "two",
                    "--artifact-path",
                    "evidence/evaluation.json",
                    "-o",
                    str(output),
                ]
            )
            self.assertEqual(exit_code, 0)
            record = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                record["evaluation_result_artifact"],
                {
                    "path": "evidence/evaluation.json",
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                },
            )


if __name__ == "__main__":
    unittest.main()
