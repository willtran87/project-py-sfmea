from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_mutation_ratchet import mutation_quality_record


class MutationRatchetTests(unittest.TestCase):
    def _fixtures(self, root: Path) -> tuple[Path, Path]:
        metadata = root / "mutants" / "src" / "pysfmea" / "runtime.py.meta"
        metadata.parent.mkdir(parents=True)
        metadata.write_text(
            json.dumps(
                {
                    "exit_code_by_key": {
                        "pysfmea.runtime.x__span_timing__mutmut_1": 1,
                        "pysfmea.runtime.x__span_timing__mutmut_2": 0,
                        "pysfmea.runtime.x__span_timing__mutmut_3": 36,
                        "unrelated.x_other__mutmut_1": 34,
                    }
                }
            ),
            encoding="utf-8",
        )
        policy = root / "policy.json"
        policy.write_text(
            json.dumps(
                {
                    "format": "pysfmea-mutation-ratchet-policy-2",
                    "selectors": ["*pysfmea.runtime.x__span_timing__mutmut_*"],
                    "minimum_mutants": 3,
                    "minimum_score": 0.5,
                    "maximum_survived": 1,
                    "maximum_invalid": 0,
                    "maximum_skipped": 0,
                    "allowed_runner_exit_codes": [0, 1],
                    "groups": [
                        {
                            "id": "span-timing",
                            "selectors": ["*pysfmea.runtime.x__span_timing__mutmut_*"],
                            "minimum_mutants": 3,
                            "minimum_score": 0.5,
                            "maximum_survived": 1,
                            "maximum_invalid": 0,
                            "maximum_skipped": 0,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return root / "mutants", policy

    def test_record_filters_scope_and_exposes_every_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            metadata, policy = self._fixtures(Path(directory))
            result = mutation_quality_record(metadata, policy, runner_exit_code=1)
        self.assertEqual(result["counts"]["total"], 3)
        self.assertEqual(result["counts"]["killed"], 1)
        self.assertEqual(result["counts"]["survived"], 1)
        self.assertEqual(result["counts"]["invalid"], 1)
        self.assertEqual(result["mutation_score"], 0.5)
        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["maximum_invalid"])
        self.assertFalse(result["checks"]["all_groups"])
        self.assertEqual(result["groups"][0]["counts"]["total"], 3)
        self.assertTrue(result["checks"]["runner_exit_code"])

    def test_policy_regression_fails_even_when_runner_exit_is_zero(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            metadata, policy = self._fixtures(Path(directory))
            document = json.loads(policy.read_text(encoding="utf-8"))
            document["maximum_invalid"] = 1
            document["groups"][0]["maximum_invalid"] = 1
            document["maximum_survived"] = 0
            policy.write_text(json.dumps(document), encoding="utf-8")
            result = mutation_quality_record(metadata, policy, runner_exit_code=0)
        self.assertFalse(result["checks"]["maximum_survived"])
        self.assertFalse(result["passed"])

    def test_function_group_failure_cannot_be_masked_by_aggregate_score(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            metadata, policy = self._fixtures(Path(directory))
            document = json.loads(policy.read_text(encoding="utf-8"))
            document["minimum_score"] = 0
            document["maximum_invalid"] = 1
            document["groups"][0]["minimum_score"] = 0.9
            document["groups"][0]["maximum_invalid"] = 1
            policy.write_text(json.dumps(document), encoding="utf-8")
            result = mutation_quality_record(metadata, policy, runner_exit_code=0)
        self.assertTrue(result["checks"]["minimum_score"])
        self.assertFalse(result["checks"]["all_groups"])
        self.assertFalse(result["passed"])

    def test_empty_or_out_of_scope_report_fails_minimum_population(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            metadata, policy = self._fixtures(Path(directory))
            document = json.loads(policy.read_text(encoding="utf-8"))
            document["selectors"] = ["does.not.match.*"]
            document["groups"][0]["selectors"] = ["does.not.match.*"]
            policy.write_text(json.dumps(document), encoding="utf-8")
            result = mutation_quality_record(metadata, policy, runner_exit_code=0)
        self.assertEqual(result["counts"]["total"], 0)
        self.assertFalse(result["checks"]["minimum_mutants"])


if __name__ == "__main__":
    unittest.main()
