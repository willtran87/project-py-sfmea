from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from os import stat_result
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea import discovery
from pysfmea.cli import main
from pysfmea.discovery import (
    compare_evaluation_results,
    evaluate_candidates,
    load_evaluation_spec,
)
from pysfmea.scanner import scan_repository
from pysfmea.store import save_analysis


class EvaluationBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "service.py").write_text(
            "def perform(value):\n    return value\n", encoding="utf-8"
        )
        self.analysis = scan_repository(self.root)
        first = self.analysis["items"][0]
        self.spec = {
            "schema_version": "pysfmea-golden-corpus-1",
            "name": "Boundary corpus",
            "purpose": "Exercise exact candidate matching.",
            "scope": ["service.py:*"],
            "cases": [
                {
                    "source": first["source"]["path"],
                    "component": first["component"]["qualname"],
                    "rule_id": first["scanner"]["rule_id"],
                }
            ],
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_spec(self, name: str = "expected.json") -> Path:
        path = self.root / name
        path.write_text(json.dumps(self.spec), encoding="utf-8")
        return path

    def test_loaded_corpus_is_strict_content_addressed_and_reproducible(self) -> None:
        path = self._write_spec()
        loaded = load_evaluation_spec(path)
        first = evaluate_candidates(self.analysis, loaded)
        second = evaluate_candidates(self.analysis, copy.deepcopy(loaded))
        self.assertEqual(first, second)
        self.assertEqual(first["format"], "pysfmea-evaluation-result-1")
        self.assertEqual(first["corpus"]["format"], "pysfmea-golden-corpus-1")
        self.assertEqual(first["corpus"]["case_count"], 1)
        self.assertEqual(first["corpus"]["call_case_count"], 0)
        self.assertEqual(len(first["corpus"]["content_sha256"]), 64)
        self.assertEqual(first["matched"], 1)
        self.assertFalse(first["call_resolution"]["enabled"])
        self.assertTrue(first["confidence_calibration"]["enabled"])
        self.assertIn("medium", first["confidence_calibration"]["bins"])

        analysis_path = self.root / "analysis.json"
        save_analysis(analysis_path, self.analysis)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(["evaluate", str(analysis_path), str(path), "--json"])
        cli_result = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, int(bool(cli_result["unexpected"])))
        self.assertEqual(cli_result["corpus"], first["corpus"])

        output_path = self.root / "evaluation-result.json"
        with contextlib.redirect_stdout(io.StringIO()):
            output_exit = main(
                [
                    "evaluate",
                    str(analysis_path),
                    str(path),
                    "-o",
                    str(output_path),
                ]
            )
        self.assertEqual(output_exit, int(bool(first["unexpected"])))
        self.assertEqual(json.loads(output_path.read_text()), first)

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            invalid_exit = main(
                [
                    "evaluate",
                    str(analysis_path),
                    str(path),
                    "--json",
                    "-o",
                    str(self.root / "invalid.json"),
                ]
            )
        self.assertEqual(invalid_exit, 2)
        self.assertIn("cannot be combined", stderr.getvalue())

    def test_governed_confidence_and_control_calibration(self) -> None:
        component = self.analysis["components"][0]
        component["detected_controls"] = [
            {
                "kind": "circuit_breaker",
                "roles": ["admission_guard", "failure_recording"],
            }
        ]
        all_cases = [
            {
                "source": value["source"]["path"],
                "component": value["component"]["qualname"],
                "rule_id": value["scanner"]["rule_id"],
            }
            for value in self.analysis["items"]
            if value["component_id"] == component["id"]
        ]
        spec = {
            **self.spec,
            "cases": all_cases,
            "control_cases": [
                {
                    "source": component["source"]["path"],
                    "component": component["qualname"],
                    "kind": "circuit_breaker",
                    "roles": ["failure_recording", "admission_guard"],
                }
            ],
            "governance": {
                "independent": True,
                "repositories": ["cohort/repository-a"],
                "labeled_by": "Independent labeler",
                "approved_by": "Assurance approver",
                "approval_date": "2026-08-09",
            },
        }

        result = evaluate_candidates(self.analysis, spec)

        self.assertTrue(result["corpus"]["governance"]["qualification_ready"])
        self.assertEqual(result["control_detection"]["recall"], 1.0)
        self.assertEqual(result["control_detection"]["precision"], 1.0)
        self.assertEqual(
            result["control_detection"]["by_kind"]["circuit_breaker"]["matched"],
            1,
        )
        self.assertEqual(
            result["confidence_calibration"]["bins"]["medium"]["empirical_precision"],
            1.0,
        )

    def test_control_scope_measures_negative_components_and_false_positives(
        self,
    ) -> None:
        positive = self.analysis["components"][0]
        positive["detected_controls"] = [
            {"kind": "circuit_breaker", "roles": ["admission_guard"]}
        ]
        negative = copy.deepcopy(positive)
        negative["id"] = "CMP-NEGATIVE-CONTROL"
        negative["qualname"] = "near_miss"
        negative["detected_controls"] = [
            {"kind": "circuit_breaker", "roles": ["admission_guard"]}
        ]
        self.analysis["components"].append(negative)
        spec = {
            **self.spec,
            "control_scope": ["service.py:*"],
            "control_cases": [
                {
                    "source": "service.py",
                    "component": positive["qualname"],
                    "kind": "circuit_breaker",
                    "roles": ["admission_guard"],
                }
            ],
        }

        result = evaluate_candidates(self.analysis, spec)

        self.assertEqual(result["control_detection"]["recall"], 1.0)
        self.assertEqual(result["control_detection"]["precision"], 0.5)
        self.assertEqual(len(result["control_detection"]["unexpected"]), 1)
        self.assertEqual(
            result["control_detection"]["population"]["negative_components"], 1
        )
        self.assertEqual(
            result["control_detection"]["population"]["evaluated_components"], 2
        )

    def test_control_cases_must_be_inside_explicit_control_scope(self) -> None:
        component = self.analysis["components"][0]
        spec = {
            **self.spec,
            "control_scope": ["other.py:*"],
            "control_cases": [
                {
                    "source": "service.py",
                    "component": component["qualname"],
                    "kind": "circuit_breaker",
                    "roles": ["admission_guard"],
                }
            ],
        }

        with self.assertRaisesRegex(ValueError, "outside control_scope"):
            evaluate_candidates(self.analysis, spec)

    def test_semantic_output_qualifies_exact_deterministic_claims(self) -> None:
        item = self.analysis["items"][0]
        scanner = item["scanner"]
        review = item["review"]
        citation_ids = sorted(
            value["citation_id"] for value in scanner.get("citations", [])
        )
        semantic_expect = {
            "failure_mode": review["failure_mode"],
            "trigger": review["trigger"],
            "causes": review["causes"],
            "local_effect": review["local_effect"],
            "recommended_actions": review["recommended_actions"],
            "citation_ids": citation_ids,
            "confidence": scanner["confidence"],
            "screening_priority": scanner["screening_priority"],
        }
        spec = {
            **self.spec,
            "semantic_cases": [
                {
                    "source": item["source"]["path"],
                    "component": item["component"]["qualname"],
                    "rule_id": scanner["rule_id"],
                    "expect": semantic_expect,
                }
            ],
        }

        result = evaluate_candidates(self.analysis, spec)

        semantics = result["semantic_output"]
        self.assertTrue(semantics["enabled"])
        self.assertEqual(semantics["matched"], 1)
        self.assertEqual(semantics["claim_matched"], len(semantic_expect))
        self.assertEqual(semantics["recall"], 1.0)
        self.assertEqual(semantics["claim_precision"], 1.0)
        self.assertFalse(semantics["mismatches"])
        self.assertEqual(result["corpus"]["semantic_case_count"], 1)
        self.assertEqual(
            result["corpus"]["semantic_claim_count"], len(semantic_expect)
        )

        mismatched = copy.deepcopy(spec)
        mismatched["semantic_cases"][0]["expect"]["failure_mode"] += " changed"
        mismatch_result = evaluate_candidates(self.analysis, mismatched)
        self.assertEqual(mismatch_result["semantic_output"]["matched"], 0)
        self.assertEqual(
            mismatch_result["semantic_output"]["mismatches"][0]["field"],
            "failure_mode",
        )

        analysis_path = self.root / "semantic-analysis.json"
        save_analysis(analysis_path, self.analysis)
        corpus_path = self.root / "semantic-corpus.json"
        corpus_path.write_text(json.dumps(mismatched), encoding="utf-8")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(["evaluate", str(analysis_path), str(corpus_path)])
        self.assertEqual(exit_code, 1)
        self.assertIn("Semantic mismatch:", stdout.getvalue())

    def test_semantic_cases_are_closed_unique_and_bounded(self) -> None:
        item = self.analysis["items"][0]
        base_case = {
            "source": item["source"]["path"],
            "component": item["component"]["qualname"],
            "rule_id": item["scanner"]["rule_id"],
            "expect": {"confidence": item["scanner"]["confidence"]},
        }
        duplicate = {**self.spec, "semantic_cases": [base_case, base_case]}
        with self.assertRaisesRegex(ValueError, "duplicate source/component/rule"):
            evaluate_candidates(self.analysis, duplicate)

        unsupported = copy.deepcopy(base_case)
        unsupported["expect"] = {"severity": "high"}
        with self.assertRaisesRegex(ValueError, "unsupported fields: severity"):
            evaluate_candidates(
                self.analysis, {**self.spec, "semantic_cases": [unsupported]}
            )

        duplicate_claims = copy.deepcopy(base_case)
        duplicate_claims["expect"] = {"citation_ids": ["NASA-A", "NASA-A"]}
        with self.assertRaisesRegex(ValueError, "must not contain duplicates"):
            evaluate_candidates(
                self.analysis, {**self.spec, "semantic_cases": [duplicate_claims]}
            )

        negative_set_claim = copy.deepcopy(base_case)
        negative_set_claim["expect"] = {"adapter_ids": []}
        negative_set_result = evaluate_candidates(
            self.analysis,
            {**self.spec, "semantic_cases": [negative_set_claim]},
        )
        self.assertTrue(negative_set_result["semantic_output"]["enabled"])

        missing = copy.deepcopy(base_case)
        missing["component"] = "missing_component"
        missing_result = evaluate_candidates(
            self.analysis, {**self.spec, "semantic_cases": [missing]}
        )
        self.assertEqual(missing_result["semantic_output"]["actual"], 0)
        self.assertEqual(len(missing_result["semantic_output"]["missing"]), 1)

    def test_governed_before_after_calibration_comparison_and_cli(self) -> None:
        complete_spec = {
            **self.spec,
            "cases": [
                {
                    "source": value["source"]["path"],
                    "component": value["component"]["qualname"],
                    "rule_id": value["scanner"]["rule_id"],
                }
                for value in self.analysis["items"]
            ],
            "governance": {
                "independent": True,
                "repositories": ["repository-a"],
                "labeled_by": "Labeler",
                "approved_by": "Approver",
                "approval_date": "2026-08-09",
            },
        }
        after = evaluate_candidates(self.analysis, complete_spec)
        before = copy.deepcopy(after)
        changed_rule = next(iter(after["by_rule"]))
        before["precision"] = max(0.0, float(after["precision"]) - 0.1)
        before["by_rule"][changed_rule]["precision"] = max(
            0.0, float(after["by_rule"][changed_rule]["precision"]) - 0.1
        )
        change = {
            "id": "CAL-001",
            "changed_rule_ids": [changed_rule],
            "rationale": "Reduce false positives without reducing recall.",
            "authored_by": "Rule author",
            "approved_by": "Independent approver",
            "approval_date": "2026-08-09",
            "max_recall_regression": 0.0,
            "max_control_recall_regression": 0.0,
        }

        comparison = compare_evaluation_results(before, after, change)

        self.assertEqual(comparison["decision"], "eligible_for_review")
        self.assertTrue(comparison["gates"]["global_precision_non_decreasing"])
        self.assertEqual(comparison["rules"][0]["precision_delta"], 0.1)
        self.assertEqual(len(comparison["content_sha256"]), 64)

        paths = []
        for name, value in (
            ("before.json", before),
            ("after.json", after),
            ("change.json", change),
        ):
            path = self.root / name
            path.write_text(json.dumps(value), encoding="utf-8")
            paths.append(path)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(
                ["evaluate-compare", *(str(value) for value in paths), "--json"]
            )
        self.assertEqual(exit_code, 0)
        self.assertEqual(
            json.loads(stdout.getvalue())["decision"], "eligible_for_review"
        )

    def test_semantic_regression_blocks_governed_calibration(self) -> None:
        item = self.analysis["items"][0]
        rule_id = item["scanner"]["rule_id"]
        semantic_expect = {
            "failure_mode": item["review"]["failure_mode"],
            "confidence": item["scanner"]["confidence"],
        }
        specification = {
            **self.spec,
            "governance": {
                "independent": True,
                "repositories": ["repository-a"],
                "labeled_by": "Labeler",
                "approved_by": "Approver",
                "approval_date": "2026-08-09",
            },
            "semantic_cases": [
                {
                    "source": item["source"]["path"],
                    "component": item["component"]["qualname"],
                    "rule_id": rule_id,
                    "expect": semantic_expect,
                }
            ],
        }
        before = evaluate_candidates(self.analysis, specification)
        after = copy.deepcopy(before)
        before["precision"] = 0.9
        before["by_rule"][rule_id]["precision"] = 0.9
        after["semantic_output"]["precision"] = 0.9
        after["semantic_output"]["claim_precision"] = 0.9
        comparison = compare_evaluation_results(
            before,
            after,
            {
                "id": "CAL-SEM-001",
                "changed_rule_ids": [rule_id],
                "rationale": "Semantic claims are governed alongside rule calibration.",
                "authored_by": "Rule author",
                "approved_by": "Independent approver",
                "approval_date": "2026-08-09",
                "max_recall_regression": 0.0,
                "max_control_recall_regression": 0.0,
                "max_semantic_recall_regression": 0.0,
                "max_semantic_claim_recall_regression": 0.0,
            },
        )
        self.assertEqual(comparison["decision"], "blocked")
    def test_file_loader_rejects_unsafe_or_malformed_inputs(self) -> None:
        directory = self.root / "directory"
        directory.mkdir()
        with self.assertRaisesRegex(ValueError, "regular non-symbolic-link"):
            load_evaluation_spec(directory)

        invalid_utf8 = self.root / "invalid.json"
        invalid_utf8.write_bytes(b"\xff")
        with self.assertRaisesRegex(ValueError, "UTF-8 JSON"):
            load_evaluation_spec(invalid_utf8)

        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"cases":[],"cases":[]}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate object key"):
            load_evaluation_spec(duplicate)

        nonfinite = self.root / "nonfinite.json"
        nonfinite.write_text('{"cases":[],"score":NaN}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "non-finite"):
            load_evaluation_spec(nonfinite)

        valid = self._write_spec("oversized.json")
        with patch("pysfmea.discovery.MAX_EVALUATION_FILE_BYTES", 10):
            with self.assertRaisesRegex(ValueError, "byte limit"):
                load_evaluation_spec(valid)

    def test_file_loader_rejects_links(self) -> None:
        target = self._write_spec("target.json")
        linked = self.root / "linked.json"
        try:
            linked.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symbolic links unavailable: {exc}")
        with self.assertRaisesRegex(ValueError, "regular non-symbolic-link"):
            load_evaluation_spec(linked)

    def test_file_loader_rejects_opened_identity_changes(self) -> None:
        target = self._write_spec("target.json")
        original_fstat = discovery.os.fstat
        calls = 0

        def changed_fstat(descriptor: int) -> stat_result:
            nonlocal calls
            observed = original_fstat(descriptor)
            calls += 1
            if calls == 1:
                return observed
            values = list(observed)
            values[6] += 1
            return stat_result(values)

        with patch("pysfmea.discovery.os.fstat", side_effect=changed_fstat):
            with self.assertRaisesRegex(ValueError, "changed while"):
                load_evaluation_spec(target)

    def test_json_shape_and_contract_limits_fail_closed(self) -> None:
        deep: dict[str, object] = {"cases": []}
        cursor = deep
        for _ in range(25):
            child: dict[str, object] = {}
            cursor["nested"] = child
            cursor = child
        deep_path = self.root / "deep.json"
        deep_path.write_text(json.dumps(deep), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "depth limit"):
            load_evaluation_spec(deep_path)

        valid = self._write_spec("nodes.json")
        with patch("pysfmea.discovery.MAX_EVALUATION_JSON_NODES", 5):
            with self.assertRaisesRegex(ValueError, "node limit"):
                load_evaluation_spec(valid)

        for invalid, message in (
            ({**self.spec, "decision": "pass"}, "unsupported fields"),
            (
                {**self.spec, "cases": [{**self.spec["cases"][0], "note": "x"}]},
                "case 1 contains unsupported fields",
            ),
            (
                {**self.spec, "cases": [{**self.spec["cases"][0], "rule_id": 1}]},
                "fields must be strings",
            ),
            ({**self.spec, "scope": ["service.py:*", "service.py:*"]}, "duplicate"),
            ({**self.spec, "call_cases": "invalid"}, "call_cases"),
            (
                {
                    **self.spec,
                    "call_cases": [
                        {
                            "source": "service.py",
                            "component": "perform",
                            "raw_reference": "value",
                            "reference": "value",
                            "resolution": "lexical_name",
                            "candidate_confidence": "certain",
                            "line": 1,
                            "order": 0,
                            "awaited": False,
                            "control_context": [],
                        }
                    ],
                },
                "candidate_confidence",
            ),
            (
                {
                    **self.spec,
                    "call_cases": [
                        {
                            "source": "service.py",
                            "component": "perform",
                            "raw_reference": "value",
                            "reference": "value",
                            "resolution": "lexical_name",
                            "candidate_confidence": "",
                            "line": -1,
                            "order": 0,
                            "awaited": False,
                            "control_context": [],
                        }
                    ],
                },
                "line must be a non-negative integer",
            ),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    evaluate_candidates(self.analysis, invalid)

        with patch("pysfmea.discovery.MAX_EVALUATION_CASES", 0):
            with self.assertRaisesRegex(ValueError, "record limit"):
                evaluate_candidates(self.analysis, self.spec)
        with patch("pysfmea.discovery.MAX_EVALUATION_CANDIDATES", 0):
            with self.assertRaisesRegex(ValueError, "active evaluation candidates"):
                evaluate_candidates(self.analysis, self.spec)


if __name__ == "__main__":
    unittest.main()
