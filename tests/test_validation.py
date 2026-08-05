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
from pysfmea.repository_inventory import legacy_repository_inventory
from pysfmea.scanner import scan_repository
from pysfmea.store import save_analysis, update_item_review
from pysfmea.validation import review_queue, validate_analysis


class ValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "service.py").write_text(
            "def authorize(user):\n    return bool(user)\n",
            encoding="utf-8",
        )
        self.analysis = scan_repository(self.root)
        self.item = self.analysis["items"][0]

    def tearDown(self) -> None:
        self.temp.cleanup()

    def rules(self) -> set[str]:
        return {finding["rule_id"] for finding in validate_analysis(self.analysis)["findings"]}

    def test_accepted_item_requires_trace_effect_severity_and_rationale(self) -> None:
        update_item_review(
            self.analysis,
            self.item["id"],
            {"disposition": "accepted", "reviewer": "Jordan"},
        )
        update_item_review(
            self.analysis,
            self.item["id"],
            {"local_effect": "", "causes": []},
        )
        rules = self.rules()
        self.assertTrue(
            {
                "accepted.missing_requirement",
                "accepted.missing_end_effect",
                "accepted.missing_severity",
                "accepted.missing_local_effect",
                "accepted.missing_causes",
            }
            <= rules
        )

        update_item_review(
            self.analysis,
            self.item["id"],
            {
                "requirement": "REQ-AUTH-1",
                "end_effect": "A legitimate user is denied access.",
                "next_higher_effect": "The authentication subsystem rejects the session.",
                "severity": 6,
                "severity_rationale": "Service is unavailable to one user.",
                "local_effect": "Authorization returns the wrong decision.",
                "causes": ["The authorization condition is incorrect."],
                "detection_controls": ["Authentication integration test"],
            },
        )
        item_errors = [
            finding
            for finding in validate_analysis(self.analysis)["findings"]
            if finding["item_id"] == self.item["id"] and finding["level"] == "error"
        ]
        self.assertEqual(item_errors, [])

    def test_action_and_closure_gates(self) -> None:
        update_item_review(
            self.analysis,
            self.item["id"],
            {
                "disposition": "accepted",
                "reviewer": "Jordan",
                "requirement": "REQ-AUTH-1",
                "end_effect": "Unauthorized access is granted.",
                "severity": 9,
                "severity_rationale": "Protected data can be disclosed.",
                "status": "action_required",
                "recommended_actions": [],
            },
        )
        self.assertTrue(
            {
                "action.missing_description",
                "action.missing_owner",
                "action.missing_target_date",
            }
            <= self.rules()
        )
        update_item_review(
            self.analysis,
            self.item["id"],
            {"status": "closed", "owner": "Safety lead", "target_date": "2026-08-31"},
        )
        self.assertTrue(
            {"closure.missing_verification", "closure.missing_approval"} <= self.rules()
        )

    def test_closed_residual_rating_requires_rationale(self) -> None:
        update_item_review(
            self.analysis,
            self.item["id"],
            {
                "disposition": "accepted",
                "requirement": "REQ-AUTH-1",
                "next_higher_effect": "Authorization subsystem returns the wrong decision.",
                "end_effect": "Protected data may be disclosed.",
                "severity": 7,
                "severity_rationale": "Confidentiality impact.",
                "detection_controls": ["Authorization integration test"],
                "actions_taken": ["No further action; risk accepted by the product owner."],
                "verification_evidence": ["Review record SAF-42"],
                "post_action_severity": 7,
                "status": "closed",
            },
        )
        self.assertIn("closure.missing_post_action_rationale", self.rules())

    def test_original_high_severity_still_requires_closure_approval(self) -> None:
        review = self.item["review"]
        review.update(
            {
                "disposition": "accepted",
                "reviewer": "Jordan",
                "status": "closed",
                "severity": 9,
                "post_action_severity": 3,
            }
        )
        self.assertIn("closure.missing_approval", self.rules())

    def test_boolean_rating_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "ratings"):
            update_item_review(self.analysis, self.item["id"], {"severity": True})
        self.item["review"]["severity"] = True
        self.assertIn("integrity.invalid_rating", self.rules())

    def test_cli_validation_exit_code(self) -> None:
        update_item_review(
            self.analysis,
            self.item["id"],
            {"disposition": "accepted", "reviewer": "Jordan"},
        )
        path = self.root / "analysis.json"
        save_analysis(path, self.analysis)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main(["validate", str(path), "--max-findings", "2"])
        self.assertEqual(exit_code, 1)
        self.assertIn("Validation: errors=", output.getvalue())

    def test_cli_summary_recomputes_repository_artifact_totals(self) -> None:
        inventory = self.analysis["repository_inventory"]
        expected_files = len(inventory["entries"])
        inventory["summary"]["files"] = expected_files + 999
        self.analysis["summary"]["repository_artifacts"] = expected_files + 999
        path = self.root / "analysis.json"
        save_analysis(path, self.analysis)

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main(["summary", str(path), "--json"])
        self.assertEqual(exit_code, 0)
        summary = json.loads(output.getvalue())
        self.assertEqual(summary["repository_artifacts"], expected_files)
        self.assertEqual(
            summary["repository_inventory"]["status"], "recomputed"
        )

    def test_rejection_traceability_and_integrity_checks(self) -> None:
        update_item_review(
            self.analysis,
            self.item["id"],
            {"disposition": "rejected", "reviewer": "Jordan"},
        )
        self.assertIn("review.missing_rejection_rationale", self.rules())
        update_item_review(
            self.analysis,
            self.item["id"],
            {"disposition_rationale": "Generic omission is not credible for this pure helper."},
        )
        self.assertNotIn("review.missing_rejection_rationale", self.rules())

        self.item["review"]["severity"] = 99
        self.analysis["context"]["critical_functions"] = [
            {"pattern": "missing.py:*", "hazards": []}
        ]
        rules = self.rules()
        self.assertIn("integrity.invalid_rating", rules)
        self.assertIn("trace.unmatched_critical_function", rules)

    def test_categorical_severity_scale(self) -> None:
        self.analysis["context"]["risk"] = {
            "method": "severity_only",
            "severity_categories": ["minor", "major", "catastrophic"],
        }
        update_item_review(
            self.analysis,
            self.item["id"],
            {
                "disposition": "accepted",
                "reviewer": "Jordan",
                "requirement": "REQ-1",
                "next_higher_effect": "Subsystem authorization is incorrect.",
                "end_effect": "Protected data may be disclosed.",
                "severity_category": "catastrophic",
                "severity_rationale": "Worst credible protected-data consequence.",
                "detection_controls": ["Independent authorization check"],
            },
        )
        rules = self.rules()
        self.assertNotIn("accepted.missing_severity", rules)
        self.assertNotIn("integrity.invalid_severity_category", rules)
        self.item["review"]["severity_category"] = "unknown"
        self.assertIn("integrity.invalid_severity_category", self.rules())

    def test_syntax_error_makes_scan_incomplete(self) -> None:
        (self.root / "broken.py").write_text("def broken(:\n", encoding="utf-8")
        analysis = scan_repository(self.root)
        rules = {finding["rule_id"] for finding in validate_analysis(analysis)["findings"]}
        self.assertIn("scan.warning", rules)
        scan_finding = next(
            finding
            for finding in validate_analysis(analysis)["findings"]
            if finding["rule_id"] == "scan.warning"
        )
        self.assertEqual(scan_finding["level"], "error")

    def test_repository_snapshot_provenance_and_summary_are_gated(self) -> None:
        self.assertNotIn("coverage.invalid_snapshot_provenance", self.rules())
        self.assertNotIn("coverage.inventory_summary_mismatch", self.rules())

        inventory = self.analysis["repository_inventory"]
        inventory["entries"][0]["snapshot_source"] = "unrecognized_snapshot"
        self.assertIn("coverage.invalid_snapshot_provenance", self.rules())

        self.analysis = scan_repository(self.root)
        inventory = self.analysis["repository_inventory"]
        inventory["summary"]["files"] += 1
        inventory["summary"]["opaque_or_unresolved"] = 999
        inventory["summary"]["semantic_coverage_percent"] = -1
        findings = validate_analysis(self.analysis)["findings"]
        self.assertIn("coverage.inventory_summary_mismatch", self.rules())
        self.assertFalse(
            any(
                finding["rule_id"] == "coverage.opaque_or_unresolved_artifacts"
                and "999" in finding["message"]
                for finding in findings
            )
        )

    def test_malformed_repository_inventory_records_are_bounded_findings(self) -> None:
        inventory = self.analysis["repository_inventory"]
        inventory["entries"][0] = "not-an-object"
        findings = validate_analysis(self.analysis)["findings"]
        invalid = [
            finding
            for finding in findings
            if finding["rule_id"] == "coverage.invalid_inventory_records"
        ]
        self.assertEqual(len(invalid), 1)
        self.assertEqual(invalid[0]["level"], "error")

        self.analysis = scan_repository(self.root)
        self.analysis["repository_inventory"]["summary"] = []
        self.assertIn("coverage.inventory_summary_mismatch", self.rules())

    def test_legacy_zero_file_inventory_retains_null_coverage_compatibility(self) -> None:
        self.analysis["repository_inventory"] = legacy_repository_inventory(
            "Historical scan did not capture repository coverage."
        )
        rules = self.rules()
        self.assertNotIn("coverage.inventory_summary_mismatch", rules)
        self.assertNotIn("coverage.invalid_snapshot_provenance", rules)

    def test_empty_failure_mode_set_is_an_error(self) -> None:
        self.analysis["items"] = []
        self.assertIn("analysis.no_failure_modes", self.rules())

    def test_review_queue_prioritizes_revalidation(self) -> None:
        self.assertGreater(validate_analysis(self.analysis)["counts"]["error"], 0)
        self.item["review"]["revalidation_required"] = True
        queue = review_queue(self.analysis, limit=2)
        self.assertEqual(queue[0]["id"], self.item["id"])
        self.assertTrue(queue[0]["revalidation_required"])

    def test_repository_baseline_and_component_integrity_are_gated(self) -> None:
        update_item_review(
            self.analysis,
            self.item["id"],
            {"disposition": "rejected", "disposition_rationale": "Not credible.", "reviewer": "Jordan"},
        )
        self.analysis["project"]["baseline"]["id"] = "BASELINE-TAMPERED"
        self.analysis["components"].append(dict(self.analysis["components"][0]))
        self.item["component_id"] = "CMP-UNKNOWN"
        rules = self.rules()
        self.assertIn("review.stale_validation_baseline", rules)
        self.assertIn("analysis.duplicate_or_missing_component_id", rules)
        self.assertIn("integrity.unknown_component", rules)

    def test_incomplete_catalogs_and_unknown_approver_are_gated(self) -> None:
        self.analysis["context"]["hazards"] = [{"id": "HZ-EMPTY"}]
        self.analysis["context"]["requirements"] = [{"id": "REQ-EMPTY"}]
        self.analysis["context"]["system_interfaces"] = [{"id": "IF-EMPTY"}]
        self.analysis["context"]["reviewers"] = [
            {"name": "Jordan", "role": "Safety", "organization": "Example"},
            {"name": "Alex", "role": "Software", "organization": "Example"},
        ]
        review = self.item["review"]
        review.update(
            {
                "disposition": "accepted",
                "reviewer": "Jordan",
                "status": "closed",
                "severity": 9,
                "post_action_severity": 9,
                "approved_by": "Unknown approver",
                "approval_date": "2026-08-03",
            }
        )
        rules = self.rules()
        self.assertTrue(
            {
                "catalog.hazard_missing_description",
                "catalog.hazard_missing_end_effect",
                "catalog.requirement_missing_text",
                "catalog.interface_missing_endpoint",
                "closure.unidentified_approver",
            }
            <= rules
        )


if __name__ == "__main__":
    unittest.main()
