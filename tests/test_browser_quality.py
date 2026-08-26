from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.browser_quality import (
    BROWSER_QUALITY_CHECKS,
    BROWSER_QUALITY_FORMAT,
    BROWSER_QUALITY_VERIFICATION_FORMAT,
    bind_browser_quality_receipt,
    verify_browser_quality_receipt,
    verify_browser_quality_receipt_file,
)
from pysfmea.cli import main
from pysfmea.integrity import canonical_json_sha256
from pysfmea.schemas import schema_document


class BrowserQualityReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.report = self.root / "report.html"
        self.report.write_text("<!doctype html><title>Report</title>", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _receipt(self, *, passed: bool = True) -> dict[str, object]:
        checks = {name: True for name in BROWSER_QUALITY_CHECKS}
        checks["manual_accessibility_evidence"] = None
        browser_error = ""
        load_seconds: float | None = 0.25
        if not passed:
            checks["browser_execution"] = False
            checks["load_budget"] = False
            checks["js_heap_measurement"] = False
            checks["js_heap_budget"] = False
            checks["progressive_rendering"] = False
            checks["navigation"] = False
            checks["responsive_layout"] = False
            checks["saved_and_shareable_views"] = False
            checks["automated_accessibility"] = False
            browser_error = "TimeoutError: required report control was unavailable"
            load_seconds = None
        return bind_browser_quality_receipt(
            {
                "format": BROWSER_QUALITY_FORMAT,
                "tool": {"name": "PySFMEA", "version": "test"},
                "report": "replaced-during-binding",
                "bytes": 0,
                "load_seconds": load_seconds,
                "budgets": {
                    "max_bytes": 52_428_800,
                    "max_load_seconds": 10.0,
                    "max_js_heap_bytes": 268_435_456,
                    "authority": "supported_default_not_representative_evidence",
                },
                "browser_memory": {
                    "maximum_used_js_heap_bytes": 1_000_000 if passed else None,
                    "samples": (
                        [{"view": "overview", "used_js_heap_bytes": 1_000_000}]
                        if passed
                        else []
                    ),
                    "measurement": "Chromium usedJSHeapSize",
                    "limitations": "Native and operating-system memory are excluded.",
                },
                "rendering": {
                    "mode": "progressive_on_demand",
                    "initial_view": "overview",
                    "initial_ready": passed,
                    "boot_seconds": 0.3 if passed else None,
                    "initial_render_seconds": 0.1 if passed else None,
                    "rendered_view_count": 1 if passed else 0,
                    "total_view_count": 1,
                    "all_views_ready": passed,
                    "maximum_view_render_seconds": 0.1 if passed else None,
                    "samples": (
                        [
                            {
                                "view": "overview",
                                "state": "ready",
                                "render_seconds": 0.1,
                            }
                        ]
                        if passed
                        else []
                    ),
                    "limitations": "Paint and native memory are excluded.",
                },
                "checks": checks,
                "views": (
                    [
                        {
                            "view": "overview",
                            "visible": True,
                            "navigation_active": True,
                            "render_state": "ready",
                        }
                    ]
                    if passed
                    else []
                ),
                "responsive": (
                    [{"viewport": "desktop", "passed": True}] if passed else []
                ),
                "saved_views": {"passed": passed},
                "accessibility": {
                    "automated_rules": [{"passed": passed}],
                    "manual_evidence": None,
                },
                "console_errors": [],
                "page_errors": [],
                "browser_execution_error": browser_error,
                "passed": passed,
                "notice": "Browser quality evidence is not user acceptance evidence.",
            },
            self.report,
        )

    def _write_receipt(self, receipt: dict[str, object]) -> Path:
        path = self.root / "browser-quality.json"
        path.write_text(
            json.dumps(receipt, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return path

    def test_passing_receipt_is_schema_valid_integrity_bound_and_cli_verifiable(
        self,
    ) -> None:
        receipt = self._receipt()
        Draft202012Validator(schema_document("report-browser-quality")).validate(
            receipt
        )
        in_memory = verify_browser_quality_receipt(receipt, report=self.report)
        self.assertTrue(in_memory["valid"])
        self.assertTrue(in_memory["quality_passed"])
        self.assertTrue(in_memory["checks"]["report_binding"])

        receipt_path = self._write_receipt(receipt)
        verification = verify_browser_quality_receipt_file(
            receipt_path, report=self.report
        )
        self.assertTrue(verification["valid"])
        self.assertTrue(verification["quality_passed"])
        Draft202012Validator(
            schema_document("report-browser-quality-verification")
        ).validate(verification)

        output = self.root / "verification.json"
        status = main(
            [
                "report-browser-verify",
                str(receipt_path),
                "--report",
                str(self.report),
                "--output",
                str(output),
            ]
        )
        self.assertEqual(status, 0)
        self.assertTrue(output.is_file())
        exported = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(exported["format"], BROWSER_QUALITY_VERIFICATION_FORMAT)
        self.assertTrue(exported["quality_passed"])

    def test_failed_quality_result_remains_valid_evidence_and_fails_quality_gate(
        self,
    ) -> None:
        receipt = self._receipt(passed=False)
        Draft202012Validator(schema_document("report-browser-quality")).validate(
            receipt
        )
        receipt_path = self._write_receipt(receipt)
        verification = verify_browser_quality_receipt_file(
            receipt_path, report=self.report
        )
        self.assertTrue(verification["valid"])
        self.assertFalse(verification["quality_passed"])
        self.assertEqual(
            main(
                [
                    "report-browser-verify",
                    str(receipt_path),
                    "--report",
                    str(self.report),
                ]
            ),
            1,
        )

    def test_tamper_semantic_drift_and_report_drift_fail_closed(self) -> None:
        receipt = self._receipt()
        tampered = copy.deepcopy(receipt)
        tampered["passed"] = False
        tampered["content_sha256"] = canonical_json_sha256(
            {key: value for key, value in tampered.items() if key != "content_sha256"}
        )
        semantic = verify_browser_quality_receipt(tampered, report=self.report)
        self.assertFalse(semantic["valid"])
        self.assertFalse(semantic["checks"]["semantic_consistency"])

        rendering_drift = copy.deepcopy(receipt)
        rendering_drift["rendering"]["rendered_view_count"] = 0
        rendering_drift["content_sha256"] = canonical_json_sha256(
            {
                key: value
                for key, value in rendering_drift.items()
                if key != "content_sha256"
            }
        )
        rendering_result = verify_browser_quality_receipt(
            rendering_drift, report=self.report
        )
        self.assertFalse(rendering_result["valid"])
        self.assertFalse(rendering_result["checks"]["semantic_consistency"])

        self.report.write_text("changed report", encoding="utf-8")
        drifted = verify_browser_quality_receipt(receipt, report=self.report)
        self.assertFalse(drifted["valid"])
        self.assertFalse(drifted["checks"]["report_binding"])

        receipt["report"] = "tampered path"
        integrity = verify_browser_quality_receipt(receipt)
        self.assertFalse(integrity["valid"])
        self.assertFalse(integrity["checks"]["content_integrity"])

    def test_malformed_or_missing_receipt_returns_schema_backed_rejection(self) -> None:
        malformed = self.root / "malformed.json"
        malformed.write_text("[]", encoding="utf-8")
        for source in (malformed, self.root / "missing.json"):
            with self.subTest(source=source.name):
                verification = verify_browser_quality_receipt_file(
                    source, report=self.report
                )
                self.assertFalse(verification["valid"])
                self.assertFalse(verification["quality_passed"])
                Draft202012Validator(
                    schema_document("report-browser-quality-verification")
                ).validate(verification)


if __name__ == "__main__":
    unittest.main()
