from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from pysfmea.accessibility import (
    build_accessibility_evidence,
    seal_accessibility_evidence,
    verify_accessibility_evidence,
    verify_accessibility_evidence_file,
)
from pysfmea.cli import main
from pysfmea.html_report import export_html_report
from pysfmea.integrity import canonical_json_sha256
from pysfmea.scanner import scan_repository
from pysfmea.schemas import schema_document


class AccessibilityEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "service.py").write_text(
            "def process(value):\n    return value + 1\n", encoding="utf-8"
        )
        self.report = self.root / "report.html"
        export_html_report(scan_repository(self.root), self.report)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_complete_evidence_is_exact_report_bound(self) -> None:
        evidence = build_accessibility_evidence(self.report)
        Draft202012Validator(schema_document("accessibility-evidence-draft")).validate(
            evidence
        )
        evidence["evaluator"]["name"] = "Accessibility Reviewer"
        evidence["reviewed_at"] = "2026-08-09"
        for scenario in evidence["scenarios"]:
            scenario["status"] = "pass"
            scenario["environment"] = "Recorded test environment"
            scenario["evidence_refs"] = [f"evidence/{scenario['id']}.md"]
        path = self.root / "accessibility.json"
        path.write_text(json.dumps(evidence), encoding="utf-8")
        seal_accessibility_evidence(path)
        sealed = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator(schema_document("accessibility-evidence")).validate(sealed)

        result = verify_accessibility_evidence(sealed, report=self.report)
        Draft202012Validator(
            schema_document("accessibility-evidence-verification")
        ).validate(result)

        self.assertTrue(result["valid"])
        self.assertTrue(result["qualified"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(
                [
                    "accessibility-verify",
                    str(path),
                    "--report",
                    str(self.report),
                    "--json",
                ]
            )
        self.assertEqual(status, 0)
        self.assertTrue(json.loads(output.getvalue())["qualified"])
        self.report.write_text("changed", encoding="utf-8")
        stale = verify_accessibility_evidence(sealed, report=self.report)
        self.assertFalse(stale["valid"])
        self.assertFalse(stale["checks"]["report_binding"])

    def test_unexecuted_template_is_valid_after_seal_but_not_qualified(self) -> None:
        evidence = build_accessibility_evidence(self.report)
        path = self.root / "accessibility.json"
        path.write_text(json.dumps(evidence), encoding="utf-8")
        seal_accessibility_evidence(path)
        result = verify_accessibility_evidence(
            json.loads(path.read_text(encoding="utf-8")), report=self.report
        )
        self.assertTrue(result["valid"])
        self.assertFalse(result["qualified"])
        self.assertFalse(result["checks"]["manual_scenarios_complete"])

    def test_closed_contract_and_missing_file_return_schema_backed_rejections(self) -> None:
        evidence = build_accessibility_evidence(self.report)
        evidence["format"] = "pysfmea-accessibility-evidence-1"
        evidence["unexpected"] = True
        evidence.pop("content_sha256")
        evidence["content_sha256"] = canonical_json_sha256(evidence)
        rejected = verify_accessibility_evidence(evidence)
        self.assertFalse(rejected["valid"])
        self.assertFalse(rejected["checks"]["structure"])

        unavailable = verify_accessibility_evidence_file(self.root / "missing.json")
        self.assertFalse(unavailable["valid"])
        Draft202012Validator(
            schema_document("accessibility-evidence-verification")
        ).validate(unavailable)

    def test_accessibility_inputs_preserve_final_link_identity(self) -> None:
        report_link = self.root / "linked-report.html"
        try:
            report_link.symlink_to(self.report)
        except OSError:
            self.skipTest("symbolic links are unavailable on this platform")

        with self.assertRaisesRegex(ValueError, "must not be a symbolic link"):
            build_accessibility_evidence(report_link)

        draft = build_accessibility_evidence(self.report)
        evidence = self.root / "accessibility.json"
        evidence.write_text(json.dumps(draft), encoding="utf-8")
        evidence_link = self.root / "linked-accessibility.json"
        evidence_link.symlink_to(evidence)
        with self.assertRaisesRegex(ValueError, "must not be a symbolic link"):
            seal_accessibility_evidence(evidence_link)

        verdict = verify_accessibility_evidence_file(evidence_link)
        self.assertFalse(verdict["valid"])
        self.assertEqual(verdict["path"], str(evidence_link))
        Draft202012Validator(
            schema_document("accessibility-evidence-verification")
        ).validate(verdict)

        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                main(["accessibility-init", str(report_link)]),
                2,
            )


if __name__ == "__main__":
    unittest.main()
