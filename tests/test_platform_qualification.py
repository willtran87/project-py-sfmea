from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.platform_qualification import platform_qualification_receipt


class PlatformQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_receipt_binds_platform_and_exact_passing_junit(self) -> None:
        junit = self.root / "junit.xml"
        junit.write_text(
            '<testsuites><testsuite tests="12" failures="0" errors="0" skipped="1"/></testsuites>',
            encoding="utf-8",
        )

        receipt = platform_qualification_receipt(junit)

        self.assertEqual(receipt["format"], "pysfmea-platform-qualification-1")
        self.assertEqual(receipt["junit"]["counts"]["tests"], 12)
        self.assertTrue(receipt["passed"])
        self.assertTrue(receipt["environment"]["system"])
        self.assertEqual(len(receipt["content_sha256"]), 64)
        json.dumps(receipt)

    def test_receipt_rejects_failed_or_malformed_evidence(self) -> None:
        failed = self.root / "failed.xml"
        failed.write_text(
            '<testsuite tests="2" failures="1" errors="0" skipped="0"/>',
            encoding="utf-8",
        )
        self.assertFalse(platform_qualification_receipt(failed)["passed"])

        invalid = self.root / "invalid.xml"
        invalid.write_text("<not-junit />", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "testsuite"):
            platform_qualification_receipt(invalid)


if __name__ == "__main__":
    unittest.main()
