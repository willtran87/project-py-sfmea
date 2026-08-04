from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.pdf_report import export_pdf_report, resolve_pdf_browser, verify_pdf_file
from pysfmea.scanner import scan_repository


def _minimal_pdf() -> bytes:
    return b"%PDF-1.4\n" + (b"0" * 1100) + b"\n%%EOF\n"


class PdfReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "service.py").write_text(
            "def perform(value):\n    return value\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_pdf_structural_verification_and_explicit_browser_validation(self) -> None:
        document = self.root / "report.pdf"
        document.write_bytes(_minimal_pdf())
        result = verify_pdf_file(document)
        self.assertGreater(result["bytes"], 1024)
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            resolve_pdf_browser(self.root / "missing-browser")

    def test_export_is_self_contained_verified_and_atomically_published(self) -> None:
        browser = self.root / "browser.exe"
        browser.write_bytes(b"placeholder")
        analysis = scan_repository(self.root)

        def render(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            output = next(
                value.removeprefix("--print-to-pdf=")
                for value in command
                if value.startswith("--print-to-pdf=")
            )
            Path(output).write_bytes(_minimal_pdf())
            self.assertTrue(command[-1].startswith("file:"))
            return subprocess.CompletedProcess(command, 0, "", "")

        output = self.root / "published.pdf"
        with patch("pysfmea.pdf_report.subprocess.run", side_effect=render):
            result = export_pdf_report(analysis, output, browser=browser)
        self.assertEqual(result, output.resolve())
        self.assertEqual(output.read_bytes(), _minimal_pdf())
        self.assertFalse(list(self.root.glob(".*.tmp")))


if __name__ == "__main__":
    unittest.main()
