from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from os import stat_result
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea import pdf_report
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

        with patch("pysfmea.pdf_report.MAX_PDF_REPORT_BYTES", 10):
            with self.assertRaisesRegex(ValueError, "bounded verification size"):
                verify_pdf_file(document)

    def _browser_and_analysis(self) -> tuple[Path, dict[str, object]]:
        browser = self.root / "browser.exe"
        browser.write_bytes(b"placeholder")
        return browser, scan_repository(self.root)

    @staticmethod
    def _render_pdf(
        command: list[str], payload: bytes | None = None
    ) -> subprocess.CompletedProcess[str]:
        output = next(
            value.removeprefix("--print-to-pdf=")
            for value in command
            if value.startswith("--print-to-pdf=")
        )
        Path(output).write_bytes(payload if payload is not None else _minimal_pdf())
        return subprocess.CompletedProcess(command, 0, "", "")

    def test_export_is_self_contained_verified_and_atomically_published(self) -> None:
        browser, analysis = self._browser_and_analysis()

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
        included_id = analysis["items"][-1]["id"]
        with patch("pysfmea.pdf_report.subprocess.run", side_effect=render):
            result = export_pdf_report(
                analysis,
                output,
                browser=browser,
                propagation_record_limit=1,
                propagation_path_limit=0,
                propagation_depth=0,
                propagation_include_finding_ids=[included_id],
            )
        self.assertEqual(result, output.resolve())
        self.assertEqual(output.read_bytes(), _minimal_pdf())
        self.assertFalse(list(self.root.glob(".*.tmp")))

    def test_export_rejects_unsafe_destinations_before_rendering(self) -> None:
        browser, analysis = self._browser_and_analysis()
        directory = self.root / "report-directory"
        directory.mkdir()
        with self.assertRaisesRegex(ValueError, "PDF destination"):
            export_pdf_report(analysis, directory, browser=browser)

        target = self.root / "linked-target.pdf"
        target.write_bytes(b"trusted")
        linked = self.root / "linked-report.pdf"
        try:
            linked.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"symbolic links unavailable: {exc}")
        with self.assertRaisesRegex(ValueError, "PDF destination"):
            export_pdf_report(analysis, linked, browser=browser)
        self.assertEqual(target.read_bytes(), b"trusted")

    def test_invalid_or_oversized_render_preserves_previous_report(self) -> None:
        browser, analysis = self._browser_and_analysis()
        output = self.root / "preserved.pdf"
        output.write_bytes(b"trusted previous report")

        with patch(
            "pysfmea.pdf_report.subprocess.run",
            side_effect=lambda command, **_: self._render_pdf(command, b"not a pdf" * 200),
        ):
            with self.assertRaisesRegex(ValueError, "no PDF header"):
                export_pdf_report(analysis, output, browser=browser)
        self.assertEqual(output.read_bytes(), b"trusted previous report")

        with (
            patch("pysfmea.pdf_report.MAX_PDF_REPORT_BYTES", 1024),
            patch(
                "pysfmea.pdf_report.subprocess.run",
                side_effect=lambda command, **_: self._render_pdf(command),
            ),
        ):
            with self.assertRaisesRegex(ValueError, "bounded verification size"):
                export_pdf_report(analysis, output, browser=browser)
        self.assertEqual(output.read_bytes(), b"trusted previous report")
        self.assertFalse(list(self.root.glob(f".{output.name}.*.tmp")))

    def test_destination_race_and_replace_failure_never_overwrite_existing_bytes(
        self,
    ) -> None:
        browser, analysis = self._browser_and_analysis()
        output = self.root / "race.pdf"
        output.write_bytes(b"trusted previous report")
        original_copy = pdf_report._copy_stable_pdf

        def copy_then_race(source: Path, descriptor: int) -> None:
            original_copy(source, descriptor)
            output.write_bytes(b"concurrent writer")

        with (
            patch(
                "pysfmea.pdf_report.subprocess.run",
                side_effect=lambda command, **_: self._render_pdf(command),
            ),
            patch("pysfmea.pdf_report._copy_stable_pdf", side_effect=copy_then_race),
        ):
            with self.assertRaisesRegex(ValueError, "changed before atomic replacement"):
                export_pdf_report(analysis, output, browser=browser)
        self.assertEqual(output.read_bytes(), b"concurrent writer")
        self.assertFalse(list(self.root.glob(f".{output.name}.*.tmp")))

        output.write_bytes(b"trusted previous report")
        with (
            patch(
                "pysfmea.pdf_report.subprocess.run",
                side_effect=lambda command, **_: self._render_pdf(command),
            ),
            patch("pysfmea.pdf_report.os.replace", side_effect=OSError("blocked")),
        ):
            with self.assertRaisesRegex(OSError, "blocked"):
                export_pdf_report(analysis, output, browser=browser)
        self.assertEqual(output.read_bytes(), b"trusted previous report")
        self.assertFalse(list(self.root.glob(f".{output.name}.*.tmp")))

    def test_pdf_verifier_rejects_opened_identity_change(self) -> None:
        document = self.root / "identity.pdf"
        document.write_bytes(_minimal_pdf())
        original_fstat = pdf_report.os.fstat
        call_count = 0

        def changed_fstat(descriptor: int) -> stat_result:
            nonlocal call_count
            observed = original_fstat(descriptor)
            call_count += 1
            if call_count == 1:
                return observed
            values = list(observed)
            values[6] += 1
            return stat_result(values)

        with patch("pysfmea.pdf_report.os.fstat", side_effect=changed_fstat):
            with self.assertRaisesRegex(ValueError, "changed while"):
                verify_pdf_file(document)


if __name__ == "__main__":
    unittest.main()
