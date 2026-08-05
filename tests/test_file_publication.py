from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.file_publication import (
    atomic_publish_bytes,
    atomic_publish_text,
    inspect_artifact_destination,
)


class FilePublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_text_publication_is_exact_and_creates_parents(self) -> None:
        destination = self.root / "nested" / "artifact.csv"
        result = atomic_publish_text(
            destination,
            "heading\r\nvalue\r\n",
            encoding="utf-8-sig",
            label="test CSV",
        )

        self.assertEqual(result, destination)
        self.assertEqual(
            destination.read_bytes(),
            b"\xef\xbb\xbfheading\r\nvalue\r\n",
        )

    def test_rejects_oversized_content_before_touching_destination(self) -> None:
        destination = self.root / "preserved.txt"
        destination.write_text("prior", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "5-byte publication limit"):
            atomic_publish_bytes(destination, b"123456", max_bytes=5)

        self.assertEqual(destination.read_text(encoding="utf-8"), "prior")
        self.assertFalse(list(self.root.glob(".preserved.txt.*.tmp")))

    def test_rejects_symlink_without_changing_its_target(self) -> None:
        trusted = self.root / "trusted.txt"
        trusted.write_text("trusted", encoding="utf-8")
        linked = self.root / "linked.txt"
        try:
            linked.symlink_to(trusted)
        except OSError as exc:
            self.skipTest(f"file symbolic links are unavailable: {exc}")

        with self.assertRaisesRegex(ValueError, "symbolic link"):
            atomic_publish_text(linked, "replacement")

        self.assertTrue(linked.is_symlink())
        self.assertEqual(trusted.read_text(encoding="utf-8"), "trusted")

    def test_failed_atomic_replace_preserves_prior_file_and_cleans_staging(self) -> None:
        destination = self.root / "preserved.json"
        destination.write_text("prior\n", encoding="utf-8")

        with patch(
            "pysfmea.file_publication.os.replace", side_effect=OSError("blocked")
        ):
            with self.assertRaisesRegex(ValueError, "could not be published safely"):
                atomic_publish_text(destination, "new\n", label="JSON export")

        self.assertEqual(destination.read_text(encoding="utf-8"), "prior\n")
        self.assertFalse(list(self.root.glob(".preserved.json.*.tmp")))

    def test_concurrent_destination_change_is_preserved(self) -> None:
        destination = self.root / "concurrent.txt"
        destination.write_text("initial", encoding="utf-8")

        def replace_before_identity_check(
            path: Path,
            expected: tuple[int, int, int, int, int] | None,
        ) -> bool:
            destination.write_text("concurrent edit with new size", encoding="utf-8")
            return False

        with patch(
            "pysfmea.file_publication._destination_is_unchanged",
            side_effect=replace_before_identity_check,
        ):
            with self.assertRaisesRegex(ValueError, "changed before atomic replacement"):
                atomic_publish_text(destination, "new content")

        self.assertTrue(destination.exists())
        self.assertEqual(
            destination.read_text(encoding="utf-8"), "concurrent edit with new size"
        )
        self.assertFalse(list(self.root.glob(".concurrent.txt.*.tmp")))

    def test_retained_absent_state_refuses_a_newly_appeared_destination(self) -> None:
        destination = self.root / "reserved.json"
        expected = inspect_artifact_destination(destination, label="reserved artifact")
        destination.write_text("concurrent owner\n", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "changed before staging"):
            atomic_publish_text(
                destination,
                "generated artifact\n",
                label="reserved artifact",
                expected_destination=expected,
            )

        self.assertEqual(
            destination.read_text(encoding="utf-8"), "concurrent owner\n"
        )
        self.assertFalse(list(self.root.glob(".reserved.json.*.tmp")))


if __name__ == "__main__":
    unittest.main()
