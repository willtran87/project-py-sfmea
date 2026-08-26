from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.file_publication import (
    _destination_is_unchanged,
    _read_destination_snapshot_bytes,
    atomic_publish_bytes,
    atomic_publish_pair,
    atomic_publish_text,
    inspect_artifact_destination,
)


class FilePublicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()

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

    def test_rejects_invalid_publication_arguments_before_staging(self) -> None:
        destination = self.root / "invalid.txt"
        with self.assertRaisesRegex(TypeError, "content must be bytes"):
            atomic_publish_bytes(destination, "not bytes")  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "byte limit must be a positive integer"):
            atomic_publish_bytes(destination, b"content", max_bytes=True)
        with self.assertRaisesRegex(TypeError, "destination state is invalid"):
            atomic_publish_bytes(
                destination,
                b"content",
                expected_destination=object(),  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(TypeError, "content must be text"):
            atomic_publish_text(destination, b"not text")  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "could not be encoded"):
            atomic_publish_text(destination, "content", encoding="unknown-encoding")
        self.assertFalse(destination.exists())
        self.assertFalse(list(self.root.glob(".invalid.txt.*.tmp")))

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

    def test_unsafe_destination_is_treated_as_changed(self) -> None:
        directory = self.root / "not-a-file"
        directory.mkdir()

        self.assertFalse(_destination_is_unchanged(directory, None))
        with self.assertRaisesRegex(ValueError, "regular file path"):
            inspect_artifact_destination(directory)

    def test_rollback_snapshot_rejects_read_failures_and_oversized_prior_content(
        self,
    ) -> None:
        secondary = self.root / "receipt.json"
        secondary.write_bytes(b"prior receipt")
        state = inspect_artifact_destination(secondary, label="receipt")
        with patch("pysfmea.file_publication.os.open", side_effect=OSError("blocked")):
            with self.assertRaisesRegex(ValueError, "could not be retained for rollback"):
                _read_destination_snapshot_bytes(state, max_bytes=100, label="receipt")

        primary = self.root / "analysis.json"
        with self.assertRaisesRegex(
            ValueError, "prior secondary artifact exceeds the rollback byte limit"
        ):
            atomic_publish_pair(
                primary,
                b"analysis",
                secondary,
                b"receipt",
                secondary_max_bytes=3,
            )
        self.assertFalse(primary.exists())
        self.assertEqual(secondary.read_bytes(), b"prior receipt")

    def test_coordinated_pair_refuses_mismatched_or_conflicted_destinations(self) -> None:
        primary = self.root / "analysis.json"
        secondary = self.root / "receipt.json"
        expected = inspect_artifact_destination(primary, label="analysis")
        primary.write_bytes(b"concurrent owner")
        with self.assertRaisesRegex(ValueError, "primary artifact destination changed"):
            atomic_publish_pair(
                primary,
                b"analysis",
                secondary,
                b"receipt",
                expected_primary=expected,
            )
        with self.assertRaisesRegex(ValueError, "must be different files"):
            atomic_publish_pair(primary, b"analysis", primary, b"receipt")

        primary.unlink()
        real_replace = __import__("os").replace
        replacements = 0

        def fail_primary_after_secondary(source: str | Path, destination: str | Path) -> None:
            nonlocal replacements
            replacements += 1
            if replacements == 2:
                secondary.write_bytes(b"external owner")
                raise OSError("blocked primary")
            real_replace(source, destination)

        with patch(
            "pysfmea.file_publication.os.replace",
            side_effect=fail_primary_after_secondary,
        ):
            with self.assertRaisesRegex(
                ValueError, "primary artifact publication failed and secondary artifact rollback failed"
            ):
                atomic_publish_pair(primary, b"analysis", secondary, b"receipt")
        self.assertFalse(primary.exists())
        self.assertEqual(secondary.read_bytes(), b"external owner")

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

    def test_staged_verification_controls_atomic_replacement(self) -> None:
        destination = self.root / "verified.html"
        destination.write_text("trusted prior", encoding="utf-8")
        observed: list[bytes] = []

        def accept_staged(path: Path) -> bool:
            observed.append(path.read_bytes())
            return True

        atomic_publish_text(
            destination,
            "verified replacement",
            label="verified report",
            staged_verifier=accept_staged,
        )
        self.assertEqual(observed, [b"verified replacement"])
        self.assertEqual(
            destination.read_text(encoding="utf-8"), "verified replacement"
        )
        self.assertFalse(list(self.root.glob(".verified.html.*.tmp")))

    def test_failed_or_mutated_staged_verification_preserves_prior_content(
        self,
    ) -> None:
        destination = self.root / "preserved-report.html"

        def reject_staged(path: Path) -> bool:
            self.assertTrue(path.is_file())
            return False

        def raise_during_verification(path: Path) -> bool:
            self.assertTrue(path.is_file())
            raise RuntimeError("sensitive verifier detail")

        def mutate_staged(path: Path) -> bool:
            path.write_bytes(b"corrupt")
            return True

        def replace_staged_identity(path: Path) -> bool:
            replacement = path.with_name(path.name + ".replacement")
            replacement.write_bytes(path.read_bytes())
            replacement.replace(path)
            return True

        for label, verifier in (
            ("rejected", reject_staged),
            ("exception", raise_during_verification),
            ("mutated", mutate_staged),
            ("replaced", replace_staged_identity),
        ):
            with self.subTest(label=label):
                destination.write_text("trusted prior", encoding="utf-8")
                with self.assertRaisesRegex(
                    ValueError,
                    "staged verified report (verification failed|changed during verification)",
                ) as raised:
                    atomic_publish_text(
                        destination,
                        "changed",
                        label="verified report",
                        staged_verifier=verifier,
                    )
                self.assertNotIn("sensitive verifier detail", str(raised.exception))
                self.assertEqual(
                    destination.read_text(encoding="utf-8"), "trusted prior"
                )
                self.assertFalse(
                    list(self.root.glob(".preserved-report.html.*.tmp"))
                )

    def test_staged_verifier_cannot_hide_concurrent_destination_change(self) -> None:
        destination = self.root / "concurrent-report.html"
        destination.write_text("trusted prior", encoding="utf-8")

        def replace_destination(path: Path) -> bool:
            self.assertTrue(path.is_file())
            destination.write_text("concurrent owner", encoding="utf-8")
            return True

        with self.assertRaisesRegex(ValueError, "changed before atomic replacement"):
            atomic_publish_text(
                destination,
                "verified replacement",
                label="verified report",
                staged_verifier=replace_destination,
            )

        self.assertEqual(
            destination.read_text(encoding="utf-8"), "concurrent owner"
        )
        self.assertFalse(list(self.root.glob(".concurrent-report.html.*.tmp")))

    def test_coordinated_pair_publishes_both_artifacts(self) -> None:
        primary = self.root / "analysis.json"
        secondary = self.root / "receipt.json"
        primary.write_bytes(b"prior analysis")
        secondary.write_bytes(b"prior receipt")

        published = atomic_publish_pair(
            primary,
            b"new analysis",
            secondary,
            b"new receipt",
            primary_label="analysis",
            secondary_label="receipt",
        )

        self.assertEqual(published, (primary, secondary))
        self.assertEqual(primary.read_bytes(), b"new analysis")
        self.assertEqual(secondary.read_bytes(), b"new receipt")

    def test_coordinated_pair_rolls_back_receipt_when_analysis_fails(self) -> None:
        primary = self.root / "analysis.json"
        secondary = self.root / "receipt.json"
        primary.write_bytes(b"prior analysis")
        secondary.write_bytes(b"prior receipt")
        real_replace = __import__("os").replace
        replacements = 0

        def fail_primary(source: str | Path, destination: str | Path) -> None:
            nonlocal replacements
            replacements += 1
            if replacements == 2:
                raise OSError("blocked primary")
            real_replace(source, destination)

        with patch("pysfmea.file_publication.os.replace", side_effect=fail_primary):
            with self.assertRaisesRegex(
                ValueError, "analysis publication failed; receipt was rolled back"
            ):
                atomic_publish_pair(
                    primary,
                    b"new analysis",
                    secondary,
                    b"new receipt",
                    primary_label="analysis",
                    secondary_label="receipt",
                )

        self.assertEqual(primary.read_bytes(), b"prior analysis")
        self.assertEqual(secondary.read_bytes(), b"prior receipt")
        self.assertEqual(replacements, 3)

    def test_coordinated_pair_removes_new_receipt_when_analysis_fails(self) -> None:
        primary = self.root / "analysis.json"
        secondary = self.root / "receipt.json"
        primary.write_bytes(b"prior analysis")
        real_replace = __import__("os").replace
        replacements = 0

        def fail_primary(source: str | Path, destination: str | Path) -> None:
            nonlocal replacements
            replacements += 1
            if replacements == 2:
                raise OSError("blocked primary")
            real_replace(source, destination)

        with patch("pysfmea.file_publication.os.replace", side_effect=fail_primary):
            with self.assertRaisesRegex(
                ValueError, "analysis publication failed; receipt was rolled back"
            ):
                atomic_publish_pair(
                    primary,
                    b"new analysis",
                    secondary,
                    b"new receipt",
                    primary_label="analysis",
                    secondary_label="receipt",
                )

        self.assertEqual(primary.read_bytes(), b"prior analysis")
        self.assertFalse(secondary.exists())
        self.assertEqual(replacements, 2)


if __name__ == "__main__":
    unittest.main()
