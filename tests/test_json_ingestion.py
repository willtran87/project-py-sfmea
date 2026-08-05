from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.json_ingestion import (
    BoundedFileSnapshotError,
    load_bounded_file_snapshot,
    load_bounded_json_document,
    load_bounded_json_file,
    parse_bounded_json_bytes,
)


class JsonIngestionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def load(self, path: Path, **limits: int) -> tuple[Path, object, int]:
        return load_bounded_json_file(
            path,
            label="governed test JSON",
            max_bytes=limits.get("max_bytes", 10_000),
            max_depth=limits.get("max_depth", 20),
            max_nodes=limits.get("max_nodes", 1_000),
        )

    def test_exact_strict_utf8_json_round_trip(self) -> None:
        path = self.root / "valid.json"
        raw = '{"name":"café","values":[1,true,null]}'.encode()
        path.write_bytes(raw)

        loaded_path, value, size = self.load(path)

        self.assertEqual(loaded_path, path)
        self.assertEqual(value, {"name": "café", "values": [1, True, None]})
        self.assertEqual(size, len(raw))

        document = load_bounded_json_document(
            path,
            label="governed test JSON",
            max_bytes=10_000,
            max_depth=20,
            max_nodes=1_000,
        )
        self.assertEqual(document.path, path)
        self.assertEqual(document.value, value)
        self.assertEqual(document.raw, raw)
        self.assertEqual(document.size, len(raw))

        snapshot = load_bounded_file_snapshot(
            path,
            label="governed test file",
            max_bytes=10_000,
        )
        self.assertEqual(snapshot.path, path)
        self.assertEqual(snapshot.raw, raw)
        self.assertEqual(snapshot.size, len(raw))

        with self.assertRaisesRegex(ValueError, "10-byte limit") as captured:
            load_bounded_file_snapshot(
                path,
                label="governed test file",
                max_bytes=10,
            )
        self.assertIsInstance(captured.exception, BoundedFileSnapshotError)
        self.assertEqual(captured.exception.bytes_consumed, 11)

    def test_duplicate_keys_and_non_finite_numbers_are_rejected(self) -> None:
        cases = {
            "duplicate.json": ('{"value":1,"value":2}', "duplicate object key"),
            "nan.json": ('{"value":NaN}', "non-finite number"),
            "infinity.json": ('{"value":Infinity}', "non-finite number"),
            "overflow.json": ('{"value":1e9999}', "non-finite number"),
            "negative-overflow.json": ('{"value":-1e9999}', "non-finite number"),
        }
        for filename, (document, message) in cases.items():
            with self.subTest(filename=filename):
                path = self.root / filename
                path.write_text(document, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, message):
                    self.load(path)

    def test_captured_bytes_use_the_same_strict_contract(self) -> None:
        loaded = parse_bounded_json_bytes(
            b'{"values":[1,2,3]}',
            label="captured JSON",
            max_bytes=100,
            max_depth=10,
            max_nodes=10,
        )
        self.assertEqual(loaded, {"values": [1, 2, 3]})

        cases = (
            (b'{"value":1,"value":2}', "duplicate object key"),
            (b'{"value":1e9999}', "non-finite number"),
            (b"\xff", "valid UTF-8 JSON"),
        )
        for raw, message in cases:
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(ValueError, message):
                    parse_bounded_json_bytes(
                        raw,
                        label="captured JSON",
                        max_bytes=100,
                        max_depth=10,
                        max_nodes=10,
                    )
        with self.assertRaisesRegex(ValueError, "2-node JSON structure limit"):
            parse_bounded_json_bytes(
                b'{"values":[1,2,3]}',
                label="captured JSON",
                max_bytes=100,
                max_depth=10,
                max_nodes=2,
            )

    def test_byte_depth_and_node_limits_are_enforced(self) -> None:
        path = self.root / "bounded.json"
        path.write_text(json.dumps({"outer": {"inner": [1, 2, 3]}}), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "10-byte limit"):
            self.load(path, max_bytes=10)
        with self.assertRaisesRegex(ValueError, "1-level JSON depth limit"):
            self.load(path, max_depth=1)
        with self.assertRaisesRegex(ValueError, "2-node JSON structure limit"):
            self.load(path, max_nodes=2)

    def test_opened_and_final_identity_must_match(self) -> None:
        path = self.root / "changing.json"
        path.write_text("{}", encoding="utf-8")

        with patch(
            "pysfmea.json_ingestion._same_file_identity",
            side_effect=[True, False],
        ):
            with self.assertRaisesRegex(
                ValueError, "changed during bounded consumption"
            ) as captured:
                self.load(path)
        self.assertIsInstance(captured.exception, BoundedFileSnapshotError)
        self.assertEqual(captured.exception.bytes_consumed, 2)

    def test_non_file_and_symbolic_link_inputs_are_rejected(self) -> None:
        directory = self.root / "directory"
        directory.mkdir()
        with self.assertRaisesRegex(ValueError, "regular non-symbolic-link file"):
            self.load(directory)

        target = self.root / "target.json"
        target.write_text("{}", encoding="utf-8")
        linked = self.root / "linked.json"
        try:
            linked.symlink_to(target)
        except OSError as exc:
            self.skipTest(f"file symbolic links are unavailable: {exc}")
        with self.assertRaisesRegex(ValueError, "regular non-symbolic-link file"):
            self.load(linked)


if __name__ == "__main__":
    unittest.main()
