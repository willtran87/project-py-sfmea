from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pysfmea.report import analysis_state_sha256
from pysfmea.scanner import scan_repository
from pysfmea.store import (
    AnalysisRevisionConflictError,
    load_analysis,
    save_analysis,
    update_item_review,
)


class StoreTests(unittest.TestCase):
    def test_atomic_save_refuses_to_replace_a_newer_disk_revision(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "code.py").write_text(
                "def act(value):\n    return value\n", encoding="utf-8"
            )
            path = root / "analysis.json"
            original = scan_repository(root)
            save_analysis(path, original)
            expected = hashlib.sha256(path.read_bytes()).hexdigest()

            newer = load_analysis(path)
            newer["project"]["name"] = "newer external revision"
            save_analysis(path, newer)
            newer_bytes = path.read_bytes()

            original["project"]["name"] = "stale reviewer revision"
            with self.assertRaises(AnalysisRevisionConflictError):
                save_analysis(path, original, expected_sha256=expected)

            self.assertEqual(path.read_bytes(), newer_bytes)

    def test_loading_preserves_stored_sfta_and_canonical_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "code.py").write_text(
                "def act(value):\n    return value\n", encoding="utf-8"
            )
            path = root / "analysis.json"
            save_analysis(path, scan_repository(root))

            first = load_analysis(path)
            second = load_analysis(path)

            self.assertEqual(first["sfta"]["generated_at"], second["sfta"]["generated_at"])
            self.assertEqual(
                analysis_state_sha256(first),
                analysis_state_sha256(second),
            )

    def test_atomic_round_trip_and_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "code.py").write_text("def act(value):\n    return value\n", encoding="utf-8")
            analysis = scan_repository(root)
            item_id = analysis["items"][0]["id"]
            path = root / "analysis.json"
            save_analysis(path, analysis)
            loaded = load_analysis(path)
            update_item_review(
                loaded,
                item_id,
                {
                    "severity": "7",
                    "causes": "First cause\nSecond cause",
                    "status": "in_review",
                },
            )
            self.assertEqual(loaded["items"][0]["review"]["severity"], 7)
            self.assertEqual(loaded["items"][0]["review"]["causes"], ["First cause", "Second cause"])
            update_item_review(
                loaded,
                item_id,
                {"reviewer": "Jordan", "end_effect": "Incorrect system output."},
            )
            history = loaded["items"][0]["review_history"]
            self.assertEqual(history[-1]["reviewer"], "Jordan")
            self.assertIn("end_effect", history[-1]["changes"])
            history_size = len(history)
            update_item_review(
                loaded,
                item_id,
                {"reviewer": "Jordan", "end_effect": "Incorrect system output."},
            )
            self.assertEqual(len(loaded["items"][0]["review_history"]), history_size)
            update_item_review(
                loaded,
                item_id,
                {
                    "status": "closed",
                    "approved_by": "Safety lead",
                    "approval_date": "2026-08-03",
                },
            )
            update_item_review(
                loaded,
                item_id,
                {"end_effect": "A revised system consequence."},
            )
            self.assertEqual(loaded["items"][0]["review"]["status"], "in_review")
            self.assertEqual(loaded["items"][0]["review"]["approved_by"], "")
            loaded["items"][0]["review"]["status"] = "closed"
            loaded["items"][0]["review"]["approved_by"] = "Safety lead"
            loaded["items"][0]["review"]["approval_date"] = "2026-08-03"
            update_item_review(
                loaded,
                item_id,
                {"post_action_severity_rationale": "Residual consequence reassessed."},
            )
            self.assertEqual(loaded["items"][0]["review"]["status"], "in_review")
            self.assertEqual(loaded["items"][0]["review"]["approved_by"], "")
            with self.assertRaises(ValueError):
                update_item_review(loaded, item_id, {"severity": 11})
            with self.assertRaises(ValueError):
                update_item_review(loaded, item_id, {"target_date": "tomorrow"})
            with self.assertRaises(ValueError):
                update_item_review(loaded, item_id, {"scanner": "not editable"})

    def test_migrates_legacy_analysis_without_losing_review(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "code.py").write_text("def act():\n    return True\n", encoding="utf-8")
            analysis = scan_repository(root)
            analysis["schema_version"] = "0.1"
            analysis.pop("generator", None)
            analysis.pop("system_context", None)
            analysis.pop("repository_inventory", None)
            analysis.pop("adapter_runs", None)
            item = analysis["items"][0]
            item["review"] = {"disposition": "accepted", "severity": 6}
            item.pop("source_change", None)
            path = root / "legacy.json"
            path.write_text(__import__("json").dumps(analysis), encoding="utf-8")

            loaded = load_analysis(path)
            migrated = loaded["items"][0]
            self.assertEqual(loaded["schema_version"], "0.6")
            self.assertEqual(loaded["generator"]["version"], "unknown")
            self.assertEqual(migrated["review"]["disposition"], "accepted")
            self.assertEqual(migrated["review"]["severity"], 6)
            self.assertIn("post_action_severity", migrated["review"])
            self.assertIn("required_safe_state", migrated["review"])
            self.assertEqual(
                loaded["repository_inventory"]["summary"]["by_status"],
                {"unresolved": 1},
            )
            self.assertEqual(
                loaded["adapter_runs"]["schema_version"],
                "pysfmea-adapter-run-ledger-1",
            )
            self.assertEqual(migrated["source_change"], "legacy")

    def test_malformed_persisted_analysis_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "analysis.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "root must be a JSON object"):
                load_analysis(path)

            (root / "code.py").write_text("def act():\n    return True\n", encoding="utf-8")
            analysis = scan_repository(root)
            analysis["items"][0]["review"]["causes"] = "not a list"
            path.write_text(json.dumps(analysis), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "review.causes"):
                load_analysis(path)

            analysis = scan_repository(root)
            analysis["context"]["quality"]["unreviewed_level"] = "ignore"
            path.write_text(json.dumps(analysis), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "quality.unreviewed_level"):
                load_analysis(path)

    def test_fractional_rating_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "code.py").write_text("def act():\n    return True\n", encoding="utf-8")
            analysis = scan_repository(root)
            with self.assertRaisesRegex(ValueError, "ratings"):
                update_item_review(analysis, analysis["items"][0]["id"], {"severity": 1.5})


if __name__ == "__main__":
    unittest.main()
