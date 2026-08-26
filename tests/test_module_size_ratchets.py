from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_module_size_ratchets import module_size_record


class ModuleSizeRatchetTests(unittest.TestCase):
    def test_growth_and_concentration_are_both_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "large.py").write_text("x = 1\n" * 5, encoding="utf-8")
            (root / "small.py").write_text("x = 1\n", encoding="utf-8")
            policy = root / "policy.json"
            policy.write_text(
                json.dumps(
                    {
                        "format": "pysfmea-module-size-ratchet-1",
                        "watched_maximum_lines": {"large.py": 4},
                        "maximum_unlisted_module_lines": 1,
                        "maximum_top_five_percent": 80.0,
                        "minimum_module_count": 2,
                    }
                ),
                encoding="utf-8",
            )
            result = module_size_record(root, policy)
        self.assertFalse(result["passed"])
        self.assertEqual(
            {value["code"] for value in result["violations"]},
            {"watched_module_growth", "top_five_concentration_regression"},
        )

    def test_current_repository_policy_is_satisfied(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        result = module_size_record(
            repository / "src" / "pysfmea",
            repository / "quality" / "module-size-ratchet.json",
        )
        self.assertTrue(result["passed"], result["violations"])


if __name__ == "__main__":
    unittest.main()
