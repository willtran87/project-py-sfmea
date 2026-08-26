from __future__ import annotations

import unittest
from pathlib import Path

from pysfmea.scanner import scan_repository


class DynamicBehaviorCorpusTests(unittest.TestCase):
    def test_dynamic_boundaries_are_retained_without_false_unique_targets(self) -> None:
        repository = (
            Path(__file__).resolve().parents[1]
            / "benchmarks"
            / "dynamic_python_corpus"
            / "repository"
        )
        analysis = scan_repository(repository)
        components = {
            f"{value['source']['path']}:{value['qualname']}": value
            for value in analysis["components"]
        }
        self.assertIn(
            "dynamic_dispatch.py:direct_dispatch",
            components["targets.py:primary"]["called_by"],
        )
        dynamic_components = [
            components[f"dynamic_dispatch.py:{name}"]
            for name in (
                "registry_dispatch",
                "reflective_dispatch",
                "imported_dispatch",
                "monkey_patch_dispatch",
            )
        ]
        dynamic_sites = [
            site
            for component in dynamic_components
            for site in component["call_sites"]
        ]
        self.assertGreaterEqual(len(dynamic_sites), 4)
        self.assertTrue(
            all(site.get("resolution") != "unique_static_target" for site in dynamic_sites)
        )
        self.assertNotIn(
            "dynamic_dispatch.py:monkey_patch_dispatch",
            components["targets.py:primary"]["called_by"],
        )
        inventory = {
            value["path"]: value
            for value in analysis["repository_inventory"]["entries"]
        }
        self.assertEqual(inventory["dynamic_dispatch.py"]["status"], "analyzed")
        self.assertEqual(inventory["targets.py"]["status"], "analyzed")


if __name__ == "__main__":
    unittest.main()
