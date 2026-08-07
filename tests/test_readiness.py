from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pysfmea.config import write_config_template
from pysfmea.readiness import repository_readiness


class ReadinessTests(unittest.TestCase):
    def test_evidence_onboarding_resolves_relative_coverage_and_actions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("def run():\n    return True\n", encoding="utf-8")
            missing = repository_readiness(root)
            self.assertFalse(missing["ready"])
            self.assertEqual(missing["checks"][-1]["id"], "configuration.file")

            config_path = root / "sfmea.toml"
            write_config_template(config_path)
            configured = (
                config_path.read_text(encoding="utf-8")
                .replace("Example Python System", "Evidence Service")
                .replace("Example unacceptable system condition", "Incorrect result")
                .replace("Example reviewer", "Independent Reviewer")
                .replace("src/example/", "")
                .replace('coverage_json = ""', 'coverage_json = "evidence/coverage.json"')
            )
            config_path.write_text(configured, encoding="utf-8")
            unavailable = repository_readiness(root)
            coverage = next(
                check
                for check in unavailable["checks"]
                if check["id"] == "evidence.coverage"
            )
            self.assertEqual(coverage["status"], "error")
            self.assertIn("coverage json", coverage["next_action"].casefold())

            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "coverage.json").write_text(
                '{"files": {}}', encoding="utf-8"
            )
            available = repository_readiness(root)
            coverage = next(
                check
                for check in available["checks"]
                if check["id"] == "evidence.coverage"
            )
            self.assertEqual(coverage["status"], "pass")


if __name__ == "__main__":
    unittest.main()
