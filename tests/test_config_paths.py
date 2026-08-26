from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pysfmea.config import load_config


class ConfigurationPathTests(unittest.TestCase):
    def test_cache_output_path_remains_repository_relative(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = root / ".artifacts"
            artifacts.mkdir()
            config_path = artifacts / "sfmea.toml"
            config_path.write_text(
                "[project]\nname = 'Example'\n\n"
                "[scan]\ncache_enabled = true\n"
                "cache_path = '.artifacts/pysfmea-fact-cache.json'\n",
                encoding="utf-8",
            )

            config, _ = load_config(config_path)

            self.assertEqual(
                config["scan"]["cache_path"],
                ".artifacts/pysfmea-fact-cache.json",
            )

    def test_diagnostic_targets_are_governed_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "sfmea.toml"
            config_path.write_text(
                "[scan]\n"
                "target_evidence_readiness_percent = 80\n"
                "target_architecture_traceability_percent = 92\n"
                "target_cross_stack_percent = 93\n"
                "target_guidance_specificity_percent = 96\n"
                "target_cold_scan_seconds = 8\n",
                encoding="utf-8",
            )

            config, _ = load_config(config_path)

            self.assertEqual(config["scan"]["target_evidence_readiness_percent"], 80)
            self.assertEqual(config["scan"]["target_cold_scan_seconds"], 8)

            config_path.write_text(
                "[scan]\ntarget_cross_stack_percent = 101\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "target_cross_stack_percent"):
                load_config(config_path)


if __name__ == "__main__":
    unittest.main()
