from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class PerformanceBenchmarkTests(unittest.TestCase):
    def test_benchmark_is_bounded_reproducible_and_machine_readable(self) -> None:
        repository = (
            Path(__file__).resolve().parents[1]
            / "benchmarks"
            / "python_sfmea_corpus"
            / "repository"
        )
        script = Path(__file__).resolve().parents[1] / "scripts" / "benchmark_scan.py"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "performance.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    str(repository),
                    "--repeats",
                    "2",
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            evidence = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(evidence["format"], "pysfmea-scan-performance-1")
            self.assertTrue(evidence["repository"]["stable_baseline"])
            self.assertEqual(evidence["summary"]["repeats"], 2)
            self.assertGreater(evidence["summary"]["maximum_peak_traced_bytes"], 0)
            self.assertEqual(len(evidence["runs"]), 2)
            phase_medians = evidence["summary"]["phase_medians_seconds"]
            self.assertIn("python_parsing", phase_medians)
            self.assertIn("component_and_candidate_generation", phase_medians)
            self.assertTrue(all(value >= 0 for value in phase_medians.values()))
            self.assertEqual(
                set(evidence["runs"][0]["phases_seconds"]), set(phase_medians)
            )
            self.assertIsInstance(evidence["repository"]["inventory_bytes"], int)
            self.assertGreater(evidence["repository"]["inventory_bytes"], 0)
            self.assertGreater(evidence["repository"]["source_snapshot_bytes"], 0)
            self.assertGreaterEqual(
                evidence["repository"]["test_evidence_snapshot_bytes"], 0
            )

    def test_invalid_repeat_count_fails_closed(self) -> None:
        from scripts.benchmark_scan import benchmark_repository

        with self.assertRaisesRegex(ValueError, "between 1 and 20"):
            benchmark_repository(Path.cwd(), repeats=0)

    def test_exact_fact_reuse_and_ci_budgets_are_explicit(self) -> None:
        from scripts.benchmark_scan import benchmark_repository

        repository = (
            Path(__file__).resolve().parents[1]
            / "benchmarks"
            / "python_sfmea_corpus"
            / "repository"
        )
        result = benchmark_repository(
            repository,
            repeats=2,
            reuse_facts=True,
            max_median_seconds=0.000000001,
            max_peak_bytes=1,
        )
        self.assertTrue(result["summary"]["fact_reuse_enabled"])
        self.assertGreater(result["summary"]["fact_cache_hits"], 0)
        self.assertFalse(result["budgets"]["passed"])
        self.assertFalse(result["budgets"]["checks"]["median_seconds"])
        self.assertFalse(result["budgets"]["checks"]["peak_traced_bytes"])


if __name__ == "__main__":
    unittest.main()
