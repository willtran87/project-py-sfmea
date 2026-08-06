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

    def test_invalid_repeat_count_fails_closed(self) -> None:
        from scripts.benchmark_scan import benchmark_repository

        with self.assertRaisesRegex(ValueError, "between 1 and 20"):
            benchmark_repository(Path.cwd(), repeats=0)


if __name__ == "__main__":
    unittest.main()
