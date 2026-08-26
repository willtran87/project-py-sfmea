from __future__ import annotations

import unittest

from scripts.report_browser_gate import _validate_analysis_population


class ReportBrowserPopulationTests(unittest.TestCase):
    def test_population_thresholds_pass_and_fail_explicitly(self) -> None:
        analysis = {"summary": {"components": 1441, "candidate_failure_modes": 11521}}
        _validate_analysis_population(
            analysis, min_components=1400, min_failure_modes=11000
        )
        with self.assertRaisesRegex(ValueError, "at least 1442"):
            _validate_analysis_population(
                analysis, min_components=1442, min_failure_modes=None
            )
        with self.assertRaisesRegex(ValueError, "require --analysis"):
            _validate_analysis_population(
                None, min_components=1, min_failure_modes=None
            )
