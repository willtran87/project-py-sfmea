from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.qualification_readiness import qualification_readiness


class QualificationReadinessTests(unittest.TestCase):
    def test_public_template_is_explicitly_not_ready(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        result = qualification_readiness(
            repository / "examples" / "qualification-campaign.json"
        )
        self.assertFalse(result["ready_for_campaign_execution"])
        self.assertFalse(result["checks"]["no_placeholders"])
        self.assertFalse(result["checks"]["all_retained_artifacts_present"])

    def test_complete_local_population_passes_execution_preflight(self) -> None:
        repository = Path(__file__).resolve().parents[1]
        template = json.loads(
            (repository / "examples" / "qualification-campaign.json").read_text(
                encoding="utf-8"
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = copy.deepcopy(template)
            manifest["title"] = "Independent retained scanner campaign"
            manifest["purpose"] = "Measure exact scanner behavior on a preselected corpus."
            manifest["governance"] = {
                "independent": True,
                "labeled_by": "Benchmark Team",
                "approved_by": "Assurance Authority",
                "approval_date": "2026-08-25",
                "selection_method": "Risk-stratified preselection.",
                "representativeness_rationale": "Three declared segments are covered.",
            }
            manifest["thresholds"]["minimum_repositories"] = 1
            manifest["thresholds"]["minimum_frameworks"] = 1
            manifest["thresholds"]["minimum_domains"] = 1
            manifest["repositories"] = [manifest["repositories"][0]]
            manifest["repositories"][0]["id"] = "service-a"
            manifest["repositories"][0]["selection_rationale"] = "Preselected service."
            for field in ("analysis", "corpus", "evaluation"):
                path = root / manifest["repositories"][0][field]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}\n", encoding="utf-8")
            path = root / "campaign.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            result = qualification_readiness(path)
        self.assertTrue(result["ready_for_campaign_execution"], result["next_actions"])


if __name__ == "__main__":
    unittest.main()
